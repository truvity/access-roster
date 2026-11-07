//! The item engine: the four calls of the item contract that store@ makes
//! (`sluis.port.item.v2alpha1.ItemService`).
//!
//! The trait is the seam of the unit tests, which run an in-process engine. The Connect client
//! below is the only code that talks to a driver, through `sluis_kit::dial`.

use std::future::Future;

use connectrpc::error::ErrorCode;
use sluis_kit::{Client, Transport, refusal_reason};
use sluis_proto::sluis::port::item::v2alpha1::{
    DriverItem, ItemGetRequest, ItemServiceClient, QueryRequest, QueryResponse, TailLogRequest,
    TailLogResponse, TransactRequest, TransactResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::Refusal;

/// Why an engine call did not give an answer.
#[derive(Debug, PartialEq, Eq)]
pub enum EngineError {
    /// A condition of a `Transact` failed; the index of the first one that did, when the driver
    /// says it (`conditions[N]` in the `Refusal` field path).
    Aborted(Option<usize>),
    /// The driver is down, slow or answered something outside its contract: store@ fails closed.
    Unavailable,
    /// The change log no longer holds the sequence asked for, or has not reached it: a change could be missed.
    SequenceExpired,
}

/// The rows of the change log as a task reads them from the driver: bounded, so a slow consumer stops the read and
/// the driver's stream waits (flow control is the only buffer). The channel closing without an error is a driver that
/// ended its stream.
pub type LogRows = tokio::sync::mpsc::Receiver<Result<TailLogResponse, EngineError>>;

/// Rows a tail task may hold before it waits for the consumer.
const LOG_BUFFER: usize = 64;

/// The durable or the temp engine, as store@ sees it. A clone shares the engine: a watch stream outlives the call.
pub trait ItemEngine: Clone + Send + Sync + 'static {
    /// The item at a key, or None when it is absent or expired (the driver hides an expired item).
    fn get(
        &self,
        key: Vec<u8>,
        linearizable: bool,
    ) -> impl Future<Output = Result<Option<DriverItem>, EngineError>> + Send;

    /// One page of items by key prefix or by index entry.
    fn query(
        &self,
        request: QueryRequest,
    ) -> impl Future<Output = Result<QueryResponse, EngineError>> + Send;

    /// Conditions, puts and deletes, all or none. The reply holds the puts as written.
    fn transact(
        &self,
        request: TransactRequest,
    ) -> impl Future<Output = Result<TransactResponse, EngineError>> + Send;

    /// The change log after `from_sequence` (0: from now) of the log with `log_epoch`. The stream ends with an error when
    /// the driver fails; a sequence the log does not hold, or an epoch it does not have (the log was made again), is
    /// [`EngineError::SequenceExpired`], as the first thing it says or as the end of the stream.
    fn tail_log(
        &self,
        from_sequence: u64,
        log_epoch: u64,
    ) -> impl Future<Output = Result<LogRows, EngineError>> + Send;
}

/// The driver on its socket.
#[derive(Clone)]
pub struct DriverEngine {
    client: ItemServiceClient<Transport>,
    port: &'static str,
}

impl DriverEngine {
    /// A client of the driver at the socket of `client`. `port` names the port in logs.
    #[must_use]
    pub fn new(client: &Client, port: &'static str) -> Self {
        Self {
            client: ItemServiceClient::new(client.transport(), client.config()),
            port,
        }
    }

    fn down(&self, e: &connectrpc::ConnectError) -> EngineError {
        // The code and the reason only: an error never carries a value.
        tracing::warn!(port = self.port, code = e.code.as_str(), reason = ?refusal_reason(e), "driver call failed");
        EngineError::Unavailable
    }
}

/// The field path of the `Refusal` detail of an error, if it has one. The kit exposes the reason
/// only (`refusal_reason`); the same decoding gives the path.
fn field_path(err: &connectrpc::ConnectError) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use buffa::Message as _;
    err.details.iter().find_map(|d| {
        if d.type_url.rsplit('/').next()? != "sluis.type.v2alpha1.Refusal" {
            return None;
        }
        let raw = d.value.as_deref()?;
        let bytes = STANDARD_NO_PAD
            .decode(raw)
            .or_else(|_| STANDARD.decode(raw))
            .ok()?;
        Refusal::decode_from_slice(&bytes)
            .ok()
            .map(|r| r.field_path)
    })
}

/// The index in a `conditions[N]` field path.
fn condition_index(path: &str) -> Option<usize> {
    path.strip_prefix("conditions[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

impl ItemEngine for DriverEngine {
    async fn get(
        &self,
        key: Vec<u8>,
        linearizable: bool,
    ) -> Result<Option<DriverItem>, EngineError> {
        let req = ItemGetRequest {
            key,
            linearizable,
            ..ItemGetRequest::default()
        };
        match self.client.get(req).await {
            Ok(r) => Ok(Some(
                r.into_owned()
                    .item
                    .into_option()
                    .ok_or(EngineError::Unavailable)?,
            )),
            Err(e) if e.code == ErrorCode::NotFound => Ok(None),
            Err(e) => Err(self.down(&e)),
        }
    }

    async fn query(&self, request: QueryRequest) -> Result<QueryResponse, EngineError> {
        match self.client.query(request).await {
            Ok(r) => Ok(r.into_owned()),
            Err(e) => Err(self.down(&e)),
        }
    }

    async fn transact(&self, request: TransactRequest) -> Result<TransactResponse, EngineError> {
        match self.client.transact(request).await {
            Ok(r) => Ok(r.into_owned()),
            Err(e) if e.code == ErrorCode::Aborted => {
                // The driver names the first failed condition in the field path of the detail.
                Err(EngineError::Aborted(
                    field_path(&e).as_deref().and_then(condition_index),
                ))
            }
            Err(e) => Err(self.down(&e)),
        }
    }

    async fn tail_log(&self, from_sequence: u64, log_epoch: u64) -> Result<LogRows, EngineError> {
        self.tail(from_sequence, log_epoch).await
    }
}

impl DriverEngine {
    /// The reason of a refusal that says the sequence is gone.
    fn tail_error(&self, e: &connectrpc::ConnectError) -> EngineError {
        if e.code == ErrorCode::FailedPrecondition
            && refusal_reason(e).as_deref() == Some("sequence_expired")
        {
            return EngineError::SequenceExpired;
        }
        self.down(e)
    }
}

impl DriverEngine {
    async fn tail(&self, from_sequence: u64, log_epoch: u64) -> Result<LogRows, EngineError> {
        let mut stream = self
            .client
            .tail_log(TailLogRequest {
                from_sequence,
                log_epoch,
                ..TailLogRequest::default()
            })
            .await
            .map_err(|e| self.tail_error(&e))?;
        let (tx, rx) = tokio::sync::mpsc::channel(LOG_BUFFER);
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let next = match stream.message().await {
                    Ok(Some(m)) => Ok(m.to_owned_message()),
                    Ok(None) => return,
                    Err(e) => Err(this.tail_error(&e)),
                };
                let failed = next.is_err();
                // The consumer is gone (the watch ended): stop reading, and the driver's stream is dropped.
                if tx.send(next).await.is_err() || failed {
                    return;
                }
            }
        });
        Ok(rx)
    }
}
