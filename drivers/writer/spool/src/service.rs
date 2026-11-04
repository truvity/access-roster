//! The `TransportService` over a [`Spool`], as two servers: [`Emit`] on `emit.sock` (every
//! emitting actor, by the call graph) and [`Consume`] on `receive.sock` (the writer only). A
//! method that is not the socket's is `unimplemented`. Each [`Error`] becomes a Connect code with a
//! `Refusal` reason (contracts.md "Errors"); an error names a field, never a value.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use connectrpc::error::ErrorCode;
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use sluis_kit::{peer, refusal};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, AuditMessage, Delivery, EmitRequest, EmitResponse, ReceiveRequest,
    ReceiveResponse, TransportService,
};

use buffa::Message as _;

use crate::{Entry, Error, Spool};

/// The most deliveries in one response when the consumer names none, and the most it may ask for.
const DEFAULT_BATCH: usize = 64;
const MAX_BATCH: usize = 1024;
/// About how many bytes of message one response holds.
const BATCH_BYTES: usize = 4 << 20;
/// The most ids in one acknowledgement.
const MAX_ACK: usize = 10_000;

/// The emit side of one spool.
#[derive(Clone)]
pub struct Emit {
    /// The spool.
    pub spool: Spool,
    /// The boundary, which completes the emitter name `<actor>@<boundary>`.
    pub boundary: String,
}

/// The consume side of one spool.
#[derive(Clone)]
pub struct Consume(pub Spool);

fn refuse(e: &Error, field: &str) -> ConnectError {
    match e {
        Error::Bound => refusal(ErrorCode::InvalidArgument, "bound", field),
        // The bound is full: the emitter is told, and nothing is dropped (0029).
        Error::Full => {
            tracing::error!("the spool is full; emits are refused");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
        // An earlier disk failure left the files uncertain: every call fails until a restart
        // recovers the directory, and nothing is acknowledged on a basis the spool cannot vouch for.
        Error::Poisoned => {
            tracing::error!("the spool is poisoned by an earlier disk failure; restart to recover");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
        Error::Corrupt => {
            tracing::error!("a stored frame no longer holds its sum");
            refusal(ErrorCode::Internal, "engine", "")
        }
        Error::Io(io) => {
            tracing::error!(error = %io, "the spool directory failed");
            refusal(ErrorCode::Unavailable, "engine", "")
        }
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
    field: &'static str,
) -> Result<T, ConnectError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r.map_err(|e| refuse(&e, field)),
        Err(_) => Err(refusal(ErrorCode::Internal, "engine", "")),
    }
}

fn unsupported<T>() -> ServiceResult<T> {
    Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
}

impl TransportService for Emit {
    async fn emit(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        // The emitter is the peer of the socket, never a field of the message. The guard has
        // already named it; a call without a peer cannot have passed it.
        let p = peer(ctx.extensions())
            .ok_or_else(|| refusal(ErrorCode::PermissionDenied, "caller", ""))?;
        let emitter = format!("{}@{}", p.name, self.boundary);
        let req = request.to_owned_message();
        let m = req
            .message
            .as_option()
            .ok_or_else(|| refusal(ErrorCode::InvalidArgument, "schema", "message"))?;
        if m.uid.is_empty() {
            return Err(refusal(ErrorCode::InvalidArgument, "schema", "message.uid"));
        }
        if m.record.is_empty() {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "schema",
                "message.record",
            ));
        }
        let bytes = m.encode_to_vec();
        let spool = self.spool.clone();
        // `blocking` changes nothing here: every accepted message is already on disk (0029).
        blocking(move || spool.append(&emitter, &bytes), "message").await?;
        Response::ok(EmitResponse::default())
    }

    async fn receive(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<ServiceStream<ReceiveResponse>> {
        unsupported()
    }

    async fn ack(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        unsupported()
    }
}

fn delivery(e: Entry) -> Result<Delivery, ConnectError> {
    let message = AuditMessage::decode_from_slice(&e.message)
        .map_err(|_| refusal(ErrorCode::Internal, "engine", ""))?;
    Ok(Delivery {
        delivery_id: e.seq,
        emitter: e.emitter,
        message: message.into(),
        ..Delivery::default()
    })
}

impl TransportService for Consume {
    async fn emit(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        unsupported()
    }

    async fn receive(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<ServiceStream<ReceiveResponse>> {
        // One consumer: two would split the order between them.
        let slot = self
            .0
            .take_receiver()
            .ok_or_else(|| refusal(ErrorCode::AlreadyExists, "taken", ""))?;
        let max = match usize::try_from(request.max_batch).unwrap_or(MAX_BATCH) {
            0 => DEFAULT_BATCH,
            n => n.min(MAX_BATCH),
        };
        let spool = self.0.clone();
        let (tail, closed) = (spool.watch_tail(), spool.closed());
        // The state: where the consumer is, and what it waits on. A fresh stream starts from the
        // oldest unacknowledged message, which is how a restart replays.
        let state = (spool, slot, 0u64, tail, Some(Box::pin(closed)));
        let stream = futures::stream::unfold(
            state,
            move |(spool, slot, cursor, mut tail, mut closed)| async move {
                loop {
                    let s = spool.clone();
                    let after = cursor;
                    let read = blocking(move || s.read_from(after, max, BATCH_BYTES), "").await;
                    let (entries, seen) = match read {
                        Ok(r) => r,
                        // An error ends the stream; the consumer opens another.
                        Err(e) => return Some((Err(e), (spool, slot, u64::MAX, tail, None))),
                    };
                    if let Some(last) = entries.last().map(|e| e.seq) {
                        let deliveries = entries
                            .into_iter()
                            .map(delivery)
                            .collect::<Result<Vec<_>, _>>();
                        return Some((
                            deliveries.map(|deliveries| ReceiveResponse {
                                deliveries,
                                ..ReceiveResponse::default()
                            }),
                            (spool, slot, last, tail, closed),
                        ));
                    }
                    // Nothing newer than what was read: wait for a newer message, or the end.
                    let c = closed.as_mut()?;
                    tokio::select! {
                        r = tail.wait_for(|t| *t > seen) => if r.is_err() { return None },
                        () = c => return None,
                    }
                }
            },
        );
        Response::stream_ok(Box::pin(stream))
    }

    async fn ack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        let ids: Vec<u64> = request.delivery_ids.iter().copied().collect();
        if ids.len() > MAX_ACK {
            return Err(refusal(ErrorCode::InvalidArgument, "bound", "delivery_ids"));
        }
        let spool = self.0.clone();
        blocking(move || spool.ack(&ids), "delivery_ids").await?;
        Response::ok(AckResponse::default())
    }
}
