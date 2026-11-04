//! The ports the indexer calls, as clients of the kit, and how their answers are told apart.
//!
//! The indexer is a client of everything it uses and serves no socket of its own. Every answer that is
//! not a success is one of two things (0028: a check that fails stops indexing and raises an alert,
//! never a skip):
//!
//! - [`Failure::Transient`]: the other side is down, late or busy, or a second indexer moved the cursor.
//!   Nothing is wrong with the log. The pass is tried again, later.
//! - [`Failure::Refused`]: the log, or an answer about it, is not what it must be. The log is halted:
//!   its cursor stays where it is, and the alert names the closed word and the position, never a value.

use std::path::Path;
use std::time::Duration;

use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use sluis_kit::{Client, Transport, dial};
use sluis_proto::sluis::key::v2alpha1::KeyServiceClient;
use sluis_proto::sluis::policy::v2alpha1::PolicyServiceClient;
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobListRequest, BlobServiceClient,
};
use sluis_proto::sluis::port::index::v2alpha1::IndexServiceClient;

/// How long one call may take.
pub const CALL: Duration = Duration::from_secs(30);

/// Why a pass stopped.
#[derive(Debug)]
pub enum Failure {
    /// Try again later.
    Transient(String),
    /// Halt the log: the closed word, and where.
    Refused(&'static str, String),
}

impl Failure {
    /// A refusal with a word and a position (a size, an index; never a value).
    #[must_use]
    pub fn refused(word: &'static str, at: impl std::fmt::Display) -> Self {
        Self::Refused(word, at.to_string())
    }

    /// Classifies a Connect error: a service that is down or busy is transient, anything else the
    /// service said on purpose is a refusal.
    #[must_use]
    pub fn of(what: &'static str, e: &ConnectError) -> Self {
        let reason = sluis_kit::refusal_reason(e).unwrap_or_else(|| "-".into());
        match e.code {
            ErrorCode::Unavailable
            | ErrorCode::DeadlineExceeded
            | ErrorCode::ResourceExhausted
            | ErrorCode::Aborted
            | ErrorCode::Internal
            | ErrorCode::Unknown
            | ErrorCode::Canceled => {
                Self::Transient(format!("{what}: {} ({reason})", e.code.as_str()))
            }
            _ => Self::Refused(what, format!("{} ({reason})", e.code.as_str())),
        }
    }
}

/// The clients the indexer uses, each on its own socket.
#[derive(Clone)]
pub struct Ports {
    /// The audit blob, read only (the blob port).
    pub blob: BlobServiceClient<Transport>,
    /// key@, on the indexer's own socket: Open of `evidence`.
    pub keys: KeyServiceClient<Transport>,
    /// policy: the grant of each pass.
    pub policy: PolicyServiceClient<Transport>,
    /// The index driver, write side.
    pub index: IndexServiceClient<Transport>,
}

/// The sockets of [`Ports`].
#[derive(Clone, Debug)]
pub struct Sockets {
    /// The blob driver the indexer reads.
    pub blob: std::path::PathBuf,
    /// key@'s socket for the indexer.
    pub key: std::path::PathBuf,
    /// policy's socket.
    pub policy: std::path::PathBuf,
    /// The index driver's write socket (`index.sock`).
    pub index: std::path::PathBuf,
    /// store@'s socket.
    pub store: std::path::PathBuf,
}

impl Sockets {
    /// The sockets of the layout (PLAN.md "Socket layout") below `run`, for a boundary.
    #[must_use]
    pub fn under(run: &Path, boundary: &str) -> Self {
        Self {
            blob: run.join("indexer").join(boundary).join("blob.sock"),
            key: run
                .join("key")
                .join(boundary)
                .join("indexer")
                .join("key.sock"),
            policy: run.join("policy").join(format!("{boundary}.sock")),
            index: run.join("indexer").join(boundary).join("index.sock"),
            store: run.join("store").join(format!("{boundary}.sock")),
        }
    }
}

impl Ports {
    /// Clients for the sockets; nothing is dialled until the first call.
    #[must_use]
    pub fn new(s: &Sockets) -> Self {
        let (b, k, p, i): (Client, Client, Client, Client) =
            (dial(&s.blob), dial(&s.key), dial(&s.policy), dial(&s.index));
        Self {
            blob: BlobServiceClient::new(b.transport(), b.config()),
            keys: KeyServiceClient::new(k.transport(), k.config()),
            policy: PolicyServiceClient::new(p.transport(), p.config()),
            index: IndexServiceClient::new(i.transport(), i.config()),
        }
    }

    /// Reads an object of the blob; `None` when there is none.
    ///
    /// # Errors
    ///
    /// [`Failure`] for any other answer.
    pub async fn get(&self, path: &str) -> Result<Option<Vec<u8>>, Failure> {
        let req = BlobGetRequest {
            path: path.to_owned(),
            ..BlobGetRequest::default()
        };
        match tokio::time::timeout(CALL, self.blob.get(req)).await {
            Err(_) => Err(Failure::Transient("blob.get: timed out".into())),
            Ok(Ok(r)) => Ok(Some(r.into_owned().data)),
            Ok(Err(e)) if e.code == ErrorCode::NotFound => Ok(None),
            Ok(Err(e)) => Err(Failure::of("blob.get", &e)),
        }
    }

    /// Lists the paths below a prefix, all pages.
    ///
    /// # Errors
    ///
    /// [`Failure`] for any other answer.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Failure> {
        let mut out = Vec::new();
        let mut token = String::new();
        loop {
            let req = BlobListRequest {
                prefix: prefix.to_owned(),
                page_token: token,
                ..BlobListRequest::default()
            };
            let page = match tokio::time::timeout(CALL, self.blob.list(req)).await {
                Err(_) => return Err(Failure::Transient("blob.list: timed out".into())),
                Ok(Err(e)) => return Err(Failure::of("blob.list", &e)),
                Ok(Ok(r)) => r.into_owned(),
            };
            out.extend(page.paths);
            if page.next_page_token.is_empty() {
                return Ok(out);
            }
            token = page.next_page_token;
        }
    }
}
