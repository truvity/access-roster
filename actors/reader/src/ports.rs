//! The ports the reader calls, as clients of the kit, and how a failure of one is told to the caller.
//!
//! A dependency that is down gives `unavailable` / `engine`: the reader fails closed and never answers
//! on a weaker basis (contracts.md "Errors"). What a dependency refuses on purpose is passed on as what it
//! is: key@'s refusal of a grant is `permission_denied` / `grant`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use sluis_kit::{Client, Transport, dial, refusal, refusal_reason};
use sluis_proto::sluis::key::v2alpha1::KeyServiceClient;
use sluis_proto::sluis::policy::v2alpha1::PolicyServiceClient;
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobListRequest, BlobServiceClient,
};
use sluis_proto::sluis::port::index::v2alpha1::IndexReadServiceClient;

/// How long one call to a dependency may take.
pub const CALL: Duration = Duration::from_secs(20);

/// The sockets of the dependencies.
#[derive(Clone, Debug)]
pub struct Sockets {
    /// The read-only blob driver, for the reader (`blob-ro.sock`).
    pub blob: PathBuf,
    /// key@'s socket for the reader: Open of `evidence`.
    pub key: PathBuf,
    /// policy's socket.
    pub policy: PathBuf,
    /// The index driver's read socket (`index-ro.sock`).
    pub index: PathBuf,
    /// store@'s socket.
    pub store: PathBuf,
    /// The audit transport's emit socket.
    pub audit: PathBuf,
}

impl Sockets {
    /// The sockets of the layout (PLAN.md "Socket layout") below `run`, for a boundary.
    #[must_use]
    pub fn under(run: &Path, boundary: &str) -> Self {
        Self {
            blob: run.join("indexer").join(boundary).join("blob-ro.sock"),
            key: run
                .join("key")
                .join(boundary)
                .join("reader")
                .join("key.sock"),
            policy: run.join("policy").join(format!("{boundary}.sock")),
            index: run.join("indexer").join(boundary).join("index-ro.sock"),
            store: run.join("store").join(format!("{boundary}.sock")),
            audit: run.join("audit").join(boundary).join("emit.sock"),
        }
    }
}

/// The clients, one per socket. Nothing is dialled until the first call.
#[derive(Clone)]
pub struct Ports {
    pub blob: BlobServiceClient<Transport>,
    pub keys: KeyServiceClient<Transport>,
    pub policy: PolicyServiceClient<Transport>,
    pub index: IndexReadServiceClient<Transport>,
}

impl Ports {
    #[must_use]
    pub fn new(s: &Sockets) -> Self {
        let (b, k, p, i): (Client, Client, Client, Client) =
            (dial(&s.blob), dial(&s.key), dial(&s.policy), dial(&s.index));
        Self {
            blob: BlobServiceClient::new(b.transport(), b.config()),
            keys: KeyServiceClient::new(k.transport(), k.config()),
            policy: PolicyServiceClient::new(p.transport(), p.config()),
            index: IndexReadServiceClient::new(i.transport(), i.config()),
        }
    }

    /// Reads an object of the blob; `None` when there is none.
    ///
    /// # Errors
    ///
    /// A dependency that did not answer, or refused.
    pub async fn get(&self, path: &str) -> Result<Option<Vec<u8>>, ConnectError> {
        let req = BlobGetRequest {
            path: path.to_owned(),
            ..BlobGetRequest::default()
        };
        match tokio::time::timeout(CALL, self.blob.get(req)).await {
            Err(_) => Err(down("blob")),
            Ok(Ok(r)) => Ok(Some(r.into_owned().data)),
            Ok(Err(e)) if e.code == ErrorCode::NotFound => Ok(None),
            Ok(Err(e)) => Err(passed("blob", &e)),
        }
    }

    /// Lists the paths below a prefix, all pages.
    ///
    /// # Errors
    ///
    /// A dependency that did not answer, or refused.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, ConnectError> {
        let mut out = Vec::new();
        let mut token = String::new();
        loop {
            let req = BlobListRequest {
                prefix: prefix.to_owned(),
                page_token: token,
                ..BlobListRequest::default()
            };
            let page = match tokio::time::timeout(CALL, self.blob.list(req)).await {
                Err(_) => return Err(down("blob")),
                Ok(Err(e)) => return Err(passed("blob", &e)),
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

/// A dependency that did not answer in time.
#[must_use]
pub fn down(what: &str) -> ConnectError {
    refusal(ErrorCode::Unavailable, "engine", what)
}

/// What a dependency said, as the reader says it: a refusal on purpose keeps its code and reason when the
/// reader's own list has it; anything else that is not an answer is `unavailable`.
#[must_use]
pub fn passed(what: &str, e: &ConnectError) -> ConnectError {
    match e.code {
        ErrorCode::PermissionDenied => {
            let reason = match refusal_reason(e).as_deref() {
                Some("grant") => "grant",
                Some("open") => "open",
                _ => "rule",
            };
            refusal(ErrorCode::PermissionDenied, reason, what)
        }
        ErrorCode::InvalidArgument => refusal(ErrorCode::InvalidArgument, "schema", what),
        _ => {
            tracing::warn!(
                dependency = what,
                code = e.code.as_str(),
                "a dependency did not answer"
            );
            down(what)
        }
    }
}
