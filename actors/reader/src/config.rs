//! What the reader reads of the boundary's config, through store@ (ADR 0005, "Configuration loading"):
//! `AuditLog`, which declares the project and its logs. The reader serves the logs of kind `audit`, the
//! ones the indexer follows; the usage log has no index (0028, REQ-AUDIT-098).

use std::time::Duration;

use connectrpc::ConnectError;
use sluis_kit::Client;
use sluis_proto::sluis::config::v2alpha1::AuditLog;
use sluis_store::{Error as StoreError, Kind, Store};

use crate::ports::down;

/// The singleton id of a singleton config kind (PLAN.md D-17).
const ID: &str = "default";
/// The kind of log the reader serves.
pub const AUDIT: &str = "audit";
/// How long one read may take.
const READ: Duration = Duration::from_secs(5);

struct AuditLogKind;
impl Kind for AuditLogKind {
    type Id = &'static str;
    type Value = AuditLog;
    const NAME: &'static str = "AuditLog";
}

/// A log the reader serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    /// The audit project.
    pub project: String,
    /// The log kind (`audit`).
    pub kind: String,
    /// The log's id.
    pub id: String,
}

impl Log {
    /// `<kind>/<log>/`: the prefix of the log in the project's bucket.
    #[must_use]
    pub fn prefix(&self) -> String {
        format!("{}/{}/", self.kind, self.id)
    }
}

/// The reader of `AuditLog`.
pub struct Config {
    logs: Store<AuditLogKind>,
}

impl Config {
    /// A reader over store@'s socket.
    ///
    /// # Errors
    ///
    /// When the kind is not in the registry.
    pub fn new(store: &Client) -> Result<Self, StoreError> {
        Ok(Self {
            logs: Store::new(store.clone())?,
        })
    }

    /// The logs of kind `audit`.
    ///
    /// # Errors
    ///
    /// `unavailable` when store@ does not answer or the config is absent: the reader does not know what to
    /// read, so it reads nothing.
    pub async fn logs(&self) -> Result<Vec<Log>, ConnectError> {
        let doc = match tokio::time::timeout(READ, self.logs.get("", ID)).await {
            Ok(Ok(item)) => item.value,
            Ok(Err(StoreError::NotFound)) | Ok(Err(_)) | Err(_) => return Err(down("config")),
        };
        let project = doc.project;
        if project.is_empty() || project.contains('/') {
            return Err(down("config"));
        }
        let mut out = Vec::new();
        for l in doc.logs {
            if l.kind != AUDIT {
                continue;
            }
            if l.id.is_empty() || l.id.contains('/') {
                return Err(down("config"));
            }
            out.push(Log {
                project: project.clone(),
                kind: l.kind,
                id: l.id,
            });
        }
        Ok(out)
    }
}
