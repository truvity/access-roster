//! What the indexer reads of the boundary's config, through store@ (ADR 0005, "Configuration loading"):
//! `AuditLog`, which declares the project and its logs, and the verifier key of each log.
//!
//! The indexer follows the logs of kind `audit`. The usage log has no index (0028, REQ-AUDIT-098), the
//! `billing/` prefix is not indexed either, and the issuance log has no writer yet.
//!
//! **The verifier key** is the public half of the log's key, as a C2SP verifier key text. Tonight it is
//! a file `<log id>.vkey` in `--verifier-key-dir`, which the deploy writes from the key the writer logs
//! at its start. The registry gives the indexer no right to ask key@ for it, a cluster has one log key
//! per writer instance and key@ knows only its own, and `AuditLog` has no field for it. Where it
//! belongs is a decision for the maintainer (see the pull request).

use std::path::Path;
use std::time::Duration;

use sluis_kit::Client;
use sluis_proto::sluis::config::v2alpha1::AuditLog;
use sluis_store::{Error as StoreError, Kind, Store};

use crate::follow::Log;
use crate::note::LogKey;
use crate::ports::Failure;

/// The singleton id of a singleton config kind (PLAN.md D-17).
const ID: &str = "default";
/// The kind of log the indexer follows.
pub const AUDIT: &str = "audit";
/// How long one read may take.
const READ: Duration = Duration::from_secs(5);

struct AuditLogKind;
impl Kind for AuditLogKind {
    type Id = &'static str;
    type Value = AuditLog;
    const NAME: &'static str = "AuditLog";
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

    /// The logs to follow, each with its verifier key from `key_dir`.
    ///
    /// # Errors
    ///
    /// [`Failure::Transient`] when store@ does not answer; [`Failure::Refused`] when the config or a
    /// key is not usable.
    pub async fn logs(&self, key_dir: &Path) -> Result<Vec<Log>, Failure> {
        let doc = match tokio::time::timeout(READ, self.logs.get("", ID)).await {
            Err(_) => return Err(Failure::Transient("auditlog/default: timed out".into())),
            Ok(Err(StoreError::NotFound)) => {
                return Err(Failure::refused("config.auditlog", "absent"));
            }
            Ok(Err(e)) => return Err(Failure::Transient(format!("auditlog/default: {e}"))),
            Ok(Ok(item)) => item.value,
        };
        let project = doc.project;
        if project.is_empty() || project.contains('/') {
            return Err(Failure::refused("config.auditlog", "project"));
        }
        let mut out = Vec::new();
        for l in doc.logs {
            if l.kind != AUDIT {
                continue;
            }
            if l.id.is_empty() || l.id.contains('/') || l.origin.is_empty() {
                return Err(Failure::refused(
                    "config.auditlog",
                    format!("logs.{}", l.id),
                ));
            }
            let key = load_key(key_dir, &l.id)?;
            out.push(Log {
                project: project.clone(),
                kind: l.kind,
                id: l.id,
                origin: l.origin,
                key,
            });
        }
        Ok(out)
    }
}

/// Reads `<log id>.vkey`.
///
/// # Errors
///
/// [`Failure::Refused`] when the file is missing or is not a verifier key.
pub fn load_key(dir: &Path, log_id: &str) -> Result<LogKey, Failure> {
    let path = dir.join(format!("{log_id}.vkey"));
    let text = std::fs::read_to_string(&path).map_err(|e| {
        Failure::refused("config.verifier_key", format!("{log_id}: {:?}", e.kind()))
    })?;
    LogKey::parse(&text)
        .map_err(|e| Failure::refused("config.verifier_key", format!("{log_id}: {e}")))
}
