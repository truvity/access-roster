//! The signed config snapshot (WP-11): the seam between the store service and the config kinds.
//!
//! A config kind is read-only to sluis: it comes from the snapshot, never from an engine (ADR 0005,
//! "Configuration loading"). [`Loader`] reads the signed documents of the boundary from the config
//! source, verifies them against the publisher keys pinned in the bootstrap file, validates the
//! set, and holds the snapshot in force.

pub mod document;
pub mod payload;
pub mod reload;
pub mod snapshot;

use crate::audit::AuditEvent;

pub use snapshot::{LoadError, Loader, Reloaded, Snapshot, Summary};

/// The snapshot of the config kinds, as the store service reads it.
pub trait ConfigSnapshot: Send + Sync {
    /// The item of a config kind (segment, id), or None. Config kinds are read-only to sluis.
    fn get(&self, segment: &str, id: &str) -> Option<Vec<u8>>; // the kind's Protobuf bytes
    /// The items of a config kind as (id, bytes), sorted by id.
    fn list(&self, segment: &str) -> Vec<(String, Vec<u8>)>;
    /// The document's seq. None: no document of this kind is loaded, which the store service
    /// answers as `unavailable`/`engine` (fail closed), never as an empty kind.
    fn version(&self, segment: &str) -> Option<u64>;
}

/// No snapshot: every config read is unavailable. For tests of the service; `serve` never uses it.
pub struct NoConfig;

impl ConfigSnapshot for NoConfig {
    fn get(&self, _segment: &str, _id: &str) -> Option<Vec<u8>> {
        None
    }
    fn list(&self, _segment: &str) -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }
    fn version(&self, _segment: &str) -> Option<u64> {
        None
    }
}

/// The loader is the snapshot the service reads: every read sees the snapshot in force at that
/// moment, and a swap never shows half of a set.
impl ConfigSnapshot for Loader {
    fn get(&self, segment: &str, id: &str) -> Option<Vec<u8>> {
        self.snapshot().get(segment, id)
    }
    fn list(&self, segment: &str) -> Vec<(String, Vec<u8>)> {
        self.snapshot().list(segment)
    }
    fn version(&self, segment: &str) -> Option<u64> {
        self.snapshot().version(segment)
    }
}

/// The documents of a snapshot as one audit field: `Kind:seq:sha384`, joined by `;`.
#[must_use]
pub fn documents_field(summaries: &[Summary]) -> String {
    summaries
        .iter()
        .map(|d| format!("{}:{}:{}", d.kind, d.seq, d.sha384))
        .collect::<Vec<_>>()
        .join(";")
}

/// The audit fact of a reload, or None for a reload that changed nothing or a refusal that was
/// already reported for the same document (ADR 0005, "A failed reload").
#[must_use]
pub fn reload_event(boundary: &str, outcome: &Reloaded) -> Option<AuditEvent> {
    match outcome {
        Reloaded::Unchanged | Reloaded::Refused { report: false, .. } => None,
        Reloaded::Applied(documents) => Some(AuditEvent {
            action: "store.reload",
            failure: false,
            reason: String::new(),
            fields: vec![
                ("boundary", boundary.to_owned()),
                ("documents", documents_field(documents)),
            ],
            correlation_id: None,
        }),
        Reloaded::Refused { error, .. } => {
            let mut fields = vec![("boundary", boundary.to_owned())];
            if let Some(kind) = error.kind {
                fields.push(("document", kind.to_owned()));
            }
            if let Some(digest) = &error.label {
                fields.push(("digest", digest.clone()));
            }
            // The rule broken, as the loader words it: a step and a rule, never a value.
            fields.push(("why", error.reason.clone()));
            Some(AuditEvent {
                action: "store.reload.refused",
                failure: true,
                reason: if error.unreachable {
                    "engine"
                } else {
                    "config"
                }
                .to_owned(),
                fields,
                correlation_id: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(kind: &'static str, seq: u64) -> Summary {
        Summary {
            kind,
            seq,
            sha384: "ab".repeat(48),
        }
    }

    #[test]
    fn a_reload_is_a_fact_naming_each_document_and_a_repeated_refusal_is_none() {
        let applied = Reloaded::Applied(vec![summary("Boundary", 3), summary("KeyPlan", 2)]);
        let e = reload_event("dev", &applied).unwrap();
        assert_eq!((e.action, e.failure), ("store.reload", false));
        let docs = e.fields.iter().find(|(k, _)| *k == "documents").unwrap();
        assert_eq!(
            docs.1,
            format!(
                "Boundary:3:{};KeyPlan:2:{}",
                "ab".repeat(48),
                "ab".repeat(48)
            )
        );
        assert!(reload_event("dev", &Reloaded::Unchanged).is_none());

        let error = LoadError {
            kind: Some("KeyPlan"),
            label: Some("cd".repeat(48)),
            reason: "step 4: a signature does not verify".into(),
            unreachable: false,
            fingerprint: String::new(),
        };
        let first = Reloaded::Refused {
            error: error.clone(),
            report: true,
        };
        let e = reload_event("dev", &first).unwrap();
        assert_eq!(
            (e.action, e.failure, e.reason.as_str()),
            ("store.reload.refused", true, "config")
        );
        assert!(e.fields.contains(&("document", "KeyPlan".to_owned())));
        assert!(e.fields.contains(&("digest", "cd".repeat(48))));
        // The same refused digest is reported once.
        assert!(
            reload_event(
                "dev",
                &Reloaded::Refused {
                    error,
                    report: false
                }
            )
            .is_none()
        );
    }
}
