//! What `exporter` tells the audit log (ADR 0028 "Four pieces"; ADR 0030 "The class mapping").
//!
//! - `exporter.start`: the process began, with how many destinations and documents it publishes and how many documents
//!   the check refused (6002 Application Lifecycle / 99 Start).
//! - `exporter.write`: a document was written to a destination (REQ-EXPORT-017): the destination, the document, the
//!   address, the digest, whether it replaced a document and the number of kids a key set lists (3004 Entity Management /
//!   3 Update: one activity, so that the action table of ADR 0030 has one row for it). The facts of a public document are public; a count and a digest are all a record carries, never a
//!   joined list (a record's string holds 1024 bytes, and a ring may grow).
//! - `exporter.refused`: the check refused a document, with the closed reason (6003 API Activity / 99 Refuse). It is
//!   written once, at the start; the next start tries again (ADR 0009, "Refusals": not a retry loop).
//!
//! An idle `exporter` writes none of them: a reconcile that finds the document at the destination writes nothing.
//! Every fact is best effort (`emit`): the write it describes has happened, and a fact that cannot be delivered is
//! counted by the emitter for the next record (ADR 0029, "Facts that are lost are counted"). None fails an operation,
//! so `emit_required` is not used: a publication that waited for the spool could leave a revoked key published.

use serde_json::{Map, Value};
use sluis_audit::{Action, Config, Emitter, Event, Status};

/// OCSF class 6002, Application Lifecycle.
const LIFECYCLE: u32 = 6002;
/// OCSF class 3004, Entity Management.
const ENTITY_MANAGEMENT: u32 = 3004;
/// OCSF class 6003, API Activity.
const API_ACTIVITY: u32 = 6003;

/// The actions of `exporter`, for the audit catalogue.
pub const ACTIONS: [&str; 3] = ["exporter.start", "exporter.write", "exporter.refused"];

/// The emitter of `exporter`.
#[derive(Clone)]
pub struct Auditor {
    emitter: Emitter,
}

fn text(v: &str) -> Value {
    Value::String(v.to_owned())
}

impl Auditor {
    /// Builds the emitter; nothing is dialled until the first fact.
    ///
    /// # Errors
    ///
    /// When the configuration of the emitter is refused.
    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        Ok(Self {
            emitter: Emitter::new(cfg)
                .map_err(|e| anyhow::anyhow!("audit emitter: {}", e.code.as_str()))?,
        })
    }

    /// The best-effort facts this process failed to deliver, for a metric.
    #[must_use]
    pub fn lost(&self) -> i64 {
        self.emitter.lost()
    }

    async fn emit(&self, name: &str, ev: Event) {
        if let Err(e) = self.emitter.emit(ev).await {
            tracing::warn!(action = name, code = e.code.as_str(), "audit emit failed");
        }
    }

    /// The process began.
    pub async fn started(&self, destinations: usize, documents: usize, refused: usize) {
        let mut sluis = Map::new();
        for (k, v) in [
            ("destinations", destinations),
            ("documents", documents),
            ("refused", refused),
        ] {
            sluis.insert(k.into(), Value::from(v as u64));
        }
        let ev = Event {
            action: Action {
                name: "exporter.start".into(),
                class_uid: LIFECYCLE,
                activity_id: 99,
                activity_name: "Start".into(),
            },
            status: Status::Success,
            sluis,
            ..Event::default()
        };
        self.emit("exporter.start", ev).await;
    }

    /// A document was written to a destination.
    pub async fn written(&self, w: &Written<'_>) {
        let mut sluis = Map::new();
        sluis.insert("destination".into(), text(w.destination));
        sluis.insert("document".into(), text(w.document));
        sluis.insert("address".into(), text(w.address));
        sluis.insert("sha256".into(), text(w.sha256));
        sluis.insert("kids".into(), Value::from(w.kids as u64));
        sluis.insert("replaced".into(), Value::Bool(w.replaced));
        let ev = Event {
            action: Action {
                name: "exporter.write".into(),
                class_uid: ENTITY_MANAGEMENT,
                activity_id: 3,
                activity_name: String::new(),
            },
            status: Status::Success,
            sluis,
            ..Event::default()
        };
        self.emit("exporter.write", ev).await;
    }

    /// The check refused a document.
    pub async fn refused(&self, destination: &str, document: &str, reason: &str) {
        let mut sluis = Map::new();
        sluis.insert("destination".into(), text(destination));
        sluis.insert("document".into(), text(document));
        let ev = Event {
            action: Action {
                name: "exporter.refused".into(),
                class_uid: API_ACTIVITY,
                activity_id: 99,
                activity_name: "Refuse".into(),
            },
            status: Status::Failure,
            status_code: reason.into(),
            sluis,
            ..Event::default()
        };
        self.emit("exporter.refused", ev).await;
    }
}

/// A write, as the fact says it.
pub struct Written<'a> {
    /// The destination.
    pub destination: &'a str,
    /// The document.
    pub document: &'a str,
    /// The address at the destination.
    pub address: &'a str,
    /// The SHA-256 of the body.
    pub sha256: &'a str,
    /// How many kids a key set lists.
    pub kids: usize,
    /// Whether the write replaced a document.
    pub replaced: bool,
}
