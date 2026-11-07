//! What `exporter` tells the audit log (ADR 0028 "Four pieces"; ADR 0030 "The class mapping").
//!
//! - `exporter.start`: the process began, with how many destinations and documents it publishes and how many documents
//!   the check refused (6002 Application Lifecycle / 3 Start).
//! - `exporter.write`: a document was written to a destination (REQ-EXPORT-017): the destination, the document, the
//!   address, the digest, whether it replaced a document and the number of kids a key set lists (3004 Entity Management /
//!   3 Update: one activity, so that the action table of ADR 0030 has one row for it). The facts of a public document are public; a count and a digest are all a record carries, never a
//!   joined list (a record's string holds 1024 bytes, and a ring may grow).
//! - `exporter.unverified`: a document went into the state `unverified` (exporter cannot tell whether the published object
//!   is right: a kind cannot be read, a watch broke, the destination takes no write) or came out of it. One fact for each
//!   transition, never for each retry or each repeat of the alarm (6003 API Activity / 99 Unverified; Failure
//!   with the closed reason in `status_code` on the way in, Success on the way out).
//! - `exporter.refused`: the check refused a document, with the closed reason (6003 API Activity / 99 Refuse). It is
//!   written once, at the start; the next start tries again (ADR 0009, "Refusals": not a retry loop).
//!
//! An idle `exporter` writes none of them: a reconcile that finds the document at the destination writes nothing.
//! Every fact is best effort (`emit`): the write it describes has happened, and a fact that cannot be delivered is
//! counted by the emitter for the next record (ADR 0029, "Facts that are lost are counted"). None fails an operation,
//! so `emit_required` is not used: a publication that waited for the spool could leave a revoked key published.

use serde_json::{Map, Value};
use sluis_audit::{Action, Config, Emitter, Event, Status};

/// OCSF class 3004, Entity Management.
const ENTITY_MANAGEMENT: u32 = 3004;
/// OCSF class 6003, API Activity.
const API_ACTIVITY: u32 = 6003;
/// OCSF class 6002, Application Lifecycle, and its activity 3, Start.
const APPLICATION_LIFECYCLE: u32 = 6002;

/// The actions of `exporter`, for the audit catalogue.
pub const ACTIONS: [&str; 4] = [
    "exporter.start",
    "exporter.write",
    "exporter.unverified",
    "exporter.refused",
];

/// The emitter of `exporter`.
#[derive(Clone)]
pub struct Auditor {
    emitter: Emitter,
}

fn text(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// A name for an `ident` field of the audit table (`^[A-Za-z0-9][A-Za-z0-9._:/+=@~*-]{0,255}$`, and no e-mail shape).
/// The names of a destination, a document and an address come from the operator's file, and the check that refuses a
/// document is the very case in which one is empty, has a space or starts with `-`; a record the emitter refuses is a
/// fact lost exactly when it matters. A name that fits is written as it is; any other is its SHA-256 (the first 16 hex
/// digits) after `h-`, which the operator can compute from the name.
fn ident(v: &str) -> Value {
    let fits = !v.is_empty()
        && v.len() <= 128
        && v.starts_with(|c: char| c.is_ascii_alphanumeric())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
    if fits {
        text(v)
    } else {
        text(&format!(
            "h-{}",
            &sluis_destination::sha256_hex(v.as_bytes())[..16]
        ))
    }
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
                class_uid: APPLICATION_LIFECYCLE,
                activity_id: 3,
                activity_name: String::new(),
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
        sluis.insert("destination".into(), ident(w.destination));
        sluis.insert("document".into(), ident(w.document));
        sluis.insert("address".into(), ident(w.address));
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

    /// A document went into the state `unverified` (`reason` is the closed word for why) or came out of it (`None`).
    pub async fn unverified(&self, destination: &str, document: &str, reason: Option<&str>) {
        let mut sluis = Map::new();
        sluis.insert("destination".into(), ident(destination));
        sluis.insert("document".into(), ident(document));
        let ev = Event {
            action: Action {
                name: "exporter.unverified".into(),
                class_uid: API_ACTIVITY,
                activity_id: 99,
                activity_name: "Unverified".into(),
            },
            status: if reason.is_some() {
                Status::Failure
            } else {
                Status::Success
            },
            status_code: reason.unwrap_or_default().into(),
            sluis,
            ..Event::default()
        };
        self.emit("exporter.unverified", ev).await;
    }

    /// The check refused a document.
    pub async fn refused(&self, destination: &str, document: &str, reason: &str) {
        let mut sluis = Map::new();
        sluis.insert("destination".into(), ident(destination));
        sluis.insert("document".into(), ident(document));
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
