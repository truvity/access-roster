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
//!   transition, never for each retry or each repeat of the alarm (3004 Entity Management / 99 Unverified, the document in `entity`; Failure
//!   with the closed reason in `status_code` on the way in, Success on the way out).
//! - `exporter.refused`: the check refused a document, with the closed reason (3004 Entity Management / 99 Refuse, the document in `entity`). It is
//!   written once, at the start; the next start tries again (ADR 0009, "Refusals": not a retry loop).
//!
//! An idle `exporter` writes none of them: a reconcile that finds the document at the destination writes nothing.
//! Every fact is best effort (`emit`): the write it describes has happened, and a fact that cannot be delivered is
//! counted by the emitter for the next record (ADR 0029, "Facts that are lost are counted"). None fails an operation,
//! so `emit_required` is not used: a publication that waited for the spool could leave a revoked key published.

use serde_json::{Map, Value};
use sluis_audit::{Action, Config, Emitter, Entity, Event, Status};

/// OCSF class 3004, Entity Management.
const ENTITY_MANAGEMENT: u32 = 3004;
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

/// A name for an `ident` field of the audit table (`^[A-Za-z0-9._:/+=@~*-]{1,256}$`, which any character may begin; no
/// e-mail shape reaches the emitter). The names of a destination, a document and an address come from the operator's
/// file, and the check that refuses a document is the very case in which one is empty or has a space; a record the
/// emitter refuses is a fact lost exactly when it matters. A name made of letters, digits and `.`, `_`, `-` and `/`, of at
/// most 128 bytes, is written as it is (that leaves out `@`, `:` and the rest of the pattern, which no name of the store
/// holds and which would look like an address); any other is its SHA-256 (the first 16 hex digits) after `h-`, which the
/// operator can compute from the name. A name that begins with `h-` is hashed too, so that no name can be taken for the
/// digest form of another.
fn ident(v: &str) -> Value {
    text(&ident_string(v))
}

/// The text of [`ident`].
fn ident_string(v: &str) -> String {
    let fits = !v.is_empty()
        && v.len() <= 128
        && !v.starts_with("h-")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
    if fits {
        v.to_owned()
    } else {
        format!("h-{}", &sluis_destination::sha256_hex(v.as_bytes())[..16])
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
            entity: document(w.document),
            sluis,
            ..Event::default()
        };
        self.emit("exporter.write", ev).await;
    }

    /// A document went into the state `unverified` (`reason` is the closed word for why) or came out of it (`None`).
    pub async fn unverified(&self, destination: &str, document_name: &str, reason: Option<&str>) {
        let mut sluis = Map::new();
        sluis.insert("destination".into(), ident(destination));
        sluis.insert("document".into(), ident(document_name));
        let ev = Event {
            action: Action {
                name: "exporter.unverified".into(),
                class_uid: ENTITY_MANAGEMENT,
                activity_id: 99,
                activity_name: "Unverified".into(),
            },
            status: if reason.is_some() {
                Status::Failure
            } else {
                Status::Success
            },
            status_code: reason.unwrap_or_default().into(),
            entity: document(document_name),
            sluis,
            ..Event::default()
        };
        self.emit("exporter.unverified", ev).await;
    }

    /// The check refused a document.
    pub async fn refused(&self, destination: &str, document_name: &str, reason: &str) {
        let mut sluis = Map::new();
        sluis.insert("destination".into(), ident(destination));
        sluis.insert("document".into(), ident(document_name));
        let ev = Event {
            action: Action {
                name: "exporter.refused".into(),
                class_uid: ENTITY_MANAGEMENT,
                activity_id: 99,
                activity_name: "Refuse".into(),
            },
            status: Status::Failure,
            status_code: reason.into(),
            entity: document(document_name),
            sluis,
            ..Event::default()
        };
        self.emit("exporter.refused", ev).await;
    }
}

/// The document at a destination as the entity of a fact: its name is the `ident` form of the document, as in the members
/// of `unmapped.sluis`. A name in the safe set (alphanumeric first, then alphanumerics and `. _ - /`, at most 128) is
/// written as the operator wrote it, here and in `unmapped.sluis`; any other name is its digest.
fn document(name: &str) -> Option<Entity> {
    Some(Entity {
        kind: "export_document".into(),
        name: ident_string(name),
        ..Entity::default()
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn name(v: &str) -> String {
        ident(v).as_str().unwrap().to_owned()
    }

    /// A name that is written as it is holds only letters, digits and `. _ - /`: never `@` or `:`, which the table's
    /// `ident` allows but which would make a name look like an address or an e-mail. Any other name is its digest; names
    /// that the table once refused for their first character (`-`, `_`, `.`) are ordinary names now.
    ///
    /// verifies: REQ-EXPORT-017
    #[test]
    fn a_name_is_written_as_it_is_only_from_the_safe_set() {
        for ok in [
            "jwks",
            "-jwks",
            "_edge",
            ".well-known/jwks",
            "a/b_c.d-e",
            "A1",
        ] {
            assert_eq!(name(ok), ok);
        }
        for odd in [
            "",
            "user@host",
            "a:b",
            "x@y.example",
            "has a space",
            "tab\there",
            "ünï",
            &"a".repeat(129),
        ] {
            let got = name(odd);
            assert!(got.starts_with("h-") && got.len() == 18, "{odd:?} -> {got}");
            assert!(!got.contains(['@', ':']));
        }
        assert_eq!(name(&"a".repeat(128)), "a".repeat(128));
        // A real name that looks like the digest form of another is hashed too, so the two cannot be the same.
        let digest_form = name("a:b");
        assert_ne!(name(&digest_form), digest_form);
        assert!(name(&digest_form).starts_with("h-"));
        assert_eq!(name("h"), "h");
        assert_eq!(
            name("a:b"),
            name("a:b"),
            "the digest is a function of the name"
        );
        assert_ne!(name("a:b"), name("a@b"));
    }
}
