//! What `signer` tells the audit log (ADR 0028 "Four pieces"; ADR 0030 "The class mapping").
//!
//! - `signer.refused`: every refusal of a call, with the caller, the method, the closed reason and
//!   the path of the field at fault. Never a claim, a token or a value from the request.
//! - `signer.sign`: a token was issued, with the audience (a registered client id), the type, and the
//!   key. key@ makes its own durable fact for the signature (`key.sign`, D-24); this one says which
//!   token it was for.
//! - `signer.ring.add`, `signer.ring.change` and `signer.ring.drop`: a change of the published key
//!   set. The key is public material, so the fact holds its id and the state.
//!
//! Nothing here names a person: `signer` has no pseudonym rule, and the actors that ask for a token
//! audit the person's action themselves. The facts of the calls use the non-blocking emit; the
//! changes of the key set wait for the transport, as an administrative change does (0028).

use serde_json::{Map, Value, json};
use sluis_audit::{Action, Config, Emitter, Event, Status};

use crate::ring::{Change, ChangeKind};

/// OCSF class 6003, API Activity.
const API_ACTIVITY: u32 = 6003;
/// OCSF class 3004, Entity Management.
const ENTITY_MANAGEMENT: u32 = 3004;

/// The emitter of `signer`.
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

    /// A refusal of a call. A failed emit is logged and never turns the answer into something else.
    pub async fn refused(&self, caller: &str, method: &str, reason: &str, path: &str) {
        let mut sluis = Map::new();
        sluis.insert("caller".into(), text(caller));
        sluis.insert("method".into(), text(method));
        if !path.is_empty() {
            sluis.insert("path".into(), text(path));
        }
        let ev = Event {
            action: Action {
                name: "signer.refused".into(),
                class_uid: API_ACTIVITY,
                activity_id: 99,
                activity_name: "Refuse".into(),
            },
            status: Status::Failure,
            status_code: reason.into(),
            sluis,
            ..Event::default()
        };
        self.emit("signer.refused", ev).await;
    }

    /// A token was issued.
    pub async fn signed(&self, caller: &str, typ: &str, key_id: &str, audience: &str) {
        let mut sluis = Map::new();
        sluis.insert("caller".into(), text(caller));
        sluis.insert("typ".into(), text(typ));
        sluis.insert("key_id".into(), text(key_id));
        sluis.insert("token".into(), json!({ "audience": audience }));
        let ev = Event {
            action: Action {
                name: "signer.sign".into(),
                class_uid: API_ACTIVITY,
                activity_id: 99,
                activity_name: "Issue".into(),
            },
            status: Status::Success,
            sluis,
            ..Event::default()
        };
        self.emit("signer.sign", ev).await;
    }

    /// A change of the key set, returned only when the transport says the fact is durable.
    ///
    /// # Errors
    ///
    /// The transport's error.
    pub async fn ring(&self, c: &Change) -> Result<(), connectrpc::ConnectError> {
        let (name, activity, state) = match c.kind {
            ChangeKind::Added(s) => ("signer.ring.add", 1, s),
            ChangeKind::Activated => ("signer.ring.change", 3, crate::ring::ACTIVE),
            ChangeKind::Retired => ("signer.ring.change", 3, crate::ring::RETIRING),
            ChangeKind::Dropped => ("signer.ring.drop", 4, "dropped"),
        };
        let mut sluis = Map::new();
        sluis.insert("key_id".into(), text(&c.key_id));
        sluis.insert("state".into(), text(state));
        sluis.insert("algorithm".into(), text(crate::keys::ALGORITHM));
        let ev = Event {
            action: Action {
                name: name.into(),
                class_uid: ENTITY_MANAGEMENT,
                activity_id: activity,
                activity_name: String::new(),
            },
            status: Status::Success,
            sluis,
            ..Event::default()
        };
        self.emitter.emit_blocking(ev).await
    }

    async fn emit(&self, name: &str, ev: Event) {
        if let Err(e) = self.emitter.emit(ev).await {
            tracing::warn!(action = name, code = e.code.as_str(), "audit emit failed");
        }
    }
}
