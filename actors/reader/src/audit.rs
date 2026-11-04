//! What the reader tells the audit log: every search, answered or refused (ADR 0028 "The reader": "Every
//! read is itself audited, with the rule that granted it").
//!
//! One record per call, `reader.search`, OCSF API Activity (6003), activity Read (2). It names the tenants
//! asked for, how many records were returned and the decisions of policy that took part, with their ids, so
//! the record of the decision and the record of the read meet by id. It holds no record, no query word and no
//! filter value: a query is a person's interest. The record is routed to the operator's own tenant; the tenants
//! read are in the body, because a tenant that is mistyped must not get a key by being named (decision D-4).

use serde_json::{Map, Value, json};
use sluis_audit::{Action, Decision as Verdict, Event, PolicyRef, Status};

use crate::search::Decision;

/// The action name the writer's catalogue must list.
pub const SEARCH: &str = "reader.search";

/// OCSF's API Activity class (6003) and its activity Read (2).
const CLASS_API_ACTIVITY: u32 = 6003;
const ACTIVITY_READ: u32 = 2;

/// What a call came to.
pub struct Outcome<'a> {
    pub tenants: &'a [String],
    pub decisions: &'a [Decision],
    /// The records returned; 0 for a refusal.
    pub hits: usize,
    /// Empty on success; the closed reason of a refusal.
    pub status_code: &'a str,
}

/// The record of a call.
#[must_use]
pub fn search(o: &Outcome<'_>) -> Event {
    let mut sluis = Map::new();
    sluis.insert("tenants".into(), json!(o.tenants));
    sluis.insert("hits".into(), json!(o.hits));
    sluis.insert(
        "decisions".into(),
        Value::from(o.decisions.iter().map(|d| d.id.clone()).collect::<Vec<_>>()),
    );
    // The first decision is the rule that granted the read; the others are in `decisions`.
    let policy = o
        .decisions
        .iter()
        .find(|d| !d.id.is_empty())
        .map(|d| PolicyRef {
            decision_id: d.id.clone(),
            digest: d.digest.clone(),
            policy_ids: d.policy_ids.clone(),
            decision: Some(if d.allowed {
                Verdict::Allowed
            } else {
                Verdict::Denied
            }),
        });
    Event {
        action: Action {
            name: SEARCH.into(),
            class_uid: CLASS_API_ACTIVITY,
            activity_id: ACTIVITY_READ,
            activity_name: String::new(),
        },
        status: if o.status_code.is_empty() {
            Status::Success
        } else {
            Status::Failure
        },
        status_code: o.status_code.into(),
        policy,
        sluis,
        ..Event::default()
    }
}
