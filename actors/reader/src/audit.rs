//! What the reader tells the audit log: every search, answered or refused (ADR 0028 "The reader": "Every
//! read is itself audited, with the rule that granted it").
//!
//! One record per call, `reader.search`, OCSF API Activity (6003), activity Read (2). It names the tenants
//! asked for, how many records were returned and the decisions of policy that took part, with their ids, so
//! the record of the decision and the record of the read meet by id. `decisions[i]` is the decision for
//! `tenants[i]` (the reader serves the one audit log of its `AuditLog`, so a decision is for a tenant), and
//! `authorizations[i]` is its result; the record names no log, because the action table has no field for it yet. It holds no record, no query word and no
//! filter value: a query is a person's interest. The record is routed to the operator's own tenant; the tenants
//! read are in the body, because a tenant that is mistyped must not get a key by being named (decision D-4).

use serde_json::{Map, Value, json};
use sluis_audit::{Action, Decided, Decision as Verdict, Event, PolicyRef, Status};

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
    // `policy` and `action_id` name the decision that settled the call: the one that denied it, and otherwise the
    // first. (Every decision has an id: `search` refuses a policy that gave none.)
    let settled = o
        .decisions
        .iter()
        .position(|d| !d.allowed)
        .or(if o.decisions.is_empty() {
            None
        } else {
            Some(0)
        });
    let policy = settled.map(|at| {
        let d = &o.decisions[at];
        PolicyRef {
            decision_id: d.id.clone(),
            digest: d.digest.clone(),
            policy_ids: d.policy_ids.clone(),
            decision: Some(verdict(d)),
            // `authorizations[i]` is the result of `decisions[i]`, one entry each, in the order they were asked: the
            // rule that determined it (the first by id, when several did; the rest are in the record of the decision,
            // which `decisions` names) or the verdict alone when none did.
            results: o
                .decisions
                .iter()
                .map(|d| Decided {
                    policy_id: d.policy_ids.iter().min().cloned().unwrap_or_default(),
                    decision: Some(verdict(d)),
                })
                .collect(),
        }
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

fn verdict(d: &Decision) -> Verdict {
    if d.allowed {
        Verdict::Allowed
    } else {
        Verdict::Denied
    }
}
