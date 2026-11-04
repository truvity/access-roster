//! What `policy` tells the audit log (ADR 0007: every decision is audited with the ids of its
//! determining policies and the digest of the policy set it used).
//!
//! `policy.decide` is one record per decision, with the decision in `security_control` form
//! (`PolicyRef`). A person is a pseudonym made by key@, never a name. A field holds a closed word,
//! a registry name or a count, never a value of a request.

use serde_json::{Map, Value, json};
use sluis_audit::{Action, Decision, Event, PolicyRef, Status, Subject};

use crate::engine::LoadError;
use crate::engine::Reason;

/// OCSF's API Activity class (6003) and its activity 99, Other (0030 "The class mapping").
const CLASS_API_ACTIVITY: u32 = 6003;
const ACTIVITY_OTHER: u32 = 99;

/// The action names `policy` emits. The writer accepts only names of the catalogue
/// (`AuditCatalogue`, decision D-15).
pub const ACTIONS: [&str; 4] = [
    "policy.decide",
    "policy.start",
    "policy.reload",
    "policy.reload.refused",
];

fn action(name: &str, activity: &str) -> Action {
    Action {
        name: name.to_owned(),
        class_uid: CLASS_API_ACTIVITY,
        activity_id: ACTIVITY_OTHER,
        activity_name: activity.to_owned(),
    }
}

/// What one question came to: Cedar's answer, or a refusal of the question.
pub struct Outcome<'a> {
    /// The id of the decision, a UUIDv7; also in the grant, so `key@` and `store@` records name it.
    pub decision_id: &'a str,
    pub digest: &'a str,
    /// The actor that asked, from the transport.
    pub asker: &'a str,
    /// The principal's type and, for a person, the subject (pseudonymised by the emitter).
    pub principal_type: &'a str,
    pub subject: Option<&'a str>,
    /// The Cedar action, or `unknown`: the text of an action the asker made up is not recorded.
    pub action: &'a str,
    pub tenant: &'a str,
    /// The policies that determined the decision.
    pub reasons: &'a [Reason],
    pub grant_count: usize,
    pub errors: usize,
    /// Empty for Cedar's answer; `evaluation` for an allow past an erroring policy; the reason of
    /// the refusal for a question that was not one.
    pub status_code: &'a str,
    /// The path of the field a refusal names.
    pub path: &'a str,
    /// `None` for a refusal: nothing was decided.
    pub decision: Option<Decision>,
}

/// The record of a question.
#[must_use]
pub fn decide(o: &Outcome<'_>) -> Event {
    let mut sluis = Map::new();
    sluis.insert("cedar_action".into(), json!(o.action));
    sluis.insert("asker".into(), json!(o.asker));
    sluis.insert("principal_type".into(), json!(o.principal_type));
    sluis.insert("grant_count".into(), json!(o.grant_count));
    sluis.insert(
        "step_up".into(),
        json!(
            o.reasons
                .iter()
                .any(|r| r.annotations.contains_key("step_up"))
        ),
    );
    if o.errors > 0 {
        sluis.insert("policy_errors".into(), json!(o.errors));
    }
    if !o.path.is_empty() {
        sluis.insert("path".into(), json!(o.path));
    }
    let layers: Vec<Value> = {
        let mut l: Vec<&str> = o.reasons.iter().map(|r| r.layer.as_str()).collect();
        l.sort_unstable();
        l.dedup();
        l.into_iter().map(|s| json!(s)).collect()
    };
    sluis.insert("layers".into(), Value::Array(layers));
    // `*` is every tenant of the boundary: the record belongs to the operator's own tenant.
    let tenant = if o.tenant == "*" { "" } else { o.tenant };
    Event {
        action: action("policy.decide", "Decide"),
        // A failure is a question that was not decided, or whose answer was withdrawn;
        // `status_code` says why.
        status: if o.status_code.is_empty() {
            Status::Success
        } else {
            Status::Failure
        },
        status_code: o.status_code.to_owned(),
        tenant: tenant.to_owned(),
        subject: o.subject.filter(|_| !tenant.is_empty()).map(|s| Subject {
            tenant: tenant.to_owned(),
            kind: "person".into(),
            value: s.to_owned(),
        }),
        policy: Some(PolicyRef {
            decision_id: o.decision_id.to_owned(),
            digest: o.digest.to_owned(),
            policy_ids: o.reasons.iter().map(|r| r.policy_id.clone()).collect(),
            decision: o.decision,
        }),
        sluis,
        correlation_id: None,
    }
}

/// `policy.start`: the set the process started with.
#[must_use]
pub fn start(digest: &str, policies: usize) -> Event {
    Event {
        action: action("policy.start", "Start"),
        sluis: fields(digest, policies, &[]),
        ..Event::default()
    }
}

/// `policy.reload`: a new set is in force.
#[must_use]
pub fn reloaded(digest: &str, policies: usize) -> Event {
    Event {
        action: action("policy.reload", "Reload"),
        sluis: fields(digest, policies, &[]),
        ..Event::default()
    }
}

/// `policy.reload.refused`: a set was refused and the one in force stays (ADR 0005 "A failed
/// reload"). The faults name policy ids and paths, never a value.
#[must_use]
pub fn reload_refused(in_force: &str, why: &LoadError) -> Event {
    Event {
        action: action("policy.reload.refused", "Refuse"),
        status: Status::Failure,
        status_code: "invalid".into(),
        sluis: {
            let mut m = fields(in_force, 0, &why.0);
            if let Some(d) = m.remove("digest") {
                m.insert("in_force_digest".into(), d);
            }
            m
        },
        ..Event::default()
    }
}

fn fields(digest: &str, policies: usize, faults: &[String]) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("digest".into(), json!(digest));
    m.insert("policies".into(), json!(policies));
    if !faults.is_empty() {
        let shown: Vec<Value> = faults
            .iter()
            .take(8)
            .map(|f| json!(f.chars().take(200).collect::<String>()))
            .collect();
        m.insert("faults".into(), Value::Array(shown));
    }
    m
}
