//! The checks on an event and the layout of the record (0030 "The record format").

use serde_json::{Map, Value, json};

use crate::canonical::{MAX_DEPTH, MAX_SAFE_INT, canonical, invalid};
use crate::{Decision, Event, LostNote, OCSF_VERSION, RECORD_MAX, Result, STRING_MAX};

/// The member of `unmapped.sluis` that carries the loss note: `{"process": id, "total": n, "since": ms}`.
pub(crate) const LOST_KEY: &str = "lost";

/// `actor.user.type_id` 3: "System" in the OCSF 1.9.0 user type enum (0 Unknown, 1 User, 2 Admin,
/// 3 System, 99 Other) and "sluis actor" in 0030 "The record format". The two agree.
const USER_TYPE_SYSTEM: i64 = 3;
/// OCSF `severity_id` 1, Informational.
const SEVERITY_INFORMATIONAL: i64 = 1;
/// OCSF class 6002, Application Lifecycle, and class 3002, Authentication: the classes whose required
/// attributes the record fills from what the emitter knows (0030 "The OCSF attributes a class requires").
const CLASS_APPLICATION_LIFECYCLE: u32 = 6002;
const CLASS_AUTHENTICATION: u32 = 3002;
const CLASS_API_ACTIVITY: u32 = 6003;
/// The `user.uid` of an Authentication record whose subject is not known: OCSF requires the user, and a refusal
/// before anyone is identified has none to name. It cannot be a pseudonym (those begin `p1.`).
const USER_UNKNOWN: &str = "unknown";
/// `user.type_id` of the subject (OCSF 1.9.0: 0 Unknown, 1 User, 2 Admin, 3 System, 99 Other): a person is a User, a client
/// or a workload is a System (a service identity), any other kind of identity is Other, and no subject is Unknown.
const USER_TYPE_UNKNOWN: i64 = 0;
const USER_TYPE_USER: i64 = 1;
const USER_TYPE_SYSTEM_SUBJECT: i64 = 3;
const USER_TYPE_OTHER: i64 = 99;

/// `resources[].type` of the subject of an API Activity record, by its kind of identity (0029 "Pseudonyms").
fn resource_type(s: Option<&crate::Subject>) -> &'static str {
    match s.map(|s| s.kind.as_str()) {
        Some("person") => "person",
        Some("client") => "client",
        Some("workload") => "workload",
        _ => "other",
    }
}

/// `user.type_id` by the kind of identity (0029 "Pseudonyms"), so that a pseudonym of a client does not pass for one of a
/// person.
fn subject_type(s: Option<&crate::Subject>) -> i64 {
    match s.map(|s| s.kind.as_str()) {
        Some("person") => USER_TYPE_USER,
        Some("client" | "workload") => USER_TYPE_SYSTEM_SUBJECT,
        _ => USER_TYPE_OTHER,
    }
}
/// `entity.type_id` 99, Other: the type of an entity is the row's own word.
const ENTITY_TYPE_OTHER: i64 = 99;

/// Whether `s` has an e-mail shape: the pattern `[^@\s]+@[^@\s]+\.[^@\s]+` found anywhere in it
/// (0030: a record never carries an e-mail address). `\s` is the ASCII white space of RE2, as in
/// the Go crate, and the shared vectors keep the two in step.
pub(crate) fn email_shaped(s: &str) -> bool {
    let ws = |c: char| matches!(c, '\t' | '\n' | '\x0c' | '\r' | ' ');
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c != '@' || i == 0 {
            continue;
        }
        let before = chars[i - 1];
        if before == '@' || ws(before) {
            continue;
        }
        // The run after the '@' that holds no '@' and no white space must have a '.' with a
        // character on each side of it.
        let run: Vec<char> = chars[i + 1..]
            .iter()
            .copied()
            .take_while(|&x| x != '@' && !ws(x))
            .collect();
        if run.len() >= 3 && run[1..run.len() - 1].contains(&'.') {
            return true;
        }
    }
    false
}

/// Whether `s` is a name that `src_endpoint.name` may hold, the form of the type `source` of the table: a letter or an
/// underscore, then letters, digits and `. _ -`, at most 64 bytes. An IP address (numeric forms included), a host and a port, a
/// path and an address with a user have none of that shape; a host name cannot be told from a name of the registry and passes.
fn source_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b.iter().enumerate().all(|(i, &c)| {
            c.is_ascii_alphabetic()
                || c == b'_'
                || (i > 0 && (c.is_ascii_digit() || c == b'.' || c == b'-'))
        })
}

fn bound(s: &str, path: &str) -> Result<()> {
    if s.len() > STRING_MAX {
        return Err(invalid("bound", path));
    }
    Ok(())
}

fn check_text(s: &str, path: &str) -> Result<()> {
    bound(s, path)?;
    if email_shaped(s) {
        return Err(invalid("schema", path));
    }
    Ok(())
}

/// Checks what the library can know before it asks key@ for anything.
pub(crate) fn validate_event(ev: &Event) -> Result<()> {
    let a = &ev.action;
    if a.name.is_empty() || !(1000..=99999).contains(&a.class_uid) || a.activity_id > 99 {
        return Err(invalid("schema", "action"));
    }
    if ev.subject_best_effort && ev.status != crate::Status::Failure {
        // A subject is optional only on a refusal (ADR 0005). A success that went without the name of its subject would be a
        // fact that says less than it should, and nobody would be told.
        return Err(invalid("schema", "subject_best_effort"));
    }
    if a.activity_id == 99 && a.activity_name.is_empty() {
        // 0030: activity 99 (Other) is described by activity_name.
        return Err(invalid("schema", "action.activity_name"));
    }
    for (v, path) in [
        (a.name.as_str(), "action.name"),
        (a.activity_name.as_str(), "action.activity_name"),
        (ev.status_code.as_str(), "status_code"),
        (ev.tenant.as_str(), "tenant"),
    ] {
        check_text(v, path)?;
    }
    if let Some(s) = &ev.subject {
        if s.value.is_empty() {
            return Err(invalid("schema", "subject.value"));
        }
        // The subject is hashed and never sent, so an e-mail address is a fine subject.
        if s.kind.is_empty() {
            return Err(invalid("schema", "subject.kind"));
        }
        bound(&s.value, "subject.value")?;
        bound(&s.tenant, "subject.tenant")?;
        bound(&s.kind, "subject.kind")?;
    }
    if let Some(p) = &ev.policy {
        // OCSF's Policy object needs one of name, type or uid, and the record gives it a uid: the
        // decision id. A digest or a list of policies with no decision id has nothing to hang on.
        if p.decision_id.is_empty() {
            return Err(invalid("schema", "policy.decision_id"));
        }
        check_text(&p.decision_id, "policy.decision_id")?;
        check_text(&p.digest, "policy.digest")?;
        for (i, id) in p.policy_ids.iter().enumerate() {
            check_text(id, &format!("policy.policy_ids[{i}]"))?;
        }
        if p.results.len() > crate::RESULTS_MAX {
            return Err(invalid("bound", "policy.results"));
        }
        for (i, r) in p.results.iter().enumerate() {
            check_text(&r.policy_id, &format!("policy.results[{i}].policy_id"))?;
        }
    }
    if a.class_uid == CLASS_API_ACTIVITY {
        // OCSF's API Activity needs the operation and the source, and the library never invents either.
        if ev.operation.is_empty() {
            return Err(invalid("schema", "api.operation"));
        }
        if ev.caller.is_empty() {
            return Err(invalid("schema", "src_endpoint.name"));
        }
    } else if !ev.operation.is_empty() || !ev.caller.is_empty() {
        // Said for a class that has no place for them, they would be dropped without a word.
        return Err(invalid("schema", "api"));
    }
    check_text(&ev.operation, "api.operation")?;
    check_text(&ev.caller, "src_endpoint.name")?;
    if !ev.caller.is_empty() && !source_name(&ev.caller) {
        // The source is a name the transport read from the registry, never an address (ADR 0030): an IP address of a caller is
        // personal data of the person behind it, and the library would not know it for a name. The form is the schema's.
        return Err(invalid("schema", "src_endpoint.name"));
    }
    if let Some(e) = &ev.entity {
        if e.kind.is_empty() || (e.name.is_empty() && e.uid.is_empty()) {
            // OCSF's managed entity needs one of name and uid, and the record gives it a type.
            return Err(invalid("schema", "entity"));
        }
        for (v, path) in [
            (&e.kind, "entity.type"),
            (&e.name, "entity.name"),
            (&e.uid, "entity.uid"),
            (&e.version, "entity.version"),
        ] {
            check_text(v, path)?;
        }
    }
    // unmapped.sluis.lost is the emitter's own (0030 "The sluis fields"); a caller cannot write it.
    if ev.sluis.contains_key(LOST_KEY) {
        return Err(invalid("schema", &format!("unmapped.sluis.{LOST_KEY}")));
    }
    check_sluis(&ev.sluis, "unmapped.sluis", 0)
}

/// Admits only the types of `Event::sluis`: strings, booleans, integers within +-(2^53-1), lists of
/// strings and nested objects; bounded, with no e-mail shape in any string.
fn check_sluis(m: &Map<String, Value>, path: &str, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid("bound", path));
    }
    for (k, v) in m {
        let p = format!("{path}.{k}");
        bound(k, &p)?;
        match v {
            Value::String(s) => check_text(s, &p)?,
            Value::Bool(_) => {}
            Value::Number(n) => match n.as_i64() {
                Some(i) if (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) => {}
                Some(_) => return Err(invalid("bound", &p)),
                // Above i64::MAX is above the bound; anything else is a float.
                None if n.is_u64() => return Err(invalid("bound", &p)),
                None => return Err(invalid("schema", &p)),
            },
            Value::Array(items) => {
                for (i, e) in items.iter().enumerate() {
                    match e {
                        Value::String(s) => check_text(s, &format!("{p}[{i}]"))?,
                        _ => return Err(invalid("schema", &p)),
                    }
                }
            }
            Value::Object(o) => check_sluis(o, &p, depth + 1)?,
            Value::Null => return Err(invalid("schema", &p)),
        }
    }
    Ok(())
}

/// Everything the record depends on, resolved: tests feed it fixed values.
pub(crate) struct RecordInput<'a> {
    pub actor: &'a str,
    pub boundary: &'a str,
    pub release: &'a str,
    pub uid: &'a str,
    pub time_ms: i64,
    pub correlation: Option<&'a str>,
    pub pseudonym: Option<&'a str>,
    pub ev: &'a Event,
    /// The running total of facts lost for the record's tenant; none when the total is 0.
    pub lost: LostNote,
}

/// Lays out the record and returns its RFC 8785 bytes. The members are OCSF 1.9.0 base event
/// attributes: `activity_id`, `category_uid`, `class_uid`, `severity_id`, `status_id`,
/// `status_code`, `time` and `type_uid`; the `metadata` object; `actor.user`; `user`; and, from the
/// `security_control` profile, `policy` and `authorizations`.
pub(crate) fn build_record(inp: &RecordInput<'_>) -> Result<Vec<u8>> {
    let ev = inp.ev;
    let a = &ev.action;
    let class = i64::from(a.class_uid);
    let activity = i64::from(a.activity_id);
    let mut md = json!({
        "event_code": a.name,
        "log_name": inp.boundary,
        "product": {"name": "sluis", "version": inp.release},
        "uid": inp.uid,
        "version": OCSF_VERSION,
    });
    // REQ-AUDIT-120: the record declares the profiles whose attributes it uses. The security_control profile holds
    // policy, action_id and authorizations; Application Lifecycle takes `actor` from the host profile.
    let mut profiles = Vec::new();
    if a.class_uid == CLASS_APPLICATION_LIFECYCLE {
        profiles.push("host");
    }
    if ev.policy.is_some() {
        profiles.push("security_control");
    }
    if !profiles.is_empty() {
        md["profiles"] = json!(profiles);
    }
    if let Some(c) = inp.correlation.filter(|c| !c.is_empty()) {
        md["correlation_uid"] = json!(c);
    }
    if !ev.tenant.is_empty() {
        md["tenant_uid"] = json!(ev.tenant);
    }
    let mut rec = json!({
        "activity_id": activity,
        "category_uid": class / 1000,
        "class_uid": class,
        "metadata": md,
        "actor": {"user": {"type_id": USER_TYPE_SYSTEM, "uid": format!("{}@{}", inp.actor, inp.boundary)}},
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": ev.status as i64,
        "time": inp.time_ms,
        "type_uid": class * 100 + activity,
    });
    if !a.activity_name.is_empty() {
        rec["activity_name"] = json!(a.activity_name);
    }
    if !ev.status_code.is_empty() {
        rec["status_code"] = json!(ev.status_code);
    }
    if let Some(p) = inp.pseudonym.filter(|p| !p.is_empty()) {
        if a.class_uid == CLASS_API_ACTIVITY {
            // OCSF gives API Activity no user: the person or client a call concerns is the resource of the call, with the kind
            // of identity as its type.
            rec["resources"] = json!([{"type": resource_type(ev.subject.as_ref()), "uid": p}]);
        } else {
            rec["user"] = json!({"uid": p, "type_id": subject_type(ev.subject.as_ref())});
        }
    } else if a.class_uid == CLASS_AUTHENTICATION {
        // OCSF requires the subject of an authentication; none is known, and the record says so.
        rec["user"] = json!({"uid": USER_UNKNOWN, "type_id": USER_TYPE_UNKNOWN});
    }
    if let Some(e) = &ev.entity {
        // OCSF's managed entity: type_id 99 (Other) is required beside a type of the sender's own.
        let mut ent = json!({"type": e.kind, "type_id": ENTITY_TYPE_OTHER});
        for (k, v) in [("name", &e.name), ("uid", &e.uid), ("version", &e.version)] {
            if !v.is_empty() {
                ent[k] = json!(v);
            }
        }
        rec["entity"] = ent;
    }
    // The attributes a class requires that the emitter's own name fills: the application that started or reloaded,
    // the service that authenticated. Both are the emitting actor, a name of the registry.
    match a.class_uid {
        CLASS_API_ACTIVITY => {
            // The call and where it came from, both chosen by the actor from what the transport told it.
            if !ev.operation.is_empty() {
                rec["api"] = json!({"operation": ev.operation});
            }
            if !ev.caller.is_empty() {
                rec["src_endpoint"] = json!({"name": ev.caller});
            }
        }
        CLASS_APPLICATION_LIFECYCLE => rec["application"] = json!({"name": inp.actor}),
        CLASS_AUTHENTICATION => rec["service"] = json!({"name": inp.actor}),
        _ => {}
    }
    let with_lost;
    let sluis = if inp.lost.total > 0 {
        let mut m = ev.sluis.clone();
        m.insert(
            LOST_KEY.into(),
            json!({"process": inp.lost.process, "total": inp.lost.total, "since": inp.lost.since}),
        );
        with_lost = m;
        &with_lost
    } else {
        &ev.sluis
    };
    if !sluis.is_empty() {
        rec["unmapped"] = json!({"sluis": sluis});
    }
    if let Some(p) = &ev.policy {
        // security_control profile: the policy object names the decision (uid) and the policy
        // bundle (version, the digest); action_id is the outcome; each policy that took part is an
        // authorization_result with its policy.uid and the same decision.
        let mut pol = Map::new();
        pol.insert("uid".into(), json!(p.decision_id));
        if !p.digest.is_empty() {
            pol.insert("version".into(), json!(p.digest));
        }
        rec["policy"] = Value::Object(pol);
        if let Some(d) = p.decision {
            rec["action_id"] = json!(d as i64);
        }
        // The policies that took part, each with the verdict, as ever; or, when the caller gives the results of
        // several decisions, one entry for each of them, in its order.
        let entry = |id: &str, decision: Option<Decision>| {
            let mut au = if id.is_empty() {
                json!({})
            } else {
                json!({"policy": {"uid": id}})
            };
            if let Some(d) = decision {
                au["decision"] = json!(d.caption());
            }
            au
        };
        let auths: Vec<Value> = if p.results.is_empty() {
            p.policy_ids
                .iter()
                .map(|id| entry(id, p.decision))
                .collect()
        } else {
            p.results
                .iter()
                .map(|r| entry(&r.policy_id, r.decision))
                .collect()
        };
        if !auths.is_empty() {
            rec["authorizations"] = Value::Array(auths);
        }
    }
    let out = canonical(&rec)?;
    if out.len() > RECORD_MAX {
        return Err(invalid("bound", "record"));
    }
    Ok(out)
}

#[cfg(test)]
mod decisions {
    use super::*;
    use crate::{Action, Decided, PolicyRef, RESULTS_MAX, Status};

    fn event(p: PolicyRef) -> Event {
        Event {
            caller: "entry".into(),
            operation: "Search".into(),
            action: Action {
                name: "reader.search".into(),
                class_uid: 6003,
                activity_id: 2,
                activity_name: String::new(),
            },
            status: Status::Failure,
            policy: Some(p),
            ..Event::default()
        }
    }

    fn record(ev: &Event) -> Value {
        let bytes = build_record(&RecordInput {
            actor: "reader",
            boundary: "dev",
            release: "r",
            uid: "u",
            time_ms: 0,
            correlation: None,
            pseudonym: None,
            ev,
            lost: LostNote::default(),
        })
        .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn pol(id: &str, d: Decision, results: Vec<Decided>) -> PolicyRef {
        PolicyRef {
            decision_id: id.into(),
            digest: "sha384:x".into(),
            policy_ids: vec!["ignored-when-results".into()],
            decision: Some(d),
            results,
        }
    }

    fn res(id: &str, d: Decision) -> Decided {
        Decided {
            policy_id: id.into(),
            decision: Some(d),
        }
    }

    /// verifies: REQ-AUDIT-074
    #[test]
    fn the_results_of_several_decisions_are_the_authorizations_in_their_order() {
        // A read of two tenants where the second was denied by default: `policy` names the denying decision and the
        // authorizations list both, in the order they were made, the denial with its verdict alone.
        let ev = event(pol(
            "d-deny",
            Decision::Denied,
            vec![res("bind-a", Decision::Allowed), res("", Decision::Denied)],
        ));
        let r = record(&ev);
        assert_eq!(r["policy"]["uid"], "d-deny");
        assert_eq!(r["action_id"], 2);
        assert_eq!(
            r["authorizations"],
            serde_json::json!([
                {"policy": {"uid": "bind-a"}, "decision": "Allowed"},
                {"decision": "Denied"},
            ])
        );
    }

    /// verifies: REQ-AUDIT-074
    #[test]
    fn a_record_without_results_is_as_it_was_and_the_results_are_bounded_and_checked() {
        // The policies of one decision, each with its verdict, and nothing for a denial no policy determined.
        let mut one = pol("d-1", Decision::Allowed, vec![]);
        one.policy_ids = vec!["p-1".into(), "p-2".into()];
        let r = record(&event(one));
        assert_eq!(r["authorizations"].as_array().unwrap().len(), 2);
        let mut none = pol("d-1", Decision::Denied, vec![]);
        none.policy_ids.clear();
        let r = record(&event(none));
        assert!(r.get("authorizations").is_none(), "{r}");
        assert_eq!(r["action_id"], 2);

        let many = |n: usize| {
            event(pol(
                "d-1",
                Decision::Denied,
                (0..n).map(|_| res("p", Decision::Allowed)).collect(),
            ))
        };
        assert!(validate_event(&many(RESULTS_MAX)).is_ok());
        assert!(validate_event(&many(RESULTS_MAX + 1)).is_err());
        let mail = event(pol(
            "d-1",
            Decision::Denied,
            vec![res("a@b.example", Decision::Allowed)],
        ));
        assert!(
            validate_event(&mail).is_err(),
            "a policy id holds an e-mail address"
        );
    }
}
