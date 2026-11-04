//! The checks on an event and the layout of the record (0030 "The record format").

use serde_json::{Map, Value, json};

use crate::canonical::{MAX_DEPTH, MAX_SAFE_INT, canonical, invalid};
use crate::{Event, OCSF_VERSION, RECORD_MAX, Result, STRING_MAX};

/// `actor.user.type_id` 3: "System" in the OCSF 1.9.0 user type enum (0 Unknown, 1 User, 2 Admin,
/// 3 System, 99 Other) and "sluis actor" in 0030 "The record format". The two agree.
const USER_TYPE_SYSTEM: i64 = 3;
/// OCSF `severity_id` 1, Informational.
const SEVERITY_INFORMATIONAL: i64 = 1;

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
    for (v, path) in [
        (a.name.as_str(), "action.name"),
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
        bound(&s.value, "subject.value")?;
        bound(&s.tenant, "subject.tenant")?;
    }
    if let Some(p) = &ev.policy {
        check_text(&p.decision_id, "policy.decision_id")?;
        check_text(&p.digest, "policy.digest")?;
        for (i, id) in p.policy_ids.iter().enumerate() {
            check_text(id, &format!("policy.policy_ids[{i}]"))?;
        }
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
    if !ev.status_code.is_empty() {
        rec["status_code"] = json!(ev.status_code);
    }
    if let Some(p) = inp.pseudonym.filter(|p| !p.is_empty()) {
        rec["user"] = json!({"uid": p});
    }
    if !ev.sluis.is_empty() {
        rec["unmapped"] = json!({"sluis": ev.sluis});
    }
    if let Some(p) = &ev.policy {
        // security_control: the policy object names the decision (uid) and the policy bundle
        // (version, the digest); each policy that took part is an authorization_result with its
        // policy.uid.
        let mut pol = Map::new();
        if !p.decision_id.is_empty() {
            pol.insert("uid".into(), json!(p.decision_id));
        }
        if !p.digest.is_empty() {
            pol.insert("version".into(), json!(p.digest));
        }
        if !pol.is_empty() {
            rec["policy"] = Value::Object(pol);
        }
        if !p.policy_ids.is_empty() {
            let auths: Vec<Value> = p
                .policy_ids
                .iter()
                .map(|id| json!({"policy": {"uid": id}}))
                .collect();
            rec["authorizations"] = Value::Array(auths);
        }
    }
    let out = canonical(&rec)?;
    if out.len() > RECORD_MAX {
        return Err(invalid("bound", "record"));
    }
    Ok(out)
}
