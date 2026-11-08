#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The shared vectors of `kits/conformance/audit`, which the Go package passes too, and the
//! checks that need no socket.

use serde_json::{Map, Value};

use crate::canonical::{canonical, invalid};
use crate::record::{RecordInput, build_record, email_shaped, validate_event};
use crate::uuid::{State, new_uuid_v7, next_uuid_v7, uuid_v7};
use crate::{
    Action, Decision, Event, LostNote, PolicyRef, RECORD_MAX, STRING_MAX, Status, Subject,
    epoch_of, format_pseudonym, pseudonym_input,
};

const JCS: &str = include_str!("../../../conformance/audit/jcs-vectors.json");
const RECORDS: &str = include_str!("../../../conformance/audit/record-vectors.json");

pub(crate) fn parse(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

pub(crate) fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("{k} is not a list"))
}

pub(crate) fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

/// The members OCSF gives to the text of an enum id; a stored record holds the ids.
const CAPTION_KEYS: [&str; 9] = [
    "caption",
    "severity",
    "status",
    "type",
    "category",
    "class",
    "activity",
    "action",
    "disposition",
];

/// What a stored record must not hold outside `unmapped`: observables, enrichments and enum captions.
/// `activity_name` describes activity 99, `entity.type` names the kind of an entity of type_id 99 (the toolkit requires it
/// beside the id), and `authorizations[].decision` is the one caption OCSF requires.
fn lean_violations(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, e) in m {
                let p = format!("{path}/{k}");
                if p == "/unmapped" {
                    continue;
                }
                let caption = (p != "/entity/type"
                    && (k == "observables"
                        || k == "enrichments"
                        || CAPTION_KEYS.contains(&k.as_str())))
                    || (k.ends_with("_name")
                        && ![
                            "/activity_name",
                            "/metadata/log_name",
                            "/metadata/product/name",
                        ]
                        .contains(&p.as_str()))
                    || (k == "decision" && p != "/authorizations[]/decision");
                if caption {
                    out.push(p.clone());
                }
                lean_violations(e, &p, out);
            }
        }
        Value::Array(a) => {
            for e in a {
                lean_violations(e, &format!("{path}[]"), out);
            }
        }
        _ => {}
    }
}

/// The note of lost facts a record vector carries; none when it has no `lost`.
fn lost_of(c: &Value) -> LostNote {
    c.get("lost").map_or_else(LostNote::default, |l| LostNote {
        process: text(l, "process").to_owned(),
        total: l["total"].as_i64().unwrap(),
        since: l["since"].as_i64().unwrap(),
    })
}

/// The record the emitter builds from the inputs of a record vector.
pub(crate) fn built_record(c: &Value) -> String {
    let ev = event_of(&c["event"]);
    let got = build_record(&RecordInput {
        actor: text(c, "actor"),
        boundary: text(c, "boundary"),
        release: text(c, "release"),
        uid: text(c, "uid"),
        time_ms: c["time_ms"].as_i64().unwrap(),
        correlation: c.get("correlation").and_then(Value::as_str),
        pseudonym: c.get("pseudonym").and_then(Value::as_str),
        ev: &ev,
        lost: lost_of(c),
    })
    .unwrap();
    String::from_utf8(got).unwrap()
}

/// verifies: REQ-AUDIT-091
#[test]
fn record_vectors_are_lean() {
    let f = parse(RECORDS);
    assert!(!arr(&f, "cases").is_empty());
    for c in arr(&f, "cases") {
        let mut bad = Vec::new();
        lean_violations(&parse(&built_record(c)), "", &mut bad);
        assert!(bad.is_empty(), "{}: not lean: {bad:?}", text(c, "name"));
    }
    // The check is not vacuous: a record with each kind of violation is flagged.
    let dirty = serde_json::json!({
        "class_name": "API Activity", "observables": [], "enrichments": [],
        "severity": "Informational", "status": "Success", "caption": "x",
        "actor": {"user": {"type": "System"}, "user_name": "x"},
        "authorizations": [{"decision": "Allowed"}],
        "policy": {"decision": "Allowed"}
    });
    let mut bad = Vec::new();
    lean_violations(&dirty, "", &mut bad);
    bad.sort();
    assert_eq!(
        bad,
        [
            "/actor/user/type",
            "/actor/user_name",
            "/caption",
            "/class_name",
            "/enrichments",
            "/observables",
            "/policy/decision",
            "/severity",
            "/status"
        ]
    );
}

fn delegation_uses(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, e) in m {
                let p = format!("{path}/{k}");
                if k == "delegation" {
                    out.push(p.clone());
                }
                if p == "/metadata/profiles" {
                    for pr in e.as_array().into_iter().flatten() {
                        if pr != "security_control" && pr != "host" {
                            out.push(format!("{p}={}", pr.as_str().unwrap_or("?")));
                        }
                    }
                }
                delegation_uses(e, &p, out);
            }
        }
        Value::Array(a) => a
            .iter()
            .for_each(|e| delegation_uses(e, &format!("{path}[]"), out)),
        _ => {}
    }
}

/// verifies: REQ-AUDIT-124
#[test]
fn record_vectors_use_no_delegation_and_no_ai_profile() {
    let f = parse(RECORDS);
    assert!(!arr(&f, "cases").is_empty());
    for c in arr(&f, "cases") {
        let mut bad = Vec::new();
        delegation_uses(&parse(&built_record(c)), "", &mut bad);
        assert!(bad.is_empty(), "{}: {bad:?}", text(c, "name"));
    }
    let dirty = serde_json::json!({"delegation": {}, "metadata": {"profiles": ["security_control", "ai_operation"]}});
    let mut bad = Vec::new();
    delegation_uses(&dirty, "", &mut bad);
    bad.sort();
    assert_eq!(bad, ["/delegation", "/metadata/profiles=ai_operation"]);
}

#[test]
fn canonical_matches_the_jcs_vectors() {
    let f = parse(JCS);
    assert!(!arr(&f, "vectors").is_empty() && !arr(&f, "refused").is_empty());
    for v in arr(&f, "vectors") {
        let got = canonical(&v["input"]).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            text(v, "expected"),
            "{}",
            text(v, "name")
        );
    }
    for v in arr(&f, "refused") {
        assert!(
            canonical(&v["input"]).is_err(),
            "{} was accepted",
            text(v, "name")
        );
    }
}

/// The reason and the field path of a refusal.
pub(crate) fn refusal_of(e: &connectrpc::ConnectError) -> (String, String) {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use buffa::Message as _;
    let d = e
        .details
        .iter()
        .find(|d| d.type_url.ends_with("sluis.type.v2alpha1.Refusal"))
        .expect("a Refusal detail");
    let raw = d.value.as_deref().unwrap();
    let bytes = STANDARD_NO_PAD
        .decode(raw)
        .or_else(|_| STANDARD.decode(raw))
        .unwrap();
    let r = sluis_proto::sluis::r#type::v2alpha1::Refusal::decode_from_slice(&bytes).unwrap();
    (r.reason, r.field_path)
}

#[test]
fn canonical_refuses_what_is_not_record_data() {
    let big = Value::from(1_u64 << 53);
    assert_eq!(refusal_of(&canonical(&big).unwrap_err()).0, "bound");
    assert_eq!(
        refusal_of(&canonical(&Value::from(u64::MAX)).unwrap_err()).0,
        "bound"
    );
    assert_eq!(
        refusal_of(&canonical(&Value::from(1.5_f64)).unwrap_err()).0,
        "schema"
    );
    let mut deep = Value::from("x");
    for _ in 0..crate::canonical::MAX_DEPTH + 2 {
        deep = Value::Array(vec![deep]);
    }
    assert!(canonical(&deep).is_err());
    assert_eq!(refusal_of(&invalid("bound", "a.b")).1, "a.b");
}

fn event_of(v: &Value) -> Event {
    let v = &expand(v);
    let a = &v["action"];
    Event {
        action: Action {
            name: text(a, "name").into(),
            class_uid: u32::try_from(a["class_uid"].as_u64().unwrap()).unwrap(),
            activity_id: u32::try_from(a["activity_id"].as_u64().unwrap()).unwrap(),
            activity_name: text(a, "activity_name").into(),
        },
        status: if v["status"] == 2 {
            Status::Failure
        } else {
            Status::Success
        },
        status_code: text(v, "status_code").into(),
        tenant: text(v, "tenant").into(),
        subject: v.get("subject").map(|s| Subject {
            tenant: text(s, "tenant").into(),
            kind: text(s, "kind").into(),
            value: text(s, "value").into(),
        }),
        policy: v.get("policy").map(|p| PolicyRef {
            decision: match p.get("decision").and_then(Value::as_i64) {
                Some(1) => Some(Decision::Allowed),
                Some(2) => Some(Decision::Denied),
                _ => None,
            },
            decision_id: text(p, "decision_id").into(),
            digest: text(p, "digest").into(),
            policy_ids: p
                .get("policy_ids")
                .and_then(Value::as_array)
                .map(|l| l.iter().map(|s| s.as_str().unwrap().into()).collect())
                .unwrap_or_default(),
            ..PolicyRef::default()
        }),
        sluis: sluis_of(v.get("sluis")),
        correlation_id: None,
        entity: v.get("entity").map(|e| crate::Entity {
            kind: text(e, "type").into(),
            name: text(e, "name").into(),
            uid: text(e, "uid").into(),
            version: text(e, "version").into(),
        }),
        subject_best_effort: false,
    }
}

/// `{"$repeat": "a", "times": n}` is a string of n copies, so a vector can hold a long string.
fn expand(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            if let Some(Value::String(s)) = m.get("$repeat") {
                return Value::String(
                    s.repeat(usize::try_from(m["times"].as_u64().unwrap()).unwrap()),
                );
            }
            Value::Object(m.iter().map(|(k, e)| (k.clone(), expand(e))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(expand).collect()),
        other => other.clone(),
    }
}

fn sluis_of(v: Option<&Value>) -> Map<String, Value> {
    match v.map(expand) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// verifies: REQ-AUDIT-186, REQ-AUDIT-188
#[test]
fn records_match_the_vectors() {
    let f = parse(RECORDS);
    assert!(!arr(&f, "cases").is_empty());
    for c in arr(&f, "cases") {
        let ev = event_of(&c["event"]);
        let got = build_record(&RecordInput {
            actor: text(c, "actor"),
            boundary: text(c, "boundary"),
            release: text(c, "release"),
            uid: text(c, "uid"),
            time_ms: c["time_ms"].as_i64().unwrap(),
            correlation: c.get("correlation").and_then(Value::as_str),
            pseudonym: c.get("pseudonym").and_then(Value::as_str),
            ev: &ev,
            lost: lost_of(c),
        })
        .unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            text(c, "expected"),
            "{}",
            text(c, "name")
        );
    }
}

/// verifies: REQ-AUDIT-051
#[test]
fn uuids_match_the_vectors() {
    let f = parse(RECORDS);
    assert!(!arr(&f, "uuids").is_empty());
    for v in arr(&f, "uuids") {
        let h = text(v, "rand_b_hex");
        let mut rb = [0u8; 8];
        for (i, b) in rb.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        let got = uuid_v7(
            v["ms"].as_u64().unwrap(),
            u16::try_from(v["counter"].as_u64().unwrap()).unwrap(),
            rb,
        );
        assert_eq!(got, text(v, "expected"));
    }
}

#[test]
fn pseudonyms_match_the_vectors() {
    let f = parse(RECORDS);
    assert!(!arr(&f, "pseudonyms").is_empty());
    for v in arr(&f, "pseudonyms") {
        let h = text(v, "mac_hex");
        let mac: Vec<u8> = (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let epoch = epoch_of(v["time_ms"].as_i64().unwrap());
        assert_eq!(epoch, text(v, "epoch"));
        assert_eq!(format_pseudonym(&epoch, &mac), text(v, "expected"));
    }
}

fn base_event() -> Event {
    Event {
        action: Action {
            name: "key.sign".into(),
            class_uid: 6003,
            activity_id: 99,
            activity_name: "Sign".into(),
        },
        ..Event::default()
    }
}

/// verifies: REQ-AUDIT-188
#[test]
fn a_success_cannot_leave_its_subject_best_effort() {
    let mut ev = base_event();
    ev.subject_best_effort = true;
    let e = validate_event(&ev).unwrap_err();
    assert_eq!(
        refusal_of(&e),
        ("schema".into(), "subject_best_effort".into())
    );
    ev.status = Status::Failure;
    validate_event(&ev).unwrap();
}

/// verifies: REQ-AUDIT-188
///
/// While key@ is down every refusal of session goes without its subject, and a warning for each would be a flood: one in a
/// minute, with the others counted for the next.
#[test]
fn the_warning_that_a_subject_went_unnamed_is_limited() {
    let lost = crate::Lost::new();
    let unnamed = |l: &crate::Lost| l.state().subject_unnamed;
    for _ in 0..5 {
        lost.warn_subject_unnamed(1_000, "session.signin");
    }
    assert_eq!(
        unnamed(&lost),
        4,
        "the first warned, the other four are counted"
    );
    lost.warn_subject_unnamed(1_000 + crate::SUBJECT_WARN_EVERY_MS - 1, "session.signin");
    assert_eq!(unnamed(&lost), 5, "still inside the minute");
    lost.warn_subject_unnamed(1_000 + crate::SUBJECT_WARN_EVERY_MS, "session.signin");
    assert_eq!(
        unnamed(&lost),
        0,
        "a minute on, it warned and started again"
    );
}

#[test]
fn refusals_match_the_vectors() {
    let f = parse(RECORDS);
    assert!(!arr(&f, "refusals").is_empty());
    for r in arr(&f, "refusals") {
        let mut ev = base_event();
        ev.sluis = sluis_of(r.get("sluis"));
        let err = validate_event(&ev).expect_err(text(r, "name"));
        let (reason, path) = refusal_of(&err);
        assert_eq!(reason, text(r, "reason"), "{}", text(r, "name"));
        assert_eq!(path, text(r, "path"), "{}", text(r, "name"));
        assert!(
            !err.to_string().contains("example"),
            "the error shows a value"
        );
    }
    for a in arr(&f, "accepted") {
        let mut ev = base_event();
        ev.sluis = sluis_of(a.get("sluis"));
        validate_event(&ev).unwrap_or_else(|e| panic!("{}: {e}", text(a, "name")));
    }
}

#[test]
fn the_email_shape_agrees_with_the_vectors() {
    let f = parse(RECORDS);
    for s in arr(&f["email"], "match") {
        assert!(email_shaped(s.as_str().unwrap()), "{s} should match");
    }
    for s in arr(&f["email"], "no_match") {
        assert!(!email_shaped(s.as_str().unwrap()), "{s} should not match");
    }
}

#[test]
fn a_record_above_its_bound_is_refused() {
    let mut ev = base_event();
    for i in 0..20 {
        ev.sluis
            .insert(format!("k{i}"), Value::from("a".repeat(STRING_MAX)));
    }
    validate_event(&ev).unwrap();
    let err = build_record(&RecordInput {
        actor: "a",
        boundary: "dev",
        release: "r",
        uid: "u",
        time_ms: 0,
        correlation: None,
        pseudonym: None,
        ev: &ev,
        lost: LostNote::default(),
    })
    .unwrap_err();
    assert_eq!(refusal_of(&err), ("bound".into(), "record".into()));
    const { assert!(RECORD_MAX < 20 * STRING_MAX) };
}

#[test]
fn the_event_checks() {
    type Case = (&'static str, fn(&mut Event));
    let cases: Vec<Case> = vec![
        ("no action name", |e| e.action.name.clear()),
        ("class below 1000", |e| e.action.class_uid = 3),
        ("activity above 99", |e| e.action.activity_id = 100),
        ("long status code", |e| {
            e.status_code = "a".repeat(STRING_MAX + 1)
        }),
        ("e-mail in tenant", |e| e.tenant = "a@b.example".into()),
        ("e-mail in decision", |e| {
            e.policy = Some(PolicyRef {
                decision_id: "a@b.example".into(),
                ..PolicyRef::default()
            });
        }),
        ("empty subject", |e| {
            e.subject = Some(crate::Subject {
                tenant: "acme".into(),
                kind: "person".into(),
                value: String::new(),
            });
        }),
        ("a list of numbers", |e| {
            e.sluis.insert("n".into(), Value::from(vec![1, 2]));
        }),
    ];
    for (name, f) in cases {
        let mut ev = base_event();
        f(&mut ev);
        assert!(validate_event(&ev).is_err(), "{name} accepted");
    }
    // An e-mail address is a fine subject: it is hashed, and the record never carries it.
    let mut ev = base_event();
    ev.subject = Some(crate::Subject {
        tenant: "acme".into(),
        kind: "person".into(),
        value: "alice@example.com".into(),
    });
    validate_event(&ev).unwrap();
}

/// verifies: REQ-AUDIT-051
#[test]
fn uuid_v7_has_version_variant_and_the_clock() {
    // Far ahead of the other tests: the generator never goes back, and they share its state.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 1_000_000_000_000;
    let u = new_uuid_v7(now);
    let b = u.as_bytes();
    assert_eq!(u.len(), 36);
    assert!([8, 13, 18, 23].iter().all(|&i| b[i] == b'-'));
    assert_eq!(b[14], b'7', "version (RFC 9562 section 5.7)");
    assert!(b"89ab".contains(&b[19]), "variant (RFC 9562 section 4.1)");
    let ms = u64::from_str_radix(&u.replace('-', "")[..12], 16).unwrap();
    assert_eq!(ms, u64::try_from(now).unwrap());
}

#[test]
fn uuid_v7_increases_within_one_millisecond_and_when_the_clock_steps_back() {
    // A state of its own: the tests share the process-wide one and run side by side.
    let mut st = State::new();
    let mut prev = String::new();
    // More than the 4,096 values of the counter: the timestamp moves on instead of repeating.
    for i in 0..6000 {
        let u = next_uuid_v7(&mut st, 1_793_750_500_000);
        assert!(u > prev, "value {i} ({u}) does not follow {prev}");
        prev = u;
    }
    let a = next_uuid_v7(&mut st, 1_793_750_600_000);
    let b = next_uuid_v7(&mut st, 1_793_750_599_000);
    assert!(b > a);
}

#[test]
fn uuid_v7_follows_the_clock_again_after_a_spike_of_more_than_a_minute() {
    let mut st = State::new();
    let spiked = next_uuid_v7(&mut st, 1_793_750_500_000 + 20 * 86_400_000);
    let back = next_uuid_v7(&mut st, 1_793_750_500_000);
    let ms = |u: &str| u64::from_str_radix(&u.replace('-', "")[..12], 16).unwrap();
    assert_eq!(ms(&spiked), 1_793_750_500_000 + 20 * 86_400_000);
    assert_eq!(
        ms(&back),
        1_793_750_500_000,
        "an id keeps the time of a spike"
    );
    // Within the minute the values still follow each other.
    let again = next_uuid_v7(&mut st, 1_793_750_500_000 - 30_000);
    assert!(again > back);
}

/// verifies: REQ-AUDIT-129
#[test]
fn the_epoch_is_the_utc_month() {
    assert_eq!(epoch_of(0), "197001");
    assert_eq!(epoch_of(1_793_750_400_000), "202611");
    assert_eq!(epoch_of(1_767_225_599_999), "202512");
    assert_eq!(epoch_of(1_767_225_600_000), "202601");
    assert_eq!(epoch_of(951_782_400_000), "200002"); // 2000-02-29
    assert_eq!(epoch_of(-1), "196912");
}

#[test]
fn event_refusals_and_acceptances_match_the_vectors() {
    let f = parse(RECORDS);
    assert!(!arr(&f, "event_refusals").is_empty() && !arr(&f, "event_accepted").is_empty());
    for r in arr(&f, "event_refusals") {
        let err = validate_event(&event_of(&r["event"])).expect_err(text(r, "name"));
        let (reason, path) = refusal_of(&err);
        assert_eq!(reason, text(r, "reason"), "{}", text(r, "name"));
        assert_eq!(path, text(r, "path"), "{}", text(r, "name"));
    }
    for a in arr(&f, "event_accepted") {
        validate_event(&event_of(&a["event"]))
            .unwrap_or_else(|e| panic!("{}: {e}", text(a, "name")));
    }
}

#[test]
fn the_pseudonym_input_matches_the_vectors() {
    let f = parse(RECORDS);
    assert_eq!(text(&f, "mac_label"), crate::PSEUDONYM_LABEL);
    assert!(!arr(&f, "mac_inputs").is_empty());
    let mut seen = std::collections::HashSet::new();
    for v in arr(&f, "mac_inputs") {
        let got: String = pseudonym_input(
            text(v, "boundary"),
            &Subject {
                tenant: text(v, "tenant").into(),
                kind: text(v, "kind").into(),
                value: text(v, "value").into(),
            },
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
        assert_eq!(got, text(v, "input_hex"));
        assert!(seen.insert(got), "two vectors give the same input");
    }
}

#[test]
fn a_policy_declares_its_profile_and_a_record_without_one_does_not() {
    let rec = |ev: &Event| {
        String::from_utf8(
            build_record(&RecordInput {
                actor: "a",
                boundary: "dev",
                release: "r",
                uid: "u",
                time_ms: 0,
                correlation: None,
                pseudonym: None,
                ev,
                lost: LostNote::default(),
            })
            .unwrap(),
        )
        .unwrap()
    };
    let mut ev = base_event();
    assert!(!rec(&ev).contains("profiles") && !rec(&ev).contains("action_id"));
    ev.policy = Some(PolicyRef {
        decision_id: "d-1".into(),
        decision: Some(Decision::Denied),
        policy_ids: vec!["p-1".into()],
        ..PolicyRef::default()
    });
    let r = rec(&ev);
    assert!(r.contains(r#""profiles":["security_control"]"#), "{r}");
    assert!(
        r.contains(r#""action_id":2"#) && r.contains(r#""decision":"Denied""#),
        "{r}"
    );
}

// ---- RFC 8785 through the library (REQ-SEC-018): the corpus of the RFC's author, the differential
// file shared with the Go package, and a property test.

use std::fmt::Write as _;
use std::path::PathBuf;

use proptest::prelude::*;

/// `kits/conformance/audit`, which the Go package reads too.
fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/audit")
}

/// The corpus input file names, sorted, as the Go package sorts them.
fn corpus_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(conformance_dir().join("jcs-corpus/input"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("json"))
        })
        .collect();
    names.sort();
    names
}

fn corpus_file(dir: &str, name: &str) -> String {
    std::fs::read_to_string(conformance_dir().join("jcs-corpus").join(dir).join(name)).unwrap()
}

/// The corpus inputs that carry a number which is not an integer: the library canonicalises them
/// and the sluis profile refuses them.
const PROFILE_REFUSES: [&str; 2] = ["structures.json", "values.json"];

/// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
#[test]
fn the_corpus_through_the_library() {
    let names = corpus_names();
    assert!(!names.is_empty(), "no corpus input");
    for name in names {
        let got = serde_json_canonicalizer::pipe(&corpus_file("input", &name)).unwrap();
        assert_eq!(got, corpus_file("output", &name), "{name}");
    }
}

/// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
#[test]
fn the_corpus_through_canonical() {
    for name in corpus_names() {
        let v = parse(&corpus_file("input", &name));
        let got = canonical(&v);
        if PROFILE_REFUSES.contains(&name.as_str()) {
            assert!(
                got.is_err(),
                "{name}: a number that is not an integer was accepted"
            );
        } else {
            assert_eq!(
                String::from_utf8(got.unwrap()).unwrap(),
                corpus_file("output", &name),
                "{name}"
            );
        }
    }
}

/// One line per case: `name TAB canonical text`, or `!refused`; canonical JSON holds no raw tab
/// or newline. The Go package builds the same lines from the same inputs.
fn differential_lines() -> String {
    let mut out = String::new();
    let mut line = |name: &str, got: Option<Vec<u8>>| {
        let text = got.map_or_else(|| "!refused".to_owned(), |b| String::from_utf8(b).unwrap());
        assert!(!text.contains(['\t', '\n']), "{name}: a raw tab or newline");
        writeln!(out, "{name}\t{text}").unwrap();
    };
    for name in corpus_names() {
        let input = corpus_file("input", &name);
        line(
            &format!("corpus-library/{name}"),
            serde_json_canonicalizer::pipe(&input)
                .ok()
                .map(String::into_bytes),
        );
        line(
            &format!("corpus-profile/{name}"),
            canonical(&parse(&input)).ok(),
        );
    }
    let f = parse(JCS);
    for v in arr(&f, "vectors") {
        line(
            &format!("jcs-vectors/{}", text(v, "name")),
            canonical(&v["input"]).ok(),
        );
    }
    for v in arr(&f, "refused") {
        line(
            &format!("jcs-vectors-refused/{}", text(v, "name")),
            canonical(&v["input"]).ok(),
        );
    }
    let f = parse(RECORDS);
    for c in arr(&f, "cases") {
        let ev = event_of(&c["event"]);
        line(
            &format!("record/{}", text(c, "name")),
            build_record(&RecordInput {
                actor: text(c, "actor"),
                boundary: text(c, "boundary"),
                release: text(c, "release"),
                uid: text(c, "uid"),
                time_ms: c["time_ms"].as_i64().unwrap(),
                correlation: c.get("correlation").and_then(Value::as_str),
                pseudonym: c.get("pseudonym").and_then(Value::as_str),
                ev: &ev,
                lost: lost_of(c),
            })
            .ok(),
        );
    }
    out
}

/// The Rust half of the differential test: the Go package builds the same lines and compares them
/// with the same file, so Go and Rust give identical bytes for the corpus and for the audit
/// vectors. The Go test writes the file; a changed byte is a changed audit record hash.
///
/// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
#[test]
fn rust_and_go_give_identical_bytes() {
    let want = std::fs::read_to_string(conformance_dir().join("jcs-differential.tsv")).unwrap();
    let got = differential_lines();
    for (i, (g, w)) in got.lines().zip(want.lines()).enumerate() {
        assert_eq!(g, w, "line {} differs", i + 1);
    }
    assert_eq!(got.lines().count(), want.lines().count(), "line count");
}

/// Whether a value is inside the sluis profile, decided without the code under test.
fn in_profile(v: &Value, depth: usize) -> bool {
    depth <= 16
        && match v {
            Value::Null | Value::Bool(_) | Value::String(_) => true,
            Value::Number(n) => n
                .as_i64()
                .is_some_and(|i| i.unsigned_abs() <= 9_007_199_254_740_991),
            Value::Array(a) => a.iter().all(|e| in_profile(e, depth + 1)),
            Value::Object(m) => m.values().all(|e| in_profile(e, depth + 1)),
        }
}

fn any_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        (-(1_i64 << 53)..=(1_i64 << 53)).prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_map(|f| serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)),
        any::<String>().prop_map(Value::from),
        "[a\u{e9}\u{20ac}\u{fb33}\u{1f600}\u{10000}\\n\"\\\\<]{0,4}".prop_map(Value::from),
    ];
    leaf.prop_recursive(20, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::hash_map(
                prop_oneof![
                    any::<String>(),
                    "[a\u{e9}\u{20ac}\u{fb33}\u{1f600}\u{10000}]{0,3}"
                ],
                inner,
                0..6
            )
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// What `canonical` accepts is exactly the sluis profile; it is valid JSON, its own canonical
    /// form (the library maps it to itself) and the value it was given. What it refuses, it
    /// refuses with a reason.
    ///
    /// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
    #[test]
    fn canonical_accepts_the_profile_and_is_idempotent(v in any_value()) {
        match canonical(&v) {
            Ok(out) => {
                prop_assert!(in_profile(&v, 0), "accepted a value outside the profile");
                let text = String::from_utf8(out).unwrap();
                let back: Value = serde_json::from_str(&text).unwrap();
                prop_assert_eq!(&back, &v);
                prop_assert_eq!(serde_json_canonicalizer::pipe(&text).unwrap(), text);
            }
            Err(e) => {
                prop_assert!(!in_profile(&v, 0), "refused a value inside the profile");
                prop_assert!(!refusal_of(&e).0.is_empty());
            }
        }
    }
}

/// A loss starts a new run when the last total has been reported, the total stops at the largest
/// integer of a record, and the tenants kept are bounded.
///
/// verifies: REQ-AUDIT-186
#[test]
fn the_total_of_lost_facts_starts_a_run_after_a_report_and_is_bounded() {
    let mut st = crate::LostState::default();
    st.record_loss("a", 50, "p");
    st.record_loss("a", 70, "p");
    let l = st.by_tenant["a"];
    assert_eq!(
        (l.total, l.since),
        (2, 50),
        "since is the first loss of the run"
    );
    st.by_tenant.get_mut("a").unwrap().reported = 2;
    st.record_loss("a", 90, "p");
    let l = st.by_tenant["a"];
    assert_eq!((l.total, l.since), (3, 90), "a report ends the run");

    let max = crate::canonical::MAX_SAFE_INT;
    st.by_tenant.get_mut("a").unwrap().total = max;
    st.record_loss("a", 99, "p");
    assert_eq!(st.by_tenant["a"].total, max);

    for i in 0..crate::MAX_LOST_TENANTS + 10 {
        st.record_loss(&format!("t{i}"), 1, "p");
    }
    assert!(
        st.by_tenant.len() <= crate::MAX_LOST_TENANTS + 1,
        "the map is bounded"
    );
    st.record_loss(&"x".repeat(STRING_MAX + 1), 1, "p");
    assert!(st.by_tenant.len() <= crate::MAX_LOST_TENANTS + 1);
}
