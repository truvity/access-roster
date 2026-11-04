#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The shared vectors of `kits/conformance/audit`, which the Go package passes too, and the
//! checks that need no socket.

use serde_json::{Map, Value};

use crate::canonical::{canonical, invalid};
use crate::record::{RecordInput, build_record, email_shaped, validate_event};
use crate::uuid::{new_uuid_v7, uuid_v7};
use crate::{
    Action, Decision, Event, PolicyRef, RECORD_MAX, STRING_MAX, Status, Subject, epoch_of,
    format_pseudonym, pseudonym_input,
};

const JCS: &str = include_str!("../../../conformance/audit/jcs-vectors.json");
const RECORDS: &str = include_str!("../../../conformance/audit/record-vectors.json");

fn parse(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("{k} is not a list"))
}

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
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
        }),
        sluis: sluis_of(v.get("sluis")),
        correlation_id: None,
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
    let mut prev = String::new();
    // More than the 4,096 values of the counter: the timestamp moves on instead of repeating.
    for i in 0..6000 {
        let u = new_uuid_v7(1_793_750_500_000);
        assert!(u > prev, "value {i} ({u}) does not follow {prev}");
        prev = u;
    }
    let a = new_uuid_v7(1_793_750_600_000);
    let b = new_uuid_v7(1_793_750_599_000);
    assert!(b > a);
}

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
