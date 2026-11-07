#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The action table and the schemas generated from it, against the shared vectors of `kits/conformance/audit`
//! that the Go package reads too.

use std::collections::HashSet;

use serde_json::Value;

use crate::table::Table;
use crate::tests::{arr, built_record, parse, refusal_of, text};
use crate::{Action, Event, Status};

const ACTIONS: &str = include_str!("../../../conformance/audit/action-vectors.json");
const SCHEMA: &str = include_str!("../../../conformance/audit/schema-vectors.json");
const DOMAINS: &str = include_str!("../../../conformance/audit/domain-vectors.json");

/// verifies: REQ-AUDIT-002
///
/// Every action of the table has an example record, the example is what the crate builds from its inputs (the same
/// bytes as the Go package), and it validates against the schema of its action.
#[test]
fn every_action_has_an_example_that_validates_against_its_schema() {
    let table = Table::sluis();
    let f = parse(ACTIONS);
    let mut seen = HashSet::new();
    for c in arr(&f, "cases") {
        let name = text(c, "name");
        let got = built_record(c);
        assert_eq!(
            got,
            text(c, "expected"),
            "{name}: not the bytes of the vector"
        );
        table
            .validate(got.as_bytes())
            .unwrap_or_else(|e| panic!("the schema of {name} refuses its own example: {e:?}"));
        seen.insert(name.to_owned());
    }
    for n in table.names() {
        assert!(seen.contains(n), "the action {n} has no example record");
    }
    assert_eq!(seen.len(), table.names().len());
}

fn set(root: &mut Value, path: &str, value: Option<Value>) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = root;
    for p in &parts[..parts.len() - 1] {
        if !cur.get(p).is_some_and(Value::is_object) {
            cur[*p] = Value::Object(serde_json::Map::new());
        }
        cur = cur.get_mut(*p).unwrap();
    }
    let last = parts[parts.len() - 1];
    match value {
        Some(v) => cur[last] = v,
        None => {
            cur.as_object_mut().unwrap().remove(last);
        }
    }
}

/// verifies: REQ-AUDIT-002, REQ-AUDIT-090, REQ-AUDIT-116, REQ-AUDIT-117, REQ-AUDIT-120, REQ-AUDIT-186
///
/// The verdicts of `kits/conformance/audit/schema-vectors.json`, the same file the Go package reads: what the schemas
/// accept and refuse, including the member `lost` (#1546) and the `documents` of a start as one object (#1552).
#[test]
fn the_schemas_give_the_verdicts_of_the_shared_vectors() {
    let table = Table::sluis();
    let mut examples = std::collections::HashMap::new();
    for c in arr(&parse(ACTIONS), "cases") {
        examples.insert(text(c, "name").to_owned(), text(c, "expected").to_owned());
    }
    let f = parse(SCHEMA);
    assert!(
        arr(&f, "cases").len() >= 50,
        "the vector file lost its cases"
    );
    for c in arr(&f, "cases") {
        let mut rec: Value = serde_json::from_str(&examples[text(c, "action")]).unwrap();
        for op in arr(c, "ops") {
            let value = (text(op, "op") == "set").then(|| op["value"].clone());
            set(&mut rec, text(op, "path"), value);
        }
        let verdict = table.validate(rec.to_string().as_bytes());
        let valid = c["valid"].as_bool().unwrap();
        assert_eq!(
            verdict.is_ok(),
            valid,
            "{}: {:?}",
            text(c, "name"),
            verdict.err().map(|e| refusal_of(&e))
        );
    }
}

/// The values of a domain, the way the Go test makes them: for each first character, a value of the shortest and one of
/// the longest length, the rest going through the characters of `rest` from the position of the first; minus `except`,
/// plus `extra`.
fn domain_values(d: &Value) -> Vec<String> {
    let chars = |k: &str| text(d, k).chars().collect::<Vec<_>>();
    let (first, rest) = (chars("first"), chars("rest"));
    let strings = |k: &str| -> Vec<String> {
        d.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default()
    };
    let except = strings("except");
    let lengths = [
        usize::try_from(d["min"].as_u64().unwrap()).unwrap(),
        usize::try_from(d["max"].as_u64().unwrap()).unwrap(),
    ];
    let mut out = Vec::new();
    for (i, c) in first.iter().enumerate() {
        for n in lengths {
            let mut v = c.to_string();
            v.extend((0..n - 1).map(|k| rest[(i + k) % rest.len()]));
            if !except.contains(&v) {
                out.push(v);
            }
        }
    }
    out.extend(strings("extra"));
    out
}

/// Puts `v` where the shape has "$v".
fn shaped(shape: &Value, v: &str) -> Value {
    match shape {
        Value::String(s) if s == "$v" => Value::String(v.to_owned()),
        Value::Array(a) => Value::Array(a.iter().map(|e| shaped(e, v)).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, e)| (k.clone(), shaped(e, v))).collect())
        }
        other => other.clone(),
    }
}

/// verifies: REQ-AUDIT-002, REQ-AUDIT-099, REQ-AUDIT-101
///
/// Every value that really reaches an audit field validates against the table. The class of bug: the type `ident` took
/// a name only if it began with a letter or a digit, one key id in thirty-two (a base64url thumbprint) began with `-` or
/// `_`, and the signer's facts for such a key were refused (#1610). The fields and the domains of their values are in
/// `kits/conformance/audit/domain-vectors.json`, which the Go package reads too.
#[test]
fn every_value_that_reaches_an_audit_field_validates() {
    let table = Table::sluis();
    let mut examples = std::collections::HashMap::new();
    for c in arr(&parse(ACTIONS), "cases") {
        examples.insert(text(c, "name").to_owned(), text(c, "expected").to_owned());
    }
    let f = parse(DOMAINS);
    let fields = arr(&f, "fields");
    assert!(fields.len() >= 25, "the vector file lost its entries");
    for fld in fields {
        let (action, path) = (text(fld, "action"), text(fld, "path"));
        let d = &f["domains"][text(fld, "domain")];
        assert!(d.is_object(), "{action} {path}: no such domain");
        let check = |v: &str| {
            let mut rec: Value = serde_json::from_str(&examples[action]).unwrap();
            set(&mut rec, path, Some(shaped(&fld["shape"], v)));
            table.validate(rec.to_string().as_bytes())
        };
        let values = domain_values(d);
        assert!(values.len() >= text(d, "first").chars().count());
        for v in &values {
            if let Err(e) = check(v) {
                panic!(
                    "{action} {path}: the table refuses {v:?} of its domain: {:?}",
                    refusal_of(&e)
                );
            }
        }
        for v in d
            .get("refused")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let v = v.as_str().unwrap();
            assert!(
                check(v).is_err(),
                "{action} {path}: the table accepts {v:?}"
            );
        }
    }
}

fn sign() -> Event {
    Event {
        action: Action {
            name: "key.sign".into(),
            class_uid: 6003,
            activity_id: 99,
            activity_name: "Sign".into(),
        },
        status: Status::Success,
        ..Event::default()
    }
}

/// verifies: REQ-AUDIT-022
#[test]
fn the_table_refuses_an_action_that_is_not_one_of_its_rows() {
    let t = Table::sluis();
    t.check_action(&sign().action).unwrap();
    for (name, a) in [
        (
            "a name that is no row",
            Action {
                name: "key.open".into(),
                activity_name: "Open".into(),
                ..sign().action
            },
        ),
        (
            "another class",
            Action {
                class_uid: 3004,
                ..sign().action
            },
        ),
        (
            "another activity",
            Action {
                activity_id: 1,
                activity_name: String::new(),
                ..sign().action
            },
        ),
        (
            "another activity name",
            Action {
                activity_name: "Open".into(),
                ..sign().action
            },
        ),
    ] {
        let e = t.check_action(&a).expect_err(name);
        assert_eq!(refusal_of(&e).0, "schema", "{name}");
    }
}

/// verifies: REQ-AUDIT-099
#[test]
fn the_table_refuses_a_record_whose_member_is_not_in_the_row_and_names_no_value() {
    let t = Table::sluis();
    let mut rec: Value =
        serde_json::from_str(text(&arr(&parse(ACTIONS), "cases")[0], "expected")).unwrap();
    rec["unmapped"] = serde_json::json!({"sluis": {"a_secret_value": "x"}});
    let e = t.validate(rec.to_string().as_bytes()).unwrap_err();
    let (reason, path) = refusal_of(&e);
    assert_eq!(reason, "schema");
    assert!(path.starts_with("record"), "{path}");
}

/// The table of sluis is built the first time an emitter needs it, in every actor that emits. It must not hold a start
/// back: a bound of a second is far above what it takes (measured 2026-11-07: tens of milliseconds in a debug build).
#[test]
fn the_table_of_sluis_is_built_quickly() {
    let t0 = std::time::Instant::now();
    let table = Table::sluis();
    let took = t0.elapsed();
    assert!(!table.names().is_empty());
    assert!(took < std::time::Duration::from_secs(1), "{took:?}");
    eprintln!("the table of sluis was built in {took:?}");
}

/// verifies: REQ-AUDIT-022
///
/// The emitter refuses an unknown action as an action, before it builds a record, and not as a record that fails its
/// schema: the path of the refusal is `action`.
#[tokio::test]
async fn the_emitter_refuses_an_unknown_action_by_name() {
    let e = crate::Emitter::new(crate::Config {
        actor: "key".into(),
        boundary: "dev".into(),
        release: "0.0.0-test".into(),
        transport_socket: "/nonexistent/emit.sock".into(),
        key_socket: None,
        now: None,
    })
    .unwrap();
    let mut ev = sign();
    ev.action.name = "key.open".into();
    let err = e.record(ev).await.unwrap_err();
    let (reason, path) = refusal_of(&err);
    assert_eq!((reason.as_str(), path.as_str()), ("schema", "action"));
}

const POLICY: &str = include_str!("../../../conformance/audit/schema-policy-vectors.json");
const SEMVER: &str = include_str!("../../../conformance/audit/semver-vectors.json");

/// verifies: REQ-AUDIT-149
///
/// The policy of the schema documents of an `AuditCatalogue`, on the corpus the Go package reads too: the closed keywords, the
/// references to the shared definitions only, patterns RE2 and Rust read alike, bounded depth and size. A document the policy
/// takes also compiles.
#[test]
fn the_policy_of_the_catalogue_schemas_gives_the_verdicts_of_the_shared_vectors() {
    let f = parse(POLICY);
    assert!(
        arr(&f, "cases").len() >= 50,
        "the vector file lost its cases"
    );
    for c in arr(&f, "cases") {
        let docs: Vec<(String, String)> = c["docs"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect();
        let ok = c["ok"].as_bool().unwrap();
        let verdict = crate::check_documents(&docs);
        assert_eq!(verdict.is_ok(), ok, "{}: {verdict:?}", text(c, "name"));
        if ok {
            assert!(crate::check_policy(&docs).is_ok(), "{}", text(c, "name"));
        }
    }
}

/// verifies: REQ-AUDIT-149
#[test]
fn the_releases_of_the_shared_vectors() {
    let f = parse(SEMVER);
    assert!(arr(&f, "accept").len() >= 10 && arr(&f, "reject").len() >= 20);
    for s in arr(&f, "accept") {
        assert!(crate::valid_release(s.as_str().unwrap()), "{s} refused");
    }
    for s in arr(&f, "reject") {
        assert!(!crate::valid_release(s.as_str().unwrap()), "{s} taken");
    }
}

/// verifies: REQ-AUDIT-149
///
/// The patterns the policy takes mean the same in both engines: each accepted pattern matches and refuses the strings of the
/// corpus, here through the engine the Rust library uses (and the `regex` crate), in Go through RE2.
#[test]
fn accepted_patterns_match_as_the_corpus_says() {
    let f = parse(POLICY);
    assert!(
        arr(&f, "matches").len() >= 8,
        "the vector file lost its matches"
    );
    for m in arr(&f, "matches") {
        let p = text(m, "pattern");
        let docs = vec![
            (
                crate::DEFS_NAME.to_owned(),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#.to_owned(),
            ),
            (
                "x.a.schema.json".to_owned(),
                serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema","properties":{"a":{"type":"string","pattern":p}}}).to_string(),
            ),
        ];
        crate::check_documents(&docs).unwrap_or_else(|e| panic!("{p}: refused by the policy: {e}"));
        let v =
            jsonschema::validator_for(&serde_json::json!({"type":"string","pattern":p})).unwrap();
        let re = regex::Regex::new(p).unwrap();
        for (key, want) in [("yes", true), ("no", false)] {
            for s in arr(m, key) {
                let s = s.as_str().unwrap();
                assert_eq!(
                    v.is_valid(&serde_json::json!(s)),
                    want,
                    "{p} on {s:?} (the library)"
                );
                assert_eq!(re.is_match(s), want, "{p} on {s:?} (the regex crate)");
            }
        }
    }
}

fn corpus_docs(c: &Value) -> Vec<(String, String)> {
    c["docs"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect()
}

/// verifies: REQ-AUDIT-149
///
/// The policy is linear: every case of the corpus is checked in well under a second, the pathological ones included (a check
/// that walked every duplicate reference did not finish in a minute).
#[test]
fn the_policy_is_fast_on_every_case_of_the_corpus() {
    let f = parse(POLICY);
    let start = std::time::Instant::now();
    for c in arr(&f, "cases") {
        let t0 = std::time::Instant::now();
        let _ = crate::check_policy(&corpus_docs(c));
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(500),
            "{}: {:?}",
            text(c, "name"),
            t0.elapsed()
        );
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
}

/// verifies: REQ-AUDIT-149
///
/// The cost of the real catalogue is a fraction of the limit, so the limit loses nothing.
#[test]
fn the_real_catalogue_costs_a_fraction_of_the_limit() {
    let docs: Vec<(String, String)> = crate::generated::SCHEMAS
        .iter()
        .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
        .collect();
    let worst = crate::max_cost(&docs).unwrap();
    assert!(
        (100..=2000).contains(&worst),
        "the worst cost of the real catalogue is {worst}"
    );
}
