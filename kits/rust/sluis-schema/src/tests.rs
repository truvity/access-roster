use serde_json::{Value, json};

use super::*;

const VECTORS: &str = include_str!("../../../conformance/config/schema-vectors.json");

/// The pointer's parent and its last segment.
fn walk<'a>(doc: &'a mut Value, path: &str) -> (&'a mut Value, String) {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (last, parents) = segs.split_last().unwrap();
    let mut cur = doc;
    for s in parents {
        cur = match cur {
            Value::Object(m) => m.get_mut(*s).unwrap(),
            Value::Array(a) => a.get_mut(s.parse::<usize>().unwrap()).unwrap(),
            _ => panic!("path {path}: not a container"),
        };
    }
    (cur, (*last).to_owned())
}

fn apply(mut doc: Value, ops: &[Value]) -> Value {
    for o in ops {
        let value = o["value"].clone();
        let path = o["path"].as_str().unwrap_or_default();
        match o["op"].as_str().unwrap() {
            "replace" => doc = value,
            "set" => {
                let (p, last) = walk(&mut doc, path);
                match p {
                    Value::Object(m) => {
                        m.insert(last, value);
                    }
                    Value::Array(a) => a[last.parse::<usize>().unwrap()] = value,
                    _ => panic!("not a container"),
                }
            }
            "remove" => {
                let (p, last) = walk(&mut doc, path);
                p.as_object_mut().unwrap().remove(&last);
            }
            "append" => {
                let (p, last) = walk(&mut doc, path);
                p.as_object_mut().unwrap()[&last]
                    .as_array_mut()
                    .unwrap()
                    .push(value);
            }
            other => panic!("unknown op {other}"),
        }
    }
    doc
}

/// verifies: REQ-DATA-038, REQ-OPS-002, REQ-DATA-044
///
/// The vectors that the Go package runs too: each document gets the verdict, and the words, the vector names. A case is a
/// mutation of the base document by one fault. The error shows no value: no string a case writes is in the error.
#[test]
fn the_shared_vectors() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let schema = v["schema"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(
        cases.len() >= 50,
        "{} cases: the vector file is nearly empty",
        cases.len()
    );
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let doc = apply(v["base"].clone(), c["ops"].as_array().unwrap());
        let got = validate(schema, &doc).err().map(|e| e.to_string());
        let want = c["want"].as_str().map(str::to_owned);
        assert_eq!(got, want, "{name}");
        if let Some(e) = got {
            for o in c["ops"].as_array().unwrap() {
                if let Some(s) = o["value"].as_str()
                    && s.len() >= 4
                {
                    assert!(!e.contains(s), "{name}: the error shows a value: {e}");
                }
            }
            for secret in ["secret-name", "startTimeout", "role", "extra"] {
                assert!(!e.contains(secret), "{name}: the error shows a key: {e}");
            }
        }
    }
}

/// A schema may retire a name: the key is declared as false, and the error says so by the schema's own name for it.
#[test]
fn a_retired_key_is_named_as_retired() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"kept": {"type": "string"}, "old": false},
        "unevaluatedProperties": false
    });
    let v = jsonschema::validator_for(&schema).unwrap();
    for (doc, want) in [
        (json!({"kept": "a"}), None),
        (json!({"kept": "a", "old": 1}), Some("old: retired key")),
        (json!({"kept": "a", "other": 1}), Some("<key>: unknown key")),
    ] {
        let got = check(&v, &doc).err().map(|e| e.to_string());
        assert_eq!(got.as_deref(), want, "{doc}");
    }
}

#[test]
fn an_unknown_schema_is_refused() {
    assert!(validate("nothing/v1/nothing.schema.json", &json!({})).is_err());
}
