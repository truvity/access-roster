use serde_json::{Value, json};

use super::*;

const VECTORS: &str = include_str!("../../../conformance/config/schema-vectors.json");
const DOMAINS: &str = include_str!("../../../conformance/config/domain-vectors.json");

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
    let sets = v["sets"].as_array().unwrap();
    let mut total = 0;
    for set in sets {
        let schema = set["schema"].as_str().unwrap();
        let cases = set["cases"].as_array().unwrap();
        total += cases.len();
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let doc = apply(set["base"].clone(), c["ops"].as_array().unwrap());
            let got = validate(schema, &doc).err().map(|e| e.to_string());
            let want = c["want"].as_str().map(str::to_owned);
            assert_eq!(got, want, "{schema}: {name}");
            if let Some(e) = got {
                for o in c["ops"].as_array().unwrap() {
                    if let Some(s) = o["value"].as_str()
                        && s.len() >= 4
                    {
                        assert!(!e.contains(s), "{name}: the error shows a value: {e}");
                    }
                }
                for h in c["hidden"].as_array().into_iter().flatten() {
                    let h = h.as_str().unwrap();
                    assert!(!e.contains(h), "{name}: the error shows {h:?}: {e}");
                }
                for secret in [
                    "secret-name",
                    "startTimeout",
                    "role",
                    "extra",
                    "Workforce",
                    "Example",
                    "other",
                ] {
                    assert!(!e.contains(secret), "{name}: the error shows a key: {e}");
                }
            }
        }
    }
    assert!(
        sets.len() >= 9 && total >= 250,
        "{} sets and {total} cases: the vector file lost its entries",
        sets.len()
    );
}

/// Every schema the crate embeds has a set of vectors, and the schemas of `schema/` are the ones it embeds.
#[test]
fn every_schema_has_vectors_and_is_embedded() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let mut have: Vec<&str> = v["sets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["schema"].as_str().unwrap())
        .collect();
    have.sort_unstable();
    let mut embedded = ids();
    embedded.sort_unstable();
    assert_eq!(embedded, have);
    // The files of schema/ are the embedded ones: a schema added there and not here is a schema no binary applies.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../schema");
    let mut on_disk: Vec<String> = Vec::new();
    for name in std::fs::read_dir(&dir).unwrap() {
        let name = name.unwrap();
        if !name.file_type().unwrap().is_dir() {
            continue;
        }
        for ver in std::fs::read_dir(name.path()).unwrap() {
            let ver = ver.unwrap();
            for f in std::fs::read_dir(ver.path()).unwrap() {
                on_disk.push(format!(
                    "{}/{}/{}",
                    name.file_name().to_string_lossy(),
                    ver.file_name().to_string_lossy(),
                    f.unwrap().file_name().to_string_lossy()
                ));
            }
        }
    }
    on_disk.sort_unstable();
    assert_eq!(on_disk, embedded);
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

/// Puts `v` where the shape has "$v": a string that is "$v" becomes the value, a string that holds it has the text put in.
fn shaped(shape: &Value, v: &Value) -> Value {
    match shape {
        Value::String(s) if s == "$v" => v.clone(),
        Value::String(s) if s.contains("$v") && v.is_string() => {
            Value::String(s.replace("$v", v.as_str().unwrap()))
        }
        Value::Array(a) => Value::Array(a.iter().map(|e| shaped(e, v)).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, e)| (k.clone(), shaped(e, v))).collect())
        }
        other => other.clone(),
    }
}

/// The values of a domain, the way the Go test makes them: for each first character, a value of the shortest and one of the
/// longest length, the rest going through the characters of `rest` from the position of the first; minus `except`, plus
/// `extra`; and the `values` themselves.
fn domain_values(d: &Value) -> Vec<Value> {
    let chars = |k: &str| {
        d[k].as_str()
            .unwrap_or_default()
            .chars()
            .collect::<Vec<_>>()
    };
    let (first, rest) = (chars("first"), chars("rest"));
    let strings = |k: &str| -> Vec<String> {
        d.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default()
    };
    let except = strings("except");
    let mut out: Vec<Value> = Vec::new();
    if !first.is_empty() {
        let lengths = [
            usize::try_from(d["min"].as_u64().unwrap()).unwrap(),
            usize::try_from(d["max"].as_u64().unwrap()).unwrap(),
        ];
        for (i, c) in first.iter().enumerate() {
            for n in lengths {
                let mut v = c.to_string();
                v.extend((0..n - 1).map(|k| rest[(i + k) % rest.len()]));
                if !except.contains(&v) {
                    out.push(Value::String(v));
                }
            }
        }
    }
    out.extend(strings("extra").into_iter().map(Value::String));
    if let Some(a) = d.get("values").and_then(Value::as_array) {
        out.extend(a.iter().cloned());
    }
    out
}

fn domain_refused(d: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for k in ["refused", "refused_values"] {
        if let Some(a) = d.get(k).and_then(Value::as_array) {
            out.extend(a.iter().cloned());
        }
    }
    out
}

fn bases() -> std::collections::HashMap<String, Value> {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    v["sets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["schema"].as_str().unwrap().to_owned(), s["base"].clone()))
        .collect()
}

/// verifies: REQ-DATA-038, REQ-OPS-002, REQ-DATA-044
///
/// Every value that really reaches a field of a signed config document or of the bootstrap file validates. The class of bug:
/// the audit table took a key id only if it began with a letter or a digit, and one thumbprint in thirty-two begins with `-`
/// or `_`, so key@ withheld the signature of such a key (#1610). A schema is never stricter than its loaders, and the domains
/// of the values are in `kits/conformance/config/domain-vectors.json`, which the Go package reads too.
#[test]
fn every_value_that_reaches_a_field_validates() {
    let f: Value = serde_json::from_str(DOMAINS).unwrap();
    let bases = bases();
    let fields = f["fields"].as_array().unwrap();
    assert!(fields.len() >= 45, "the vector file lost its entries");
    let mut used = std::collections::HashSet::new();
    for fld in fields {
        let schema = fld["schema"].as_str().unwrap();
        let name = fld["domain"].as_str().unwrap();
        let d = &f["domains"][name];
        assert!(d.is_object(), "{schema}: no domain {name}");
        used.insert(name.to_owned());
        let id = fld["id"].as_bool().unwrap_or(false);
        let path = fld["path"].as_str().unwrap_or_default();
        let check = |v: &Value| {
            let mut doc = bases[schema].clone();
            if id {
                let m = doc.as_object_mut().unwrap();
                let (_, item) = m
                    .iter()
                    .next()
                    .map(|(k, i)| (k.clone(), i.clone()))
                    .unwrap();
                m.clear();
                m.insert(v.as_str().unwrap().to_owned(), item);
            } else {
                let (p, last) = path.rsplit_once('/').unwrap();
                let parent = doc.pointer_mut(p).unwrap();
                match parent {
                    Value::Object(m) => {
                        m.insert(last.to_owned(), shaped(&fld["shape"], v));
                    }
                    Value::Array(a) => a[last.parse::<usize>().unwrap()] = shaped(&fld["shape"], v),
                    _ => panic!("not a container"),
                }
            }
            validate(schema, &doc)
        };
        let values = domain_values(d);
        assert!(!values.is_empty(), "{name}: no value");
        for v in &values {
            if let Err(e) = check(v) {
                let shown = v.to_string();
                panic!(
                    "{schema} {path}: the schema refuses {:.60} of the domain {name}: {e}",
                    shown
                );
            }
        }
        for v in domain_refused(d) {
            assert!(
                check(&v).is_err(),
                "{schema} {path}: the schema accepts {:.60}, which no value of the domain {name} is",
                v.to_string()
            );
        }
    }
    for name in f["domains"].as_object().unwrap().keys() {
        assert!(used.contains(name), "the domain {name} is used by no field");
    }
}

/// Random bytes of every length from 1 to 600 are base64url that the schema takes, and random strings of the alphabets of
/// the domains are names and credential names that it takes: the patterns hold for values nobody chose.
///
/// verifies: REQ-DATA-038, REQ-OPS-002
#[test]
fn random_values_of_the_domains_validate() {
    use base64::Engine as _;
    let rnd = |n: usize| -> Vec<u8> {
        let mut b = vec![0u8; n];
        rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty()).unwrap();
        b
    };
    let f: Value = serde_json::from_str(DOMAINS).unwrap();
    let bases = bases();
    for fld in f["fields"].as_array().unwrap() {
        let d = &f["domains"][fld["domain"].as_str().unwrap()];
        let (Some(first), Some(rest)) = (d["first"].as_str(), d["rest"].as_str()) else {
            continue;
        };
        if fld["id"].as_bool().unwrap_or(false) {
            continue;
        }
        let (first, rest): (Vec<char>, Vec<char>) =
            (first.chars().collect(), rest.chars().collect());
        let (min, max) = (
            usize::try_from(d["min"].as_u64().unwrap()).unwrap(),
            usize::try_from(d["max"].as_u64().unwrap()).unwrap(),
        );
        let except: Vec<&str> = d["except"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap()).collect())
            .unwrap_or_default();
        let schema = fld["schema"].as_str().unwrap();
        let (p, last) = fld["path"].as_str().unwrap().rsplit_once('/').unwrap();
        for _ in 0..200 {
            let r = rnd(2 + max.min(1000));
            let n = min + (usize::from(r[0]) << 8 | usize::from(r[1])) % (max - min + 1);
            let more = rnd(n);
            let mut v = String::new();
            v.push(first[usize::from(r[2]) % first.len()]);
            v.extend(
                more.iter()
                    .take(n - 1)
                    .map(|b| rest[usize::from(*b) % rest.len()]),
            );
            if except.contains(&v.as_str()) {
                continue;
            }
            let mut doc = bases[schema].clone();
            let shaped = shaped(&fld["shape"], &Value::String(v.clone()));
            match doc.pointer_mut(p).unwrap() {
                Value::Object(m) => {
                    m.insert(last.to_owned(), shaped);
                }
                Value::Array(a) => a[last.parse::<usize>().unwrap()] = shaped,
                _ => panic!("not a container"),
            }
            if let Err(e) = validate(schema, &doc) {
                panic!("{schema} {p}/{last}: the schema refuses {v:.60?}: {e}");
            }
        }
    }
    for n in 1..=600 {
        let v = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rnd(n));
        let mut doc = bases["key-plan/v1/key-plan.schema.json"].clone();
        doc["default"]["slot_map"][0]["slots"][0]["attestation"] = Value::String(v);
        validate("key-plan/v1/key-plan.schema.json", &doc).unwrap();
    }
}
