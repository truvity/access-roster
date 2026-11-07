#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! A config document with a key the schema does not know is refused (REQ-DATA-041): at every mapping of every config
//! kind that this build reads, the error names the place and never shows the value, and a kind that this build cannot
//! read has no document to take at all.
//!
//! The vectors are made from the documents of the local installation and from two richer ones (a `KeyPlan` with a slot map,
//! an `ExchangeTrust` with an issuer), which hold every nested mapping the readers know. One unknown key is put into one
//! mapping at a time, so that a refusal can only be the unknown key's.

mod config_support;

use config_support::LOCAL;
use sluis_registry::{Class, Kind};
use store::config::payload;
use store::yaml::{self, Value};

/// A key and a value that no schema holds and no error may print.
const KEY: &str = "zq-unknown-key-4c1e";
const SECRET: &str = "zq-secret-value-9b7d";

/// A `KeyPlan` that has an entry in each list the reader knows: a recipient, a slot map with a node and a slot, a purpose.
const KEY_PLAN_FULL: &str = "default:
  cache_ttl: 15m
  recipients: [\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"]
  slot_map:
    - node: core1
      slots:
        - { slot: \"9a\", purpose: token-signing, public_key: AAAA, attestation: BBBB, attestation_signer: CCCC }
  purposes:
    - { purpose: wrapping, algorithm: ECDH-P384, slot: 9d }
";

/// An `ExchangeTrust` with one issuer.
const EXCHANGE_TRUST_FULL: &str = "default:
  issuers:
    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks, jwks_uri: \"https://idp.example.com/jwks\" }
";

/// A flow-style YAML text of a value: the strict profile reads it back to the same value. A string is written as a JSON
/// string, which is a double-quoted YAML scalar.
fn flow(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.clone(),
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Seq(items) => format!(
            "[{}]",
            items.iter().map(flow).collect::<Vec<_>>().join(", ")
        ),
        Value::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, v)| format!("{}: {}", serde_json::to_string(k).unwrap(), flow(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The mappings of an item below its root, by the path the payload reader names them with: `item`, `item.key` and
/// `item.key[i]`.
fn mappings(v: &Value, path: &str, out: &mut Vec<String>) {
    let Value::Map(entries) = v else { return };
    out.push(path.to_owned());
    for (k, child) in entries {
        let at = format!("{path}.{k}");
        match child {
            Value::Map(_) => mappings(child, &at, out),
            Value::Seq(items) => {
                for (i, item) in items.iter().enumerate() {
                    mappings(item, &format!("{at}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
}

/// `v` with the unknown key put into the mapping at `path` (the paths of [`mappings`]).
fn with_unknown(v: &Value, path: &str, at: &str) -> Value {
    match v {
        Value::Map(entries) => {
            let mut entries: Vec<(String, Value)> = entries
                .iter()
                .map(|(k, child)| {
                    let child_at = format!("{at}.{k}");
                    let mutated = match child {
                        Value::Seq(items) => Value::Seq(
                            items
                                .iter()
                                .enumerate()
                                .map(|(i, item)| {
                                    with_unknown(item, path, &format!("{child_at}[{i}]"))
                                })
                                .collect(),
                        ),
                        other => with_unknown(other, path, &child_at),
                    };
                    (k.clone(), mutated)
                })
                .collect();
            if at == path {
                entries.push((KEY.into(), Value::String(SECRET.into())));
            }
            Value::Map(entries)
        }
        other => other.clone(),
    }
}

fn kinds() -> Vec<&'static Kind> {
    sluis_registry::kinds()
        .iter()
        .filter(|k| k.class == Class::Config)
        .collect()
}

/// The sources that carry the vectors, by kind name: the local documents, with the two richer ones in place of theirs.
fn sources() -> Vec<(&'static str, String)> {
    LOCAL
        .iter()
        .map(|(segment, text)| {
            let kind = sluis_registry::kind_by_segment(segment).unwrap();
            let text = match kind.name {
                "KeyPlan" => KEY_PLAN_FULL,
                "ExchangeTrust" => EXCHANGE_TRUST_FULL,
                _ => text,
            };
            (kind.name, text.to_owned())
        })
        .collect()
}

/// verifies: REQ-DATA-041
#[test]
fn an_unknown_key_in_any_mapping_of_any_readable_kind_is_refused_by_place_and_shows_no_value() {
    let mut cases = 0;
    let mut covered = std::collections::BTreeSet::new();
    let mut nested = 0;
    for (name, text) in sources() {
        let kind = sluis_registry::kind_by_name(name).unwrap();
        // Policy is Cedar text and GrantVocabulary is the vocabulary file that policy reads (actors/policy/src/vocab.rs
        // refuses an unknown key of it): neither is a mapping from item id to item here.
        if matches!(name, "Policy" | "GrantVocabulary") {
            continue;
        }
        let doc = yaml::parse(&text).unwrap();
        // The control: the document as it is loads, so a refusal below is the key's.
        payload::decode(kind, text.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        // The flow form is the same value: the vectors are made from it.
        assert_eq!(yaml::parse(&flow(&doc)).unwrap(), doc, "{name}");

        let Value::Map(items) = &doc else {
            panic!("{name}: not a mapping")
        };
        for (id, item) in items {
            let mut places = Vec::new();
            mappings(item, id, &mut places);
            for place in places {
                // The item is the root of the walk: `with_unknown` of the whole document needs the id in front.
                let mutated = Value::Map(
                    items
                        .iter()
                        .map(|(i, v)| {
                            if i == id {
                                (i.clone(), with_unknown(v, &place, i))
                            } else {
                                (i.clone(), v.clone())
                            }
                        })
                        .collect(),
                );
                let text = flow(&mutated);
                assert!(text.contains(KEY), "{name} {place}: the key was not put in");
                let e = payload::decode(kind, text.as_bytes())
                    .expect_err(&format!("{name} {place}: an unknown key was taken"))
                    .0;
                assert_eq!(e, format!("{place}.<key>: unknown key"), "{name} {place}");
                assert!(!e.contains(SECRET), "{name} {place}: shows the value: {e}");
                assert!(!e.contains(KEY), "{name} {place}: shows the key: {e}");
                cases += 1;
                covered.insert(name);
                nested += usize::from(place.contains('.'));
            }
        }
    }
    // Every readable kind that is a mapping from id to item was swept, and the nested mappings were reached.
    let readable: std::collections::BTreeSet<&str> = kinds()
        .into_iter()
        .filter(|k| payload::readable(k) && !matches!(k.name, "Policy" | "GrantVocabulary"))
        .map(|k| k.name)
        .collect();
    assert_eq!(covered, readable, "a readable kind has no vector");
    assert!(readable.len() >= 8, "{readable:?}");
    assert!(cases >= 15 && nested >= 6, "{cases} cases, {nested} nested");
}

/// verifies: REQ-DATA-041
#[test]
fn a_config_kind_this_build_cannot_read_takes_no_document_so_an_unknown_key_in_one_is_refused() {
    let mut unread = 0;
    for kind in kinds() {
        if payload::readable(kind) {
            continue;
        }
        unread += 1;
        let doc = format!("default: {{ {KEY}: {SECRET} }}\n");
        let e = payload::decode(kind, doc.as_bytes())
            .expect_err(&format!(
                "{}: a document of an unread kind was taken",
                kind.name
            ))
            .0;
        assert_eq!(e, "this build has no reader for the kind", "{}", kind.name);
        assert!(
            !e.contains(SECRET) && !e.contains(KEY),
            "{}: {e}",
            kind.name
        );
    }
    assert!(
        unread > 0,
        "every config kind is readable: the test checks nothing"
    );
}
