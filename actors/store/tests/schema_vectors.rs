#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The decoders of store@ against the generated schemas (REQ-DATA-038, REQ-OPS-002): every document of the shared vectors
//! (`kits/conformance/config/schema-vectors.json`) goes through the whole reader of its file or kind. A schema is never
//! stricter than the loader it stands before: a document the reader accepts is a document the schema accepts, and a document
//! the schema refuses is refused by the reader. The reverse is not true by design: the schema states the form, the reader the
//! rest.

use serde_json::Value as J;
use store::bootstrap::Bootstrap;
use store::config::payload;

const VECTORS: &str = include_str!("../../../kits/conformance/config/schema-vectors.json");

/// The parent of the node a JSON Pointer names, and the pointer's last segment.
fn parent<'a>(d: &'a mut J, path: &str) -> (&'a mut J, String) {
    let (p, last) = path.rsplit_once('/').unwrap();
    (d.pointer_mut(p).unwrap(), last.to_owned())
}

fn apply(mut doc: J, ops: &[J]) -> J {
    for o in ops {
        let value = o["value"].clone();
        let path = o["path"].as_str().unwrap_or_default();
        match o["op"].as_str().unwrap() {
            "replace" => doc = value,
            "set" => match parent(&mut doc, path) {
                (J::Object(m), last) => {
                    m.insert(last, value);
                }
                (J::Array(a), last) => a[last.parse::<usize>().unwrap()] = value,
                _ => unreachable!(),
            },
            "remove" => {
                let (p, last) = parent(&mut doc, path);
                p.as_object_mut().unwrap().remove(&last);
            }
            "append" => {
                let (p, last) = parent(&mut doc, path);
                p[&last].as_array_mut().unwrap().push(value);
            }
            other => panic!("{other}"),
        }
    }
    doc
}

/// verifies: REQ-DATA-038, REQ-OPS-002
#[test]
fn the_reader_of_each_file_and_kind_is_never_looser_than_its_schema() {
    let v: J = serde_json::from_str(VECTORS).unwrap();
    let (mut read, mut kinds) = (0, 0);
    for set in v["sets"].as_array().unwrap() {
        let schema = set["schema"].as_str().unwrap();
        let kind = set["kind"].as_str();
        if let Some(k) = kind {
            kinds += 1;
            // The kind is the schema's: the reader finds the schema by the kind name.
            assert_eq!(
                sluis_schema::payload_id(k),
                Some(schema),
                "the kind {k} and its schema"
            );
        }
        for c in set["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let doc = apply(set["base"].clone(), c["ops"].as_array().unwrap());
            let text = doc.to_string();
            let accepted = match kind {
                None => Bootstrap::parse(&text).is_ok(),
                Some(k) => {
                    payload::decode(sluis_registry::kind_by_name(k).unwrap(), text.as_bytes())
                        .is_ok()
                }
            };
            if let Some(want) = c["want"].as_str() {
                assert!(
                    !accepted,
                    "{schema}: {name}: the schema refuses it and the reader accepted it"
                );
                // The schema answers first: the reader's refusal is the schema's, in its words, not the decoder's.
                let said = match kind {
                    None => Bootstrap::parse(&text).unwrap_err().0,
                    Some(k) => {
                        payload::decode(sluis_registry::kind_by_name(k).unwrap(), text.as_bytes())
                            .unwrap_err()
                            .0
                    }
                };
                let said = said.strip_prefix("bootstrap: ").unwrap_or(&said);
                assert_eq!(said, want, "{schema}: {name}");
            }
            if accepted {
                read += 1;
                assert!(
                    c["want"].is_null(),
                    "{schema}: {name}: the reader accepted a document that the schema refuses"
                );
            }
        }
    }
    assert!(kinds >= 8, "{kinds} kinds: the vectors lost a payload");
    assert!(read >= 60, "{read} documents of the vectors were read");
}

/// verifies: REQ-DATA-038, REQ-DATA-044
///
/// A kind this build reads and that has no generated schema is a kind whose document nothing checks before it decodes it. The
/// kinds with no schema are exactly `Policy` (Cedar text) and `GrantVocabulary` (policy's document, whose schema is its own and
/// not generated yet).
/// A new readable kind fails here until it comes with a schema, and so a duration in a new kind does.
#[test]
fn the_readable_kinds_with_no_schema_are_exactly_the_two_that_are_listed() {
    let mut exempt: Vec<&str> = sluis_registry::kinds()
        .iter()
        .filter(|k| payload::readable(k) && sluis_schema::payload_id(k.name).is_none())
        .map(|k| k.name)
        .collect();
    exempt.sort_unstable();
    assert_eq!(exempt, ["GrantVocabulary", "Policy"]);
    let with: usize = sluis_registry::kinds()
        .iter()
        .filter(|k| payload::readable(k) && sluis_schema::payload_id(k.name).is_some())
        .count();
    assert_eq!(with, 10);
}

/// verifies: REQ-DATA-038, REQ-OPS-002, REQ-DATA-044
///
/// Plain scalars, in YAML text, read by the strict reader and judged by the schema: an unquoted slot 84 is a number and 1e3 is
/// a number, while 0x1f, 010 and 1_000 are strings (bootstrap-file.md, "Format", rule 4). The vectors of
/// `schema-vectors.json` are JSON and never meet this typing; these are the numeric-looking values that a hand-written file
/// really holds. The Go package `kits/go/signedconfig` reads the same file.
#[test]
fn plain_scalars_in_yaml_are_typed_and_judged_as_the_go_reader_does() {
    const YAML: &str = include_str!("../../../kits/conformance/config/yaml-vectors.json");
    let v: J = serde_json::from_str(YAML).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 70, "the vector file lost its entries");
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let doc = store::yaml::parse(c["yaml"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: the reader refuses the text: {e}"));
        let got = sluis_schema::validate(c["schema"].as_str().unwrap(), &doc.to_json())
            .err()
            .map(|e| e.to_string());
        assert_eq!(got.as_deref(), c["want"].as_str(), "{name}");
    }
}
