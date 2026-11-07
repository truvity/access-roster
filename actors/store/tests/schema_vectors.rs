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
