#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The shared vectors of the signed config document: `tests/testdata/signed-config/vectors.json`, which
//! `kits/go/signedconfig` runs too. Both implementations must give the same verdict, step for step, because key@
//! verifies in Go the documents that store@ verifies in Rust (ADR 0005, "Signed config documents"; principle 6: a
//! contract and vectors, not shared code).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use store::bootstrap::Publisher;
use store::config::document::{Sequence, Verified, hex, sequence, verify};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/testdata/signed-config/vectors.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn publishers(v: &Value, set: &str) -> Vec<Publisher> {
    let list = v["publisher_sets"][set].as_array().unwrap();
    assert!(!list.is_empty(), "no publisher set {set}");
    list.iter()
        .map(|p| Publisher {
            kid: p["kid"].as_str().unwrap().to_owned(),
            spki_der: STANDARD.decode(p["spki_der"].as_str().unwrap()).unwrap(),
            spki_sha384: String::new(), // checked when the bootstrap file is read, not here
            co_signs: p["co_signs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap().to_owned())
                .collect(),
        })
        .collect()
}

/// verifies: REQ-DATA-076, REQ-DATA-077, REQ-DATA-078, REQ-DATA-079
#[test]
fn every_case_of_the_shared_vectors_gets_the_same_verdict_as_in_go() {
    let v = vectors();
    let kind = sluis_registry::kind_by_name(v["kind"].as_str().unwrap()).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(
        cases.len() >= 60,
        "the vector file holds too few cases: a sweep over nothing proves nothing"
    );
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let keys = publishers(&v, c["publishers"].as_str().unwrap());
        // A document is text, or bytes in `document_base64` where they are not UTF-8.
        let doc: Vec<u8> = match c.get("document_base64") {
            Some(b) => STANDARD.decode(b.as_str().unwrap()).unwrap(),
            None => c["document"].as_str().unwrap().as_bytes().to_vec(),
        };
        let got = verify(&doc, kind, &keys);
        if let Some(read) = c.get("read") {
            let ok = got.unwrap_or_else(|e| panic!("{name}: want it read, got {e}"));
            assert_eq!(ok.seq, read["seq"].as_u64().unwrap(), "{name}: seq");
            assert_eq!(
                hex(&ok.digest),
                read["sha384"].as_str().unwrap(),
                "{name}: digest"
            );
            assert_eq!(
                ok.payload,
                read["payload"].as_str().unwrap().as_bytes(),
                "{name}: payload"
            );
        } else {
            let want = u8::try_from(c["refused_step"].as_u64().unwrap()).unwrap();
            let e = got.expect_err(name);
            assert_eq!(
                e.step, want,
                "{name}: refused at step {} ({})",
                e.step, e.rule
            );
        }
    }
}

fn digest(h: &str) -> [u8; 48] {
    let mut d = [0u8; 48];
    for (i, b) in d.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    d
}

/// verifies: REQ-DATA-080
#[test]
fn the_sequence_vectors_get_the_same_verdict_as_in_go() {
    let v = vectors();
    let rows = v["sequence"].as_array().unwrap();
    assert!(!rows.is_empty());
    for r in rows {
        let name = r["name"].as_str().unwrap();
        let doc = Verified {
            seq: r["document"]["seq"].as_u64().unwrap(),
            payload: Vec::new(),
            digest: digest(r["document"]["sha384"].as_str().unwrap()),
        };
        let held = r.get("in_force").filter(|h| !h.is_null()).map(|h| {
            (
                h["seq"].as_u64().unwrap(),
                digest(h["sha384"].as_str().unwrap()),
            )
        });
        let got = sequence(held.as_ref().map(|(s, d)| (*s, d)), &doc);
        let want = match r["verdict"].as_str().unwrap() {
            "newer" => Sequence::Newer,
            "same" => Sequence::Same,
            "conflict" => Sequence::Conflict,
            "older" => Sequence::Older,
            other => panic!("{name}: unknown verdict {other}"),
        };
        assert_eq!(got, want, "{name}");
    }
}
