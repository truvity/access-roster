#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The vectors of docs/reference/signed-config.md "Test vectors": every verdict of the table,
//! through the same functions the loader uses. The two key pairs of the page guard nothing; their
//! private halves were discarded after signing.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use store::bootstrap::Publisher;
use store::config::document::{Refused, Sequence, Verified, hex, sequence, verify};

const PUBLISHER_KEY: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEdptVIkeiLoSFwBZWL2/LzRofOQCC7BA2BYGuTFE2wadFKaURYGvjspVnyguB6GsAACzu7DrWqKQHCCIbBKyxDEBjjhO8P2aVMqgSE/MMGEjXQqtRIMj/MKggB9rQK8MI";
const PARTY_KEY: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExkRYxl6/8Is/5qok2qf/MLahNJT8LOi6CH7ct31uCPNnozzwz7HmzNcPif4OFs341KMQJTvHAgGlHp+Hl3Ck/0Qog8jfiNY09Np96Vat4tP454C9gPE/eLebMQLshttM";

/// The kind of the vectors: any config kind will do, the signature layer does not look at it.
const KIND: &str = "Boundary";

const VECTOR_1: &str = r#"{
  "payload": "dmVjdG9yOiAxCg",
  "signatures": [{
    "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6InB1Ymxpc2hlci0xIiwic2VxIjoxfQ",
    "signature": "zKiPOs9_bUguvx-pEdmt7tct6fDu0uLJxfxaOmHWwNJydkZ18J8OJ4XjNEcJ8SlHeG8IFbfRd_jDPo3LhbUckbADNdt-dbrkQa0l9_NVox2eblSjQRMFiyemLXjrPsxK"
  }]
}"#;

const VECTOR_2: &str = r#"{
  "payload": "dmVjdG9yOiAyCg",
  "signatures": [
    {
      "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6InB1Ymxpc2hlci0xIiwic2VxIjoyfQ",
      "signature": "rS79BXecFNgvtbwdii5y_wX8BbslTxvelJ1zgVVtglOJcNkpH_whyaojPrce1JqnQ9tS1twx2fVKxiRLF5hjLxVE5FxDcEy8g8GJvWSuuaQiCze5u6oSiO7ogaSS-F_Q"
    },
    {
      "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6InBhcnR5LTEiLCJzZXEiOjJ9",
      "signature": "kZY-ULrPDd8Tk65F9iZAb7-Hdal3A84CbpxHLHWsDud3Kx8Ld3ItFR3Y2_z7wiMD0nAu9SRWVeG8XVqrhpwZGdQHjwGVUmf9MO1ky-IoszOuRifC4cCRJ00dq1ITDA1A"
    }
  ]
}"#;

const DIGEST_1: &str = "956168af938823b9fd7adf5d32a50101eb661ae94b14a6575470b29e27f4f7ac666fd14466d508eb475fa99036276db0";
const DIGEST_2: &str = "a9a502900b44f260cc6330a43a76b53f6ddb40acb16c7ae9569afeef3080481827219faa7effa42a336265c73b39032e";

fn key(kid: &str, b64: &str, co_signs: &[&str]) -> Publisher {
    Publisher {
        kid: kid.into(),
        spki_der: STANDARD.decode(b64).unwrap(),
        spki_sha384: String::new(), // checked when the bootstrap file is read, not here
        co_signs: co_signs.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// Both keys listed, the party co-signing the kind of the vectors.
fn both() -> Vec<Publisher> {
    vec![
        key("publisher-1", PUBLISHER_KEY, &[]),
        key("party-1", PARTY_KEY, &[KIND]),
    ]
}

/// Both keys listed, nobody co-signing.
fn plain() -> Vec<Publisher> {
    vec![
        key("publisher-1", PUBLISHER_KEY, &[]),
        key("party-1", PARTY_KEY, &[]),
    ]
}

fn run(doc: &str, keys: &[Publisher]) -> Result<Verified, Refused> {
    verify(
        doc.as_bytes(),
        sluis_registry::kind_by_name(KIND).unwrap(),
        keys,
    )
}

fn step(doc: &str, keys: &[Publisher]) -> u8 {
    run(doc, keys).expect_err("must be refused").step
}

fn json(doc: &str) -> Value {
    serde_json::from_str(doc).unwrap()
}

/// A protected header, as the pipeline would write it.
fn header(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}

#[test]
fn vector_2_is_read_with_both_signatures() {
    let v = run(VECTOR_2, &both()).unwrap();
    assert_eq!((v.seq, hex(&v.digest)), (2, DIGEST_2.to_owned()));
    assert_eq!(v.payload, b"vector: 2\n");
    // Nothing in force: it replaces nothing and is taken.
    assert_eq!(sequence(None, &v), Sequence::Newer);
}

#[test]
fn vector_1_needs_the_party_only_when_the_party_co_signs_its_kind() {
    assert_eq!(step(VECTOR_1, &both()), 4);
    let v = run(VECTOR_1, &plain()).unwrap();
    assert_eq!((v.seq, hex(&v.digest)), (1, DIGEST_1.to_owned()));
}

#[test]
fn a_missing_co_signature_a_foreign_kid_and_a_repeated_kid_are_refused() {
    // Vector 2 with the party's signature removed.
    let mut d = json(VECTOR_2);
    d["signatures"].as_array_mut().unwrap().pop();
    assert_eq!(step(&d.to_string(), &both()), 4);
    // The party's kid is not in the bootstrap file.
    let only_publisher = vec![key("publisher-1", PUBLISHER_KEY, &[])];
    assert_eq!(step(VECTOR_2, &only_publisher), 3);
    // Two signatures with one kid.
    let mut d = json(VECTOR_2);
    let first = d["signatures"][0].clone();
    d["signatures"].as_array_mut().unwrap().push(first);
    assert_eq!(step(&d.to_string(), &both()), 3);
}

#[test]
fn a_changed_payload_or_header_does_not_verify() {
    // One character of the payload: refused at step 4, before it is parsed.
    for vector in [VECTOR_1, VECTOR_2] {
        let mut d = json(vector);
        let p = d["payload"].as_str().unwrap().to_owned();
        let changed = format!(
            "{}{}",
            &p[..p.len() - 2],
            if p.ends_with('g') { "h" } else { "g" }
        );
        d["payload"] = json!(changed);
        assert_eq!(step(&d.to_string(), &plain()), 4);
    }
    // One character of the protected header: the signature does not verify (or the header no
    // longer reads, which is refused earlier).
    let mut d = json(VECTOR_1);
    let p = d["signatures"][0]["protected"].as_str().unwrap().to_owned();
    let flipped = if p.starts_with('e') { "f" } else { "e" };
    d["signatures"][0]["protected"] = json!(format!("{flipped}{}", &p[1..]));
    assert!(step(&d.to_string(), &plain()) >= 2);
    // A byte-for-byte change of a value inside the header: seq 1 -> 3 with the old signature.
    d = json(VECTOR_1);
    d["signatures"][0]["protected"] = json!(header(
        &json!({"alg": "ES384", "kid": "publisher-1", "seq": 3})
    ));
    assert_eq!(step(&d.to_string(), &plain()), 4);
}

#[test]
fn only_es384_and_only_the_three_members_of_the_header() {
    let signed = |h: Value| {
        let mut d = json(VECTOR_1);
        d["signatures"][0]["protected"] = json!(header(&h));
        d.to_string()
    };
    for alg in ["ES256", "ES512", "HS384", "PS384", "none", "es384"] {
        let doc = signed(json!({"alg": alg, "kid": "publisher-1", "seq": 1}));
        assert_eq!(step(&doc, &plain()), 2, "alg {alg}");
    }
    for extra in [
        ("crit", json!(["exp"])),
        ("jku", json!("https://example.com/jwks")),
        ("x5u", json!("https://example.com/cert")),
        ("x5c", json!(["AAAA"])),
        ("jwk", json!({"kty": "EC"})),
        ("typ", json!("JWT")),
    ] {
        let mut h = json!({"alg": "ES384", "kid": "publisher-1", "seq": 1});
        h[extra.0] = extra.1;
        assert_eq!(step(&signed(h), &plain()), 2, "header {}", extra.0);
    }
    // A missing member, a seq that is not a positive integer below 2^53, and a duplicate key.
    for h in [
        json!({"alg": "ES384", "seq": 1}),
        json!({"alg": "ES384", "kid": "publisher-1"}),
        json!({"alg": "ES384", "kid": "publisher-1", "seq": 0}),
        json!({"alg": "ES384", "kid": "publisher-1", "seq": -1}),
        json!({"alg": "ES384", "kid": "publisher-1", "seq": 1.5}),
        json!({"alg": "ES384", "kid": "publisher-1", "seq": "1"}),
        json!({"alg": "ES384", "kid": "publisher-1", "seq": 9_007_199_254_740_992_u64}),
    ] {
        assert_eq!(step(&signed(h.clone()), &plain()), 2, "{h}");
    }
    let dup = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES384","kid":"publisher-1","seq":1,"seq":1}"#);
    let mut d = json(VECTOR_1);
    d["signatures"][0]["protected"] = json!(dup);
    assert_eq!(step(&d.to_string(), &plain()), 2);
}

#[test]
fn the_signatures_of_one_document_carry_one_seq() {
    let mut d = json(VECTOR_2);
    d["signatures"][1]["protected"] =
        json!(header(&json!({"alg": "ES384", "kid": "party-1", "seq": 3})));
    assert_eq!(step(&d.to_string(), &both()), 2);
}

#[test]
fn a_document_is_the_general_serialisation_and_nothing_else() {
    // An unprotected header member.
    let mut d = json(VECTOR_1);
    d["signatures"][0]["header"] = json!({"kid": "publisher-1"});
    assert_eq!(step(&d.to_string(), &plain()), 1);
    // The flattened serialisation.
    let flat = json!({
        "payload": json(VECTOR_1)["payload"],
        "protected": json(VECTOR_1)["signatures"][0]["protected"],
        "signature": json(VECTOR_1)["signatures"][0]["signature"],
    });
    assert_eq!(step(&flat.to_string(), &plain()), 1);
    // The compact serialisation.
    let v = json(VECTOR_1);
    let compact = format!(
        "{}.{}.{}",
        v["signatures"][0]["protected"].as_str().unwrap(),
        v["payload"].as_str().unwrap(),
        v["signatures"][0]["signature"].as_str().unwrap()
    );
    assert_eq!(step(&compact, &plain()), 1);
    // Another member, no signature, a duplicate key, and not JSON at all.
    let mut d = json(VECTOR_1);
    d["extra"] = json!(1);
    assert_eq!(step(&d.to_string(), &plain()), 1);
    assert_eq!(
        step(r#"{"payload":"dmVjdG9yOiAxCg","signatures":[]}"#, &plain()),
        1
    );
    let dup = VECTOR_1.replacen("\"payload\"", "\"payload\": \"AA\", \"payload\"", 1);
    assert_eq!(step(&dup, &plain()), 1);
    assert_eq!(step("not json", &plain()), 1);
    assert_eq!(step("", &plain()), 1);
}

#[test]
fn a_signature_is_r_then_s_not_der() {
    // A DER ECDSA-Sig-Value (SEQUENCE of two INTEGERs) is 102 to 104 bytes for P-384.
    let mut der = vec![0x30, 0x64, 0x02, 0x30];
    der.extend_from_slice(&[0x11; 48]);
    der.extend_from_slice(&[0x02, 0x30]);
    der.extend_from_slice(&[0x22; 48]);
    let mut d = json(VECTOR_1);
    d["signatures"][0]["signature"] = json!(URL_SAFE_NO_PAD.encode(&der));
    assert_eq!(step(&d.to_string(), &plain()), 4);
    // A padded base64url string is not base64url without padding.
    let mut d = json(VECTOR_1);
    let s = d["signatures"][0]["signature"].as_str().unwrap().to_owned();
    d["signatures"][0]["signature"] = json!(format!("{s}=="));
    assert_eq!(step(&d.to_string(), &plain()), 4);
}

#[test]
fn a_key_that_co_signs_cannot_stand_alone() {
    // Only the party signed, and the party's key has a co_signs list: no publisher key signed it.
    let mut d = json(VECTOR_2);
    d["signatures"].as_array_mut().unwrap().remove(0);
    assert_eq!(step(&d.to_string(), &both()), 4);
}

#[test]
fn the_sequence_table() {
    let v1 = run(VECTOR_1, &plain()).unwrap();
    let v2 = run(VECTOR_2, &both()).unwrap();
    // Vector 1 in force, then vector 2.
    assert_eq!(sequence(Some((v1.seq, &v1.digest)), &v2), Sequence::Newer);
    // Vector 2 in force, then vector 1: a lower seq.
    assert_eq!(sequence(Some((v2.seq, &v2.digest)), &v1), Sequence::Older);
    // Vector 2 in force, then vector 2 again.
    assert_eq!(sequence(Some((v2.seq, &v2.digest)), &v2), Sequence::Same);
    // Vector 2 in force, then seq 2 with another payload.
    let other = Verified {
        digest: [7; 48],
        ..v2.clone()
    };
    assert_eq!(
        sequence(Some((v2.seq, &v2.digest)), &other),
        Sequence::Conflict
    );
    // Vector 1 as the only document at a cold start, though seq 2 was published before.
    assert_eq!(sequence(None, &v1), Sequence::Newer);
}
