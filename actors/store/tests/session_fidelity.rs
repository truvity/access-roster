#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! What store@ does with the calls that session makes, as vectors (`kits/conformance/store/session-vectors.json`). The Go
//! tests of session run against a fake of store@; the fake once disagreed with this service (a boundary-scoped kind given a
//! tenant, an update that kept the old indexes) and two bugs hid behind it. The same vectors run here against the real
//! service and there against the fake, so a rule that one of them has and the other lacks fails a test on one side.

mod common;

use buffa::Message as _;
use common::*;
use serde_json::Value;
use sluis_proto::sluis::store::v2alpha1::{ListRequest, Verb};

const VECTORS: &str = include_str!("../../../kits/conformance/store/session-vectors.json");

/// The value store@ takes for a kind: a sealed envelope for a sealed kind, the message for a kind with one, a few bytes for
/// the rest.
fn value_for(kind: &sluis_registry::Kind, tenant: &str, id: &str) -> Vec<u8> {
    if kind.treatment == "sealed" {
        return sealed_for(kind.segment);
    }
    if kind.segment == "web-authn-challenge" {
        return sluis_proto::sluis::session::v2alpha1::WebAuthnChallenge {
            ceremony: "assert".into(),
            ..Default::default()
        }
        .encode_to_vec();
    }
    assert_eq!(
        store::messages::decodes(kind.segment, tenant, id, b"x"),
        None,
        "{}: the vectors need a value for it",
        kind.name
    );
    b"x".to_vec()
}

/// The answer the vectors compare: `ok`, or `code/reason`.
fn said<T>(r: Result<T, connectrpc::ConnectError>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("{}/{}", e.code.as_str(), reason(&e)),
    }
}

/// verifies: REQ-DATA-045
#[tokio::test]
async fn the_vectors_of_what_session_meets_in_store_hold_for_the_real_service() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let mut steps = 0;
    for case in v["cases"].as_array().unwrap() {
        // A new service for every case: the cases do not share items.
        let f = F::new().await;
        f.as_("session");
        let name = case["name"].as_str().unwrap();
        for (n, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            steps += 1;
            if let Some(w) = step.get("write") {
                let kind = sluis_registry::kind_by_name(&pascal(w["kind"].as_str().unwrap()));
                let (tenant, id) = (w["tenant"].as_str().unwrap(), w["id"].as_str().unwrap());
                let value = kind.map_or(b"x".to_vec(), |k| value_for(k, tenant, id));
                let verb = match w["verb"].as_str().unwrap() {
                    "create" => Verb::CREATE,
                    "update" => Verb::UPDATE,
                    other => panic!("{other}"),
                };
                let mut o = op(verb, w["kind"].as_str().unwrap(), tenant, id, &value);
                for ix in w["indexes"].as_array().unwrap() {
                    let ix = ix.as_str().unwrap();
                    o = with_index(o, ix, format!("v:{ix}").as_bytes());
                }
                o = with_version(o, w["if_version"].as_u64().unwrap());
                let grant = if step["grant"].as_bool().unwrap() {
                    f.grant("session", &["acme"], &["create", "update"], 60)
                } else {
                    Vec::new()
                };
                let got = said(f.write(vec![o], &grant).await);
                assert_eq!(got, step["want"].as_str().unwrap(), "{name}: step {n}");
            } else {
                let l = &step["list"];
                let got = f
                    .list(ListRequest {
                        kind: l["kind"].as_str().unwrap().into(),
                        tenant: l["tenant"].as_str().unwrap().into(),
                        index: l["index"].as_str().unwrap().into(),
                        index_value: l["index_value"].as_str().unwrap().as_bytes().to_vec(),
                        ..ListRequest::default()
                    })
                    .await;
                match (&step["want_ids"], got) {
                    (Value::Array(want), Ok(r)) => {
                        let mut ids: Vec<_> =
                            r.items.iter().map(|i| i.address.id.clone()).collect();
                        ids.sort();
                        let want: Vec<_> = want
                            .iter()
                            .map(|x| x.as_str().unwrap().to_owned())
                            .collect();
                        assert_eq!(ids, want, "{name}: step {n}");
                    }
                    (Value::String(want), got) => {
                        assert_eq!(&said(got), want, "{name}: step {n}");
                    }
                    (want, got) => panic!(
                        "{name}: step {n}: want {want}, got {:?}",
                        got.map(|r| r.items.len())
                    ),
                }
            }
        }
    }
    assert!(steps >= 30, "{steps} steps: the vectors lost a case");
}

/// The registry's name of the kind with the segment (`staff-passkey` is `StaffPasskey`).
fn pascal(segment: &str) -> String {
    sluis_registry::kinds()
        .iter()
        .find(|k| k.segment == segment)
        .map_or_else(String::new, |k| k.name.to_owned())
}
