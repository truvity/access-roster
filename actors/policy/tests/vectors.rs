#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The vectors of policy.md "Test vectors" run through the engine: `local.cedar`, the vocabulary
//! and the links of the local installation, in the format of `cedar run-tests`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use policy::engine::{Engine, Inputs, Link, PolicyDoc};
use serde_json::Value;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/installations/local/policy")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(dir().join(name)).unwrap()
}

fn links() -> Vec<Link> {
    let v: Vec<Value> = serde_json::from_str(&read("links.json")).unwrap();
    v.iter()
        .map(|l| Link {
            template_id: l["template_id"].as_str().unwrap().into(),
            link_id: l["link_id"].as_str().unwrap().into(),
            args: l["args"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
                .collect::<BTreeMap<_, _>>(),
            layer: "tenant".into(),
        })
        .collect()
}

fn engine(links: Vec<Link>) -> Engine {
    Engine::build(&Inputs {
        boundary: "dev".into(),
        policies: vec![PolicyDoc {
            file: "local".into(),
            cedar: read("local.cedar"),
        }],
        vocabulary: read("vocabulary.yaml").into_bytes(),
        links,
    })
    .unwrap_or_else(|e| panic!("the local policy does not load: {e}"))
}

/// Runs every vector of the file; returns how many ran.
fn run(engine: &Engine, file: &str) -> usize {
    let vectors: Vec<Value> = serde_json::from_str(&read(file)).unwrap();
    for v in &vectors {
        let name = v["name"].as_str().unwrap();
        let r = &v["request"];
        let entities = engine
            .entities(v["entities"].as_array().unwrap().clone())
            .unwrap_or_else(|e| panic!("{name}: entities: {e:?}"));
        let got = engine
            .evaluate(
                r["principal"].as_str().unwrap(),
                r["action"].as_str().unwrap(),
                r["resource"].as_str().unwrap(),
                r["context"].clone(),
                &entities,
            )
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let want_allow = v["decision"].as_str().unwrap() == "allow";
        let want: Vec<&str> = v["reason"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        // The vectors are the example policy's; the built-in layer has rules of its own.
        let mut have: Vec<&str> = got
            .reasons
            .iter()
            .filter(|x| x.layer != "built-in")
            .map(|x| x.policy_id.as_str())
            .collect();
        have.sort_unstable();
        let mut want = want;
        want.sort_unstable();
        assert_eq!(got.allow, want_allow, "{name}: decision");
        assert_eq!(have, want, "{name}: determining policies");
        assert_eq!(
            got.errors as u64,
            v["num_errors"].as_u64().unwrap(),
            "{name}: errors"
        );
    }
    vectors.len()
}

#[test]
fn the_29_linked_vectors_pass() {
    assert_eq!(run(&engine(links()), "vectors.json"), 29);
}

#[test]
fn the_2_unlinked_vectors_pass() {
    assert_eq!(run(&engine(Vec::new()), "vectors-unlinked.json"), 2);
}
