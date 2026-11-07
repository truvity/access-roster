#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The `@step_up` annotations of a Policy text, as store@ reads them without a Cedar parser, against the parser: every row of
//! `kits/conformance/policy/step-up-vectors.json` is parsed here by `cedar-policy`, and the `acr_values` it says must be what
//! the annotations hold. store@'s lexer (actors/store/src/config/stepup.rs) reads the same rows, so the two cannot differ
//! on a text that Cedar accepts (REQ-AUTHN-009, policy.md "Step-up").

use std::str::FromStr as _;

use cedar_policy::PolicySet;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../kits/conformance/policy/step-up-vectors.json");

/// The `acr_values=` parts of an annotation value, as store@ and `session` read them.
fn acr_values(value: &str) -> Vec<String> {
    value
        .split(' ')
        .filter_map(|p| p.strip_prefix("acr_values="))
        .filter(|a| !a.is_empty())
        .map(str::to_owned)
        .collect()
}

/// verifies: REQ-AUTHN-009
#[test]
fn cedar_reads_the_annotations_of_every_vector_as_the_vectors_say() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(
        cases.len() >= 32,
        "{} rows: the vectors lost a case",
        cases.len()
    );
    for c in cases {
        let (name, cedar) = (c["name"].as_str().unwrap(), c["cedar"].as_str().unwrap());
        let set =
            PolicySet::from_str(cedar).unwrap_or_else(|e| panic!("{name}: Cedar refuses it: {e}"));
        let mut got: Vec<String> = set
            .policies()
            .filter_map(|p| p.annotation("step_up").map(str::to_owned))
            .chain(
                set.templates()
                    .filter_map(|t| t.annotation("step_up").map(str::to_owned)),
            )
            .flat_map(|v| acr_values(&v))
            .collect();
        got.sort();
        let mut want: Vec<String> = c["acr_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect();
        want.sort();
        assert_eq!(got, want, "{name}");
    }
}
