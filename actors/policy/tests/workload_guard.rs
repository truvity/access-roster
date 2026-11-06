#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The built-in refusal of `artifact.sign` for a workload that comes from a pull request
//! (REQ-WORKLOAD-007): it holds against an operator policy that permits the repository, and a
//! workload that is not from a pull request is still decided by that policy.

mod common;

use common::local;
use policy::engine::{Engine, Inputs, PolicyDoc};
use serde_json::{Value, json};

const GUARD: &str = "builtin-workload-pull-request-no-sign";

/// An operator policy that names the repository and nothing else: the mistake the guard is for.
const REPOSITORY_ONLY: &str = r#"
@id("sign-anything-of-the-repository")
permit (principal is Workload, action == Action::"artifact.sign", resource == SigningKey::"release-signing")
when { principal has repository && principal.repository == "acme/app" };
"#;

fn engine() -> Engine {
    Engine::build(&Inputs {
        boundary: "dev".into(),
        policies: vec![PolicyDoc {
            file: "repository-only".into(),
            cedar: REPOSITORY_ONLY.into(),
        }],
        vocabulary: local("vocabulary.yaml").into_bytes(),
        links: Vec::new(),
    })
    .unwrap()
}

/// Asks `artifact.sign` for a workload with these attributes; returns whether it is allowed and
/// the ids of the determining policies.
fn sign(attrs: Value) -> (bool, Vec<String>) {
    let e = engine();
    let entities = e
        .entities(vec![
            json!({"uid": {"type": "Boundary", "id": "dev"}, "attrs": {}, "parents": []}),
            json!({"uid": {"type": "SigningKey", "id": "release-signing"}, "attrs": {},
                   "parents": [{"type": "Boundary", "id": "dev"}]}),
            json!({"uid": {"type": "Workload", "id": "w/1"}, "attrs": attrs, "parents": []}),
        ])
        .unwrap();
    let got = e
        .evaluate(
            "Workload::\"w/1\"",
            "Action::\"artifact.sign\"",
            "SigningKey::\"release-signing\"",
            json!({"content_sha384": "0".repeat(96), "content_length": 1}),
            &entities,
        )
        .unwrap();
    assert_eq!(got.errors, 0, "no policy errors");
    (
        got.allow,
        got.reasons.into_iter().map(|r| r.policy_id).collect(),
    )
}

fn github(extra: Value) -> Value {
    let mut a = json!({"verifier": "github-oidc", "repository": "acme/app", "event": "push"});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    a
}

/// verifies: REQ-WORKLOAD-007
#[test]
fn a_push_to_a_tag_or_a_branch_is_decided_by_the_operators_policy() {
    for extra in [
        json!({"ref": "refs/tags/v1.2.3", "ref_type": "tag"}),
        json!({"ref": "refs/heads/main", "ref_type": "branch"}),
    ] {
        let (allow, by) = sign(github(extra.clone()));
        assert!(allow, "{extra}: {by:?}");
        assert_eq!(by, ["sign-anything-of-the-repository"]);
    }
}

/// verifies: REQ-WORKLOAD-007
#[test]
fn a_pull_request_event_cannot_sign_although_the_policy_permits_the_repository() {
    for event in [
        "pull_request",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
    ] {
        // A branch ref, as `pull_request_target` has: the event alone is enough.
        let (allow, by) = sign(github(
            json!({"event": event, "ref": "refs/heads/main", "ref_type": "branch"}),
        ));
        assert!(!allow, "{event}");
        assert_eq!(by, [GUARD], "{event}");
    }
}

/// verifies: REQ-WORKLOAD-007
#[test]
fn a_pull_request_merge_ref_cannot_sign_whatever_the_event_says() {
    let (allow, by) = sign(github(
        json!({"ref": "refs/pull/42/merge", "event": "push"}),
    ));
    assert!(!allow);
    assert_eq!(by, [GUARD]);
    // Without any event too: the ref is enough.
    let (allow, by) =
        sign(json!({"verifier": "other", "repository": "acme/app", "ref": "refs/pull/42/head"}));
    assert!(!allow);
    assert_eq!(by, [GUARD]);
}

/// verifies: REQ-WORKLOAD-007
#[test]
fn a_github_workload_with_no_event_fails_closed() {
    let (allow, by) =
        sign(json!({"verifier": "github-oidc", "repository": "acme/app", "ref": "refs/tags/v1"}));
    assert!(!allow);
    assert_eq!(by, [GUARD]);
}

/// verifies: REQ-WORKLOAD-007
#[test]
fn a_workload_of_another_verifier_without_the_claims_is_not_taken_for_a_pull_request() {
    // The attributes are absent, not empty, and the guard says nothing about the workload.
    let (allow, by) = sign(json!({"verifier": "other", "repository": "acme/app"}));
    assert!(allow);
    assert_eq!(by, ["sign-anything-of-the-repository"]);
}

/// verifies: REQ-WORKLOAD-007
#[test]
fn the_verifier_name_of_the_guard_is_the_proof_kind_exchange_sets() {
    // `Workload.verifier` is the proof kind of exchange (`KindGitHubOIDC`). A rename on either side
    // must fail here and not turn the third clause of the guard into a rule about nothing.
    let go = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../exchange/internal/exchanged/subject.go"),
    )
    .unwrap();
    assert!(
        go.contains("KindGitHubOIDC = \"github-oidc\""),
        "the Go constant KindGitHubOIDC is no longer \"github-oidc\""
    );
    assert!(
        policy::schema::BUILTIN.contains("principal.verifier == \"github-oidc\""),
        "the guard no longer names the github-oidc verifier"
    );
}

/// verifies: REQ-WORKLOAD-007
#[test]
fn an_operator_policy_cannot_take_the_id_of_the_guard() {
    let reuse = format!(
        "@id(\"{GUARD}\")\npermit (principal is Workload, action == Action::\"artifact.sign\", resource);"
    );
    let r = Engine::build(&Inputs {
        boundary: "dev".into(),
        policies: vec![PolicyDoc {
            file: "reuse".into(),
            cedar: reuse,
        }],
        vocabulary: local("vocabulary.yaml").into_bytes(),
        links: Vec::new(),
    });
    assert!(
        r.is_err(),
        "an operator policy with the id of the guard loaded"
    );
}
