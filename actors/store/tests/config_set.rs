#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The config set as a whole (ADR 0005, "The snapshot", "A failed reload"; signed-config.md "The snapshot"): the
//! checks that span documents, and a reload that refuses a changed set whole. The documents are the local
//! installation's, signed here with a key made for the test and read through the real `file` driver on a Unix socket.

mod config_support;

use std::sync::Arc;
use std::time::Duration;

use config_support::{LOCAL, Pipeline, bootstrap, put, serve_driver, up, write_local};
use sluis_kit::dial;
use store::config::{ConfigSnapshot, LoadError, Loader, Reloaded, reload_event};

fn source(segment: &str) -> &'static str {
    LOCAL.iter().find(|(s, _)| *s == segment).unwrap().1
}

struct Env {
    docs: tempfile::TempDir,
    _sock: tempfile::TempDir,
    pipeline: Pipeline,
    loader: Arc<Loader>,
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl Env {
    /// The local set at `seq` 1, loaded by a cold start.
    async fn start() -> Env {
        let (docs, sock) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let path = sock.path().join("config-source.sock");
        let stop = serve_driver(&path, docs.path());
        up(&path).await;
        let pipeline = Pipeline::new("publisher-1");
        write_local(docs.path(), &pipeline, 1);
        let loader = Loader::start(
            &dial(&path),
            &bootstrap(vec![pipeline.publisher(&[])]),
            Duration::from_millis(300),
        )
        .await
        .unwrap();
        Env {
            docs,
            _sock: sock,
            pipeline,
            loader,
            _stop: stop,
        }
    }

    fn sign(&self, segment: &str, text: &str, seq: u64) {
        put(
            self.docs.path(),
            segment,
            &self.pipeline.sign(segment, text.as_bytes(), seq),
        );
    }
}

fn refused(r: Reloaded) -> (LoadError, bool) {
    match r {
        Reloaded::Refused { error, report } => (error, report),
        other => panic!("not refused: {other:?}"),
    }
}

/// verifies: REQ-DATA-082
#[tokio::test]
async fn a_set_whose_second_document_breaks_a_rule_of_the_set_is_refused_whole() {
    let e = Env::start().await;
    let before = e.loader.snapshot().summaries();

    // Each document of this change is valid on its own. A good TokenLifetime is signed with it, so a partial swap
    // would show.
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("10m", "20m"),
        2,
    );
    // Link: an Upstream that names the credential an InstallationClient names (REQ-ISO-106).
    e.sign(
        "upstream",
        &source("upstream").replace("upstream-workforce", "client-example-app"),
        2,
    );
    let (err, _) = refused(e.loader.reload().await);
    assert_eq!(
        err.to_string(),
        "Upstream: secret: names a credential an InstallationClient names"
    );
    assert_eq!(e.loader.snapshot().summaries(), before, "nothing applies");
    assert_eq!(e.loader.version("token-lifetime"), Some(1));
    assert_eq!(e.loader.version("upstream"), Some(1));

    // Fixing the second document applies both together.
    e.sign("upstream", source("upstream"), 3);
    let Reloaded::Applied(applied) = e.loader.reload().await else {
        panic!("not applied")
    };
    assert_eq!(applied.len(), LOCAL.len());
    assert_eq!(e.loader.version("token-lifetime"), Some(2));
    assert_eq!(e.loader.version("upstream"), Some(3));
}

/// verifies: REQ-DATA-082
#[tokio::test]
async fn a_bound_of_one_document_is_checked_against_the_others_and_a_change_of_the_first_alone_is_refused()
 {
    let e = Env::start().await;
    let before = e.loader.snapshot().summaries();

    // Only the Boundary changes, to production. The Upstream and the native client, unchanged and valid under the
    // development floor, now break the https floor of the boundary (REQ-SEC-037).
    e.sign(
        "boundary",
        &source("boundary").replace("environment: development", "environment: production"),
        2,
    );
    let (err, _) = refused(e.loader.reload().await);
    assert!(
        err.to_string()
            .starts_with("Upstream: issuer: must be https"),
        "{err}"
    );
    assert_eq!(e.loader.snapshot().summaries(), before);
    assert_eq!(e.loader.version("boundary"), Some(1));
}

/// verifies: REQ-AUTHN-009
#[tokio::test]
async fn the_passkey_acr_must_be_one_the_boundary_lists() {
    let e = Env::start().await;
    let before = e.loader.snapshot().summaries();
    let listed = "    - urn:sluis:acr:passkey\n";
    assert!(
        source("boundary").contains(listed),
        "the local Boundary lists it"
    );

    // Only the Boundary changes: the list drops the passkey acr. The SignInMethods, unchanged and valid alone, names a
    // value that no request can then carry to its page.
    e.sign("boundary", &source("boundary").replace(listed, ""), 2);
    let (err, _) = refused(e.loader.reload().await);
    assert_eq!(
        err.to_string(),
        "SignInMethods: default.passkey_acr: is not in the Boundary's acr_values_supported"
    );
    assert!(!err.to_string().contains("urn:sluis"), "{err}");
    assert_eq!(e.loader.snapshot().summaries(), before, "nothing applies");

    // The same acr written another way is another value: the match is exact (REQ-AUTHN-009).
    e.sign(
        "boundary",
        &source("boundary").replace(listed, "    - URN:sluis:acr:passkey\n"),
        3,
    );
    let (err, _) = refused(e.loader.reload().await);
    assert!(
        err.to_string()
            .starts_with("SignInMethods: default.passkey_acr"),
        "{err}"
    );

    // The other way: the Boundary is right and the SignInMethods names another acr.
    e.sign("boundary", source("boundary"), 4);
    e.sign(
        "sign-in-methods",
        &source("sign-in-methods").replace("urn:sluis:acr:passkey", "urn:sluis:acr:other"),
        2,
    );
    let (err, _) = refused(e.loader.reload().await);
    assert!(
        err.to_string()
            .starts_with("SignInMethods: default.passkey_acr"),
        "{err}"
    );
    assert!(!err.to_string().contains("other"), "{err}");

    // Both right, together: applied.
    e.sign("sign-in-methods", source("sign-in-methods"), 3);
    assert!(matches!(e.loader.reload().await, Reloaded::Applied(_)));
}

/// verifies: REQ-AUTHN-009
#[tokio::test]
async fn every_step_up_acr_of_the_policy_must_be_one_the_boundary_lists() {
    let e = Env::start().await;
    let before = e.loader.snapshot().summaries();
    let listed = "    - urn:example:acr:mfa\n";
    assert!(source("boundary").contains(listed));

    // The Boundary drops the acr that the local policy's step-up rule asks for.
    e.sign("boundary", &source("boundary").replace(listed, ""), 2);
    let (err, _) = refused(e.loader.reload().await);
    assert_eq!(
        err.to_string(),
        "Policy: default: the acr_values of the @step_up number 1 is not in the Boundary's acr_values_supported"
    );
    assert!(!err.to_string().contains("urn:example"), "{err}");
    assert_eq!(e.loader.snapshot().summaries(), before, "nothing applies");

    // A second rule with an unlisted acr is refused by its number, though the first is listed.
    let rule = |acr: &str| {
        format!(
            "@id(\"extra\")\n@step_up(\"acr_values={acr} max_age=300\")\nforbid (principal is Person, action == Action::\"token.issue\", resource is Client);\n"
        )
    };
    e.sign("boundary", source("boundary"), 3);
    e.sign(
        "policy",
        &format!("{}\n{}", source("policy"), rule("urn:sluis:acr:unlisted")),
        2,
    );
    let (err, _) = refused(e.loader.reload().await);
    assert_eq!(
        err.to_string(),
        "Policy: default: the acr_values of the @step_up number 2 is not in the Boundary's acr_values_supported"
    );

    // A rule for a listed acr, and an unlisted one in a comment, load: the comment is not an annotation.
    e.sign(
        "policy",
        &format!(
            "{}\n{}// {}",
            source("policy"),
            rule("urn:sluis:acr:passkey"),
            rule("urn:sluis:acr:unlisted").replace('\n', " ")
        ),
        3,
    );
    assert!(matches!(e.loader.reload().await, Reloaded::Applied(_)));
}

/// A reload fact, as the service sends it: the action, whether it failed, and the fields as `key=value`.
fn facts(outcomes: &[Reloaded]) -> Vec<(String, bool, Vec<String>)> {
    outcomes
        .iter()
        .filter_map(|o| reload_event("dev", o))
        .map(|ev| {
            let fields = ev
                .fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .chain(
                    ev.documents
                        .iter()
                        .map(|d| format!("{}@{}={}", d.kind, d.seq, d.sha384)),
                )
                .collect();
            (ev.action.to_owned(), ev.failure, fields)
        })
        .collect()
}

/// verifies: REQ-DATA-084
#[tokio::test]
async fn one_bad_document_in_a_set_of_three_applies_none_and_is_one_fact_per_digest() {
    let e = Env::start().await;
    let before = e.loader.snapshot().summaries();
    // A marker in the bad payload: no fact may carry any of it.
    const MARK: &str = "zq-marker-5e0a";

    // Three documents change: two are good, one (KeyPlan) is not.
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("10m", "20m"),
        2,
    );
    e.sign("key-plan", &format!("default:\n  cache_ttl: {MARK}\n"), 2);
    e.sign(
        "audit-catalogue",
        &source("audit-catalogue").replace("release: 0.0.0", "release: 0.0.1"),
        2,
    );

    let mut outcomes = vec![e.loader.reload().await];
    let (err, report) = refused_ref(&outcomes[0]);
    assert!(err.to_string().starts_with("KeyPlan: step 6"), "{err}");
    assert!(report, "the first refusal is reported");
    // None of the three applies, and the snapshot in force is the old set, whole.
    assert_eq!(e.loader.snapshot().summaries(), before);
    for (segment, seq) in [
        ("token-lifetime", 1),
        ("key-plan", 1),
        ("audit-catalogue", 1),
    ] {
        assert_eq!(e.loader.version(segment), Some(seq), "{segment}");
    }

    // The same refused digest at every poll is not a new fact.
    for _ in 0..3 {
        outcomes.push(e.loader.reload().await);
    }
    let all = facts(&outcomes);
    assert_eq!(all.len(), 1, "one fact for one refused digest: {all:?}");
    let (action, failure, fields) = &all[0];
    assert_eq!((action.as_str(), *failure), ("store.reload.refused", true));
    assert!(
        fields.contains(&"document=KeyPlan".to_owned()),
        "{fields:?}"
    );
    assert!(
        fields.iter().any(|f| f.starts_with("digest=")),
        "{fields:?}"
    );
    assert!(
        fields.iter().all(|f| !f.contains(MARK)),
        "a fact names the rule broken and never a value: {fields:?}"
    );

    // Another bad digest is another fact.
    e.sign("key-plan", &format!("default:\n  cache_ttl: {MARK}-2\n"), 3);
    outcomes.push(e.loader.reload().await);
    assert_eq!(facts(&outcomes[4..]).len(), 1);

    // The fixed set applies as a whole: all three, one `store.reload` fact naming every document.
    e.sign("key-plan", source("key-plan"), 4);
    let applied = e.loader.reload().await;
    let applied_facts = facts(std::slice::from_ref(&applied));
    assert_eq!(applied_facts.len(), 1);
    assert_eq!(
        (applied_facts[0].0.as_str(), applied_facts[0].1),
        ("store.reload", false)
    );
    assert_eq!(
        applied_facts[0].2.len(),
        1 + LOCAL.len(),
        "the boundary and every document"
    );
    for (segment, seq) in [
        ("token-lifetime", 2),
        ("key-plan", 4),
        ("audit-catalogue", 2),
    ] {
        assert_eq!(e.loader.version(segment), Some(seq), "{segment}");
    }
}

fn refused_ref(r: &Reloaded) -> (&LoadError, bool) {
    match r {
        Reloaded::Refused { error, report } => (error, *report),
        other => panic!("not refused: {other:?}"),
    }
}
