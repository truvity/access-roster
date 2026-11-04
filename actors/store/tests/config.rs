#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The signed config snapshot (WP-11): the local installation's documents, the payload rules, the
//! cold start that refuses, the reload that keeps the snapshot in force, and the watcher that
//! reloads. The documents are signed here with a key made for the test and read through the real
//! `file` driver on a Unix socket.

mod config_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use buffa::Message as _;
use config_support::{LOCAL, Pipeline, bootstrap, document, put, serve_driver, up, write_local};
use sluis_kit::dial;
use sluis_proto::sluis::config::v2alpha1 as pb;
use store::config::payload;
use store::config::{ConfigSnapshot, Loader, Reloaded};

fn kind(name: &str) -> &'static sluis_registry::Kind {
    sluis_registry::kind_by_name(name).unwrap()
}

fn source(segment: &str) -> &'static str {
    LOCAL.iter().find(|(s, _)| *s == segment).unwrap().1
}

// ---- the documents of the local installation ----

#[test]
fn every_local_document_is_read_into_its_kinds_message() {
    for (segment, text) in LOCAL {
        let k = sluis_registry::kind_by_segment(segment).unwrap();
        let items =
            payload::decode(k, text.as_bytes()).unwrap_or_else(|e| panic!("{segment}: {e}"));
        assert!(!items.is_empty(), "{segment}");
        // A singleton kind has the one item `default`; a keyed kind uses its name (D-17).
        let ids: Vec<_> = items.iter().map(|(i, _)| i.as_str()).collect();
        match segment {
            "upstream" => assert_eq!(ids, ["workforce"]),
            "installation-client" => assert_eq!(ids, ["sluis-cli"]),
            _ => assert_eq!(ids, ["default"], "{segment}"),
        }
    }
}

#[test]
fn the_local_values_are_the_ones_the_skeleton_needs() {
    let one = |name: &str| {
        payload::decode(
            kind(name),
            source(sluis_registry::kind_by_name(name).unwrap().segment).as_bytes(),
        )
        .unwrap()
        .remove(0)
        .1
    };
    let b = pb::Boundary::decode_from_slice(&one("Boundary")).unwrap();
    assert_eq!(
        (
            b.name.as_str(),
            b.environment.as_str(),
            b.default_tenant.as_str()
        ),
        ("dev", "development", "acme")
    );
    assert_eq!(b.declared_kinds.len(), 8);
    let u = pb::Upstream::decode_from_slice(&one("Upstream")).unwrap();
    assert_eq!(u.name, "workforce");
    assert_eq!(u.issuer, "http://127.0.0.1:8180/realms/sluis-test");
    assert_eq!(u.subject_claim, "preferred_username");
    let c = pb::InstallationClient::decode_from_slice(&one("InstallationClient")).unwrap();
    assert_eq!((c.id.as_str(), c.kind.as_str()), ("sluis-cli", "public"));
    let t = pb::TokenLifetime::decode_from_slice(&one("TokenLifetime")).unwrap();
    assert_eq!(t.access_token.seconds, 600);
    assert_eq!(t.human_session_absolute.seconds, 12 * 3600);
    let k = pb::KeyPlan::decode_from_slice(&one("KeyPlan")).unwrap();
    assert_eq!((k.cache_ttl.seconds, k.purposes.len()), (900, 4));
    let v = pb::GrantVocabulary::decode_from_slice(&one("GrantVocabulary")).unwrap();
    assert_eq!(v.document, source("grant-vocabulary").as_bytes());
    let a = pb::AuditCatalogue::decode_from_slice(&one("AuditCatalogue")).unwrap();
    assert!(a.actions.iter().any(|x| x == "store.reload.refused"));
    let l = pb::AuditLog::decode_from_slice(&one("AuditLog")).unwrap();
    assert_eq!(l.logs.len(), 2);
}

// ---- the payload rules ----

fn refused(kind_name: &str, text: &str) -> String {
    payload::decode(kind(kind_name), text.as_bytes())
        .expect_err("must be refused")
        .0
}

#[test]
fn a_payload_is_refused_by_place_and_an_error_shows_no_value() {
    let e = refused(
        "Upstream",
        "workforce:\n  kind: oidc\n  issuer: https://idp.example.com\n  client_id: c\n  subject_claim: sub\n  surprise-value-1: x\n",
    );
    assert!(e.contains("workforce.<key>: unknown key"), "{e}");
    assert!(
        !e.contains("surprise-value-1"),
        "an error never shows a value: {e}"
    );
    // A retired or unknown field is refused, a type error names the field.
    let e = refused(
        "TokenLifetime",
        "default:\n  id_token: 10m\n  access_token: 600\n",
    );
    assert!(e.contains("default.access_token"), "{e}");
    // The strict profile: a duplicate key, an anchor, a tag.
    for bad in [
        "default:\n  id_token: 1m\n  id_token: 2m\n",
        "default: &a\n  id_token: 1m\n",
        "default: !!map\n  id_token: 1m\n",
    ] {
        assert!(!refused("TokenLifetime", bad).is_empty(), "{bad}");
    }
}

#[test]
fn durations_follow_the_grammar_and_the_built_in_cap() {
    let doc = |d: &str| {
        format!(
            "default:\n  id_token: 10m\n  access_token: {d}\n  human_session_absolute: 12h\n  refresh_idle: 8h\n"
        )
    };
    for ok in ["30s", "15m", "1h"] {
        assert!(
            payload::decode(kind("TokenLifetime"), doc(ok).as_bytes()).is_ok(),
            "{ok}"
        );
    }
    for bad in ["30", "PT30S", "1.5s", "1h30m", "-1s", "0s"] {
        let e = refused("TokenLifetime", &doc(bad));
        assert!(e.starts_with("default.access_token"), "{bad}: {e}");
    }
    let e = refused("TokenLifetime", &doc("2h"));
    assert!(e.contains("above the built-in cap"), "{e}");
}

#[test]
fn a_singleton_has_one_item_default_and_a_keyed_kind_uses_its_name() {
    let k = "default:\n  cache_ttl: 15m\n";
    assert!(payload::decode(kind("KeyPlan"), k.as_bytes()).is_ok());
    for bad in [
        "other:\n  cache_ttl: 15m\n",
        "default:\n  cache_ttl: 15m\nsecond:\n  cache_ttl: 15m\n",
        "{}",
        "- cache_ttl: 15m\n",
        "",
    ] {
        assert!(!refused("KeyPlan", bad).is_empty(), "{bad:?}");
    }
    // The name a message carries is its id.
    let up = |name: &str| {
        format!(
            "workforce:\n  name: {name}\n  kind: oidc\n  issuer: https://idp.example.com\n  client_id: c\n  subject_claim: sub\n"
        )
    };
    assert!(payload::decode(kind("Upstream"), up("workforce").as_bytes()).is_ok());
    assert!(refused("Upstream", &up("other")).contains("workforce.name"));
    // An id is an address part.
    assert!(refused("Upstream", "Work Force:\n  kind: oidc\n").contains("<id>"));
}

#[test]
fn a_kind_this_build_cannot_read_is_refused_not_skipped() {
    for name in ["RegulatedPartyPolicy", "SignInMethods", "FrontHost"] {
        if let Some(k) = sluis_registry::kind_by_name(name) {
            assert!(payload::decode(k, b"default: {}\n").is_err(), "{name}");
        }
    }
    // A non-config kind has no document at all.
    assert!(payload::decode(kind("DataKeyWrap"), b"default: {}\n").is_err());
}

// ---- the loader ----

struct Env {
    docs: tempfile::TempDir,
    _sock: tempfile::TempDir,
    pipeline: Pipeline,
    client: sluis_kit::Client,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn env() -> Env {
    let (docs, sock) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let path = sock.path().join("config-source.sock");
    let stop = serve_driver(&path, docs.path());
    up(&path).await;
    Env {
        docs,
        _sock: sock,
        pipeline: Pipeline::new("publisher-1"),
        client: dial(&path),
        _stop: stop,
    }
}

impl Env {
    async fn start(&self) -> Result<Arc<Loader>, store::config::LoadError> {
        Loader::start(
            &self.client,
            &bootstrap(vec![self.pipeline.publisher(&[])]),
            Duration::from_millis(300),
        )
        .await
    }

    fn sign(&self, segment: &str, text: &str, seq: u64) {
        put(
            self.docs.path(),
            segment,
            &self.pipeline.sign(text.as_bytes(), seq),
        );
    }
}

#[tokio::test]
async fn a_cold_start_loads_the_set_and_serves_it_read_only() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 7);
    let loader = e.start().await.unwrap();

    assert_eq!(loader.version("boundary"), Some(7));
    assert_eq!(loader.version("upstream"), Some(7));
    // A kind the boundary does not declare has no document in the snapshot.
    assert_eq!(loader.version("exchange-trust"), None);
    assert!(loader.get("exchange-trust", "default").is_none());

    let b = pb::Boundary::decode_from_slice(&loader.get("boundary", "default").unwrap()).unwrap();
    assert_eq!(b.name, "dev");
    let ups = loader.list("upstream");
    assert_eq!(ups.len(), 1);
    assert_eq!(ups[0].0, "workforce");
    assert!(loader.get("upstream", "nope").is_none());

    // The audit fact names each document's kind, seq and the SHA-384 of its payload.
    let summaries = loader.snapshot().summaries();
    assert_eq!(summaries.len(), 9);
    let up = summaries.iter().find(|s| s.kind == "Upstream").unwrap();
    assert_eq!(up.seq, 7);
    assert_eq!(up.sha384.len(), 96);
    let digest =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, source("upstream").as_bytes());
    assert_eq!(up.sha384, store::config::document::hex(digest.as_ref()));
}

#[tokio::test]
async fn a_cold_start_refuses_on_any_failure_and_says_why() {
    // Each case starts from a valid directory and breaks one thing.
    type Break = Box<dyn Fn(&Env)>;
    let cases: Vec<(&str, Break, &str)> = vec![
        (
            "a declared document is missing",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("audit-log.jws")).unwrap()),
            "AuditLog: the source has no document",
        ),
        (
            "the boundary document is missing",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("boundary.jws")).unwrap()),
            "Boundary: the source has no document",
        ),
        (
            "a document is signed by a key that is not pinned",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "key-plan",
                    &Pipeline::new("publisher-1").sign(source("key-plan").as_bytes(), 1),
                )
            }),
            "KeyPlan: step 4",
        ),
        (
            "a document names a kid that is not pinned",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "key-plan",
                    &Pipeline::new("rogue").sign(source("key-plan").as_bytes(), 1),
                )
            }),
            "KeyPlan: step 3",
        ),
        (
            "a document is not signed at all",
            Box::new(|e| put(e.docs.path(), "key-plan", source("key-plan").as_bytes())),
            "KeyPlan: step 1",
        ),
        (
            "a document is signed but its payload is not valid for the kind",
            Box::new(|e| e.sign("token-lifetime", "default:\n  id_token: ten minutes\n", 1)),
            "TokenLifetime: step 6: default.id_token",
        ),
        (
            "the boundary is not the bootstrap file's",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("name: dev", "name: other"),
                    1,
                )
            }),
            "Boundary: name: is not the boundary of the bootstrap file",
        ),
        (
            "the boundary declares a kind this build cannot read",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("- KeyPlan", "- RegulatedPartyPolicy"),
                    1,
                )
            }),
            "Boundary: declared_kinds: RegulatedPartyPolicy has no reader",
        ),
        (
            "production with a plain http issuer",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary")
                        .replace("environment: development", "environment: production"),
                    1,
                )
            }),
            "must be https outside development",
        ),
    ];
    for (name, break_it, want) in cases {
        let e = env().await;
        write_local(e.docs.path(), &e.pipeline, 1);
        break_it(&e);
        let err = e
            .start()
            .await
            .err()
            .unwrap_or_else(|| panic!("{name}: it started"));
        assert!(err.to_string().contains(want), "{name}: {err}");
        assert!(!err.unreachable, "{name}");
    }
}

#[tokio::test]
async fn a_cold_start_waits_for_a_source_and_then_gives_up_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let client = dial(&dir.path().join("none.sock"));
    let err = Loader::start(
        &client,
        &bootstrap(vec![Pipeline::new("publisher-1").publisher(&[])]),
        Duration::from_millis(400),
    )
    .await
    .err()
    .unwrap();
    assert!(err.unreachable, "{err}");
}

#[tokio::test]
async fn a_cold_start_takes_the_latest_signed_document_whatever_its_seq() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    // A lower seq than one published before: nothing is in force to compare with.
    e.sign("token-lifetime", source("token-lifetime"), 1);
    assert!(e.start().await.is_ok());
}

fn refused_reload(r: Reloaded) -> (store::config::LoadError, bool) {
    match r {
        Reloaded::Refused { error, report } => (error, report),
        other => panic!("not refused: {other:?}"),
    }
}

#[tokio::test]
async fn a_bad_document_on_reload_keeps_the_snapshot_and_is_reported_once() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    let before = loader.snapshot().summaries();

    // Nothing changed.
    assert!(matches!(loader.reload().await, Reloaded::Unchanged));

    // A good new document and a bad one in the same set: none of it is applied.
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("10m", "20m"),
        2,
    );
    e.sign("key-plan", "default:\n  cache_ttl: nonsense\n", 2);
    let (err, report) = refused_reload(loader.reload().await);
    assert!(err.to_string().starts_with("KeyPlan: step 6"), "{err}");
    assert!(report);
    assert_eq!(
        loader.snapshot().summaries(),
        before,
        "the snapshot in force stays"
    );
    assert_eq!(loader.version("token-lifetime"), Some(1));
    // The same refused document is reported once, not at every poll.
    let (_, report) = refused_reload(loader.reload().await);
    assert!(!report);
    // Another bad document is a new report.
    e.sign("key-plan", "default:\n  cache_ttl: still nonsense\n", 3);
    let (_, report) = refused_reload(loader.reload().await);
    assert!(report);

    // Fixing it applies the whole set: both documents.
    e.sign("key-plan", source("key-plan"), 4);
    let Reloaded::Applied(applied) = loader.reload().await else {
        panic!("not applied")
    };
    assert_eq!(applied.len(), 9);
    assert_eq!(loader.version("token-lifetime"), Some(2));
    assert_eq!(loader.version("key-plan"), Some(4));
    let t = pb::TokenLifetime::decode_from_slice(&loader.get("token-lifetime", "default").unwrap())
        .unwrap();
    assert_eq!(t.id_token.seconds, 1200);
}

#[tokio::test]
async fn the_sequence_number_only_grows_on_a_running_store() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 5);
    let loader = e.start().await.unwrap();
    let payload = source("token-lifetime");

    // A lower seq, with a new payload or the old one.
    e.sign("token-lifetime", &payload.replace("10m", "20m"), 4);
    let (err, _) = refused_reload(loader.reload().await);
    assert!(err.to_string().contains("step 5: a lower seq"), "{err}");
    // The same seq with another payload.
    e.sign("token-lifetime", &payload.replace("10m", "20m"), 5);
    let (err, _) = refused_reload(loader.reload().await);
    assert!(
        err.to_string()
            .contains("step 5: the same seq with another payload"),
        "{err}"
    );
    assert_eq!(loader.version("token-lifetime"), Some(5));
    // The same seq with the same payload, signed again: no change.
    e.sign("token-lifetime", payload, 5);
    assert!(matches!(loader.reload().await, Reloaded::Unchanged));
    // A higher seq replaces it.
    e.sign("token-lifetime", &payload.replace("10m", "20m"), 6);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.version("token-lifetime"), Some(6));
}

#[tokio::test]
async fn a_source_that_goes_away_keeps_the_snapshot_and_comes_back() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    std::fs::remove_file(e.docs.path().join("upstream.jws")).unwrap();
    let (err, report) = refused_reload(loader.reload().await);
    assert!(
        err.to_string()
            .contains("Upstream: the source has no document"),
        "{err}"
    );
    assert!(report);
    assert!(
        loader.get("upstream", "workforce").is_some(),
        "the old document still serves"
    );
    e.sign("upstream", source("upstream"), 1);
    assert!(matches!(loader.reload().await, Reloaded::Unchanged));
}

#[tokio::test]
async fn a_declared_kind_that_is_added_or_dropped_follows_the_boundary() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    // Declaring a kind with no document is a failure, and the set stays.
    let with_trust =
        source("boundary").replace("    - Upstream\n", "    - Upstream\n    - ExchangeTrust\n");
    e.sign("boundary", &with_trust, 2);
    let (err, _) = refused_reload(loader.reload().await);
    assert!(
        err.to_string()
            .contains("ExchangeTrust: the source has no document"),
        "{err}"
    );
    assert_eq!(loader.version("exchange-trust"), None);
    // With the document, it joins.
    e.sign("exchange-trust", "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks }\n", 1);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.version("exchange-trust"), Some(1));
    // Dropping it from the declaration removes it from the snapshot.
    e.sign("boundary", source("boundary"), 3);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.version("exchange-trust"), None);
}

#[tokio::test]
async fn a_regulated_party_co_signature_is_required_by_the_bootstrap_file() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let party = Pipeline::new("party-1");
    // The party co-signs KeyPlan: the publisher's signature alone no longer loads it.
    let b = bootstrap(vec![
        e.pipeline.publisher(&[]),
        party.publisher(&["KeyPlan"]),
    ]);
    let err = Loader::start(&e.client, &b, Duration::from_millis(300))
        .await
        .err()
        .unwrap();
    assert!(
        err.to_string()
            .contains("KeyPlan: step 4: a co-signer's signature is missing"),
        "{err}"
    );
    // With both signatures over one payload and one seq, it loads.
    let text = source("key-plan");
    let both = document(
        text.as_bytes(),
        &[
            e.pipeline.signature(text.as_bytes(), 1),
            party.signature(text.as_bytes(), 1),
        ],
    );
    put(e.docs.path(), "key-plan", &both);
    assert!(
        Loader::start(&e.client, &b, Duration::from_millis(300))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_watcher_reloads_when_a_document_changes_and_hands_over_each_outcome() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let task = tokio::spawn({
        let (loader, seen) = (Arc::clone(&loader), Arc::clone(&seen));
        async move {
            store::config::reload::run(loader, move |r| {
                let seen = Arc::clone(&seen);
                async move {
                    let line = match &r {
                        Reloaded::Unchanged => "unchanged".to_owned(),
                        Reloaded::Applied(d) => format!("applied {}", d.len()),
                        Reloaded::Refused { error, report } => format!("refused {report}: {error}"),
                    };
                    seen.lock().unwrap().push(line);
                }
            })
            .await;
        }
    });
    let wait_for = |want: &'static str| {
        let seen = Arc::clone(&seen);
        async move {
            for _ in 0..200 {
                if seen.lock().unwrap().iter().any(|l| l.contains(want)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("never saw {want:?} in {:?}", seen.lock().unwrap());
        }
    };

    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("10m", "20m"),
        2,
    );
    wait_for("applied 9").await;
    assert_eq!(loader.version("token-lifetime"), Some(2));

    e.sign("key-plan", "default: {}\n", 9);
    wait_for("refused true: KeyPlan: step 6").await;
    assert_eq!(
        loader.version("key-plan"),
        Some(1),
        "the snapshot in force stays"
    );
    task.abort();
}

#[tokio::test]
async fn a_kind_declared_later_with_no_document_yet_is_retried_until_it_arrives() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let task = tokio::spawn({
        let (loader, seen) = (Arc::clone(&loader), Arc::clone(&seen));
        async move {
            store::config::reload::run(loader, move |r| {
                let seen = Arc::clone(&seen);
                async move {
                    let line = match &r {
                        Reloaded::Unchanged => "unchanged".to_owned(),
                        Reloaded::Applied(d) => format!("applied {}", d.len()),
                        Reloaded::Refused { error, report } => format!("refused {report}: {error}"),
                    };
                    seen.lock().unwrap().push(line);
                }
            })
            .await;
        }
    });
    let wait_for = |want: &'static str| {
        let seen = Arc::clone(&seen);
        async move {
            for _ in 0..200 {
                if seen.lock().unwrap().iter().any(|l| l.contains(want)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("never saw {want:?} in {:?}", seen.lock().unwrap());
        }
    };

    // The boundary declares a kind whose document is not in the source yet: the reload is refused
    // and the snapshot stays. The kind is not in the snapshot, so nothing watches its name.
    let with_trust =
        source("boundary").replace("    - Upstream\n", "    - Upstream\n    - ExchangeTrust\n");
    e.sign("boundary", &with_trust, 2);
    wait_for("refused true: ExchangeTrust: the source has no document").await;
    assert_eq!(loader.version("exchange-trust"), None);

    // The document arrives. No watched name changes, so only the retry can find it.
    e.sign("exchange-trust", "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks }\n", 1);
    wait_for("applied 10").await;
    assert_eq!(loader.version("exchange-trust"), Some(1));
    assert_eq!(loader.version("boundary"), Some(2));
    task.abort();
}

#[tokio::test]
async fn the_https_floor_covers_the_exchange_trust_issuer_and_jwks_uri() {
    // A production boundary whose other documents are all https, so that only ExchangeTrust is at
    // fault; development takes the same document.
    let set = |e: &Env, environment: &str, trust: &str| {
        e.sign(
            "boundary",
            &source("boundary")
                .replace(
                    "environment: development",
                    &format!("environment: {environment}"),
                )
                .replace("    - Upstream\n", "    - Upstream\n    - ExchangeTrust\n"),
            1,
        );
        e.sign(
            "upstream",
            &source("upstream").replace("http://", "https://"),
            1,
        );
        e.sign(
            "installation-client",
            &source("installation-client").replace("http://", "https://"),
            1,
        );
        e.sign("exchange-trust", trust, 1);
    };
    let issuer_http = "default:\n  issuers:\n    - { issuer: \"http://idp.example.com\", audiences: [sluis], proof_kind: jwks }\n";
    let jwks_http = "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks, jwks_uri: \"http://idp.example.com/keys\" }\n";
    let all_https = "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks, jwks_uri: \"https://idp.example.com/keys\" }\n";

    for (trust, want) in [
        (
            issuer_http,
            "ExchangeTrust: issuers: issuer must be https outside development",
        ),
        (
            jwks_http,
            "ExchangeTrust: issuers: jwks_uri must be https outside development",
        ),
    ] {
        for environment in ["production", "staging"] {
            let e = env().await;
            write_local(e.docs.path(), &e.pipeline, 1);
            set(&e, environment, trust);
            let err = e.start().await.err().unwrap_or_else(|| {
                panic!("{environment}: a plain http ExchangeTrust started: {trust}")
            });
            assert!(err.to_string().contains(want), "{environment}: {err}");
        }
        // The same plain http is a development boundary's own.
        let e = env().await;
        write_local(e.docs.path(), &e.pipeline, 1);
        set(&e, "development", trust);
        assert!(e.start().await.is_ok(), "development takes plain http");
    }
    // Over https, production starts.
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    set(&e, "production", all_https);
    let loader = e.start().await.unwrap();
    assert_eq!(loader.version("exchange-trust"), Some(1));
}

#[test]
fn a_jwks_uri_that_is_not_a_url_is_refused_by_place() {
    let msg = refused(
        "ExchangeTrust",
        "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks, jwks_uri: \"ftp://idp.example.com/keys\" }\n",
    );
    assert!(msg.contains("jwks_uri"), "{msg}");
}

#[tokio::test]
async fn the_policy_kind_is_served_to_its_reader_as_the_one_cedar_file() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 3);
    let loader = e.start().await.unwrap();
    assert_eq!(loader.version("policy"), Some(3));

    // One document is one Cedar file: the one item `default`, byte for byte the reviewed file.
    let items = loader.list("policy");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].0, "default");
    let p = pb::Policy::decode_from_slice(&loader.get("policy", "default").unwrap()).unwrap();
    let cedar = include_str!("../../../tests/installations/local/policy/local.cedar");
    assert_eq!(p.cedar, cedar);
    assert_eq!(p.id, "default");

    // The registry lets policy read it, through Get and List, and nobody else; it lets no one write.
    for verb in ["get", "list"] {
        assert!(
            sluis_registry::store_allows("policy", "policy", verb),
            "{verb}"
        );
        assert!(
            !sluis_registry::store_allows("session", "policy", verb),
            "{verb}"
        );
    }
    assert!(!sluis_registry::store_allows("policy", "policy", "create"));
}

#[test]
fn the_local_policy_documents_are_the_files_the_policy_actor_is_tested_with() {
    // config/ holds the sources the harness signs; policy/ holds the files the policy tests run
    // on. They are one text, so the document cannot drift from the vectors.
    assert_eq!(
        source("policy"),
        include_str!("../../../tests/installations/local/policy/local.cedar")
    );
    assert_eq!(
        source("grant-vocabulary"),
        include_str!("../../../tests/installations/local/policy/vocabulary.yaml")
    );
}

#[test]
fn a_policy_payload_is_cedar_text_and_not_empty() {
    assert!(payload::decode(kind("Policy"), b"permit (principal, action, resource);\n").is_ok());
    assert_eq!(refused("Policy", " \n"), "has no policy");
    let bad = payload::decode(kind("Policy"), &[0xff, 0xfe]).expect_err("must be refused");
    assert_eq!(bad.0, "not UTF-8");
}

#[test]
fn the_local_catalogue_names_the_actions_policy_the_signer_and_exchange_emit() {
    let a = pb::AuditCatalogue::decode_from_slice(
        &payload::decode(kind("AuditCatalogue"), source("audit-catalogue").as_bytes())
            .unwrap()
            .remove(0)
            .1,
    )
    .unwrap();
    for action in [
        "policy.decide",
        "policy.start",
        "policy.reload",
        "policy.reload.refused",
        "signer.refused",
        "signer.sign",
        "signer.ring.add",
        "signer.ring.change",
        "signer.ring.drop",
        "exchange.token",
        "exchange.refused",
    ] {
        assert!(a.actions.iter().any(|x| x == action), "{action}");
    }
}
