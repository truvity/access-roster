#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `store check --validate DIR`, the helper `sluis config check` runs (ADR 0012): the local set passes, each class
//! of rule refuses with its kind and rule, a value of a document is never printed, and the offline check gives the
//! verdict the loader gives on the same documents, because both run the same code.

mod config_support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use config_support::{LOCAL, Pipeline, bootstrap, put, serve_driver, up, write_local};
use serde_json::Value;
use sluis_kit::dial;
use store::config::Loader;
use store::config::offline;

const EXAMPLE: &str = include_str!("../../../tests/installations/local/bootstrap.yaml");

fn source(segment: &str) -> &'static str {
    LOCAL.iter().find(|(s, _)| *s == segment).unwrap().1
}

/// The example bootstrap file of the local installation, pinning this test's publisher key, written with `mode`.
fn write_bootstrap(dir: &Path, p: &Pipeline, mode: u32) -> String {
    let pk = p.publisher(&[]);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        STANDARD.encode(&pk.spki_der)
    );
    let pin = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, &pk.spki_der);
    let mut text = EXAMPLE[..EXAMPLE.find("publishers:").unwrap()].to_owned();
    text.push_str(&format!(
        "publishers:\n  - kid: {}\n    public_key: |\n{}\n    spki_sha384: \"{}\"\n",
        p.kid,
        pem.lines()
            .map(|l| format!("      {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
        store::config::document::hex(pin.as_ref()),
    ));
    let file = dir.join("dev.yaml");
    std::fs::write(&file, text).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
    file.to_str().unwrap().to_owned()
}

fn validate(bootstrap: &str, docs: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_store"))
        .args([
            "check",
            "--output",
            "json",
            "--bootstrap",
            bootstrap,
            "--validate",
        ])
        .arg(docs)
        .output()
        .unwrap()
}

/// The exit code, the checks of the JSON object, and everything printed.
fn run(bootstrap: &str, docs: &Path) -> (Option<i32>, Vec<Value>, String) {
    let o = validate(bootstrap, docs);
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    let all = format!("{stdout}{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {all}"));
    (
        o.status.code(),
        v["checks"].as_array().unwrap().clone(),
        all,
    )
}

fn failures(checks: &[Value]) -> Vec<String> {
    checks
        .iter()
        .filter(|c| c["result"] == "fail")
        .map(|c| {
            format!(
                "{} {}: {}",
                c["name"].as_str().unwrap(),
                c["path"].as_str().unwrap(),
                c["rule"].as_str().unwrap()
            )
        })
        .collect()
}

/// What a case does to the local set before it is checked.
type Break = Box<dyn Fn(&Env)>;

struct Env {
    run: tempfile::TempDir,
    docs: tempfile::TempDir,
    p: Pipeline,
}

fn env() -> Env {
    let e = Env {
        run: tempfile::tempdir().unwrap(),
        docs: tempfile::tempdir().unwrap(),
        p: Pipeline::new("publisher-1"),
    };
    write_local(e.docs.path(), &e.p, 1);
    e
}

impl Env {
    fn sign(&self, segment: &str, text: &str) {
        put(
            self.docs.path(),
            segment,
            &self.p.sign(segment, text.as_bytes(), 2),
        );
    }
    fn bootstrap(&self) -> String {
        write_bootstrap(self.run.path(), &self.p, 0o600)
    }
}

/// verifies: REQ-DATA-090
#[test]
fn the_local_set_passes_every_check_and_exits_0() {
    let e = env();
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(0), "{all}");
    assert!(failures(&checks).is_empty(), "{all}");
    // The bootstrap file, the Boundary document, the nine kinds it declares, and the set: a sweep over nothing
    // would prove nothing.
    assert_eq!(checks.len(), 12, "{all}");
    assert!(checks.iter().all(|c| c["result"] == "ok"), "{all}");
    assert_eq!(checks.last().unwrap()["name"], "set");
}

#[test]
fn a_bootstrap_file_that_others_can_write_is_refused_and_nothing_else_is_run() {
    let e = env();
    let file = write_bootstrap(e.run.path(), &e.p, 0o620);
    let (code, checks, all) = run(&file, e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(checks[0]["name"], "bootstrap");
    assert_eq!(checks[0]["result"], "fail", "{all}");
    assert!(
        checks[1..].iter().all(|c| c["result"] == "not-run"),
        "{all}"
    );
}

#[test]
fn a_bootstrap_file_that_is_a_fifo_is_refused_at_once() {
    let e = env();
    let fifo = e.run.path().join("dev.yaml");
    let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    let (tx, rx) = std::sync::mpsc::channel();
    let (file, docs) = (fifo.to_str().unwrap().to_owned(), e.docs.path().to_owned());
    std::thread::spawn(move || tx.send(run(&file, &docs)).unwrap());
    // A FIFO with no writer would block an open without O_NONBLOCK for ever.
    let (code, checks, all) = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the check hung on a FIFO");
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(checks[0]["result"], "fail", "{all}");
    assert!(
        checks[0]["rule"]
            .as_str()
            .unwrap()
            .contains("not a regular file"),
        "{all}"
    );
}

#[test]
fn each_class_of_rule_refuses_with_its_kind_and_rule() {
    let cases: Vec<(&str, Break, &str)> = vec![
        (
            "structure (step 1)",
            Box::new(|e| put(e.docs.path(), "key-plan", b"not json")),
            "document KeyPlan: step 1",
        ),
        (
            "a key the bootstrap file does not pin (step 4)",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "audit-log",
                    &Pipeline::new("publisher-1").sign(
                        "audit-log",
                        source("audit-log").as_bytes(),
                        1,
                    ),
                );
            }),
            "document AuditLog: step 4: a signature does not verify",
        ),
        (
            "a missing declared document",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("upstream.jws")).unwrap()),
            "document Upstream: the source has no document of the kind",
        ),
        (
            "a payload rule (step 6)",
            Box::new(|e| {
                e.sign(
                    "token-lifetime",
                    &source("token-lifetime").replace("access_token: 10m", "access_token: 2h"),
                );
            }),
            "document TokenLifetime: step 6: default.access_token: above the built-in cap of one hour",
        ),
        (
            "a rule of the set",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary")
                        .replace("environment: development", "environment: production"),
                );
            }),
            "set : Upstream: issuer: must be https outside development",
        ),
    ];
    for (name, break_it, want) in cases {
        let e = env();
        break_it(&e);
        let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
        assert_eq!(code, Some(3), "{name}: {all}");
        let f = failures(&checks);
        assert!(
            f.iter().any(|l| l.starts_with(want)),
            "{name}: want {want}, got {f:?}"
        );
    }
}

/// verifies: REQ-TOKEN-038
#[test]
fn a_token_lifetime_or_a_ttl_cap_above_one_hour_is_refused_with_its_path() {
    let e = env();
    assert!(source("token-lifetime").contains("access_token: 10m"));
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("access_token: 10m", "access_token: 2h"),
    );
    let client = source("installation-client");
    assert!(!client.contains("ttl_cap"));
    e.sign(
        "installation-client",
        &client.replacen("  kind: ", "  ttl_cap: 2h\n  kind: ", 1),
    );
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    let f = failures(&checks).join("\n");
    assert!(
        f.contains("default.access_token: above the built-in cap of one hour"),
        "{f}"
    );
    assert!(
        f.contains(".ttl_cap: above the built-in cap of one hour"),
        "{f}"
    );

    // One hour itself is the cap, not above it.
    let e = env();
    e.sign(
        "installation-client",
        &client.replacen("  kind: ", "  ttl_cap: 1h\n  kind: ", 1),
    );
    let (code, _, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(0), "{all}");
}

/// verifies: REQ-KEYS-039
#[test]
fn a_key_cache_ttl_at_the_maximum_is_accepted_and_one_second_over_is_refused() {
    let plan = source("key-plan");
    assert!(plan.contains("cache_ttl: 15m"));
    for (ttl, ok) in [("3600s", true), ("3601s", false)] {
        let e = env();
        e.sign(
            "key-plan",
            &plan.replace("cache_ttl: 15m", &format!("cache_ttl: {ttl}")),
        );
        let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
        if ok {
            assert_eq!(code, Some(0), "{ttl}: {all}");
        } else {
            assert_eq!(code, Some(3), "{ttl}: {all}");
            assert_eq!(
                failures(&checks),
                [
                    "document KeyPlan: step 6: default.cache_ttl: above the built-in maximum of one hour"
                ],
                "{ttl}"
            );
        }
    }
}

/// verifies: REQ-POLICY-013
#[test]
fn a_set_that_declares_no_grant_vocabulary_is_refused() {
    let e = env();
    let b = source("boundary");
    assert!(b.contains("    - GrantVocabulary\n"));
    e.sign("boundary", &b.replace("    - GrantVocabulary\n", ""));
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(
        failures(&checks),
        ["set : Boundary: declared_kinds: must declare GrantVocabulary"]
    );
}

#[test]
fn no_value_of_a_document_is_printed() {
    // A credential name that breaks the rule, an unknown key and a wrongly typed field each hold a marker: the
    // checks name the paths, never the text.
    let marker = "zq-marker-7f3a";
    let e = env();
    let up = source("upstream");
    assert!(up.contains("secret: upstream-workforce"));
    e.sign(
        "upstream",
        &up.replace(
            "secret: upstream-workforce",
            &format!("secret: \"{marker}/x\""),
        ),
    );
    e.sign(
        "audit-log",
        &format!("{}  {marker}: {marker}\n", source("audit-log")),
    );
    e.sign(
        "token-lifetime",
        &source("token-lifetime")
            .replace("access_token: 10m", &format!("access_token: [{marker}]")),
    );
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(failures(&checks).len(), 3, "{all}");
    assert!(!all.contains(marker), "a value was printed: {all}");
    // The same in text output.
    let o = Command::new(env!("CARGO_BIN_EXE_store"))
        .args(["check", "--bootstrap", &e.bootstrap(), "--validate"])
        .arg(e.docs.path())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(o.status.code(), Some(3), "{text}");
    assert!(
        text.contains("fail document Upstream: step 6: workforce.secret: is not a credential name"),
        "{text}"
    );
    assert!(!text.contains(marker), "a value was printed: {text}");
}

/// The verdict of the loader on a set: None when it loads, else the kind and the rule of the refusal.
async fn loader_verdict(e: &Env) -> Option<String> {
    let sock = e.run.path().join("config-source.sock");
    let _ = std::fs::remove_file(&sock);
    let _stop = serve_driver(&sock, e.docs.path());
    up(&sock).await;
    match Loader::start(
        &dial(&sock),
        &bootstrap(vec![e.p.publisher(&[])]),
        Duration::from_secs(5),
    )
    .await
    {
        Ok(_) => None,
        Err(err) => Some(err.to_string()),
    }
}

/// The verdict of the offline check: None when every check passes, else the first failure as the loader words it.
fn offline_verdict(e: &Env) -> Option<String> {
    let checks = offline::check_dir(e.docs.path(), &bootstrap(vec![e.p.publisher(&[])]));
    let first = checks.iter().find(|c| c.result == "fail")?;
    Some(if first.path.is_empty() {
        first.rule.clone()
    } else {
        format!("{}: {}", first.path, first.rule)
    })
}

/// verifies: REQ-DATA-090
#[tokio::test(flavor = "multi_thread")]
async fn the_offline_check_and_the_loader_give_the_same_verdict_on_every_set() {
    let cases: Vec<(&str, Break)> = vec![
        ("the local set", Box::new(|_| {})),
        (
            "structure",
            Box::new(|e| put(e.docs.path(), "key-plan", b"{}")),
        ),
        (
            "an unpinned key",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "policy",
                    &Pipeline::new("publisher-1").sign("policy", source("policy").as_bytes(), 1),
                );
            }),
        ),
        (
            "a document under the wrong kind",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "audit-log",
                    &e.p.sign("audit-catalogue", source("audit-catalogue").as_bytes(), 1),
                );
            }),
        ),
        (
            "a missing document",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("exchange-trust.jws")).unwrap()),
        ),
        (
            "a link that leaves the directory",
            Box::new(|e| {
                let outside = e.run.path().join("outside");
                std::fs::create_dir_all(&outside).unwrap();
                put(
                    &outside,
                    "key-plan",
                    &e.p.sign("key-plan", source("key-plan").as_bytes(), 1),
                );
                std::fs::remove_file(e.docs.path().join("key-plan.jws")).unwrap();
                std::os::unix::fs::symlink(
                    outside.join("key-plan.jws"),
                    e.docs.path().join("key-plan.jws"),
                )
                .unwrap();
            }),
        ),
        (
            "a link that stays in the directory",
            Box::new(|e| {
                std::fs::create_dir_all(e.docs.path().join("..data")).unwrap();
                put(
                    &e.docs.path().join("..data"),
                    "key-plan",
                    &e.p.sign("key-plan", source("key-plan").as_bytes(), 1),
                );
                std::fs::remove_file(e.docs.path().join("key-plan.jws")).unwrap();
                std::os::unix::fs::symlink(
                    "..data/key-plan.jws",
                    e.docs.path().join("key-plan.jws"),
                )
                .unwrap();
            }),
        ),
        (
            "a document that is not a regular file",
            Box::new(|e| {
                std::fs::remove_file(e.docs.path().join("audit-log.jws")).unwrap();
                std::fs::create_dir(e.docs.path().join("audit-log.jws")).unwrap();
            }),
        ),
        (
            "a missing boundary",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("boundary.jws")).unwrap()),
        ),
        (
            "a payload type",
            Box::new(|e| e.sign("token-lifetime", "default:\n  id_token: ten minutes\n")),
        ),
        (
            "a ttl_cap above the cap",
            Box::new(|e| {
                e.sign(
                    "installation-client",
                    &source("installation-client").replacen(
                        "  kind: ",
                        "  ttl_cap: 61m\n  kind: ",
                        1,
                    ),
                );
            }),
        ),
        (
            "a cache above the maximum",
            Box::new(|e| {
                e.sign(
                    "key-plan",
                    &source("key-plan").replace("cache_ttl: 15m", "cache_ttl: 2h"),
                )
            }),
        ),
        (
            "another boundary",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("name: dev", "name: other"),
                )
            }),
        ),
        (
            "a kind this build cannot read",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("- KeyPlan", "- RegulatedPartyPolicy"),
                )
            }),
        ),
        (
            "no grant vocabulary",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("    - GrantVocabulary\n", ""),
                )
            }),
        ),
        (
            "production with plain http",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary")
                        .replace("environment: development", "environment: production"),
                );
            }),
        ),
        (
            "one credential name for two kinds",
            Box::new(|e| {
                e.sign(
                    "upstream",
                    &source("upstream")
                        .replace("secret: upstream-workforce", "secret: client-example-app"),
                );
            }),
        ),
    ];
    // The one place where the words differ: a document the file driver refuses. The loader gets that refusal over the
    // wire as a source that did not answer, without the kind it asked for or the driver's reason; the check reads the
    // directory with the driver's own Dir::read, so it names both. The loader's words are still all there, in place.
    let driver_refusals = [
        ("a link that leaves the directory", "KeyPlan"),
        ("a document that is not a regular file", "AuditLog"),
    ];
    let mut refused = 0;
    for (name, break_it) in cases {
        let e = env();
        break_it(&e);
        let (live, offline) = (loader_verdict(&e).await, offline_verdict(&e));
        let want = match driver_refusals.iter().find(|(n, _)| *n == name) {
            Some((_, kind)) => {
                assert_eq!(
                    live.as_deref(),
                    Some("the config source did not answer"),
                    "{name}"
                );
                live.as_ref()
                    .map(|l| format!("{kind}: {l}: the file driver refuses the document (bound)"))
            }
            None => live.clone(),
        };
        assert_eq!(offline, want, "{name}: the loader says {live:?}");
        refused += usize::from(live.is_some());
    }
    assert_eq!(
        refused, 15,
        "every case but the local set and the link inside is refused"
    );
}
