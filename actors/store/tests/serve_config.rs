#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `store serve` and the signed config: a cold start that refuses on a missing declared document
//! exits non-zero with the reason and serves nothing, and one with a good set serves.

mod config_support;

use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use config_support::{Pipeline, serve_driver, up, write_local};

const LOCAL: &str = include_str!("../../../tests/installations/local/bootstrap.yaml");

/// The example bootstrap file with this test's sockets and this test's publisher key.
fn bootstrap(dir: &Path, p: &Pipeline) -> (String, Vec<UnixListener>) {
    bootstrap_with(dir, p, true)
}

/// The same, with key@'s socket listening only when `with_key`.
fn bootstrap_with(dir: &Path, p: &Pipeline, with_key: bool) -> (String, Vec<UnixListener>) {
    let mut text = LOCAL.replace("start_timeout: 30s", "start_timeout: 3s");
    let mut listeners = Vec::new();
    for name in ["config-source", "secret-source", "durable", "temp"] {
        let sock = dir.join(format!("{name}.sock"));
        text = text.replace(
            &format!("/run/sluis/store/dev/{name}.sock"),
            sock.to_str().unwrap(),
        );
        // The driver of the config source is served by the test; the others only have to answer.
        if name != "config-source" {
            listeners.push(UnixListener::bind(&sock).unwrap());
        }
    }
    // The publisher key of this test, in place of the example's.
    let pk = p.publisher(&[]);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        STANDARD.encode(&pk.spki_der)
    );
    let pin = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, &pk.spki_der);
    let start = text.find("publishers:").unwrap();
    text.truncate(start);
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
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    for name in ["key", "emit"] {
        if name == "key" && !with_key {
            continue;
        }
        listeners.push(UnixListener::bind(dir.join(format!("{name}.sock"))).unwrap());
    }
    (file.to_str().unwrap().to_owned(), listeners)
}

fn serve(dir: &Path, file: &str) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_store"))
        .args(["serve", "--bootstrap", file, "--socket"])
        .arg(dir.join("store.sock"))
        .arg("--key-socket")
        .arg(dir.join("key.sock"))
        .arg("--transport-socket")
        .arg(dir.join("emit.sock"))
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cold_start_with_a_missing_declared_document_exits_nonzero_and_serves_nothing() {
    let (run, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = Pipeline::new("publisher-1");
    write_local(docs.path(), &p, 1);
    std::fs::remove_file(docs.path().join("audit-log.jws")).unwrap();
    let (file, _listeners) = bootstrap(run.path(), &p);
    let sock = run.path().join("config-source.sock");
    let _stop = serve_driver(&sock, docs.path());
    up(&sock).await;

    let child = serve(run.path(), &file);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("config: AuditLog: the source has no document of the kind"),
        "{err}"
    );
    assert!(
        !run.path().join("store.sock").exists(),
        "nothing was served"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cold_start_with_a_wrongly_signed_document_exits_nonzero_before_it_is_parsed() {
    let (run, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = Pipeline::new("publisher-1");
    write_local(docs.path(), &p, 1);
    config_support::put(
        docs.path(),
        "token-lifetime",
        &Pipeline::new("publisher-1").sign(b"default: {}\n", 1),
    );
    let (file, _listeners) = bootstrap(run.path(), &p);
    let sock = run.path().join("config-source.sock");
    let _stop = serve_driver(&sock, docs.path());
    up(&sock).await;

    let child = serve(run.path(), &file);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("TokenLifetime: step 4"), "{err}");
    assert!(!run.path().join("store.sock").exists());
}

/// A good set loads, the start is announced with the documents, and `serve` goes on to the kit's
/// own start. Under a test the kit refuses the uid of the test runner (it is not a uid of the
/// registry), which is after the config: the proof that the set loaded is that this is the failure,
/// and not a `config:` one.
#[tokio::test(flavor = "multi_thread")]
async fn a_cold_start_with_a_good_set_gets_past_the_config() {
    let (run, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = Pipeline::new("publisher-1");
    write_local(docs.path(), &p, 1);
    let (file, _listeners) = bootstrap(run.path(), &p);
    let sock = run.path().join("config-source.sock");
    let _stop = serve_driver(&sock, docs.path());
    up(&sock).await;

    let child = serve(run.path(), &file);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("is not a uid of the registry"), "{err}");
    assert!(!err.contains("store serve: config:"), "{err}");
    // The start was announced (the audit transport here only listens, so the emit times out).
    assert!(err.contains("store.start"), "{err}");
}

/// key@'s `Init` reads store@, so key@ is up only after store@ serves. A store@ that waited for
/// key@'s socket would deadlock the two (WP-17). With no key@ at all, `serve` goes past the wait for
/// the drivers and loads the config, as with one: it warns, it does not wait, and it does not fail.
#[tokio::test(flavor = "multi_thread")]
async fn a_cold_start_without_key_does_not_wait_for_it() {
    let (run, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = Pipeline::new("publisher-1");
    write_local(docs.path(), &p, 1);
    let (file, _listeners) = bootstrap_with(run.path(), &p, false);
    assert!(!run.path().join("key.sock").exists());
    let sock = run.path().join("config-source.sock");
    let _stop = serve_driver(&sock, docs.path());
    up(&sock).await;

    let started = std::time::Instant::now();
    let child = serve(run.path(), &file);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    // start_timeout is 3s in this test: a wait for key@ would have ended with "not started within".
    assert!(!err.contains("not started within"), "{err}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "{err}"
    );
    assert!(
        err.contains("key.sock"),
        "the warning names key@'s socket: {err}"
    );
    assert!(err.contains("is not a uid of the registry"), "{err}");
    assert!(!err.contains("store serve: config:"), "{err}");
    assert!(err.contains("store.start"), "{err}");
}
