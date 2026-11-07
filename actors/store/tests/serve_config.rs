#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `store serve` and the signed config: a cold start that refuses on a missing declared document
//! exits non-zero with the reason and serves nothing, and one with a good set serves.

mod config_support;

use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use config_support::{LOCAL as DOCUMENTS, Pipeline, put, serve_driver, up, write_local};
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use sluis_kit::{Allow, Identities, ServerConfig, refusal};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt as _,
};

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
        &Pipeline::new("publisher-1").sign("token-lifetime", b"default: {}\n", 1),
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

/// An audit transport that keeps what it is given.
#[derive(Default)]
struct Spool {
    reqs: Mutex<Vec<EmitRequest>>,
}

impl TransportService for Spool {
    async fn emit(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        self.reqs.lock().unwrap().push(request.to_owned_message());
        Response::ok(EmitResponse::default())
    }
    async fn receive(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<ServiceStream<ReceiveResponse>> {
        Err(refusal(
            connectrpc::error::ErrorCode::Unimplemented,
            "unsupported",
            "",
        ))
    }
    async fn ack(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        Err(refusal(
            connectrpc::error::ErrorCode::Unimplemented,
            "unsupported",
            "",
        ))
    }
}

/// The SHA-384 of a payload in lower-case hex, with the hashing of the test and not the loader's.
fn sha384sum(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, bytes)
        .as_ref()
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        })
}

/// verifies: REQ-DATA-085
/// The start of the real `store serve` is an audit fact, as the audit transport receives it, that names each of the ten
/// documents with its kind, its seq (a different one for each, so that a swap shows) and the SHA-384 of its payload, which
/// is `sha384sum` of the reviewed file.
#[tokio::test(flavor = "multi_thread")]
async fn the_start_fact_names_each_document_with_its_kind_seq_and_the_sha384_of_its_file() {
    let (run, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = Pipeline::new("publisher-1");
    let mut want = serde_json::Map::new();
    for (i, (segment, text)) in DOCUMENTS.iter().enumerate() {
        let seq = 3 + i as u64;
        put(docs.path(), segment, &p.sign(segment, text.as_bytes(), seq));
        let kind = sluis_registry::kind_by_segment(segment).unwrap().name;
        want.insert(
            kind.to_owned(),
            serde_json::json!({ "seq": seq, "sha384": sha384sum(text.as_bytes()) }),
        );
    }
    assert_eq!(want.len(), 10);

    let (file, mut listeners) = bootstrap(run.path(), &p);
    // The audit transport of the run is the recording one, in place of the listener that never answers.
    drop(listeners.pop());
    let emit = run.path().join("emit.sock");
    std::fs::remove_file(&emit).unwrap();
    let spool = Arc::new(Spool::default());
    let me = rustix::process::geteuid().as_raw();
    tokio::spawn(sluis_kit::serve_with(
        ServerConfig {
            actor: "transport",
            boundary: "dev".into(),
            socket: emit.clone(),
            mode: 0o660,
            socket_gid: None,
            allow: Allow::Exact("store"),
            default_deadline: Duration::from_secs(5),
        },
        Arc::clone(&spool).register(Router::new()),
        std::future::pending(),
        Identities::with(0, move |u| (u == me).then_some(("store", 0))),
    ));
    up(&emit).await;
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

    let reqs = spool.reqs.lock().unwrap();
    let starts: Vec<serde_json::Value> = reqs
        .iter()
        .map(|r| serde_json::from_slice::<serde_json::Value>(&r.message.record).unwrap())
        .filter(|r| r["metadata"]["event_code"] == "store.start")
        .collect();
    assert_eq!(starts.len(), 1, "one start fact: {err}");
    // One fact holds all ten, as an object with a member for each kind: a record string holds 1024 bytes, and the ten
    // together are longer (the first form of the field, one joined string, was refused by the emitter and lost).
    let documents = starts[0]["unmapped"]["sluis"]["documents"].clone();
    assert_eq!(documents, serde_json::Value::Object(want));
    assert!(
        documents.to_string().len() > 1024,
        "the set no longer needs more than a string: the test checks nothing"
    );
    assert!(!err.contains("audit emit failed"), "{err}");
}

/// verifies: REQ-DATA-013
/// `store serve` takes the boundary of the service from its own bootstrap file: the boundary `stage` there, and a signed
/// Boundary document that says `stage`, and the start fact the audit transport receives names `stage`. The boundary is
/// no constant of the build and no field of a request; a service built with another boundary would name that one.
#[tokio::test(flavor = "multi_thread")]
async fn serve_builds_the_service_with_the_boundary_of_its_bootstrap_file() {
    let (run, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = Pipeline::new("publisher-1");
    for (segment, text) in DOCUMENTS {
        let text = if segment == "boundary" {
            text.replace("name: dev", "name: stage")
        } else {
            text.to_owned()
        };
        put(docs.path(), segment, &p.sign(segment, text.as_bytes(), 1));
    }
    let (file, mut listeners) = bootstrap(run.path(), &p);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("\nboundary: dev\n"));
    std::fs::write(
        &file,
        text.replace("\nboundary: dev\n", "\nboundary: stage\n"),
    )
    .unwrap();
    drop(listeners.pop());
    let emit = run.path().join("emit.sock");
    std::fs::remove_file(&emit).unwrap();
    let spool = Arc::new(Spool::default());
    let me = rustix::process::geteuid().as_raw();
    tokio::spawn(sluis_kit::serve_with(
        ServerConfig {
            actor: "transport",
            boundary: "stage".into(),
            socket: emit.clone(),
            mode: 0o660,
            socket_gid: None,
            allow: Allow::Exact("store"),
            default_deadline: Duration::from_secs(5),
        },
        Arc::clone(&spool).register(Router::new()),
        std::future::pending(),
        Identities::with(0, move |u| (u == me).then_some(("store", 0))),
    ));
    up(&emit).await;
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
    let reqs = spool.reqs.lock().unwrap();
    let start = reqs
        .iter()
        .map(|r| serde_json::from_slice::<serde_json::Value>(&r.message.record).unwrap())
        .find(|r| r["metadata"]["event_code"] == "store.start")
        .unwrap_or_else(|| panic!("no start fact: {err}"));
    assert_eq!(start["unmapped"]["sluis"]["boundary"], "stage", "{start}");
}
