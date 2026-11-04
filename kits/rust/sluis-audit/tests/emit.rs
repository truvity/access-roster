#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The emitter against a fake `TransportService` and a fake `KeyService`, each over a Unix socket
//! of the kit, with the kit's test identities.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use serde_json::Value;
use sluis_audit::{Action, Config, Emitter, Event, Status, Subject};
use sluis_kit::{Allow, Identities, ServerConfig, refusal, refusal_reason};
use sluis_proto::sluis::key::v2alpha1::{
    KeyService, KeyServiceExt, MacRequest, MacResponse, OpenGrantRequest, OpenGrantResponse,
    OpenRequest, OpenResponse, PublicKeyRequest, PublicKeyResponse, SealGrantRequest,
    SealGrantResponse, SealRequest, SealResponse, SignRequest, SignResponse,
};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};

/// 2026-11-04T00:00:00Z.
fn fixed_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(1_793_750_400_000)
}

fn mac_bytes() -> Vec<u8> {
    (0..48).collect()
}

#[derive(Default)]
struct Spool {
    reqs: Mutex<Vec<EmitRequest>>,
    fail: Mutex<Option<ErrorCode>>,
}

impl TransportService for Spool {
    async fn emit(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        self.reqs.lock().unwrap().push(request.to_owned_message());
        if let Some(code) = *self.fail.lock().unwrap() {
            return Err(refusal(code, "engine", ""));
        }
        Response::ok(EmitResponse::default())
    }

    async fn receive(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<ServiceStream<ReceiveResponse>> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }

    async fn ack(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
}

#[derive(Default)]
struct Keys {
    reqs: Mutex<Vec<MacRequest>>,
    fail: Mutex<bool>,
}

fn unsupported<T>() -> ServiceResult<T> {
    Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
}

impl KeyService for Keys {
    async fn mac(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, MacRequest>,
    ) -> ServiceResult<MacResponse> {
        self.reqs.lock().unwrap().push(request.to_owned_message());
        if *self.fail.lock().unwrap() {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        Response::ok(MacResponse {
            mac: mac_bytes(),
            ..MacResponse::default()
        })
    }

    async fn seal(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SealRequest>,
    ) -> ServiceResult<SealResponse> {
        unsupported()
    }
    async fn open(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, OpenRequest>,
    ) -> ServiceResult<OpenResponse> {
        unsupported()
    }
    async fn seal_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SealGrantRequest>,
    ) -> ServiceResult<SealGrantResponse> {
        unsupported()
    }
    async fn open_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, OpenGrantRequest>,
    ) -> ServiceResult<OpenGrantResponse> {
        unsupported()
    }
    async fn sign(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SignRequest>,
    ) -> ServiceResult<SignResponse> {
        unsupported()
    }
    async fn public_key(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, PublicKeyRequest>,
    ) -> ServiceResult<PublicKeyResponse> {
        unsupported()
    }
}

struct Up {
    spool: Arc<Spool>,
    keys: Arc<Keys>,
    emit_socket: PathBuf,
    key_socket: PathBuf,
    _stop: Vec<tokio::sync::oneshot::Sender<()>>,
}

async fn serve(
    dir: &Path,
    name: &str,
    actor: &'static str,
    caller: &'static str,
    router: Router,
    stop: &mut Vec<tokio::sync::oneshot::Sender<()>>,
) -> PathBuf {
    let socket = dir.join(name);
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |u| (u == me).then_some((caller, 0)));
    let cfg = ServerConfig {
        actor,
        boundary: "dev".into(),
        socket: socket.clone(),
        mode: 0o660,
        allow: Allow::Exact(caller),
        default_deadline: Duration::from_secs(5),
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    stop.push(tx);
    tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        ids,
    ));
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    socket
}

async fn up(dir: &Path) -> Up {
    let spool = Arc::new(Spool::default());
    let keys = Arc::new(Keys::default());
    let mut stop = Vec::new();
    // The test process is the emitter "key" for the spool, and "store" for key@.
    let emit_socket = serve(
        dir,
        "emit.sock",
        "driver-writer-spool",
        "key",
        Arc::clone(&spool).register(Router::new()),
        &mut stop,
    )
    .await;
    let key_socket = serve(
        dir,
        "key.sock",
        "key",
        "store",
        Arc::clone(&keys).register(Router::new()),
        &mut stop,
    )
    .await;
    Up {
        spool,
        keys,
        emit_socket,
        key_socket,
        _stop: stop,
    }
}

fn emitter(u: &Up, with_keys: bool) -> Emitter {
    Emitter::new(Config {
        actor: "key".into(),
        boundary: "dev".into(),
        release: "0.0.0-test".into(),
        transport_socket: u.emit_socket.clone(),
        key_socket: with_keys.then(|| u.key_socket.clone()),
        now: Some(fixed_now),
    })
    .unwrap()
}

fn sign_event() -> Event {
    Event {
        action: Action {
            name: "key.sign".into(),
            class_uid: 6003,
            activity_id: 99,
            activity_name: "Sign".into(),
        },
        status: Status::Success,
        ..Event::default()
    }
}

#[tokio::test]
async fn emit_and_emit_blocking_set_the_flag_and_send_the_record_once() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);

    e.emit(sign_event()).await.unwrap();
    let mut ev = sign_event();
    ev.correlation_id = Some("req-9".into());
    e.emit_blocking(ev).await.unwrap();

    let reqs = u.spool.reqs.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert!(!reqs[0].blocking);
    assert!(reqs[1].blocking);
    for r in reqs.iter() {
        let m = &*r.message;
        let rec: Value = serde_json::from_slice(&m.record).unwrap();
        assert_eq!(rec["metadata"]["uid"], m.uid.as_str());
        assert!(m.usage.is_empty(), "a usage part was sent");
    }
    let second: Value = serde_json::from_slice(&reqs[1].message.record).unwrap();
    assert_eq!(second["metadata"]["correlation_uid"], "req-9");
    assert_ne!(reqs[0].message.uid, reqs[1].message.uid);
}

#[tokio::test]
async fn a_blocking_emit_returns_the_transports_error_and_does_not_retry() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    *u.spool.fail.lock().unwrap() = Some(ErrorCode::Unavailable);
    let e = emitter(&u, false);

    let err = e.emit_blocking(sign_event()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Unavailable);
    assert_eq!(refusal_reason(&err).as_deref(), Some("engine"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reqs = u.spool.reqs.lock().unwrap();
    assert_eq!(reqs.len(), 1, "the transport saw a retry");
    assert!(reqs[0].blocking);
}

#[tokio::test]
async fn the_pseudonym_comes_from_the_tenants_pseudonym_key() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, true);
    let mut ev = sign_event();
    ev.tenant = "acme".into();
    ev.subject = Some(Subject {
        tenant: "acme".into(),
        kind: "person".into(),
        value: "person-123".into(),
    });

    let (rec, uid) = e.record(ev).await.unwrap();
    {
        let reqs = u.keys.reqs.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let m = &reqs[0];
        assert_eq!(
            (
                m.purpose.as_str(),
                m.tenant.as_str(),
                m.label.as_str(),
                m.epoch.as_str()
            ),
            ("pseudonym", "acme", "sluis-pseudonym-v1", "202611")
        );
        // boundary, tenant, kind, identifier, each with a 4-byte big-endian length in front
        let mut want = Vec::new();
        for part in ["dev", "acme", "person", "person-123"] {
            want.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
            want.extend_from_slice(part.as_bytes());
        }
        assert_eq!(m.input, want);
    }
    let v: Value = serde_json::from_slice(&rec).unwrap();
    assert_eq!(v["user"]["uid"], "p1.202611.AAECAwQFBgcICQoLDA0ODw");
    assert_eq!(v["metadata"]["uid"], uid.as_str());
    assert_eq!(v["time"], 1_793_750_400_000_i64);
    assert!(!String::from_utf8(rec).unwrap().contains("person-123"));
}

#[tokio::test]
async fn a_subject_without_a_key_socket_is_an_error_and_nothing_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    let mut ev = sign_event();
    ev.subject = Some(Subject {
        tenant: "acme".into(),
        kind: "person".into(),
        value: "person-123".into(),
    });

    assert!(e.record(ev.clone()).await.is_err());
    let err = e.emit(ev.clone()).await.unwrap_err();
    assert_eq!(refusal_reason(&err).as_deref(), Some("keys"));
    assert!(e.emit_blocking(ev).await.is_err());
    assert!(u.spool.reqs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_key_failure_stops_the_emit() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    *u.keys.fail.lock().unwrap() = true;
    let e = emitter(&u, true);
    let mut ev = sign_event();
    ev.subject = Some(Subject {
        tenant: "acme".into(),
        kind: "person".into(),
        value: "p".into(),
    });

    let err = e.emit(ev).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Unavailable);
    assert!(
        u.spool.reqs.lock().unwrap().is_empty(),
        "sent without a pseudonym"
    );
}

#[tokio::test]
async fn new_refuses_an_incomplete_config() {
    let ok = Config {
        actor: "key".into(),
        boundary: "dev".into(),
        release: "r".into(),
        transport_socket: PathBuf::from("/nonexistent/emit.sock"),
        key_socket: None,
        now: None,
    };
    Emitter::new(ok.clone()).unwrap();
    for bad in [
        Config {
            actor: String::new(),
            ..ok.clone()
        },
        Config {
            boundary: String::new(),
            ..ok.clone()
        },
        Config {
            release: String::new(),
            ..ok.clone()
        },
    ] {
        assert!(Emitter::new(bad).is_err());
    }
}

#[tokio::test]
async fn the_correlation_id_of_the_call_being_served_is_taken_when_none_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);

    let (inside, _) = sluis_kit::correlation::scope(Some("req-amb".into()), e.record(sign_event()))
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&inside).unwrap();
    assert_eq!(v["metadata"]["correlation_uid"], "req-amb");

    // An id on the event wins over the ambient one.
    let mut ev = sign_event();
    ev.correlation_id = Some("req-own".into());
    let (own, _) = sluis_kit::correlation::scope(Some("req-amb".into()), e.record(ev))
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&own).unwrap();
    assert_eq!(v["metadata"]["correlation_uid"], "req-own");

    // Outside a handler there is none.
    let (outside, _) = e.record(sign_event()).await.unwrap();
    let v: Value = serde_json::from_slice(&outside).unwrap();
    assert!(v["metadata"].get("correlation_uid").is_none());
}
