#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The emitter against a fake `TransportService` and a fake `KeyService`, each over a Unix socket
//! of the kit, with the kit's test identities.

use std::ops::Not as _;
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
    /// How long the spool takes to answer; a test sets it to be slower than a caller's timeout.
    delay: Mutex<Duration>,
}

impl TransportService for Spool {
    async fn emit(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        self.reqs.lock().unwrap().push(request.to_owned_message());
        let delay = *self.delay.lock().unwrap();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
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
    /// When set, the answer depends on this key and on the input of the request, as a keyed Mac does;
    /// when not, it is `mac_bytes()` whatever the input.
    key: Mutex<Option<u8>>,
}

/// A stand-in for the Mac of key@ (the real one, HMAC-SHA384, is proved in `keyd`): 48 bytes that
/// change with the key and with every byte of the input.
fn keyed_mac(key: u8, input: &[u8]) -> Vec<u8> {
    (0..48_usize)
        .map(|i| {
            input
                .iter()
                .enumerate()
                .fold(key ^ (i as u8), |acc, (j, b)| {
                    acc.rotate_left(1) ^ b ^ (j as u8).wrapping_mul(31)
                })
        })
        .collect()
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
        let mac = match *self.key.lock().unwrap() {
            Some(k) => keyed_mac(k, request.input),
            None => mac_bytes(),
        };
        Response::ok(MacResponse {
            mac,
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
        socket_gid: None,
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

/// A person, a workload and a client, as the subject of an event, each under a pseudonym that key@
/// computed with a key, and under nothing else: the raw identifier is in neither the record nor the
/// message, and the pseudonym changes with the key, the tenant, the kind and the identifier.
///
/// verifies: REQ-AUDIT-023
#[tokio::test]
async fn an_external_actor_is_recorded_under_a_keyed_pseudonym() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, true);
    let subject = |tenant: &str, kind: &str, value: &str| Subject {
        tenant: tenant.into(),
        kind: kind.into(),
        value: value.into(),
    };
    // The pseudonym of the one record the spool received last.
    let pseudonym_of = |u: &Up| -> (String, Vec<u8>) {
        let reqs = u.spool.reqs.lock().unwrap();
        let m = &*reqs.last().unwrap().message;
        let rec: Value = serde_json::from_slice(&m.record).unwrap();
        (
            rec["user"]["uid"].as_str().unwrap().to_owned(),
            [m.record.clone(), m.uid.clone().into_bytes()].concat(),
        )
    };
    let ev = |s: Subject| {
        let mut ev = sign_event();
        ev.subject = Some(s);
        ev
    };

    *u.keys.key.lock().unwrap() = Some(7);
    let mut seen = Vec::new();
    for (kind, value) in [
        ("person", "person-123"),
        ("person", "ada.lovelace@example.org"), // an e-mail address is a fine subject: it is hashed
        ("workload", "spiffe://example.org/ns/pay/sa/api"),
        ("client", "client-abc"),
    ] {
        e.emit(ev(subject("acme", kind, value))).await.unwrap();
        let (got, sent) = pseudonym_of(&u);
        let shape = got
            .strip_prefix("p1.202611.")
            .unwrap_or_else(|| panic!("{got}"));
        assert_eq!(shape.len(), 22, "{got}: 128 bits, base64url, no padding");
        assert!(
            shape
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        // 16 bytes of the Mac, which this test computes from the key and the input of 0029.
        let mut input = Vec::new();
        for part in ["dev", "acme", kind, value] {
            input.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
            input.extend_from_slice(part.as_bytes());
        }
        let want = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&keyed_mac(7, &input)[..16])
        };
        assert_eq!(shape, want, "{kind} {value}");
        for raw in [value, value.split('@').next().unwrap()] {
            assert!(
                !sent.windows(raw.len()).any(|w| w == raw.as_bytes()),
                "{raw} is in what was sent"
            );
        }
        assert!(!seen.contains(&got), "{got} is shared");
        seen.push(got.clone());
        // The same key and subject give the same pseudonym; another key gives another one.
        e.emit(ev(subject("acme", kind, value))).await.unwrap();
        assert_eq!(pseudonym_of(&u).0, got);
        *u.keys.key.lock().unwrap() = Some(8);
        e.emit(ev(subject("acme", kind, value))).await.unwrap();
        assert_ne!(pseudonym_of(&u).0, got, "another key, the same pseudonym");
        *u.keys.key.lock().unwrap() = Some(7);
    }

    e.emit(ev(subject("acme", "person", "x"))).await.unwrap();
    let base = pseudonym_of(&u).0;
    for other in [
        subject("globex", "person", "x"),
        subject("acme", "client", "x"),
    ] {
        e.emit(ev(other)).await.unwrap();
        assert_ne!(pseudonym_of(&u).0, base);
    }

    // No subject: no Mac call and no user.
    let macs = u.keys.reqs.lock().unwrap().len();
    e.emit(sign_event()).await.unwrap();
    assert_eq!(u.keys.reqs.lock().unwrap().len(), macs);
    let reqs = u.spool.reqs.lock().unwrap();
    let rec: Value = serde_json::from_slice(&reqs.last().unwrap().message.record).unwrap();
    assert!(rec.get("user").is_none());
}

/// verifies: REQ-AUDIT-023
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

/// The id of a record, `metadata.uid`, is a UUIDv7 in the lower-case form of RFC 9562 (version 7, variant
/// 10), its first 48 bits are the emitter's clock in milliseconds, and the emitter sets it: an event has
/// no member for an id, two identical events get two ids that increase, and the message carries the id the
/// record holds.
///
/// verifies: REQ-AUDIT-051
#[tokio::test]
async fn the_record_id_is_a_uuid_v7_the_emitter_sets() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    for _ in 0..3 {
        e.emit(sign_event()).await.unwrap();
    }
    let (_, via_record) = e.record(sign_event()).await.unwrap();

    let mut ids: Vec<String> = u
        .spool
        .reqs
        .lock()
        .unwrap()
        .iter()
        .map(|r| {
            let rec: Value = serde_json::from_slice(&r.message.record).unwrap();
            assert_eq!(rec["metadata"]["uid"], r.message.uid.as_str());
            r.message.uid.clone()
        })
        .collect();
    ids.push(via_record);
    assert_eq!(ids.len(), 4);
    let now_ms = 1_793_750_400_000_u64;
    for (i, id) in ids.iter().enumerate() {
        let b = id.as_bytes();
        assert_eq!(b.len(), 36, "{id}");
        for (at, c) in b.iter().enumerate() {
            match at {
                8 | 13 | 18 | 23 => assert_eq!(*c, b'-', "{id}"),
                14 => assert_eq!(*c, b'7', "{id}: version 7 (RFC 9562 section 5.7)"),
                19 => assert!(b"89ab".contains(c), "{id}: variant 10 (section 4.1)"),
                _ => assert!(
                    c.is_ascii_digit() || (b'a'..=b'f').contains(c),
                    "{id}: lower-case hex"
                ),
            }
        }
        let ms = u64::from_str_radix(&id.replace('-', "")[..12], 16).unwrap();
        assert_eq!(ms, now_ms, "{id} does not carry the emitter's clock");
        if i > 0 {
            assert!(*id > ids[i - 1], "{id} does not follow {}", ids[i - 1]);
        }
    }
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

// ---- the count of lost facts (ADR 0029 "Facts that are lost are counted")

/// `unmapped.sluis.lost` of the `n`th request the spool saw: `(count, since)`, `None` when absent.
fn lost_of(u: &Up, n: usize) -> Option<(i64, i64)> {
    let reqs = u.spool.reqs.lock().unwrap();
    let rec: Value = serde_json::from_slice(&reqs[n].message.record).unwrap();
    let l = &rec["unmapped"]["sluis"]["lost"];
    l.is_null()
        .not()
        .then(|| (l["count"].as_i64().unwrap(), l["since"].as_i64().unwrap()))
}

fn fail(u: &Up, on: bool) {
    *u.spool.fail.lock().unwrap() = on.then_some(ErrorCode::Unavailable);
}

const FIXED_MS: i64 = 1_793_750_400_000;

/// A failing transport, then a success: the record that gets through names how many facts were
/// given up on and when the first was; the next record carries nothing (the count resets).
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn the_next_delivered_record_carries_the_count_of_lost_facts_and_the_count_resets() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    for _ in 0..3 {
        let err = e.emit(sign_event()).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Unavailable);
    }
    assert_eq!(u.spool.reqs.lock().unwrap().len(), 3, "no retry");
    assert_eq!(lost_of(&u, 0), None, "nothing was lost before the first");

    fail(&u, false);
    e.emit(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 3), Some((3, FIXED_MS)));

    e.emit(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 4), None, "the count was carried twice");
}

/// A blocking emit's failure fails the operation it belongs to, so it is not counted; a blocking
/// emit that succeeds carries a count like any other record.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn a_blocking_failure_is_not_counted_and_a_blocking_success_carries_the_count() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    e.emit_blocking(sign_event()).await.unwrap_err();
    fail(&u, false);
    e.emit(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 1), None, "a failed blocking emit was counted");

    fail(&u, true);
    e.emit(sign_event()).await.unwrap_err();
    fail(&u, false);
    e.emit_blocking(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 3), Some((1, FIXED_MS)));
}

/// A caller that carries on when a blocking emit fails (a revocation, a change of the ring) loses
/// the fact, so that failure is counted.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn a_blocking_emit_the_caller_carries_on_from_is_counted() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    e.emit_blocking_best_effort(sign_event()).await.unwrap_err();
    assert!(u.spool.reqs.lock().unwrap()[0].blocking);
    fail(&u, false);
    e.emit(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 1), Some((1, FIXED_MS)));
}

/// A record that carries a count and does not get through puts the count back: nothing is
/// forgotten until a record that carries it reaches the transport. A best-effort fact lost on the
/// way adds one; a blocking one does not.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn a_count_carried_by_a_record_that_fails_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    e.emit(sign_event()).await.unwrap_err();
    e.emit(sign_event()).await.unwrap_err(); // 2 lost
    e.emit(sign_event()).await.unwrap_err(); // carries 2, fails: 3 lost
    assert_eq!(lost_of(&u, 2), Some((2, FIXED_MS)));
    e.emit_blocking(sign_event()).await.unwrap_err(); // carries 3, fails: still 3
    assert_eq!(lost_of(&u, 3), Some((3, FIXED_MS)));
    fail(&u, false);
    e.emit(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 4), Some((3, FIXED_MS)));
}

/// An event the library refuses, or a pseudonym key@ cannot make, never reaches the transport; as a
/// best-effort fact it is lost and counted, and the caller still gets the error.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn a_fact_that_never_reaches_the_transport_is_counted_when_best_effort() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, true);
    let mut bad = sign_event();
    bad.action.activity_name = String::new(); // activity 99 needs a name
    assert_eq!(
        e.emit(bad).await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    *u.keys.fail.lock().unwrap() = true;
    let mut person = sign_event();
    person.subject = Some(Subject {
        tenant: "acme".into(),
        kind: "person".into(),
        value: "p".into(),
    });
    e.emit(person).await.unwrap_err();
    assert!(u.spool.reqs.lock().unwrap().is_empty());
    e.emit(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 0), Some((2, FIXED_MS)));
}

/// A call dropped before it finishes (a caller's timeout, as store@ sets one) is a failure too: its
/// fact is counted, and the clones of the emitter share the count.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn a_call_dropped_by_a_timeout_is_counted_and_clones_share_the_count() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    *u.spool.delay.lock().unwrap() = Duration::from_millis(400);
    let late = tokio::time::timeout(Duration::from_millis(50), e.emit(sign_event())).await;
    assert!(late.is_err(), "the spool answered in time");
    *u.spool.delay.lock().unwrap() = Duration::ZERO;
    let clone = e.clone();
    clone.emit(sign_event()).await.unwrap();
    // The first request was cut off after the spool had it; the second carries the loss.
    assert_eq!(lost_of(&u, 1), Some((1, FIXED_MS)));
}

/// A caller cannot write the member itself, and the count sits beside the caller's own fields.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn the_count_sits_beside_the_callers_fields_and_a_caller_cannot_write_it() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    e.emit(sign_event()).await.unwrap_err();
    fail(&u, false);
    let mut ev = sign_event();
    ev.sluis
        .insert("purpose".into(), Value::from("token-signing"));
    e.emit(ev).await.unwrap();
    {
        let reqs = u.spool.reqs.lock().unwrap();
        let rec: Value = serde_json::from_slice(&reqs[1].message.record).unwrap();
        assert_eq!(rec["unmapped"]["sluis"]["purpose"], "token-signing");
        assert_eq!(rec["unmapped"]["sluis"]["lost"]["count"], 1);
    }
    let mut ev = sign_event();
    ev.sluis
        .insert("lost".into(), serde_json::json!({"count": 0}));
    let err = e.emit(ev).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(
        refusal_reason(&err).as_deref(),
        Some("schema"),
        "a caller wrote unmapped.sluis.lost"
    );
}

/// `record` builds a message and neither carries nor clears the count.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn record_does_not_take_the_count() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    e.emit(sign_event()).await.unwrap_err();
    let (rec, _) = e.record(sign_event()).await.unwrap();
    let v: Value = serde_json::from_slice(&rec).unwrap();
    assert!(v.get("unmapped").is_none(), "record carried the count");
    fail(&u, false);
    e.emit(sign_event()).await.unwrap();
    assert_eq!(lost_of(&u, 1), Some((1, FIXED_MS)));
}

/// Concurrent failures are all counted, none twice, and the count is delivered once.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn concurrent_losses_are_all_counted_once() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    let n = 40;
    let tasks: Vec<_> = (0..n)
        .map(|_| {
            let e = e.clone();
            tokio::spawn(async move { e.emit(sign_event()).await.unwrap_err() })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    fail(&u, false);
    e.emit(sign_event()).await.unwrap();
    e.emit(sign_event()).await.unwrap();
    let last = u.spool.reqs.lock().unwrap().len();
    assert_eq!(lost_of(&u, last - 2), Some((n, FIXED_MS)));
    assert_eq!(lost_of(&u, last - 1), None);
}

/// The emitter returns the transport's failure and keeps no record for later: when the transport is
/// back it is sent nothing until the next call.
///
/// verifies: REQ-AUDIT-033
#[tokio::test]
async fn a_failed_record_is_returned_and_not_kept_in_memory_for_later() {
    let dir = tempfile::tempdir().unwrap();
    let u = up(dir.path()).await;
    let e = emitter(&u, false);
    fail(&u, true);
    for blocking in [false, true] {
        let err = if blocking {
            e.emit_blocking(sign_event()).await
        } else {
            e.emit(sign_event()).await
        }
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::Unavailable);
    }
    fail(&u, false);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        u.spool.reqs.lock().unwrap().len(),
        2,
        "a record was sent again"
    );
    e.emit_blocking(sign_event()).await.unwrap();
    let reqs = u.spool.reqs.lock().unwrap();
    let uids: std::collections::HashSet<_> = reqs.iter().map(|r| r.message.uid.clone()).collect();
    assert_eq!(uids.len(), 3, "a failed record was sent again");
}
