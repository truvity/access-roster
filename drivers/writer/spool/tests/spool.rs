//! The spool over real Unix sockets: the contract (`proto/`) is the only way in, the caller is
//! known from the socket's peer uid, and the real Rust emitter hands its records to it. The Go
//! emitter needs a Go toolchain run from inside a Rust test; it is covered by the shared vectors
//! of `kits/conformance/audit` and by the end-to-end test of the local installation instead.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use serde_json::Value;
use sluis_audit::{Action, Config as EmitterConfig, Emitter, Event, Status};
use sluis_driver_writer_spool::service::{Consume, Emit};
use sluis_driver_writer_spool::{Config, Spool};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AuditMessage, EmitRequest, ReceiveRequest, TransportServiceClient,
    TransportServiceExt,
};

/// A spool served on both sockets. `emit_as` is what the registry would call the test process on
/// the emit socket (`None`: unknown); on the receive socket it is always `writer`.
struct Up {
    emit: PathBuf,
    receive: PathBuf,
    spool: Spool,
    stop: Vec<tokio::sync::oneshot::Sender<()>>,
}

fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

async fn up(root: &Path, socks: &Path, emit_as: Option<&'static str>, cfg: Config) -> Up {
    up_as(root, socks, emit_as, "writer", cfg).await
}

async fn up_as(
    root: &Path,
    socks: &Path,
    emit_as: Option<&'static str>,
    receive_as: &'static str,
    cfg: Config,
) -> Up {
    let me = rustix::process::geteuid().as_raw();
    let spool = Spool::open(root, cfg).unwrap();
    let mut stop = Vec::new();
    let mut serve = |name: &str, allow, who: Option<&'static str>, router: Router| {
        let socket = socks.join(name);
        let ids = Identities::with(0, move |u| who.filter(|_| u == me).map(|w| (w, 0)));
        let cfg = ServerConfig {
            actor: "transport",
            boundary: "dev".into(),
            socket: socket.clone(),
            mode: 0o660,
            socket_gid: None,
            allow,
            default_deadline: Duration::from_secs(10),
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
        socket
    };
    let emit = serve(
        "emit.sock",
        Allow::CallGraph,
        emit_as,
        std::sync::Arc::new(Emit {
            spool: spool.clone(),
            boundary: "dev".into(),
        })
        .register(Router::new()),
    );
    let receive = serve(
        "receive.sock",
        Allow::Exact("writer"),
        Some(receive_as),
        std::sync::Arc::new(Consume(spool.clone())).register(Router::new()),
    );
    for s in [&emit, &receive] {
        for _ in 0..200 {
            if s.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(s.exists(), "no socket");
    }
    Up {
        emit,
        receive,
        spool,
        stop,
    }
}

impl Up {
    fn down(self) {
        for s in self.stop {
            let _ = s.send(());
        }
    }
}

fn client(socket: &Path) -> TransportServiceClient<sluis_kit::Transport> {
    let c = dial(socket);
    TransportServiceClient::new(c.transport(), c.config())
}

fn msg(uid: &str, body: &[u8]) -> EmitRequest {
    EmitRequest {
        message: AuditMessage {
            uid: uid.into(),
            record: body.to_vec(),
            ..AuditMessage::default()
        }
        .into(),
        ..EmitRequest::default()
    }
}

/// The next batch of a receive stream as (delivery id, emitter, message uid).
macro_rules! next {
    ($st:expr) => {{
        let r = tokio::time::timeout(Duration::from_secs(5), $st.message())
            .await
            .expect("a delivery within 5 s")
            .unwrap()
            .expect("the stream is open");
        r.deliveries()
            .iter()
            .map(|d| {
                (
                    d.delivery_id,
                    d.emitter.to_string(),
                    d.message.uid.to_string(),
                )
            })
            .collect::<Vec<(u64, String, String)>>()
    }};
}

#[tokio::test]
async fn emits_are_durable_ordered_acked_and_replayed_after_a_restart() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let u = up(r.path(), s.path(), Some("entry"), Config::default()).await;
    let emit = client(&u.emit);
    for (i, blocking) in [(1, false), (2, true), (3, true)] {
        let mut m = msg(&format!("u{i}"), b"{}");
        m.blocking = blocking;
        let before = u.spool.syncs().file.load(Ordering::SeqCst);
        emit.emit(m).await.unwrap();
        // The answer came after the fsync of the segment.
        assert_eq!(u.spool.syncs().file.load(Ordering::SeqCst), before + 1);
    }
    assert!(
        u.spool.syncs().dir.load(Ordering::SeqCst) >= 1,
        "the segment was not made durable in its directory"
    );
    assert_eq!(u.spool.depth(), 3);

    let recv = client(&u.receive);
    let mut st = recv.receive(ReceiveRequest::default()).await.unwrap();
    let got = next!(st);
    // The emitter is the peer, not a field of the message.
    assert_eq!(
        got,
        vec![
            (1, "entry@dev".into(), "u1".into()),
            (2, "entry@dev".into(), "u2".into()),
            (3, "entry@dev".into(), "u3".into()),
        ]
    );
    // A second consumer is refused while the first is open.
    let second = recv.receive(ReceiveRequest::default()).await;
    let e = match second {
        Err(e) => e,
        Ok(mut st2) => st2.message().await.unwrap_err(),
    };
    assert_eq!(e.code, ErrorCode::AlreadyExists);

    // A message emitted later arrives on the open stream.
    emit.emit(msg("u4", b"{}")).await.unwrap();
    assert_eq!(next!(st)[0].0, 4);

    // Ack 1 and 2; the rest stays, and an ack of the unknown is harmless.
    recv.ack(AckRequest {
        delivery_ids: vec![2, 1, 77],
        ..AckRequest::default()
    })
    .await
    .unwrap();
    assert_eq!(u.spool.depth(), 2);
    drop(st);

    // The consumer restarts: the unacknowledged come again, under the same ids.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut st = recv.receive(ReceiveRequest::default()).await.unwrap();
    let ids: Vec<u64> = next!(st).iter().map(|d| d.0).collect();
    assert_eq!(ids, [3, 4]);
    drop(st);

    // The spool restarts: the same.
    u.down();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let s2 = tempfile::tempdir().unwrap();
    let u = up(r.path(), s2.path(), Some("entry"), Config::default()).await;
    let recv = client(&u.receive);
    let mut st = recv.receive(ReceiveRequest::default()).await.unwrap();
    let ids: Vec<u64> = next!(st).iter().map(|d| d.0).collect();
    assert_eq!(ids, [3, 4]);
    u.down();
}

#[tokio::test]
async fn an_unknown_uid_and_an_actor_outside_the_graph_are_refused_and_nothing_is_kept() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    // The test process is not a uid of the registry.
    let u = up(r.path(), s.path(), None, Config::default()).await;
    let e = client(&u.emit).emit(msg("u1", b"{}")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&e).as_deref(), Some("caller"));
    assert_eq!(u.spool.depth(), 0);
    u.down();

    // An actor that has no audit-emit port.
    let outsider = sluis_registry::actors()
        .iter()
        .find(|a| a.family != "platform" && !sluis_registry::may_call(a.name, "transport"))
        .map(|a| a.name)
        .expect("the registry has an actor that may not emit");
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let u = up(r.path(), s.path(), Some(outsider), Config::default()).await;
    let e = client(&u.emit).emit(msg("u1", b"{}")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&e).as_deref(), Some("call_graph"));
    assert_eq!(u.spool.depth(), 0);
    u.down();
}

#[tokio::test]
async fn an_emitter_cannot_consume_and_the_consumer_socket_does_not_take_emits() {
    // An emitter that dials the receive socket is not the writer: refused before any handler.
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let u = up_as(
        r.path(),
        s.path(),
        Some("entry"),
        "entry",
        Config::default(),
    )
    .await;
    let e = match client(&u.receive).receive(ReceiveRequest::default()).await {
        Err(e) => e,
        Ok(mut st) => st.message().await.unwrap_err(),
    };
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&e).as_deref(), Some("call_graph"));
    let e = client(&u.receive)
        .ack(AckRequest {
            delivery_ids: vec![1],
            ..AckRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    u.down();

    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let u = up(r.path(), s.path(), Some("entry"), Config::default()).await;
    // Receive and Ack are not served on the emit socket.
    let e = client(&u.emit)
        .ack(AckRequest::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unimplemented);
    // Emit is not served on the receive socket.
    let e = client(&u.receive).emit(msg("u1", b"{}")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unimplemented);
    u.down();
}

#[tokio::test]
async fn a_malformed_message_is_refused_with_its_field() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let u = up(r.path(), s.path(), Some("entry"), Config::default()).await;
    let c = client(&u.emit);
    for (req, field) in [
        (EmitRequest::default(), "message"),
        (msg("", b"{}"), "message.uid"),
        (msg("u", b""), "message.record"),
    ] {
        let e = c.emit(req).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{field}");
    }
    let e = c
        .emit(msg(
            "u",
            &vec![0u8; sluis_driver_writer_spool::MAX_MESSAGE + 1],
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(u.spool.depth(), 0);
    u.down();
}

#[tokio::test]
async fn a_full_spool_refuses_with_unavailable_and_keeps_every_earlier_message() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let cfg = Config {
        limit: 1500,
        segment: 700,
    };
    let u = up(r.path(), s.path(), Some("entry"), cfg).await;
    let c = client(&u.emit);
    let mut taken = 0;
    let refused = loop {
        match c.emit(msg(&format!("u{taken}"), &[b'x'; 200])).await {
            Ok(_) => taken += 1,
            Err(e) => break e,
        }
        assert!(taken < 50, "the bound never held");
    };
    assert_eq!(refused.code, ErrorCode::Unavailable);
    assert!(taken >= 2);
    assert_eq!(u.spool.depth(), taken, "an accepted message was dropped");
    assert!(u.spool.bytes() <= 1500);

    // The writer drains it all: the earlier messages are all there, in order.
    let mut st = client(&u.receive)
        .receive(ReceiveRequest::default())
        .await
        .unwrap();
    let mut seen = Vec::new();
    while seen.len() < taken {
        seen.extend(next!(st));
    }
    let uids: Vec<_> = seen.iter().map(|d| d.2.clone()).collect();
    assert_eq!(
        uids,
        (0..taken).map(|i| format!("u{i}")).collect::<Vec<_>>()
    );
    client(&u.receive)
        .ack(AckRequest {
            delivery_ids: seen.iter().map(|d| d.0).collect(),
            ..AckRequest::default()
        })
        .await
        .unwrap();
    // Room is back.
    c.emit(msg("again", &[b'x'; 200])).await.unwrap();
    u.down();
}

#[tokio::test]
async fn the_real_rust_emitter_hands_its_record_to_the_spool() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let u = up(r.path(), s.path(), Some("entry"), Config::default()).await;
    let e = Emitter::new(EmitterConfig {
        actor: "entry".into(),
        boundary: "dev".into(),
        release: "0.0.0-test".into(),
        transport_socket: u.emit.clone(),
        key_socket: None,
        now: None,
    })
    .unwrap();
    e.emit_blocking(Event {
        action: Action {
            name: "key.sign".into(),
            class_uid: 6003,
            activity_id: 99,
            activity_name: "Sign".into(),
        },
        status: Status::Success,
        ..Event::default()
    })
    .await
    .unwrap();
    let mut st = client(&u.receive)
        .receive(ReceiveRequest::default())
        .await
        .unwrap();
    let r = st.message().await.unwrap().expect("a delivery");
    let d = r.deliveries().first().expect("one delivery");
    assert_eq!(d.emitter, "entry@dev");
    let rec: Value = serde_json::from_slice(d.message.record).unwrap();
    assert_eq!(rec["metadata"]["uid"], d.message.uid.to_string());
    u.down();
}
