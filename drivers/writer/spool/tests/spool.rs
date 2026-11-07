//! The spool over real Unix sockets: the contract (`proto/`) is the only way in, the caller is
//! known from the socket's peer uid, and the real Rust emitter hands its records to it. The Go
//! emitter needs a Go toolchain run from inside a Rust test; it is covered by the shared vectors
//! of `kits/conformance/audit` and by the end-to-end test of the local installation instead.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use serde_json::Value;
use sluis_audit::{
    Action, Activity, Config as EmitterConfig, DEFS_NAME, Emitter, Event, Row, Status, Table,
};
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

/// verifies: REQ-AUDIT-014, REQ-AUDIT-032
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
    .unwrap()
    .with_table(test_table());
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

/// A real emitter of `entry` for a spool's emit socket.
fn emitter_of(socket: &Path) -> Emitter {
    Emitter::new(EmitterConfig {
        actor: "entry".into(),
        boundary: "dev".into(),
        release: "0.0.0-test".into(),
        transport_socket: socket.to_path_buf(),
        key_socket: None,
        now: None,
    })
    .unwrap()
    .with_table(test_table())
}

/// The actions these tests send, with schemas that accept any object: the tests probe the spool, not the table of
/// sluis (whose schemas are tested in `kits/rust/sluis-audit`).
fn test_table() -> Arc<Table> {
    let mut names: Vec<&'static str> = vec![
        "key.sign",
        "test.refused",
        "test.nobody",
        "test.blocking",
        "test.lost1",
        "test.lost2",
        "test.lost3",
        "test.after",
        "test.again",
    ];
    names.extend((0..32).map(|n| &*Box::leak(format!("test.n{n}").into_boxed_str())));
    let rows: Vec<Row> = names
        .iter()
        .map(|n| Row {
            name: n,
            actor: "entry",
            class: 6003,
            activities: if *n == "key.sign" {
                &[Activity {
                    id: 99,
                    name: "Sign",
                }]
            } else {
                &[Activity {
                    id: 99,
                    name: "Test",
                }]
            },
            outcomes: &[1, 2],
        })
        .collect();
    let mut schemas: Vec<(&'static str, &'static str)> = vec![(DEFS_NAME, "{}")];
    schemas.extend(names.iter().map(|n| {
        let file: &'static str = Box::leak(format!("{n}.schema.json").into_boxed_str());
        (file, r#"{"type":"object"}"#)
    }));
    Arc::new(Table::new(Vec::leak(rows), Vec::leak(schemas)).unwrap())
}

fn event(name: &str) -> Event {
    Event {
        action: Action {
            name: name.into(),
            class_uid: 6003,
            activity_id: 99,
            activity_name: "Test".into(),
        },
        status: Status::Success,
        ..Event::default()
    }
}

/// The `event_code` of each delivery of a batch.
macro_rules! codes {
    ($st:expr) => {{
        let r = tokio::time::timeout(Duration::from_secs(5), $st.message())
            .await
            .expect("a delivery within 5 s")
            .unwrap()
            .expect("the stream is open");
        r.deliveries()
            .iter()
            .map(|d| {
                let rec: Value = serde_json::from_slice(d.message.record).unwrap();
                rec["metadata"]["event_code"].as_str().unwrap().to_owned()
            })
            .collect::<Vec<String>>()
    }};
}

/// With the writer down (no consumer is connected), the records of the real emitter, blocking and not,
/// are on disk before each emit returns: they survive a restart of the spool, come again to a writer
/// that connects and drops without acknowledging, and are gone only once it acknowledges them. The
/// bytes are read back from the segment files, so a spool that kept them in memory would fail.
///
/// verifies: REQ-AUDIT-033
#[tokio::test]
async fn records_emitted_while_the_writer_is_down_are_on_disk_and_reach_it_when_it_is_back() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let u = up(r.path(), s.path(), Some("entry"), Config::default()).await;
    let e = emitter_of(&u.emit);
    let names: Vec<String> = (0..6).map(|n| format!("test.n{n}")).collect();
    for (n, name) in names.iter().enumerate() {
        let before = u.spool.syncs().file.load(Ordering::SeqCst);
        if n % 2 == 0 {
            e.emit(event(name)).await.unwrap();
        } else {
            e.emit_blocking(event(name)).await.unwrap();
        }
        assert_eq!(
            u.spool.syncs().file.load(Ordering::SeqCst),
            before + 1,
            "{name}: the answer came before the disk was asked"
        );
    }
    assert_eq!(u.spool.depth(), names.len());
    let on_disk: Vec<u8> = std::fs::read_dir(r.path())
        .unwrap()
        .map(|f| f.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "seg"))
        .flat_map(|p| std::fs::read(p).unwrap())
        .collect();
    for name in &names {
        assert!(
            on_disk.windows(name.len()).any(|w| w == name.as_bytes()),
            "{name} is not in a segment file"
        );
    }

    // The spool process goes away and comes back: nothing was only in its memory.
    u.down();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let s2 = tempfile::tempdir().unwrap();
    let u = up(r.path(), s2.path(), Some("entry"), Config::default()).await;
    assert_eq!(
        u.spool.depth(),
        names.len(),
        "a record was lost by the restart"
    );

    // The writer comes back, reads some and goes away again without acknowledging.
    let recv = client(&u.receive);
    let mut st = recv.receive(ReceiveRequest::default()).await.unwrap();
    assert_eq!(codes!(st), names, "in the order they were emitted");
    drop(st);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        u.spool.depth(),
        names.len(),
        "a delivery is not an acknowledgement"
    );

    // It comes back once more and acknowledges: the records are then, and only then, gone.
    let mut st = recv.receive(ReceiveRequest::default()).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), st.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ids: Vec<u64> = r.deliveries().iter().map(|d| d.delivery_id).collect();
    assert_eq!(ids.len(), names.len());
    recv.ack(AckRequest {
        delivery_ids: ids,
        ..AckRequest::default()
    })
    .await
    .unwrap();
    assert_eq!(u.spool.depth(), 0);
    u.down();
}

/// The emitter never reports success for a record the transport did not take: with the spool full, or
/// with no spool at all, both calls return the transport's error and the records taken earlier are all
/// still held. The emitter holds nothing back to send later: a spool that is up again sees none of the
/// refused ones.
///
/// verifies: REQ-AUDIT-033
#[tokio::test]
async fn the_emitter_returns_the_refusal_of_a_full_or_absent_spool_and_keeps_nothing_in_memory() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let cfg = Config {
        limit: 2500,
        segment: 1200,
    };
    let u = up(r.path(), s.path(), Some("entry"), cfg).await;
    let e = emitter_of(&u.emit);
    let mut taken = 0;
    let refused = loop {
        match e.emit(event(&format!("test.n{taken}"))).await {
            Ok(()) => taken += 1,
            Err(err) => break err,
        }
        assert!(taken < 50, "the bound never held");
    };
    assert_eq!(refused.code, ErrorCode::Unavailable);
    assert!(taken >= 2);
    let refused = e.emit_blocking(event("test.refused")).await.unwrap_err();
    assert_eq!(
        refused.code,
        ErrorCode::Unavailable,
        "a blocking emit is refused too"
    );
    assert_eq!(u.spool.depth(), taken, "an accepted record was dropped");

    // With the spool gone altogether the emitter fails, and so it does after a restart: it keeps nothing.
    u.down();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(e.emit(event("test.nobody")).await.is_err());
    assert!(e.emit_blocking(event("test.nobody")).await.is_err());
    let s2 = tempfile::tempdir().unwrap();
    let u = up(r.path(), s2.path(), Some("entry"), cfg).await;
    let mut st = client(&u.receive)
        .receive(ReceiveRequest::default())
        .await
        .unwrap();
    let mut seen = Vec::new();
    while seen.len() < taken {
        seen.extend(codes!(st));
    }
    assert_eq!(
        seen,
        (0..taken).map(|n| format!("test.n{n}")).collect::<Vec<_>>(),
        "the spool holds what it took, and nothing the emitter was refused"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        u.spool.depth(),
        taken,
        "the emitter sent a refused record later"
    );
    u.down();
}

/// With the spool full, the best-effort facts the emitter could not hand over are lost, and the log says how many: the
/// first record the spool takes after room is back carries the count as `unmapped.sluis.lost`. A refused blocking emit
/// is not counted, because its caller fails the operation. The records are read back from the receive stream, so the
/// count went through the real spool and not past it.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn facts_lost_to_a_full_spool_are_counted_in_the_next_record_the_spool_takes() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let cfg = Config {
        limit: 2500,
        segment: 1200,
    };
    let u = up(r.path(), s.path(), Some("entry"), cfg).await;
    let e = emitter_of(&u.emit);
    let mut taken = 0;
    let refused = loop {
        match e.emit(event(&format!("test.n{taken}"))).await {
            Ok(()) => taken += 1,
            Err(err) => break err,
        }
        assert!(taken < 50, "the bound never held");
    };
    assert_eq!(refused.code, ErrorCode::Unavailable);
    // One best-effort fact is lost (the one that ended the loop). A blocking one is refused and its caller fails the
    // operation: it is not lost. One more best-effort fact is lost.
    assert_eq!(
        e.emit_blocking(event("test.blocking"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unavailable
    );
    assert_eq!(
        e.emit(event("test.lost2")).await.unwrap_err().code,
        ErrorCode::Unavailable
    );
    assert_eq!(u.spool.depth(), taken, "a refused record was kept");

    // The writer drains and acknowledges what the spool holds: room is back.
    let recv = client(&u.receive);
    let mut st = recv.receive(ReceiveRequest::default()).await.unwrap();
    let mut ids = Vec::new();
    while ids.len() < taken {
        let b = tokio::time::timeout(Duration::from_secs(5), st.message())
            .await
            .expect("a delivery within 5 s")
            .unwrap()
            .expect("the stream is open");
        ids.extend(b.deliveries().iter().map(|d| d.delivery_id));
        for d in b.deliveries() {
            let rec: Value = serde_json::from_slice(d.message.record).unwrap();
            assert!(
                rec["unmapped"]["sluis"].get("lost").is_none(),
                "a record taken before any loss carries a count"
            );
        }
    }
    recv.ack(AckRequest {
        delivery_ids: ids,
        ..AckRequest::default()
    })
    .await
    .unwrap();
    assert_eq!(u.spool.depth(), 0);

    // The next emit is taken, and the record the writer receives says two facts were lost.
    e.emit(event("test.after")).await.unwrap();
    let b = tokio::time::timeout(Duration::from_secs(5), st.message())
        .await
        .expect("a delivery within 5 s")
        .unwrap()
        .expect("the stream is open");
    let d = b.deliveries().first().expect("one delivery");
    let rec: Value = serde_json::from_slice(d.message.record).unwrap();
    assert_eq!(rec["metadata"]["event_code"], "test.after");
    assert_eq!(rec["unmapped"]["sluis"]["lost"]["total"], 2);
    assert!(rec["unmapped"]["sluis"]["lost"]["since"].as_i64().unwrap() > 0);

    // And once only: the record after it carries nothing.
    let id = d.delivery_id;
    recv.ack(AckRequest {
        delivery_ids: vec![id],
        ..AckRequest::default()
    })
    .await
    .unwrap();
    e.emit(event("test.again")).await.unwrap();
    let b = tokio::time::timeout(Duration::from_secs(5), st.message())
        .await
        .expect("a delivery within 5 s")
        .unwrap()
        .expect("the stream is open");
    let rec: Value =
        serde_json::from_slice(b.deliveries().first().unwrap().message.record).unwrap();
    assert!(rec.get("unmapped").is_none(), "the count was carried twice");
    u.down();
}

/// With no spool at all the facts are lost the same way: the emitter counts the failed connections, and the first record
/// a spool takes once it is up carries the count.
///
/// verifies: REQ-AUDIT-186
#[tokio::test]
async fn facts_lost_while_no_spool_is_listening_are_counted_in_the_first_record_it_takes() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let e = emitter_of(&s.path().join("emit.sock"));
    assert!(e.emit(event("test.lost1")).await.is_err());
    assert!(e.emit(event("test.lost2")).await.is_err());
    assert!(e.emit_blocking(event("test.blocking")).await.is_err());
    assert!(e.emit(event("test.lost3")).await.is_err());

    let u = up(r.path(), s.path(), Some("entry"), Config::default()).await;
    e.emit(event("test.after")).await.unwrap();
    let mut st = client(&u.receive)
        .receive(ReceiveRequest::default())
        .await
        .unwrap();
    let b = tokio::time::timeout(Duration::from_secs(5), st.message())
        .await
        .expect("a delivery within 5 s")
        .unwrap()
        .expect("the stream is open");
    let d = b.deliveries().first().expect("one delivery");
    let rec: Value = serde_json::from_slice(d.message.record).unwrap();
    assert_eq!(rec["metadata"]["event_code"], "test.after");
    assert_eq!(rec["unmapped"]["sluis"]["lost"]["total"], 3);
    u.down();
}
