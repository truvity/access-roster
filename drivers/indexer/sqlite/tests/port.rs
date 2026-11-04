//! The index port over real Unix sockets: the contract (`proto/`) is the only way in, the caller is
//! known from the socket's peer uid, the indexer's socket answers the indexer only and the reader's
//! socket answers the reader only, and the reader's socket has no way to write.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use sluis_driver_indexer_sqlite::service::{Read, Write};
use sluis_driver_indexer_sqlite::{Index, suite};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
use sluis_proto::sluis::port::index::v2alpha1::{
    ApplyRequest, Cursor, GetCursorRequest, IndexReadServiceClient, IndexReadServiceExt,
    IndexServiceClient, IndexServiceExt, LogRef, Partition, Row, SearchRequest,
};

/// Serves one side on a socket, as the process `me_is` says it is.
fn serve(
    socket: &Path,
    router: Router,
    allow: Allow,
    me_is: &'static str,
) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)));
    let cfg = ServerConfig {
        actor: "driver-indexer-sqlite",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow,
        default_deadline: std::time::Duration::from_secs(10),
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        ids,
    ));
    tx
}

async fn up(socket: &Path) {
    for _ in 0..200 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no socket");
}

fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    d
}

fn row(n: u8) -> Row {
    Row {
        tenant: "acme".into(),
        hash: vec![n; 48],
        seq: i64::from(n),
        time_ms: i64::from(n) * 10,
        action: "token.exchange".into(),
        status_code: "ok".into(),
        record_id: format!("rec-{n}"),
        record: b"{}".to_vec(),
        ..Row::default()
    }
}

fn log() -> LogRef {
    LogRef {
        project: "sluis".into(),
        kind: "audit".into(),
        log: "main".into(),
        ..LogRef::default()
    }
}

fn search() -> SearchRequest {
    SearchRequest {
        partitions: vec![Partition {
            project: "sluis".into(),
            kind: "audit".into(),
            ..Partition::default()
        }],
        tenants: vec!["acme".into()],
        ..SearchRequest::default()
    }
}

#[test]
fn the_port_suite_passes() {
    suite::run_temp().unwrap();
}

#[tokio::test]
async fn the_indexer_writes_and_the_reader_reads_each_on_its_own_socket() {
    let (d, s) = (dir(), tempfile::tempdir().unwrap());
    let index = Index::open(d.path()).unwrap();
    let (wsock, rsock) = (s.path().join("index.sock"), s.path().join("index-ro.sock"));
    let stop_w = serve(
        &wsock,
        Arc::new(Write(index.clone())).register(Router::new()),
        Allow::OwnerOnly("indexer"),
        "indexer",
    );
    let stop_r = serve(
        &rsock,
        Arc::new(Read(index)).register(Router::new()),
        Allow::Exact("reader"),
        "reader",
    );
    up(&wsock).await;
    up(&rsock).await;

    let w = dial(&wsock);
    let writer = IndexServiceClient::new(w.transport(), w.config());
    let applied = writer
        .apply(ApplyRequest {
            log: ::buffa::MessageField::some(log()),
            next: ::buffa::MessageField::some(Cursor {
                size: 2,
                root: vec![7; 32],
                ..Cursor::default()
            }),
            rows: vec![row(1), row(2)],
            ..ApplyRequest::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!((applied.inserted, applied.duplicates), (2, 0));
    let stale = writer
        .apply(ApplyRequest {
            log: ::buffa::MessageField::some(log()),
            expect_size: 0,
            next: ::buffa::MessageField::some(Cursor {
                size: 3,
                root: vec![7; 32],
                ..Cursor::default()
            }),
            ..ApplyRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (stale.code, refusal_reason(&stale).as_deref()),
        (ErrorCode::Aborted, Some("version"))
    );
    let cur = writer
        .get_cursor(GetCursorRequest {
            log: ::buffa::MessageField::some(log()),
            ..GetCursorRequest::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(cur.cursor.as_option().map(|c| c.size), Some(2));

    let r = dial(&rsock);
    let reader = IndexReadServiceClient::new(r.transport(), r.config());
    let got = reader.search(search()).await.unwrap().into_owned();
    assert_eq!(
        got.rows
            .iter()
            .map(|r| r.record_id.as_str())
            .collect::<Vec<_>>(),
        ["rec-2", "rec-1"]
    );
    let none = reader
        .search(SearchRequest {
            tenants: vec![],
            ..search()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (none.code, refusal_reason(&none).as_deref()),
        (ErrorCode::InvalidArgument, Some("argument"))
    );

    // The reader's socket serves no write method: the write service is not on it.
    let on_ro = IndexServiceClient::new(r.transport(), r.config());
    let e = on_ro
        .apply(ApplyRequest {
            log: ::buffa::MessageField::some(log()),
            rows: vec![row(9)],
            ..ApplyRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unimplemented);
    assert_eq!(
        reader
            .search(search())
            .await
            .unwrap()
            .into_owned()
            .rows
            .len(),
        2
    );
    let _ = (stop_w.send(()), stop_r.send(()));
}

#[tokio::test]
async fn a_caller_that_is_not_the_one_named_is_refused_before_anything_is_read() {
    let (d, s) = (dir(), tempfile::tempdir().unwrap());
    let index = Index::open(d.path()).unwrap();
    let (wsock, rsock) = (s.path().join("index.sock"), s.path().join("index-ro.sock"));
    // The writer's socket sees the reader as its caller, and the reader's socket sees the indexer.
    let stop_w = serve(
        &wsock,
        Arc::new(Write(index.clone())).register(Router::new()),
        Allow::OwnerOnly("indexer"),
        "reader",
    );
    let stop_r = serve(
        &rsock,
        Arc::new(Read(index.clone())).register(Router::new()),
        Allow::Exact("reader"),
        "indexer",
    );
    up(&wsock).await;
    up(&rsock).await;
    let w = dial(&wsock);
    let e = IndexServiceClient::new(w.transport(), w.config())
        .apply(ApplyRequest {
            log: ::buffa::MessageField::some(log()),
            rows: vec![row(1)],
            ..ApplyRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, refusal_reason(&e).as_deref()),
        (ErrorCode::PermissionDenied, Some("call_graph"))
    );
    let r = dial(&rsock);
    let e = IndexReadServiceClient::new(r.transport(), r.config())
        .search(search())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    // Nothing was written.
    assert!(index.search(&search()).unwrap().rows.is_empty());
    let _ = (stop_w.send(()), stop_r.send(()));
}
