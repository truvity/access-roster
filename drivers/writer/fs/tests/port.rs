//! The blob port over a real Unix socket: the contract (`proto/`) is the only way in, the caller is
//! known from the socket's peer uid, and the suite runs on the same engine.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use sluis_driver_writer_fs::service::Service;
use sluis_driver_writer_fs::{Fs, suite};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobListRequest, BlobServiceClient, BlobServiceExt, CreateRequest, PutRequest,
};

fn serve(socket: &Path, root: &Path, me_is: &'static str) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)));
    let cfg = ServerConfig {
        actor: "driver-writer-fs",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow: Allow::OwnerOnly("writer"),
        default_deadline: std::time::Duration::from_secs(10),
    };
    let router = std::sync::Arc::new(Service(Fs::open(root).unwrap())).register(Router::new());
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

fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    d
}

#[test]
fn the_port_suite_passes() {
    suite::run_temp().unwrap();
}

#[tokio::test]
async fn the_writer_uses_the_port_and_every_refusal_names_a_reason() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let sock = s.path().join("blob.sock");
    let stop = serve(&sock, r.path(), "writer");
    up(&sock).await;
    let client = dial(&sock);
    let c = BlobServiceClient::new(client.transport(), client.config());

    let made = c
        .create(CreateRequest {
            path: "a/b".into(),
            data: b"x".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    let again = c
        .create(CreateRequest {
            path: "a/b".into(),
            data: b"y".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (again.code, refusal_reason(&again).as_deref()),
        (ErrorCode::AlreadyExists, Some("taken"))
    );
    let got = c
        .get(BlobGetRequest {
            path: "a/b".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!((got.data, got.etag), (b"x".to_vec(), made.etag));
    let bad = c
        .get(BlobGetRequest {
            path: "../a".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (bad.code, refusal_reason(&bad).as_deref()),
        (ErrorCode::InvalidArgument, Some("path"))
    );
    let put = c
        .put(PutRequest {
            path: "a/b".into(),
            data: b"z".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (put.code, refusal_reason(&put).as_deref()),
        (ErrorCode::PermissionDenied, Some("rule"))
    );
    let ptr = c
        .put(PutRequest {
            path: "a/checkpoint".into(),
            data: b"z".to_vec(),
            if_match: "old".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (ptr.code, refusal_reason(&ptr).as_deref()),
        (ErrorCode::Aborted, Some("version"))
    );
    let list = c
        .list(BlobListRequest {
            prefix: "a/".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(list.paths, ["a/b"]);
    let _ = stop.send(());
}

#[tokio::test]
async fn a_caller_that_is_not_the_owner_is_refused_before_anything_is_read() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let sock = s.path().join("blob.sock");
    let stop = serve(&sock, r.path(), "indexer");
    up(&sock).await;
    let client = dial(&sock);
    let c = BlobServiceClient::new(client.transport(), client.config());
    let e = c
        .create(CreateRequest {
            path: "a".into(),
            data: vec![1],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert!(!r.path().join("a").exists());
    let _ = stop.send(());
}
