//! The read-only blob port over real Unix sockets: the contract (`proto/`) is the only way in, the caller is
//! known from the socket's peer uid, and nothing the driver serves changes the directory.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use sluis_driver_indexer_fs::{ReadOnly, suite};
use sluis_driver_writer_fs::Fs;
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobListRequest, BlobServiceClient, BlobServiceExt, CreateRequest, PutRequest,
};

fn serve(
    socket: &Path,
    fs: Fs,
    allow: Allow,
    me_is: &'static str,
) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)));
    let cfg = ServerConfig {
        actor: "driver-indexer-fs",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow,
        default_deadline: std::time::Duration::from_secs(10),
    };
    let router = std::sync::Arc::new(ReadOnly(fs)).register(Router::new());
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

fn client(sock: &Path) -> BlobServiceClient<sluis_kit::Transport> {
    let c = dial(sock);
    BlobServiceClient::new(c.transport(), c.config())
}

fn get(path: &str) -> BlobGetRequest {
    BlobGetRequest {
        path: path.into(),
        ..Default::default()
    }
}

#[test]
fn the_read_side_of_the_port_suite_passes() {
    suite::run_temp().unwrap();
}

#[tokio::test]
async fn the_indexer_reads_what_the_writer_made_and_can_change_nothing() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let me = rustix::process::geteuid().as_raw();
    let writer = Fs::open(r.path()).unwrap();
    writer.create("audit/main/tile/entries/000", b"x").unwrap();
    writer.put("audit/main/checkpoint", b"c", "").unwrap();

    let sock = s.path().join("blob.sock");
    let stop = serve(
        &sock,
        Fs::open_read_only(r.path(), me).unwrap(),
        Allow::OwnerOnly("indexer"),
        "indexer",
    );
    up(&sock).await;
    let c = client(&sock);

    let got = c
        .get(get("audit/main/tile/entries/000"))
        .await
        .unwrap()
        .into_owned();
    assert_eq!(got.data, b"x");
    let list = c
        .list(BlobListRequest {
            prefix: "audit/main/".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    assert_eq!(
        list.paths,
        ["audit/main/checkpoint", "audit/main/tile/entries/000"]
    );
    let missing = c.get(get("audit/main/none")).await.unwrap_err();
    assert_eq!(
        (missing.code, refusal_reason(&missing).as_deref()),
        (ErrorCode::NotFound, Some("absent"))
    );
    let bad = c.get(get("../a")).await.unwrap_err();
    assert_eq!(
        (bad.code, refusal_reason(&bad).as_deref()),
        (ErrorCode::InvalidArgument, Some("path"))
    );

    // Create and Put are refused by the service, and the directory is as it was.
    let create = c
        .create(CreateRequest {
            path: "audit/main/tile/entries/001".into(),
            data: vec![1],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (create.code, refusal_reason(&create).as_deref()),
        (ErrorCode::PermissionDenied, Some("rule"))
    );
    let put = c
        .put(PutRequest {
            path: "audit/main/checkpoint".into(),
            data: b"evil".to_vec(),
            if_match: String::new(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (put.code, refusal_reason(&put).as_deref()),
        (ErrorCode::PermissionDenied, Some("rule"))
    );
    assert!(!r.path().join("audit/main/tile/entries/001").exists());
    assert_eq!(
        std::fs::read(r.path().join("audit/main/checkpoint")).unwrap(),
        b"c"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn each_socket_answers_its_one_caller_and_nobody_else() {
    let (r, s) = (root(), tempfile::tempdir().unwrap());
    let me = rustix::process::geteuid().as_raw();
    Fs::open(r.path()).unwrap().create("a", b"x").unwrap();
    let open = || Fs::open_read_only(r.path(), me).unwrap();

    // The indexer's socket refuses the reader, the writer and the index driver's owner alike; the reader's refuses
    // the indexer.
    for (socket, allow, caller, ok) in [
        ("i-ok.sock", Allow::OwnerOnly("indexer"), "indexer", true),
        (
            "i-reader.sock",
            Allow::OwnerOnly("indexer"),
            "reader",
            false,
        ),
        (
            "i-writer.sock",
            Allow::OwnerOnly("indexer"),
            "writer",
            false,
        ),
        ("r-ok.sock", Allow::Exact("reader"), "reader", true),
        ("r-indexer.sock", Allow::Exact("reader"), "indexer", false),
    ] {
        let sock = s.path().join(socket);
        let stop = serve(&sock, open(), allow, caller);
        up(&sock).await;
        let answer = client(&sock).get(get("a")).await;
        if ok {
            assert_eq!(answer.unwrap().into_owned().data, b"x", "{socket}");
        } else {
            let e = answer.unwrap_err();
            assert_eq!(
                (e.code, refusal_reason(&e).as_deref()),
                (ErrorCode::PermissionDenied, Some("call_graph")),
                "{socket}"
            );
        }
        let _ = stop.send(());
    }
}
