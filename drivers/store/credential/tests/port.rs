//! The secret source over a real Unix socket: the contract (`proto/`) is the only way in, the
//! caller is known from the socket's peer uid, and only store@ is served.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use sluis_credential::service::Service;
use sluis_credential::{Dir, suite};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
use sluis_proto::sluis::port::source::v2alpha1::{
    CapabilitiesRequest, ReadRequest, SourceServiceClient, SourceServiceExt, SourceWatchRequest,
    Watch,
};

/// A value that no log, error text or label may repeat.
const SECRET: &[u8] = b"tr0ub4dor-and-three-more-words";

fn serve(socket: &Path, dir: &Path, me_is: &'static str) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)));
    let cfg = ServerConfig {
        actor: "driver-store-credential",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow: Allow::OwnerOnly("store"),
        default_deadline: Duration::from_secs(10),
    };
    let router = std::sync::Arc::new(Service(Dir::open(dir).unwrap())).register(Router::new());
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no socket");
}

fn credential(dir: &Path, name: &str, mode: u32) {
    let p = dir.join(name);
    std::fs::write(&p, SECRET).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn the_source_suite_passes() {
    suite::run_temp().unwrap();
}

#[tokio::test]
async fn store_reads_a_secret_and_no_refusal_carries_it() {
    let (creds, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let sock = s.path().join("secret-source.sock");
    credential(creds.path(), "upstream-workforce", 0o400);
    credential(creds.path(), "too-open", 0o644);
    let stop = serve(&sock, creds.path(), "store");
    up(&sock).await;
    let client = dial(&sock);
    let c = SourceServiceClient::new(client.transport(), client.config());

    let caps = c
        .capabilities(CapabilitiesRequest::default())
        .await
        .unwrap()
        .into_owned();
    assert_eq!(caps.watch.as_known(), Some(Watch::NONE));

    let read = |name: &str, held: &str| {
        c.read(ReadRequest {
            name: name.into(),
            if_none_match: held.into(),
            ..Default::default()
        })
    };
    let got = read("upstream-workforce", "").await.unwrap().into_owned();
    assert_eq!(got.data, SECRET);
    assert!(
        !String::from_utf8_lossy(got.version.as_bytes()).contains("tr0ub4dor"),
        "the label shows the value"
    );
    let again = read("upstream-workforce", &got.version)
        .await
        .unwrap()
        .into_owned();
    assert!(again.unchanged && again.data.is_empty());

    for (name, code, reason) in [
        ("nothing", ErrorCode::NotFound, "absent"),
        (
            "../upstream-workforce",
            ErrorCode::InvalidArgument,
            "schema",
        ),
        ("too-open", ErrorCode::PermissionDenied, "rule"),
    ] {
        let e = read(name, "").await.unwrap_err();
        assert_eq!(
            (e.code, refusal_reason(&e).as_deref()),
            (code, Some(reason))
        );
        assert!(
            !format!("{e:?}").contains("tr0ub4dor"),
            "an error shows the value"
        );
    }

    let w = c
        .watch(SourceWatchRequest {
            name: "upstream-workforce".into(),
            ..Default::default()
        })
        .await;
    let mut w = w.unwrap();
    let e = w.message().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unimplemented);
    let _ = stop.send(());
}

#[tokio::test]
async fn a_caller_that_is_not_store_gets_no_secret() {
    for caller in ["policy", "key", "writer", "exchange"] {
        let (creds, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let sock = s.path().join("secret-source.sock");
        credential(creds.path(), "upstream-workforce", 0o400);
        let stop = serve(&sock, creds.path(), caller);
        up(&sock).await;
        let client = dial(&sock);
        let c = SourceServiceClient::new(client.transport(), client.config());
        let e = c
            .read(ReadRequest {
                name: "upstream-workforce".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{caller}");
        assert_eq!(
            refusal_reason(&e).as_deref(),
            Some("call_graph"),
            "{caller}"
        );
        let _ = stop.send(());
    }
}

#[test]
fn serve_refuses_a_socket_gid_of_zero_or_text_before_it_listens() {
    let (dir, run) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    for gid in ["0", "wheel"] {
        let sock = run.path().join("x.sock");
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_credential"))
            .args(["serve", "--socket"])
            .arg(&sock)
            .arg("--dir")
            .arg(dir.path())
            .args(["--socket-gid", gid])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{gid}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--socket-gid"),
            "{gid}"
        );
        assert!(!sock.exists());
    }
}
