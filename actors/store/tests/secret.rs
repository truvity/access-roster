#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The secret source of store@ against the real `credential` driver, over its real contract: a secret is fetched on
//! first use and held in memory (ADR 0005, "Secret sources"; REQ-DATA-017).

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use connectrpc::Router;
use sluis_credential::Dir;
use sluis_credential::service::Service;
use sluis_kit::{Allow, Identities, ServerConfig, dial};
use sluis_proto::sluis::port::source::v2alpha1::SourceServiceExt as _;
use store::secret::{SecretError, SecretSource, SourceSecrets};

const SECRET: &[u8] = b"correct horse battery staple";

fn serve(socket: &Path, dir: &Path) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some(("store", 0)));
    let cfg = ServerConfig {
        actor: "driver-store-credential",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow: Allow::OwnerOnly("store"),
        default_deadline: Duration::from_secs(10),
    };
    let router = Arc::new(Service(Dir::open(dir).unwrap())).register(Router::new());
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
    for _ in 0..300 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no socket");
}

#[tokio::test]
async fn a_secret_is_read_from_the_driver_once_and_then_held_in_memory() {
    let (creds, run) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    std::fs::set_permissions(creds.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = creds.path().join("client-app");
    std::fs::write(&file, SECRET).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
    let sock = run.path().join("secret-source.sock");
    let stop = serve(&sock, creds.path());
    up(&sock).await;

    let secrets = SourceSecrets::new(&dial(&sock));
    let first = secrets.read("client-app").await.unwrap();
    assert_eq!(first.data, SECRET);
    assert!(
        !first.version.contains("correct"),
        "the label is not the value"
    );

    // The file is gone, and the driver would say so: the answer comes from memory.
    std::fs::remove_file(&file).unwrap();
    let again = secrets.read("client-app").await.unwrap();
    assert_eq!(again.data, SECRET);

    // A name the driver does not hold is absent, and absence is not held.
    assert_eq!(
        secrets.read("client-other").await.err(),
        Some(SecretError::Absent)
    );
    let other = creds.path().join("client-other");
    std::fs::write(&other, b"later").unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(secrets.read("client-other").await.unwrap().data, b"later");

    // A name that is not a credential name, or a driver that is gone, is a refusal that names no value.
    assert_eq!(
        secrets.read("../escape").await.err(),
        Some(SecretError::Down)
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn a_driver_that_is_gone_fails_closed() {
    let run = tempfile::tempdir().unwrap();
    let secrets = SourceSecrets::new(&dial(&run.path().join("nobody-listens.sock")));
    assert_eq!(
        secrets.read("client-app").await.err(),
        Some(SecretError::Down)
    );
}
