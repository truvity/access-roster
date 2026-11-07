//! The destination port over a real Unix socket against the directory driver: the contract (`proto/`) is the only
//! way in, the caller is known from the socket's peer uid, and the suite runs through the wire as well as in process.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::path::Path;
use std::sync::Arc;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use sluis_destination::rpc::{Client, Service};
use sluis_destination::suite::{Caps, run};
use sluis_destination::{Destination, Document, Error};
use sluis_driver_exporter_dir::{Directory, Until, suite};
use sluis_kit::{Allow, Identities, ServerConfig, dial};
use sluis_proto::sluis::port::destination::v2alpha1::{DestinationServiceClient, ReadBackRequest};

fn serve(socket: &Path, d: Directory, me_is: &'static str) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)));
    let cfg = ServerConfig {
        actor: "driver-exporter-dir",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow: Allow::OwnerOnly("exporter"),
        default_deadline: std::time::Duration::from_secs(10),
    };
    use sluis_proto::sluis::port::destination::v2alpha1::DestinationServiceExt;
    let router = Arc::new(Service(Arc::new(d))).register(Router::new());
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

fn doc(address: &str, body: &[u8]) -> Document {
    Document {
        address: address.into(),
        content_type: "application/json".into(),
        cache_control: "public, max-age=300".into(),
        body: body.to_vec(),
    }
}

/// The port's suite and the directory's own cases pass over temporary directories (what `conformance` runs).
///
/// verifies: REQ-EXPORT-027
#[tokio::test]
async fn the_destination_port_suite_passes_for_the_directory_driver() {
    suite::run_temp().await.unwrap();
}

/// The same suite through the Connect service, from exporter@'s side: every call crosses the wire and the driver's
/// socket answers exporter@ alone.
///
/// verifies: REQ-EXPORT-027
#[tokio::test]
async fn the_suite_passes_through_the_socket() {
    let (root, state) = suite::temp().unwrap();
    let s = tempfile::tempdir().unwrap();
    let sock = s.path().join("directory.sock");
    let stop = serve(
        &sock,
        Directory::open(root.path(), state.path()).unwrap(),
        "exporter",
    );
    up(&sock).await;
    let client = Client::new(&dial(&sock));
    run(&client, &Caps::default()).await.unwrap();
    // A directory has no public address: ReadBack is unsupported on the wire, as `unimplemented`.
    assert_eq!(
        client.read_back("https://sluis.example.com/jwks").await,
        Err(Error::Unsupported)
    );
    let raw = dial(&sock);
    let c = DestinationServiceClient::new(raw.transport(), raw.config());
    let e = c
        .read_back(ReadBackRequest {
            address: "https://sluis.example.com/jwks".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, sluis_kit::refusal_reason(&e).as_deref()),
        (ErrorCode::Unimplemented, Some("unsupported"))
    );
    let _ = stop.send(());
}

/// Only exporter@ may call the driver: any other caller is refused by the guard before the message is read.
#[tokio::test]
async fn another_caller_is_refused() {
    let (root, state) = suite::temp().unwrap();
    let s = tempfile::tempdir().unwrap();
    let sock = s.path().join("directory.sock");
    let stop = serve(
        &sock,
        Directory::open(root.path(), state.path()).unwrap(),
        "signer",
    );
    up(&sock).await;
    let e = Client::new(&dial(&sock))
        .put(doc("x", b"{}"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Unavailable(_)), "{e:?}");
    assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
    let _ = stop.send(());
}

/// A crash in the middle of a write leaves the old document, never half of one; a restart sweeps the stray file and
/// the next write is whole (REQ-EXPORT-020, ADR 0009: "written whole and atomically").
///
/// verifies: REQ-EXPORT-020
#[tokio::test]
async fn a_crash_mid_write_leaves_the_old_document_and_a_restart_cleans_up() {
    let (root, state) = suite::temp().unwrap();
    let d = Directory::open(root.path(), state.path()).unwrap();
    let live = root.path().join("jwks.json");
    d.put(doc("jwks.json", br#"{"keys":[1]}"#)).await.unwrap();

    // Crash 1: the new body is in a temporary file; nothing is renamed.
    d.put_until(&doc("jwks.json", br#"{"keys":[1,2]}"#), Until::Temp)
        .unwrap();
    assert_eq!(std::fs::read(&live).unwrap(), br#"{"keys":[1]}"#);
    let strays = || {
        std::fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .count()
    };
    assert_eq!(strays(), 1, "the crash left a temporary file");
    // A listing neither shows the stray file nor the half document.
    let l = d.list("", None, 0).await.unwrap().documents;
    assert_eq!(l.len(), 1);
    assert_eq!(
        l[0].sha256,
        sluis_destination::sha256_hex(br#"{"keys":[1]}"#)
    );

    // A restarted driver (a new Directory over the same directories) sweeps it.
    let d = Directory::open(root.path(), state.path()).unwrap();
    assert_eq!(d.sweep().unwrap(), 1);
    assert_eq!(strays(), 0);

    // Crash 2: the document is in place, its record is the old one. The listing reports the file's own digest.
    d.put_until(&doc("jwks.json", br#"{"keys":[3]}"#), Until::Document)
        .unwrap();
    assert_eq!(std::fs::read(&live).unwrap(), br#"{"keys":[3]}"#);
    let l = d.list("", None, 0).await.unwrap().documents;
    assert_eq!(
        l[0].sha256,
        sluis_destination::sha256_hex(br#"{"keys":[3]}"#)
    );

    // The next write is whole, and the record is current again.
    let w = d.put(doc("jwks.json", br#"{"keys":[3,4]}"#)).await.unwrap();
    assert_eq!(std::fs::read(&live).unwrap(), br#"{"keys":[3,4]}"#);
    assert_eq!(
        w.sha256,
        sluis_destination::sha256_hex(br#"{"keys":[3,4]}"#)
    );
    assert_eq!(strays(), 0);
}

/// The directories are checked at the start: a symlink, a wrong owner mode, a missing directory.
#[test]
fn the_directories_are_checked_at_the_start() {
    use std::os::unix::fs::PermissionsExt;
    let (root, state) = suite::temp().unwrap();
    assert!(Directory::open(root.path(), state.path()).is_ok());
    let link = root.path().join("link");
    std::os::unix::fs::symlink(root.path(), &link).unwrap();
    assert!(
        Directory::open(&link, state.path()).is_err(),
        "a symlink as the root"
    );
    assert!(Directory::open(&root.path().join("missing"), state.path()).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(
        Directory::open(root.path(), state.path()).is_err(),
        "a root others' group can write"
    );
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    // The state directory may be open to traverse (its records are in closed subdirectories), never to a write.
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let d = Directory::open(root.path(), state.path()).unwrap();
    assert_eq!(
        std::fs::metadata(state.path().join("meta"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    drop(d);
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(
        Directory::open(root.path(), state.path()).is_err(),
        "a state directory a group can write"
    );
}

/// A symlink planted inside the root is not followed by a write or a delete.
#[tokio::test]
async fn a_symlink_in_the_root_is_not_followed() {
    let (root, state) = suite::temp().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("out")).unwrap();
    let d = Directory::open(root.path(), state.path()).unwrap();
    assert!(d.put(doc("out/x.json", b"{}")).await.is_err());
    assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    std::os::unix::fs::symlink(outside.path().join("target"), root.path().join("jwks.json"))
        .unwrap();
    assert!(d.put(doc("jwks.json", b"{}")).await.is_err());
    assert!(!outside.path().join("target").exists());
}
