//! The config source over a real Unix socket: the contract (`proto/`) is the only way in, and the
//! caller is known from the socket's peer uid.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::path::Path;
use std::time::Duration;

use connectrpc::Router;
use connectrpc::error::ErrorCode;
use sluis_file::service::Service;
use sluis_file::{Dir, suite};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
use sluis_proto::sluis::port::source::v2alpha1::{
    CapabilitiesRequest, ReadRequest, SourceServiceClient, SourceServiceExt, SourceWatchRequest,
    Watch,
};

fn serve(socket: &Path, dir: &Path, me_is: &'static str) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)));
    let cfg = ServerConfig {
        actor: "driver-store-file",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
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

#[test]
fn the_source_suite_passes() {
    suite::run_temp().unwrap();
}

#[tokio::test]
async fn store_reads_a_document_and_every_refusal_names_a_reason() {
    let (docs, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let sock = s.path().join("config-source.sock");
    let stop = serve(&sock, docs.path(), "store");
    up(&sock).await;
    let client = dial(&sock);
    let c = SourceServiceClient::new(client.transport(), client.config());

    let caps = c
        .capabilities(CapabilitiesRequest::default())
        .await
        .unwrap()
        .into_owned();
    assert_eq!(caps.watch.as_known(), Some(Watch::NOTIFY));

    std::fs::write(docs.path().join("boundary.jws"), b"doc one").unwrap();
    let read = |name: &str, held: &str| {
        c.read(ReadRequest {
            name: name.into(),
            if_none_match: held.into(),
            ..Default::default()
        })
    };
    let first = read("boundary", "").await.unwrap().into_owned();
    assert_eq!(first.data, b"doc one");
    assert!(!first.unchanged);
    let again = read("boundary", &first.version).await.unwrap().into_owned();
    assert!(again.unchanged && again.data.is_empty() && again.version == first.version);
    let other = read("boundary", "not-the-label")
        .await
        .unwrap()
        .into_owned();
    assert!(!other.unchanged && other.data == b"doc one");

    let absent = read("upstream", "").await.unwrap_err();
    assert_eq!(
        (absent.code, refusal_reason(&absent).as_deref()),
        (ErrorCode::NotFound, Some("absent"))
    );
    let bad = read("../boundary", "").await.unwrap_err();
    assert_eq!(
        (bad.code, refusal_reason(&bad).as_deref()),
        (ErrorCode::InvalidArgument, Some("schema"))
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn watch_tells_of_a_replaced_and_a_removed_document_and_of_nothing_else() {
    let (docs, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let sock = s.path().join("config-source.sock");
    std::fs::write(docs.path().join("key-plan.jws"), b"one").unwrap();
    let stop = serve(&sock, docs.path(), "store");
    up(&sock).await;
    let client = dial(&sock);
    let c = SourceServiceClient::new(client.transport(), client.config());
    let held = c
        .read(ReadRequest {
            name: "key-plan".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned()
        .version;
    let mut w = c
        .watch(SourceWatchRequest {
            name: "key-plan".into(),
            ..Default::default()
        })
        .await
        .unwrap();

    // Nothing changes: nothing is said.
    assert!(
        tokio::time::timeout(Duration::from_millis(700), w.message())
            .await
            .is_err(),
        "told of a change that did not happen"
    );

    // The swap of a document, as a pipeline or a mounted ConfigMap does it: write beside, rename.
    std::fs::write(docs.path().join(".next"), b"two").unwrap();
    std::fs::rename(docs.path().join(".next"), docs.path().join("key-plan.jws")).unwrap();
    let said = tokio::time::timeout(Duration::from_secs(5), w.message())
        .await
        .expect("told within five seconds")
        .unwrap()
        .expect("the stream is open")
        .to_owned_message();
    assert_eq!(said.name, "key-plan");
    assert!(!said.version.is_empty() && said.version != held);

    std::fs::remove_file(docs.path().join("key-plan.jws")).unwrap();
    let gone = tokio::time::timeout(Duration::from_secs(5), w.message())
        .await
        .expect("told within five seconds")
        .unwrap()
        .expect("the stream is open")
        .to_owned_message();
    assert_eq!(
        (gone.name.as_str(), gone.version.as_str()),
        ("key-plan", "")
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn a_caller_that_is_not_store_is_refused_before_anything_is_read() {
    let (docs, s) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let sock = s.path().join("config-source.sock");
    std::fs::write(docs.path().join("boundary.jws"), b"doc").unwrap();
    let stop = serve(&sock, docs.path(), "policy");
    up(&sock).await;
    let client = dial(&sock);
    let c = SourceServiceClient::new(client.transport(), client.config());
    let e = c
        .read(ReadRequest {
            name: "boundary".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&e).as_deref(), Some("call_graph"));
    let _ = stop.send(());
}
