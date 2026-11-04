//! Identity, default deny, deadline and correlation over a real Unix socket, through the
//! generated `StoreService` as the contract (every call between units is Connect over `proto/`,
//! even in a test). The uid table is a test's own (`Identities::with`); no flag reaches it.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use connectrpc::client::CallOptions;
use connectrpc::error::ErrorCode;
use connectrpc::{
    ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream,
};
use sluis_kit::{Allow, Identities, ServerConfig, correlation, dial, peer, refusal_reason};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, Item, ListRequest, ListResponse, StoreService, StoreServiceClient,
    StoreServiceExt, WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};

fn my_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// What a handler saw.
#[derive(Default, Clone, Debug)]
struct Seen {
    peer_name: Option<&'static str>,
    peer_uid: Option<u32>,
    left: Option<Duration>,
    correlation: Option<String>,
}

struct Fake {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Seen>>,
    /// Another server to call from the handler (to show what is passed on).
    onward: Option<sluis_kit::Client>,
}

impl StoreService for Fake {
    async fn get(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let p = peer(ctx.extensions());
        *self.seen.lock().unwrap() = Seen {
            peer_name: p.map(|p| p.name),
            peer_uid: p.map(|p| p.uid),
            left: ctx.time_remaining(),
            correlation: correlation::get(ctx.extensions()),
        };
        if let Some(onward) = &self.onward {
            let c = StoreServiceClient::new(onward.transport(), onward.config());
            c.get(GetRequest::default()).await?;
        }
        Response::ok(GetResponse {
            item: Some(Item {
                version: 7,
                ..Item::default()
            })
            .into(),
            ..GetResponse::default()
        })
    }

    async fn list(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        Err(sluis_kit::refusal(
            ErrorCode::InvalidArgument,
            "address",
            "address.id",
        ))
    }

    async fn write(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        Ok(Response::new(WriteResponse::default()))
    }

    async fn watch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Response::stream_ok(futures::stream::iter((1..=50u64).map(|n| {
            Ok(WatchResponse {
                resume_point: n,
                ..WatchResponse::default()
            })
        })))
    }
}

struct Running {
    client: sluis_kit::Client,
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Seen>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Running {
    async fn stop(mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        self.done.await.unwrap().unwrap();
    }
}

/// A server on `socket` for the actor `actor`, in which this process's uid is `caller`.
fn start(
    socket: &Path,
    actor: &'static str,
    allow: Allow,
    caller: Option<(&'static str, u32)>,
    own_block: u32,
    default_deadline: Duration,
    onward: Option<sluis_kit::Client>,
) -> Running {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let router = Arc::new(Fake {
        calls: calls.clone(),
        seen: seen.clone(),
        onward,
    })
    .register(Router::new());
    let me = my_uid();
    let ids = Identities::with(own_block, move |uid| if uid == me { caller } else { None });
    let cfg = ServerConfig {
        actor,
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o660,
        allow,
        default_deadline,
    };
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let done = tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        ids,
    ));
    Running {
        client: dial(socket),
        calls,
        seen,
        stop: Some(tx),
        done,
    }
}

async fn wait_for(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("socket {} did not appear", path.display());
}

fn store_client(r: &Running) -> StoreServiceClient<sluis_kit::Transport> {
    StoreServiceClient::new(r.client.transport(), r.client.config())
}

fn sock(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

#[tokio::test]
async fn the_uid_and_name_are_seen_by_the_handler() {
    let dir = tempfile::tempdir().unwrap();
    let s = sock(&dir, "store.sock");
    let r = start(
        &s,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s).await;
    let got = store_client(&r).get(GetRequest::default()).await.unwrap();
    assert_eq!(got.into_owned().item.version, 7);
    let seen = r.seen.lock().unwrap().clone();
    assert_eq!(seen.peer_uid, Some(my_uid()));
    assert_eq!(seen.peer_name, Some("policy"));
    r.stop().await;
}

#[tokio::test]
async fn call_graph_allows_an_edge_and_refuses_the_rest_before_the_handler() {
    // The pair is taken from the registry, not assumed: assert both facts first.
    let (allowed_caller, denied_caller, callee) = ("entry", "indexer", "session");
    assert!(
        sluis_registry::may_call(allowed_caller, callee),
        "registry: {allowed_caller} -> {callee}"
    );
    assert!(
        !sluis_registry::may_call(denied_caller, callee),
        "registry: {denied_caller} -/-> {callee}"
    );

    let dir = tempfile::tempdir().unwrap();
    let s1 = sock(&dir, "a.sock");
    let ok = start(
        &s1,
        callee,
        Allow::CallGraph,
        Some((allowed_caller, 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s1).await;
    store_client(&ok)
        .get(GetRequest::default())
        .await
        .expect("an allowed edge");
    assert_eq!(ok.calls.load(Ordering::SeqCst), 1);
    ok.stop().await;

    let s2 = sock(&dir, "b.sock");
    let no = start(
        &s2,
        callee,
        Allow::CallGraph,
        Some((denied_caller, 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s2).await;
    let e = store_client(&no)
        .get(GetRequest::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&e).as_deref(), Some("call_graph"));
    assert_eq!(
        no.calls.load(Ordering::SeqCst),
        0,
        "the handler must not be entered"
    );
    // A stream is refused as well, before the handler.
    let e = store_client(&no).watch(WatchRequest::default()).await;
    let e = match e {
        Err(e) => e,
        Ok(mut st) => st.message().await.map(|_| ()).unwrap_err(),
    };
    assert_eq!(refusal_reason(&e).as_deref(), Some("call_graph"));
    assert_eq!(no.calls.load(Ordering::SeqCst), 0);
    no.stop().await;
}

#[tokio::test]
async fn an_unknown_uid_and_another_boundary_get_caller() {
    let dir = tempfile::tempdir().unwrap();
    let s1 = sock(&dir, "u.sock");
    let unknown = start(
        &s1,
        "store",
        Allow::CallGraph,
        None,
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s1).await;
    let e = store_client(&unknown)
        .get(GetRequest::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(refusal_reason(&e).as_deref(), Some("caller"));
    assert_eq!(unknown.calls.load(Ordering::SeqCst), 0);
    unknown.stop().await;

    // The caller is a known actor, but of the boundary with uid block 1; the server is block 0.
    let s2 = sock(&dir, "o.sock");
    let other = start(
        &s2,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 1)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s2).await;
    let e = store_client(&other)
        .get(GetRequest::default())
        .await
        .unwrap_err();
    assert_eq!(refusal_reason(&e).as_deref(), Some("caller"));
    assert_eq!(other.calls.load(Ordering::SeqCst), 0);
    other.stop().await;
}

#[tokio::test]
async fn owner_only_admits_the_owner_alone() {
    let dir = tempfile::tempdir().unwrap();
    let s = sock(&dir, "d.sock");
    let r = start(
        &s,
        "driver-store-rqlite",
        Allow::OwnerOnly("store"),
        Some(("store", 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s).await;
    store_client(&r)
        .get(GetRequest::default())
        .await
        .expect("the owner");
    r.stop().await;
    let s = sock(&dir, "d2.sock");
    let r = start(
        &s,
        "driver-store-rqlite",
        Allow::OwnerOnly("store"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s).await;
    let e = store_client(&r)
        .get(GetRequest::default())
        .await
        .unwrap_err();
    assert_eq!(refusal_reason(&e).as_deref(), Some("call_graph"));
    r.stop().await;
}

#[tokio::test]
async fn a_client_deadline_reaches_the_handler_and_a_missing_one_gets_the_default() {
    let dir = tempfile::tempdir().unwrap();
    let s = sock(&dir, "t.sock");
    let r = start(
        &s,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(1),
        None,
    );
    wait_for(&s).await;
    let c = store_client(&r);
    c.get_with_options(
        GetRequest::default(),
        CallOptions::default().with_timeout(Duration::from_millis(200)),
    )
    .await
    .unwrap();
    let left = r.seen.lock().unwrap().left.expect("a deadline");
    assert!(
        left <= Duration::from_millis(200) && left > Duration::ZERO,
        "left = {left:?}"
    );

    c.get(GetRequest::default()).await.unwrap();
    let left = r.seen.lock().unwrap().left.expect("the default deadline");
    assert!(
        left <= Duration::from_secs(1) && left > Duration::from_millis(200),
        "left = {left:?}"
    );
    r.stop().await;
}

#[tokio::test]
async fn the_correlation_id_and_the_deadline_left_are_passed_on() {
    let dir = tempfile::tempdir().unwrap();
    let sb = sock(&dir, "b.sock");
    let b = start(
        &sb,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(30),
        None,
    );
    wait_for(&sb).await;
    let sa = sock(&dir, "a.sock");
    let a = start(
        &sa,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(30),
        Some(b.client.clone()),
    );
    wait_for(&sa).await;

    let opts = CallOptions::default()
        .with_timeout(Duration::from_secs(3))
        .with_header("sluis-correlation-id", "c0ffee");
    store_client(&a)
        .get_with_options(GetRequest::default(), opts)
        .await
        .unwrap();
    assert_eq!(
        a.seen.lock().unwrap().correlation.as_deref(),
        Some("c0ffee")
    );
    let at_b = b.seen.lock().unwrap().clone();
    assert_eq!(
        at_b.correlation.as_deref(),
        Some("c0ffee"),
        "passed on to the nested call"
    );
    let left = at_b.left.expect("the nested call carries a deadline");
    assert!(
        left <= Duration::from_secs(3),
        "never longer than the caller's: {left:?}"
    );
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_server_stream_of_50_arrives_in_order_and_a_refusal_keeps_its_detail() {
    let dir = tempfile::tempdir().unwrap();
    let s = sock(&dir, "s.sock");
    let r = start(
        &s,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s).await;
    let c = store_client(&r);
    let mut st = c.watch(WatchRequest::default()).await.unwrap();
    let mut n = 0u64;
    while let Some(m) = st.message().await.unwrap() {
        n += 1;
        assert_eq!(m.to_owned_message().resume_point, n);
    }
    assert_eq!(n, 50);

    let e: ConnectError = c.list(ListRequest::default()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(refusal_reason(&e).as_deref(), Some("address"));
    r.stop().await;
}

#[tokio::test]
async fn the_socket_has_its_mode_a_stale_file_is_replaced_and_a_symlink_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let s = sock(&dir, "m.sock");
    // A stale socket file from a crashed run.
    drop(std::os::unix::net::UnixListener::bind(&s).unwrap());
    assert!(s.exists());
    let r = start(
        &s,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    wait_for(&s).await;
    store_client(&r)
        .get(GetRequest::default())
        .await
        .expect("the stale file was replaced");
    let mode = std::fs::metadata(&s).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    r.stop().await;
    assert!(!s.exists(), "the socket file is removed at shutdown");

    // A symlink is in the way: refuse to start, and leave the target alone.
    let target = sock(&dir, "target");
    std::fs::write(&target, b"x").unwrap();
    let link = sock(&dir, "link.sock");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let r = start(
        &link,
        "store",
        Allow::Exact("policy"),
        Some(("policy", 0)),
        0,
        Duration::from_secs(5),
        None,
    );
    let err = r.done.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("symlink"), "{err:#}");
    assert_eq!(std::fs::read(&target).unwrap(), b"x");
}
