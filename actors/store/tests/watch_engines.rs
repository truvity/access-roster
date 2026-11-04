#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `Watch` end to end on both engines: store@ over the Connect client of a driver that passes the item suite, the
//! in-memory engine and the rqlite driver on a real rqlited (`just rqlite-fetch`; without the binary the rqlite
//! half prints `SKIP`, and `SLUIS_REQUIRE_RQLITED=1` makes that a failure). A delete and the re-creation that
//! follows it (before and while the watch is open), an expiry and the re-creation after it, and an item changed many times each end, for a consumer that
//! dedupes by the log sequence, with the right state.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connectrpc::error::ErrorCode;
use sluis_conformance::memory::MemoryEngine;
use sluis_kit::{Allow, Identities, ServerConfig, dial};
use sluis_proto::sluis::store::v2alpha1::{
    ChangeType, GetRequest, ListRequest, Operation, StoreServiceClient, StoreServiceExt as _, Verb,
    WatchRequest, WatchResponse, WriteRequest,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use sluis_rqlite::Driver;
use sluis_rqlite::client::Rq;
use sluis_rqlite::sql::Ns;
use store::audit::{AuditEvent, AuditSink};
use store::config::NoConfig;
use store::engine::DriverEngine;
use store::grant::{GrantOpener, OpenError};
use store::secret::NoSecrets;
use store::service::{Deps, Service};

/// `PinReleaseRequest`: a temp kind that key@ alone writes and watches, with a time to live.
const TEMP: &str = "pin-release-request";

type Sweeper = Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// store@ served over one engine, and the way to run that engine's sweeper once.
struct Rig {
    name: &'static str,
    client: StoreServiceClient<sluis_kit::Transport>,
    sweep: Sweeper,
    _keep: Vec<Box<dyn std::any::Any + Send>>,
}

struct NoGrants;
impl GrantOpener for NoGrants {
    async fn open(
        &self,
        _sealed: &[u8],
    ) -> Result<sluis_proto::sluis::r#type::v2alpha1::Grant, OpenError> {
        Err(OpenError::Refused)
    }
}

struct Quiet;
impl AuditSink for Quiet {
    async fn emit(&self, _event: AuditEvent) -> Result<(), String> {
        Ok(())
    }
}

async fn wait_for(path: &Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} did not appear", path.display());
}

/// Serves store@ as `key` over the two driver engines, and dials it.
async fn serve_store(
    dir: &Path,
    durable: &Path,
    temp: &Path,
) -> StoreServiceClient<sluis_kit::Transport> {
    let svc = Service::new(Deps {
        boundary: "dev".into(),
        durable: DriverEngine::new(&dial(durable), "durable"),
        temp: DriverEngine::new(&dial(temp), "temp"),
        grants: NoGrants,
        config: Arc::new(NoConfig),
        secrets: Arc::new(NoSecrets),
        audit: Quiet,
        clock: Arc::new(SystemTime::now),
    })
    .with_watch_timing(Duration::from_secs(30), Duration::from_millis(50));
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |u| (u == me).then_some(("key", 0)));
    let sock = dir.join("store.sock");
    tokio::spawn(sluis_kit::serve_with(
        ServerConfig {
            actor: "store",
            boundary: "dev".into(),
            socket: sock.clone(),
            mode: 0o660,
            socket_gid: None,
            allow: Allow::CallGraph,
            default_deadline: Duration::from_secs(10),
        },
        Arc::new(svc).register(connectrpc::Router::new()),
        std::future::pending(),
        ids,
    ));
    wait_for(&sock).await;
    let c = dial(&sock);
    StoreServiceClient::new(c.transport(), c.config())
}

async fn memory_rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let (durable, temp) = (MemoryEngine::new(), MemoryEngine::new());
    let (dsock, tsock) = (
        dir.path().join("durable.sock"),
        dir.path().join("temp.sock"),
    );
    for (engine, sock) in [
        (durable.clone(), dsock.clone()),
        (temp.clone(), tsock.clone()),
    ] {
        tokio::spawn(async move { engine.serve(&sock, std::future::pending()).await });
    }
    wait_for(&dsock).await;
    wait_for(&tsock).await;
    let client = serve_store(dir.path(), &dsock, &tsock).await;
    let swept = temp.clone();
    Rig {
        name: "memory",
        client,
        sweep: Box::new(move || {
            let t = swept.clone();
            Box::pin(async move { t.sweep() })
        }),
        _keep: vec![Box::new(dir)],
    }
}

// ---- rqlite ----

struct Node {
    child: Child,
    url: String,
    _dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn rqlited() -> Option<PathBuf> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("no rqlite release for {other}"),
    };
    let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".cache/rqlite")
        .join(format!("linux-{arch}/rqlited"));
    if bin.is_file() {
        return Some(bin);
    }
    assert!(
        std::env::var_os("SLUIS_REQUIRE_RQLITED").is_none(),
        "rqlited is not fetched ({}) and the test is required to run: run just rqlite-fetch",
        bin.display()
    );
    println!("SKIP: rqlited not fetched; run just rqlite-fetch");
    None
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_node(bin: &Path) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let (http, raft) = (free_port(), free_port());
    let child = Command::new(bin)
        .args(["-node-id", "n1"])
        .arg("-http-addr")
        .arg(format!("127.0.0.1:{http}"))
        .arg("-raft-addr")
        .arg(format!("127.0.0.1:{raft}"))
        .arg(dir.path().join("data"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start rqlited");
    let node = Node {
        child,
        url: format!("http://127.0.0.1:{http}"),
        _dir: dir,
    };
    let rq = Rq::new(&node.url, None).unwrap();
    for _ in 0..300 {
        if rq.is_leader().await.unwrap_or(false) {
            return node;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("rqlited did not become the leader of its one-node cluster");
}

/// Serves `driver` on `sock` with this process's uid as the owner `store`.
fn serve_driver(driver: &Driver, sock: PathBuf) {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some(("store", 0)));
    tokio::spawn(sluis_kit::serve_with(
        ServerConfig {
            actor: "driver-store-rqlite",
            boundary: "dev".into(),
            socket: sock,
            mode: 0o600,
            socket_gid: None,
            allow: Allow::OwnerOnly("store"),
            default_deadline: Duration::from_secs(30),
        },
        driver.clone().router(),
        std::future::pending(),
        ids,
    ));
}

async fn rqlite_rig() -> Option<Rig> {
    let bin = rqlited()?;
    let node = start_node(&bin).await;
    let dir = tempfile::tempdir().unwrap();
    let mk = |ns: &str| Driver::new(Rq::new(&node.url, None).unwrap(), Ns::new(ns).unwrap());
    let (durable, temp) = (mk("durable"), mk("temp"));
    durable.ensure_schema().await.unwrap();
    temp.ensure_schema().await.unwrap();
    let (dsock, tsock) = (
        dir.path().join("durable.sock"),
        dir.path().join("temp.sock"),
    );
    serve_driver(&durable, dsock.clone());
    serve_driver(&temp, tsock.clone());
    wait_for(&dsock).await;
    wait_for(&tsock).await;
    let client = serve_store(dir.path(), &dsock, &tsock).await;
    let swept = temp.clone();
    Some(Rig {
        name: "rqlite",
        client,
        sweep: Box::new(move || {
            let t = swept.clone();
            Box::pin(async move {
                sluis_rqlite::sweeper::sweep_once(&t, Duration::from_secs(3600))
                    .await
                    .unwrap();
            })
        }),
        _keep: vec![Box::new(dir), Box::new(node)],
    })
}

// ---- the scenarios ----

fn operation(verb: Verb, id: &str, value: &[u8], ttl: Option<i64>) -> Operation {
    Operation {
        verb: verb.into(),
        address: Address {
            kind: TEMP.into(),
            id: id.into(),
            ..Address::default()
        }
        .into(),
        value: value.to_vec(),
        ttl: ttl
            .map(|secs| buffa_types::google::protobuf::Duration {
                seconds: secs,
                ..Default::default()
            })
            .into(),
        ..Operation::default()
    }
}

impl Rig {
    async fn write(&self, op: Operation) {
        self.client
            .write(WriteRequest {
                operations: vec![op],
                ..WriteRequest::default()
            })
            .await
            .unwrap_or_else(|e| panic!("{}: write: {e:?}", self.name));
    }

    async fn position(&self) -> u64 {
        self.client
            .list(ListRequest {
                kind: TEMP.into(),
                ..ListRequest::default()
            })
            .await
            .unwrap()
            .into_owned()
            .resume_point
    }

    /// Everything the watch says from `from` until it is quiet for a while.
    async fn changes(&self, from: u64) -> Vec<WatchResponse> {
        let mut stream = self
            .client
            .watch(WatchRequest {
                kind: TEMP.into(),
                resume_point: from,
                ..WatchRequest::default()
            })
            .await
            .unwrap();
        let mut out = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(2), stream.message()).await {
                Err(_) | Ok(Ok(None)) => return out,
                Ok(Ok(Some(m))) => out.push(m.to_owned_message()),
                Ok(Err(e)) => panic!("{}: the watch failed: {e:?}", self.name),
            }
        }
    }

    async fn value_of(&self, id: &str) -> Option<Vec<u8>> {
        match self
            .client
            .get(GetRequest {
                address: Address {
                    kind: TEMP.into(),
                    id: id.into(),
                    ..Address::default()
                }
                .into(),
                ..GetRequest::default()
            })
            .await
        {
            Ok(r) => Some(r.into_owned().item.as_option().unwrap().value.clone()),
            Err(e) if e.code == ErrorCode::NotFound => None,
            Err(e) => panic!("{}: get: {e:?}", self.name),
        }
    }
}

fn kind_of(m: &WatchResponse) -> ChangeType {
    m.r#type.as_known().expect("a known change type")
}

fn id_of(m: &WatchResponse) -> String {
    m.item
        .as_option()
        .expect("an item")
        .address
        .as_option()
        .expect("an address")
        .id
        .clone()
}

/// What a consumer holds if it dedupes by the log sequence: a change at or below what it has applied is a repeat.
#[derive(Default)]
struct Consumer {
    state: std::collections::BTreeMap<String, Vec<u8>>,
    applied: u64,
    deletes: Vec<String>,
}

impl Consumer {
    fn apply(&mut self, m: &WatchResponse) {
        if kind_of(m) == ChangeType::CHANGE_TYPE_BOOKMARK || m.resume_point <= self.applied {
            return;
        }
        self.applied = m.resume_point;
        let id = id_of(m);
        if kind_of(m) == ChangeType::CHANGE_TYPE_DELETE {
            self.state.remove(&id);
            self.deletes.push(id);
        } else {
            self.state
                .insert(id, m.item.as_option().unwrap().value.clone());
        }
    }
}

async fn delete_then_re_create(rig: &Rig) {
    let from = rig.position().await;
    rig.write(operation(Verb::CREATE, "node-a/n1", b"old", Some(600)))
        .await;
    rig.write(operation(Verb::DELETE, "node-a/n1", b"", None))
        .await;
    rig.write(operation(Verb::CREATE, "node-a/n1", b"new", Some(600)))
        .await;
    let seen = rig.changes(from).await;
    let types: Vec<_> = seen.iter().map(kind_of).collect();
    let delete = types
        .iter()
        .position(|t| *t == ChangeType::CHANGE_TYPE_DELETE);
    let last_put = types
        .iter()
        .rposition(|t| *t == ChangeType::CHANGE_TYPE_PUT);
    assert!(
        delete.is_some() && last_put > delete,
        "{}: the delete, then the new put: {types:?}",
        rig.name
    );
    let mut c = Consumer::default();
    for m in &seen {
        c.apply(m);
    }
    assert_eq!(
        c.state.get("node-a/n1"),
        Some(&b"new".to_vec()),
        "{}: the consumer holds the new value",
        rig.name
    );
    assert_eq!(rig.value_of("node-a/n1").await, Some(b"new".to_vec()));
}

/// The watch is open while the item is made, delivered, removed and made again at version 1: the old value was
/// delivered at (address, 1), so a stream or a consumer that dedupes by the version would drop the new one.
async fn delete_then_re_create_while_watching(rig: &Rig) {
    let from = rig.position().await;
    let mut stream = rig
        .client
        .watch(WatchRequest {
            kind: TEMP.into(),
            resume_point: from,
            ..WatchRequest::default()
        })
        .await
        .unwrap();
    rig.write(operation(Verb::CREATE, "node-a/w1", b"old", Some(600)))
        .await;
    let mut c = Consumer::default();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("the first change in time")
        .unwrap()
        .expect("a change")
        .to_owned_message();
    assert_eq!(
        (
            kind_of(&first),
            first.item.as_option().unwrap().value.as_slice()
        ),
        (ChangeType::CHANGE_TYPE_PUT, b"old".as_slice()),
        "{}",
        rig.name
    );
    c.apply(&first);
    rig.write(operation(Verb::DELETE, "node-a/w1", b"", None))
        .await;
    rig.write(operation(Verb::CREATE, "node-a/w1", b"new", Some(600)))
        .await;
    let mut types = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), stream.message()).await {
            Err(_) | Ok(Ok(None)) => break,
            Ok(Ok(Some(m))) => {
                let m = m.to_owned_message();
                types.push(kind_of(&m));
                c.apply(&m);
            }
            Ok(Err(e)) => panic!("{}: the watch failed: {e:?}", rig.name),
        }
    }
    assert_eq!(
        types,
        vec![ChangeType::CHANGE_TYPE_DELETE, ChangeType::CHANGE_TYPE_PUT],
        "{}: the delete, then the new put",
        rig.name
    );
    assert_eq!(
        c.state.get("node-a/w1"),
        Some(&b"new".to_vec()),
        "{}: the consumer holds the new value",
        rig.name
    );
}

async fn expiry_then_re_create(rig: &Rig) {
    let from = rig.position().await;
    rig.write(operation(Verb::CREATE, "node-a/x1", b"first", Some(1)))
        .await;
    tokio::time::sleep(Duration::from_millis(1400)).await;
    (rig.sweep)().await;
    rig.write(operation(Verb::CREATE, "node-a/x1", b"second", Some(600)))
        .await;
    let seen = rig.changes(from).await;
    let mut c = Consumer::default();
    for m in &seen {
        c.apply(m);
    }
    assert_eq!(
        c.deletes,
        vec!["node-a/x1".to_owned()],
        "{}: the expiry was delivered as a delete",
        rig.name
    );
    assert_eq!(
        c.state.get("node-a/x1"),
        Some(&b"second".to_vec()),
        "{}: the consumer holds the value made after the expiry",
        rig.name
    );
}

async fn many_changes_end_with_the_last(rig: &Rig) {
    let from = rig.position().await;
    rig.write(operation(Verb::CREATE, "node-a/m1", b"v0", Some(600)))
        .await;
    for i in 1..=20u64 {
        rig.write(Operation {
            if_version: i,
            ..operation(Verb::UPDATE, "node-a/m1", format!("v{i}").as_bytes(), None)
        })
        .await;
    }
    let seen = rig.changes(from).await;
    let mut c = Consumer::default();
    for m in &seen {
        c.apply(m);
    }
    assert_eq!(
        c.state.get("node-a/m1"),
        Some(&b"v20".to_vec()),
        "{}",
        rig.name
    );
    // At-least-once, in order: the sequence only grows.
    assert!(
        seen.windows(2)
            .all(|p| p[0].resume_point <= p[1].resume_point),
        "{}: out of order",
        rig.name
    );
}

/// verifies: REQ-DATA-100, REQ-DATA-101
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_the_memory_engine_a_consumer_by_sequence_ends_with_the_right_state() {
    let rig = memory_rig().await;
    delete_then_re_create(&rig).await;
    delete_then_re_create_while_watching(&rig).await;
    expiry_then_re_create(&rig).await;
    many_changes_end_with_the_last(&rig).await;
}

/// verifies: REQ-DATA-100, REQ-DATA-101
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_rqlite_a_consumer_by_sequence_ends_with_the_right_state() {
    let Some(rig) = rqlite_rig().await else {
        return;
    };
    delete_then_re_create(&rig).await;
    delete_then_re_create_while_watching(&rig).await;
    expiry_then_re_create(&rig).await;
    many_changes_end_with_the_last(&rig).await;
}
