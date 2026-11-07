#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `Watch` end to end on both engines: store@ over the Connect client of a driver that passes the item suite, the
//! in-memory engine and the rqlite driver on a real rqlited (`just rqlite-fetch`; without the binary the rqlite
//! half prints `SKIP`, and `SLUIS_REQUIRE_RQLITED=1` makes that a failure). A delete and the re-creation that
//! follows it (before and while the watch is open), an expiry and the re-creation after it, and an item changed many times each end, for a consumer that
//! dedupes by the log sequence, with the right state. The same rigs show that an item re-created after a delete or a
//! sweep is at version 1, that two store@ instances with different clocks leave the timestamps they computed
//! themselves, and that takers racing for a lease have one winner and a fencing token that grows by one at each takeover.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connectrpc::error::ErrorCode;
use sluis_conformance::memory::MemoryEngine;
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal_reason};
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
use store::service::{Clock, Deps, Service};

/// `PinReleaseRequest`: a temp kind that key@ alone writes and watches, with a time to live.
const TEMP: &str = "pin-release-request";

type Sweeper = Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// store@ served over one engine, and the way to run that engine's sweeper once.
struct Rig {
    name: &'static str,
    client: StoreServiceClient<sluis_kit::Transport>,
    sweep: Sweeper,
    /// Makes the change log of the temp engine again, as a reset of its database or a restore into a new one does: no
    /// items, the sequence begins again, the log has a new epoch.
    reset: Sweeper,
    /// Where the engines are served, so that a second store@ can be served over the same ones.
    dir: PathBuf,
    durable_sock: PathBuf,
    temp_sock: PathBuf,
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
    serve_store_every(dir, durable, temp, Duration::from_secs(30)).await
}

/// The same, with the interval of the idle bookmark (and of the renewal of the claim) the test needs.
async fn serve_store_every(
    dir: &Path,
    durable: &Path,
    temp: &Path,
    every: Duration,
) -> StoreServiceClient<sluis_kit::Transport> {
    serve_store_with(
        dir,
        "store.sock",
        durable,
        temp,
        Arc::new(SystemTime::now),
        every,
    )
    .await
}

/// The same, on the socket `name` and with the given clock.
async fn serve_store_as(
    dir: &Path,
    name: &str,
    durable: &Path,
    temp: &Path,
    clock: Clock,
) -> StoreServiceClient<sluis_kit::Transport> {
    serve_store_with(dir, name, durable, temp, clock, Duration::from_secs(30)).await
}

async fn serve_store_with(
    dir: &Path,
    name: &str,
    durable: &Path,
    temp: &Path,
    clock: Clock,
    every: Duration,
) -> StoreServiceClient<sluis_kit::Transport> {
    let svc = Service::new(Deps {
        boundary: "dev".into(),
        durable: DriverEngine::new(&dial(durable), "durable"),
        temp: DriverEngine::new(&dial(temp), "temp"),
        grants: NoGrants,
        config: Arc::new(NoConfig),
        secrets: Arc::new(NoSecrets),
        audit: Quiet,
        clock,
    })
    .with_watch_timing(every, Duration::from_millis(50));
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |u| (u == me).then_some(("key", 0)));
    let sock = dir.join(name);
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
    let reset = temp.clone();
    Rig {
        name: "memory",
        client,
        sweep: Box::new(move || {
            let t = swept.clone();
            Box::pin(async move { t.sweep() })
        }),
        reset: Box::new(move || {
            let t = reset.clone();
            Box::pin(async move { t.reset() })
        }),
        dir: dir.path().to_path_buf(),
        durable_sock: dsock,
        temp_sock: tsock,
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
    rqlite_rig_through(false, Duration::from_secs(30))
        .await
        .map(|(rig, _)| rig)
}

async fn rqlite_rig_through_short_interval() -> Option<(Rig, Option<Arc<Proxy>>)> {
    rqlite_rig_through(true, Duration::from_millis(600)).await
}

/// A TCP proxy in front of rqlited that records the `level` of every query that passes and can hold the `weak` ones, as a
/// replica that lags (or a node that was deposed) shows the rows late: the reads of the rows of a tail are `weak`.
struct Proxy {
    url: String,
    levels: Arc<std::sync::Mutex<Vec<String>>>,
    hold_weak: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn proxy(target: &str) -> Proxy {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = target.trim_start_matches("http://").to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let levels = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hold_weak = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (seen, hold) = (levels.clone(), hold_weak.clone());
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let Ok(server) = tokio::net::TcpStream::connect(&target).await else {
                continue;
            };
            let (seen, hold) = (seen.clone(), hold.clone());
            tokio::spawn(async move {
                let (mut sr, mut sw) = server.into_split();
                let (mut cr, mut cw) = client.split();
                let up = async {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        let n = cr.read(&mut buf).await?;
                        if n == 0 {
                            return std::io::Result::Ok(());
                        }
                        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                        let mut weak = false;
                        for part in text.split("/db/query?level=").skip(1) {
                            let level: String = part
                                .chars()
                                .take_while(|c| c.is_ascii_alphabetic())
                                .collect();
                            weak |= level == "weak";
                            seen.lock().unwrap().push(level);
                        }
                        while weak && hold.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        sw.write_all(&buf[..n]).await?;
                    }
                };
                let down = tokio::io::copy(&mut sr, &mut cw);
                let _ = tokio::join!(up, down);
            });
        }
    });
    Proxy {
        url,
        levels,
        hold_weak,
        task,
    }
}

async fn rqlite_rig_through(
    through_proxy: bool,
    every: Duration,
) -> Option<(Rig, Option<Arc<Proxy>>)> {
    let bin = rqlited()?;
    let node = start_node(&bin).await;
    let dir = tempfile::tempdir().unwrap();
    let px = if through_proxy {
        Some(Arc::new(proxy(&node.url).await))
    } else {
        None
    };
    // The temp engine is the one the proxy stands in front of.
    let mk = |ns: &str| {
        let url = match (&px, ns) {
            (Some(p), "temp") => p.url.clone(),
            _ => node.url.clone(),
        };
        Driver::new(Rq::new(&url, None).unwrap(), Ns::new(ns).unwrap())
    };
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
    let client = serve_store_every(dir.path(), &dsock, &tsock, every).await;
    let swept = temp.clone();
    let reset = temp.clone();
    let rig = Rig {
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
        reset: Box::new(move || {
            let t = reset.clone();
            Box::pin(async move {
                // Every table of the namespace goes, and the schema is made again: a new database. One transaction, so that
                // a stream that is open polls the old log or the new one and never a database with no tables, which it
                // would end on with `engine` and not with the refusal of an epoch that the scenario is about.
                let epoch =
                    i64::try_from(sluis_conformance::rules::new_log_epoch().unwrap()).unwrap();
                let mut stmts: Vec<_> = ["items", "index", "log", "meta", "guard"]
                    .iter()
                    .map(|n| {
                        sluis_rqlite::client::Stmt::new(
                            format!("DROP TABLE IF EXISTS temp_{n}"),
                            vec![],
                        )
                    })
                    .collect();
                stmts.extend(sluis_rqlite::sql::Ns::new("temp").unwrap().ddl(epoch));
                let out = t.rq().request(&stmts, true).await.unwrap();
                assert!(
                    sluis_rqlite::client::first_failure(&out).is_none(),
                    "{out:?}"
                );
            })
        }),
        dir: dir.path().to_path_buf(),
        durable_sock: dsock,
        temp_sock: tsock,
        _keep: vec![Box::new(dir), Box::new(node)],
    };
    Some((rig, px))
}

// ---- the scenarios ----

fn operation(verb: Verb, id: &str, value: &[u8], ttl: Option<i64>) -> Operation {
    operation_of(TEMP, verb, id, value, ttl)
}

fn operation_of(kind: &str, verb: Verb, id: &str, value: &[u8], ttl: Option<i64>) -> Operation {
    Operation {
        verb: verb.into(),
        address: Address {
            kind: kind.into(),
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

/// store@ over the engines of `rig` with its own clock, on a socket of its own: a second node of the same installation.
impl Rig {
    async fn store_with_clock(
        &self,
        name: &str,
        at: SystemTime,
    ) -> StoreServiceClient<sluis_kit::Transport> {
        serve_store_as(
            &self.dir,
            name,
            &self.durable_sock,
            &self.temp_sock,
            Arc::new(move || at),
        )
        .await
    }

    /// A write that may be refused, through the store@ of the rig.
    async fn try_write(&self, op: Operation) -> Result<u64, connectrpc::ConnectError> {
        write_through(&self.client, op).await
    }

    /// A write that must succeed; the version it gave the item.
    async fn write(&self, op: Operation) -> u64 {
        self.try_write(op)
            .await
            .unwrap_or_else(|e| panic!("{}: write: {e:?}", self.name))
    }

    async fn position(&self) -> u64 {
        self.listing().await.0
    }

    /// The position of a listing of the temp kind, and the epoch of the log it belongs to.
    async fn listing(&self) -> (u64, u64) {
        let l = self
            .client
            .list(ListRequest {
                kind: TEMP.into(),
                ..ListRequest::default()
            })
            .await
            .unwrap()
            .into_owned();
        (l.resume_point, l.log_epoch)
    }

    /// The ids that a listing of the temp kind holds.
    async fn listed_ids(&self) -> Vec<String> {
        let l = self
            .client
            .list(ListRequest {
                kind: TEMP.into(),
                ..ListRequest::default()
            })
            .await
            .unwrap()
            .into_owned();
        l.items
            .iter()
            .map(|i| i.address.as_option().unwrap().id.clone())
            .collect()
    }

    /// The refusal a watch from this position is given, at the call or as the first thing the stream says.
    async fn refused(&self, from: u64, epoch: u64) -> connectrpc::ConnectError {
        let opened = self
            .client
            .watch(WatchRequest {
                kind: TEMP.into(),
                resume_point: from,
                log_epoch: epoch,
                ..WatchRequest::default()
            })
            .await;
        match opened {
            Err(e) => e,
            Ok(mut stream) => {
                match tokio::time::timeout(Duration::from_secs(5), stream.message()).await {
                    Ok(Err(e)) => e,
                    other => panic!(
                        "{}: the watch from ({from}, {epoch}) was not refused: {other:?}",
                        self.name
                    ),
                }
            }
        }
    }

    /// Everything the watch says from `from` in the log as it is, until it is quiet for a while.
    async fn changes(&self, from: u64) -> Vec<WatchResponse> {
        let epoch = self.listing().await.1;
        self.changes_in(from, epoch).await
    }

    /// The same, under the epoch given with the position.
    async fn changes_in(&self, from: u64, epoch: u64) -> Vec<WatchResponse> {
        let mut stream = self
            .client
            .watch(WatchRequest {
                kind: TEMP.into(),
                resume_point: from,
                log_epoch: epoch,
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

trait WithVersion {
    fn with_version(self, v: u64) -> Self;
}

impl WithVersion for Operation {
    fn with_version(mut self, v: u64) -> Self {
        self.if_version = v;
        self
    }
}

async fn write_through(
    client: &StoreServiceClient<sluis_kit::Transport>,
    op: Operation,
) -> Result<u64, connectrpc::ConnectError> {
    let done = client
        .write(WriteRequest {
            operations: vec![op],
            ..WriteRequest::default()
        })
        .await?
        .into_owned();
    Ok(done.items.first().map_or(0, |i| i.version))
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

/// What a consumer of a watch holds, as the store API tells it to behave:
/// - a change of the log carries its sequence, and one at or below the sequence applied is a repeat (at-least-once);
///   a version is not an identity, because a re-created item starts again at 1;
/// - a config change has no sequence (resume point 0) and is applied, every one; a config watch begins with the full
///   snapshot, and the items before the first bookmark replace the state of the kind.
#[derive(Default)]
struct Consumer {
    state: std::collections::BTreeMap<String, Vec<u8>>,
    applied: u64,
    /// The epoch of the log the applied sequence belongs to: the sequence is an order only inside it.
    epoch: u64,
    deletes: Vec<String>,
    /// The items of a config watch's opening snapshot, until its first bookmark.
    opening: std::collections::BTreeMap<String, Vec<u8>>,
    synced: bool,
}

impl Consumer {
    /// A consumer of a config kind, which begins with what a listing gave it.
    #[allow(dead_code)] // one of the two test files watches a config kind
    fn listed(state: std::collections::BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            state,
            ..Self::default()
        }
    }

    fn apply(&mut self, m: &WatchResponse) {
        let config = m.resume_point == 0;
        if kind_of(m) == ChangeType::CHANGE_TYPE_BOOKMARK {
            // The first bookmark of a config watch closes its snapshot: it replaces the state of the kind.
            if config && !self.synced {
                self.state = std::mem::take(&mut self.opening);
                self.synced = true;
            }
            return;
        }
        if config {
            if !self.synced {
                if kind_of(m) == ChangeType::CHANGE_TYPE_PUT {
                    self.opening
                        .insert(id_of(m), m.item.as_option().unwrap().value.clone());
                }
                return;
            }
        } else {
            // A consumer that dedupes by sequence does so inside one log: a message of another epoch is for a consumer
            // that listed the new log, not for this one.
            if self.epoch == 0 {
                self.epoch = m.log_epoch;
            }
            assert_eq!(m.log_epoch, self.epoch, "a message of another log");
            if m.resume_point <= self.applied {
                return;
            }
            self.applied = m.resume_point;
        }
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
    rig.write(operation(Verb::UPDATE, "node-a/n1", b"older", None).with_version(1))
        .await;
    rig.write(operation(Verb::DELETE, "node-a/n1", b"", None))
        .await;
    let again = rig
        .write(operation(Verb::CREATE, "node-a/n1", b"new", Some(600)))
        .await;
    assert_eq!(again, 1, "{}: re-created after a delete", rig.name);
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
            log_epoch: rig.listing().await.1,
            ..WatchRequest::default()
        })
        .await
        .unwrap();
    rig.write(operation(Verb::CREATE, "node-a/w1", b"old", Some(600)))
        .await;
    let mut c = Consumer::default();
    // The stream is opened with nothing behind it: its first message says it is caught up, and the change follows.
    let caught = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("the caught-up bookmark in time")
        .unwrap()
        .expect("a message")
        .to_owned_message();
    assert!(
        kind_of(&caught) == ChangeType::CHANGE_TYPE_BOOKMARK && caught.caught_up,
        "{}: {caught:?}",
        rig.name
    );
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
    let again = rig
        .write(operation(Verb::CREATE, "node-a/w1", b"new", Some(600)))
        .await;
    assert_eq!(again, 1, "{}: re-created after a delete", rig.name);
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
    // Made to last, then shortened by the update (which sets the expiry from its own clock): the 1 s starts at the
    // update, so a slow runner between the two calls cannot let the item expire before the version-2 write.
    rig.write(operation(Verb::CREATE, "node-a/x1", b"first", Some(600)))
        .await;
    let updated = rig
        .write(operation(Verb::UPDATE, "node-a/x1", b"first-again", Some(1)).with_version(1))
        .await;
    assert_eq!(updated, 2, "{}: the update after the create", rig.name);
    tokio::time::sleep(Duration::from_millis(1400)).await;
    (rig.sweep)().await;
    let again = rig
        .write(operation(Verb::CREATE, "node-a/x1", b"second", Some(600)))
        .await;
    assert_eq!(again, 1, "{}: re-created after a sweep", rig.name);
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

/// A frozen clock at `secs` seconds since the epoch.
fn frozen(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

async fn expiry_of(client: &StoreServiceClient<sluis_kit::Transport>, id: &str) -> i64 {
    client
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
        .unwrap()
        .into_owned()
        .item
        .as_option()
        .unwrap()
        .expires_at
        .as_option()
        .expect("an expiry")
        .seconds
}

/// Two store@ instances over the same engines, one a day ahead of the other: each item carries the expiry that the
/// instance which wrote it computed from its own clock, a later write replaces it with the later writer's own, and the
/// engine adds none of its own (a client has no field for a time other than the time to live).
async fn two_nodes_leave_the_timestamps_they_computed(rig: &Rig) {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (a_now, b_now) = (secs, secs + 86_400);
    let a = rig.store_with_clock("node-a.sock", frozen(a_now)).await;
    let b = rig.store_with_clock("node-b.sock", frozen(b_now)).await;
    let ttl = |id: &str, ttl: i64| operation(Verb::CREATE, id, b"v", Some(ttl));
    write_through(&a, ttl("node-a/c1", 600)).await.unwrap();
    write_through(&b, ttl("node-b/c1", 600)).await.unwrap();
    let want = |now: u64, ttl: u64| i64::try_from(now + ttl).unwrap();
    // Read through node a, whose clock is behind both: an item that the node ahead wrote is not yet past its expiry for
    // it. (Node b would read node a's item as expired, which is the expiry store@ computed, kept.)
    assert_eq!(
        expiry_of(&a, "node-a/c1").await,
        want(a_now, 600),
        "{}: written by the node behind",
        rig.name
    );
    assert_eq!(
        expiry_of(&a, "node-b/c1").await,
        want(b_now, 600),
        "{}: written by the node ahead",
        rig.name
    );
    // Node b changes the item that node a made: the time is b's now.
    write_through(
        &b,
        operation(Verb::UPDATE, "node-a/c1", b"w", Some(300)).with_version(1),
    )
    .await
    .unwrap();
    assert_eq!(
        expiry_of(&a, "node-a/c1").await,
        want(b_now, 300),
        "{}: an update sets the time again, from the clock of whoever wrote it",
        rig.name
    );
}

/// Takers racing for one lease through store@: one wins each round, the version is the fencing token and grows by one at
/// each takeover, and the ones that lose are told why (the lease is taken, or the version they read is stale).
async fn lease_takers_have_one_winner(rig: &Rig) {
    const TAKERS: usize = 6;
    assert_eq!(
        sluis_registry::kind_by_name("Lease").map(|k| k.class),
        Some(sluis_registry::Class::Temp),
        "the lease is a temp kind"
    );
    let lease = |verb, who: usize, v| {
        operation_of(
            "lease",
            verb,
            "key/race",
            format!("taker-{who}").as_bytes(),
            None,
        )
        .with_version(v)
    };
    for round in 0..4u64 {
        let tries = futures::future::join_all((0..TAKERS).map(|i| async move {
            let op = if round == 0 {
                lease(Verb::CREATE, i, 0)
            } else {
                lease(Verb::UPDATE, i, round)
            };
            (i, rig.try_write(op).await)
        }))
        .await;
        let mut winner = None;
        for (i, r) in tries {
            match r {
                Ok(version) => {
                    assert!(
                        winner.is_none(),
                        "{}: two winners in round {round}",
                        rig.name
                    );
                    assert_eq!(
                        version,
                        round + 1,
                        "{}: the token of round {round}",
                        rig.name
                    );
                    winner = Some(i);
                }
                Err(e) => {
                    let (code, why) = if round == 0 {
                        (ErrorCode::AlreadyExists, "taken")
                    } else {
                        (ErrorCode::Aborted, "version")
                    };
                    assert_eq!(
                        (e.code, refusal_reason(&e).as_deref()),
                        (code, Some(why)),
                        "{}: a loser of round {round}",
                        rig.name
                    );
                }
            }
        }
        let winner = winner.unwrap_or_else(|| panic!("{}: no winner in round {round}", rig.name));
        let held = rig
            .client
            .get(GetRequest {
                address: Address {
                    kind: "lease".into(),
                    id: "key/race".into(),
                    ..Address::default()
                }
                .into(),
                ..GetRequest::default()
            })
            .await
            .unwrap()
            .into_owned()
            .item
            .as_option()
            .unwrap()
            .clone();
        assert_eq!(
            (held.version, held.value),
            (round + 1, format!("taker-{winner}").into_bytes()),
            "{}: the lease after round {round}",
            rig.name
        );
    }
}

/// A saved point `(position, epoch)`, a log made again (a reset of the database, or a restore into a new one), and the new
/// log written past the saved sequence: the watch from the saved point is refused, with the epoch of the old log or with
/// none, although its number is a row of the new log; and a consumer that dedupes by sequence inside the epoch ends with the
/// new log's state. Without an epoch the watch would have resumed in the middle of the new log and skipped its first rows.
async fn a_log_made_again_refuses_the_saved_point(rig: &Rig) {
    for i in 1..=3 {
        rig.write(operation(
            Verb::CREATE,
            &format!("node-a/o{i}"),
            b"old",
            Some(600),
        ))
        .await;
    }
    let (saved, epoch) = rig.listing().await;
    assert!(epoch != 0 && saved >= 4, "{}: ({saved}, {epoch})", rig.name);
    let mut consumer = Consumer::default();
    for m in &rig.changes_in(saved - 1, epoch).await {
        consumer.apply(m);
    }

    (rig.reset)().await;
    for i in 1..=8 {
        rig.write(operation(
            Verb::CREATE,
            &format!("node-a/n{i}"),
            b"new",
            Some(600),
        ))
        .await;
    }
    let (now, e2) = rig.listing().await;
    assert_ne!(
        e2, epoch,
        "{}: a log made again has another epoch",
        rig.name
    );
    assert!(
        now >= saved,
        "{}: the new log ({now}) has reached the saved sequence ({saved}): its number is a row of it",
        rig.name
    );
    for (what, e) in [("the epoch of the old log", epoch), ("no epoch", 0)] {
        let err = rig.refused(saved, e).await;
        assert_eq!(
            (err.code, refusal_reason(&err).as_deref()),
            (ErrorCode::FailedPrecondition, Some("resume_point_expired")),
            "{}: {what}",
            rig.name
        );
    }
    // The consumer lists the new log and follows it from the new position, under the new epoch: none of the rows of the new
    // log is dropped as a repeat of the old applied point, though their numbers are below it.
    let mut fresh = Consumer::default();
    for id in rig.listed_ids().await {
        fresh.state.insert(id, b"new".to_vec());
    }
    assert_eq!(
        fresh.state.len(),
        8,
        "{}: the new log's items only",
        rig.name
    );
    assert!(
        fresh.state.keys().all(|k| k.starts_with("node-a/n")),
        "{}: {:?}",
        rig.name,
        fresh.state.keys()
    );
    rig.write(operation(Verb::CREATE, "node-a/n9", b"new", Some(600)))
        .await;
    let seen = rig.changes_in(now, e2).await;
    assert!(
        !seen.is_empty(),
        "{}: the change after the listing arrives",
        rig.name
    );
    for m in &seen {
        assert_eq!(
            m.log_epoch, e2,
            "{}: a message names the epoch of the log",
            rig.name
        );
        fresh.apply(m);
    }
    assert_eq!(
        fresh.state.len(),
        9,
        "{}: {:?}",
        rig.name,
        fresh.state.keys()
    );
    assert_eq!(
        consumer.epoch, epoch,
        "{}: the old consumer followed the old log",
        rig.name
    );
}

/// The messages of a raw watch of the temp kind until the caught-up bookmark, which is the last of them.
async fn until_caught_up(
    rig: &Rig,
    from: u64,
    epoch: u64,
) -> (Vec<WatchResponse>, tokio::time::Instant) {
    let started = tokio::time::Instant::now();
    let mut stream = rig
        .client
        .watch(WatchRequest {
            kind: TEMP.into(),
            resume_point: from,
            log_epoch: epoch,
            ..WatchRequest::default()
        })
        .await
        .unwrap();
    let mut out = Vec::new();
    loop {
        let m = tokio::time::timeout(Duration::from_secs(20), stream.message())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{}: no caught-up bookmark in 20 s: {} messages",
                    rig.name,
                    out.len()
                )
            })
            .unwrap()
            .unwrap_or_else(|| panic!("{}: the stream ended before it was caught up", rig.name))
            .to_owned_message();
        let done = kind_of(&m) == ChangeType::CHANGE_TYPE_BOOKMARK && m.caught_up;
        out.push(m);
        if done {
            return (out, started);
        }
    }
}

/// An empty catch-up, a catch-up with many rows, writes that arrive during it and a reconnect, on a real engine: the
/// stream says it is caught up when it has delivered through the head read when it opened, at once when there was nothing
/// to deliver, and not by the idle bookmark (30 seconds here). The head is the engine's linearizable read.
async fn a_watch_says_it_is_caught_up(rig: &Rig) {
    // Empty: from the head. (From now was given no point and says no claim: see the test of a watch from now.)
    let (point, epoch) = rig.listing().await;
    let (got, started) = until_caught_up(rig, point, epoch).await;
    assert_eq!(
        got.len(),
        1,
        "{}: from the head: nothing but the bookmark",
        rig.name
    );
    assert_eq!(
        (got[0].resume_point, got[0].log_epoch),
        (point, epoch),
        "{}: from the head",
        rig.name
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{}: from the head: after the idle interval",
        rig.name
    );
    // Many rows behind: more than a run and a batch of the driver.
    for i in 0..300 {
        rig.write(operation(
            Verb::CREATE,
            &format!("node-a/c{i:04}"),
            b"v",
            Some(600),
        ))
        .await;
    }
    let head = rig.listing().await.0;
    let (got, _) = until_caught_up(rig, point, epoch).await;
    let (bookmark, changes) = got.split_last().unwrap();
    assert_eq!(
        bookmark.resume_point, head,
        "{}: the head at the opening",
        rig.name
    );
    let mut ids: Vec<_> = changes.iter().map(id_of).collect();
    assert_eq!(
        ids.len(),
        300,
        "{}: every change before the bookmark",
        rig.name
    );
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 300, "{}: each once", rig.name);
    assert!(changes.iter().all(|m| m.resume_point <= head));
    // Writes that arrive while it catches up come after the bookmark, and the bookmark is still the head at the opening.
    let mut stream = rig
        .client
        .watch(WatchRequest {
            kind: TEMP.into(),
            resume_point: point,
            log_epoch: epoch,
            ..WatchRequest::default()
        })
        .await
        .unwrap();
    for i in 0..3 {
        rig.write(operation(
            Verb::CREATE,
            &format!("node-a/d{i}"),
            b"v",
            Some(600),
        ))
        .await;
    }
    let mut before = 0;
    let bookmark = loop {
        let m = tokio::time::timeout(Duration::from_secs(20), stream.message())
            .await
            .unwrap_or_else(|_| panic!("{}: no caught-up bookmark", rig.name))
            .unwrap()
            .expect("a message")
            .to_owned_message();
        if kind_of(&m) == ChangeType::CHANGE_TYPE_BOOKMARK && m.caught_up {
            break m;
        }
        assert!(
            m.resume_point <= head && !id_of(&m).starts_with("node-a/d"),
            "{}: a change past the head came before the bookmark",
            rig.name
        );
        before += 1;
    };
    assert_eq!((before, bookmark.resume_point), (300, head), "{}", rig.name);
    let mut late = Vec::new();
    while late.len() < 3 {
        let m = tokio::time::timeout(Duration::from_secs(10), stream.message())
            .await
            .unwrap()
            .unwrap()
            .expect("a change")
            .to_owned_message();
        assert!(m.resume_point > head);
        late.push(id_of(&m));
    }
    late.sort();
    assert_eq!(
        late,
        ["node-a/d0", "node-a/d1", "node-a/d2"],
        "{}",
        rig.name
    );
    // A reconnect from the last point: nothing new, so the bookmark is the first message, at the head now.
    let now = rig.listing().await.0;
    let (got, started) = until_caught_up(rig, now, epoch).await;
    assert_eq!(got.len(), 1, "{}", rig.name);
    assert_eq!(got[0].resume_point, now, "{}", rig.name);
    assert!(started.elapsed() < Duration::from_secs(10), "{}", rig.name);
}

/// verifies: REQ-DATA-100, REQ-DATA-101, REQ-DATA-054, REQ-DATA-063, REQ-DATA-098
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_the_memory_engine_a_consumer_by_sequence_ends_with_the_right_state() {
    let rig = memory_rig().await;
    delete_then_re_create(&rig).await;
    delete_then_re_create_while_watching(&rig).await;
    expiry_then_re_create(&rig).await;
    many_changes_end_with_the_last(&rig).await;
    two_nodes_leave_the_timestamps_they_computed(&rig).await;
    lease_takers_have_one_winner(&rig).await;
}

/// verifies: REQ-DATA-115, REQ-DATA-117
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_the_memory_engine_a_saved_point_is_refused_after_the_log_is_made_again() {
    let rig = memory_rig().await;
    a_log_made_again_refuses_the_saved_point(&rig).await;
}

/// verifies: REQ-DATA-115, REQ-DATA-117
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_rqlite_a_saved_point_is_refused_after_the_log_is_made_again() {
    let Some(rig) = rqlite_rig().await else {
        return;
    };
    a_log_made_again_refuses_the_saved_point(&rig).await;
}

/// verifies: REQ-DATA-100, REQ-DATA-101, REQ-DATA-054, REQ-DATA-063, REQ-DATA-098
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_rqlite_a_consumer_by_sequence_ends_with_the_right_state() {
    let Some(rig) = rqlite_rig().await else {
        return;
    };
    delete_then_re_create(&rig).await;
    delete_then_re_create_while_watching(&rig).await;
    expiry_then_re_create(&rig).await;
    many_changes_end_with_the_last(&rig).await;
    two_nodes_leave_the_timestamps_they_computed(&rig).await;
    lease_takers_have_one_winner(&rig).await;
}

/// verifies: REQ-DATA-126
/// A watch from now was given no point, so it says no `caught_up` on a real engine either: nothing arrives early (the idle
/// interval is 30 seconds here), and a change that is made comes as a change.
async fn a_watch_from_now_says_no_claim(rig: &Rig) {
    let (_, epoch) = rig.listing().await;
    let mut stream = rig
        .client
        .watch(WatchRequest {
            kind: TEMP.into(),
            resume_point: 0,
            log_epoch: epoch,
            ..WatchRequest::default()
        })
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), stream.message())
            .await
            .is_err(),
        "{}: a watch from now said something at once, where a watch with a point would have claimed",
        rig.name
    );
    rig.write(operation(Verb::CREATE, "node-a/now1", b"v", Some(600)))
        .await;
    let m = tokio::time::timeout(Duration::from_secs(10), stream.message())
        .await
        .unwrap_or_else(|_| panic!("{}: no change", rig.name))
        .unwrap()
        .expect("a message")
        .to_owned_message();
    assert_eq!(kind_of(&m), ChangeType::CHANGE_TYPE_PUT, "{}", rig.name);
    assert!(!m.caught_up, "{}", rig.name);
}

/// verifies: REQ-DATA-126
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_the_memory_engine_a_watch_from_now_says_no_claim() {
    let rig = memory_rig().await;
    a_watch_from_now_says_no_claim(&rig).await;
}

/// verifies: REQ-DATA-126
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_rqlite_a_watch_from_now_says_no_claim() {
    let Some(rig) = rqlite_rig().await else {
        return;
    };
    a_watch_from_now_says_no_claim(&rig).await;
}

/// verifies: REQ-DATA-120, REQ-DATA-122, REQ-DATA-125
/// On a real rqlited, in front of which a proxy sees the level of every query and can hold the `weak` ones (the reads of the
/// rows of a tail, as a replica that lags shows them late): the head of a watch is read at the `linearizable` level when
/// the watch opens and again at each idle tick; while the weak reads are held, 5 rows behind the head, the stream says no
/// `caught_up` (not early, though the head is known); when they pass, the five changes come and the claim after them,
/// and the idle tick that follows renews it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_rqlite_the_head_is_read_linearizably_and_the_claim_waits_for_the_rows() {
    let Some((rig, Some(px))) = rqlite_rig_through_short_interval().await else {
        return;
    };
    let (point, epoch) = rig.listing().await;
    for i in 0..5 {
        rig.write(operation(
            Verb::CREATE,
            &format!("node-a/p{i}"),
            b"v",
            Some(600),
        ))
        .await;
    }
    let head = rig.listing().await.0;
    assert!(head >= point + 5);
    px.hold_weak
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let before = px.levels.lock().unwrap().len();
    let mut stream = rig
        .client
        .watch(WatchRequest {
            kind: TEMP.into(),
            resume_point: point,
            log_epoch: epoch,
            ..WatchRequest::default()
        })
        .await
        .unwrap();
    // Nothing is delivered and nothing is claimed while the rows are held back, though the head is known.
    for _ in 0..3 {
        let m = tokio::time::timeout(Duration::from_millis(900), stream.message()).await;
        match m {
            Err(_) => {}
            Ok(m) => {
                let m = m.unwrap().expect("a message").to_owned_message();
                assert_eq!(kind_of(&m), ChangeType::CHANGE_TYPE_BOOKMARK);
                assert!(!m.caught_up, "claimed with the rows held back: {m:?}");
                assert_eq!(m.resume_point, point, "the position, no further");
            }
        }
    }
    let opened_with = px.levels.lock().unwrap()[before..].to_vec();
    assert!(
        opened_with.iter().any(|l| l == "linearizable"),
        "the head of the watch was read linearizably: {opened_with:?}"
    );
    px.hold_weak
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut changes = 0;
    let claim = loop {
        let m = tokio::time::timeout(Duration::from_secs(20), stream.message())
            .await
            .expect("the rows arrive when the weak reads pass")
            .unwrap()
            .expect("a message")
            .to_owned_message();
        match kind_of(&m) {
            ChangeType::CHANGE_TYPE_PUT => changes += 1,
            ChangeType::CHANGE_TYPE_BOOKMARK if m.caught_up => break m,
            _ => {}
        }
    };
    assert_eq!((changes, claim.resume_point), (5, head));
    // The idle tick reads the head again, linearizably, finds it at the position, and renews the claim.
    let linear_before = px
        .levels
        .lock()
        .unwrap()
        .iter()
        .filter(|l| *l == "linearizable")
        .count();
    let renewed = loop {
        let m = tokio::time::timeout(Duration::from_secs(20), stream.message())
            .await
            .expect("a renewal")
            .unwrap()
            .expect("a message")
            .to_owned_message();
        if kind_of(&m) == ChangeType::CHANGE_TYPE_BOOKMARK {
            break m;
        }
    };
    assert!(renewed.caught_up, "{renewed:?}");
    assert_eq!(renewed.resume_point, head);
    let linear_after = px
        .levels
        .lock()
        .unwrap()
        .iter()
        .filter(|l| *l == "linearizable")
        .count();
    assert!(
        linear_after > linear_before,
        "the renewal read the head again"
    );
}

/// verifies: REQ-DATA-120
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_the_memory_engine_a_watch_says_it_is_caught_up() {
    let rig = memory_rig().await;
    a_watch_says_it_is_caught_up(&rig).await;
}

/// verifies: REQ-DATA-120
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_rqlite_a_watch_says_it_is_caught_up() {
    let Some(rig) = rqlite_rig().await else {
        return;
    };
    a_watch_says_it_is_caught_up(&rig).await;
}
