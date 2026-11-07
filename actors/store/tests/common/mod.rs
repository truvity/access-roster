#![allow(refining_impl_trait)] // the generated traits return `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
#![allow(dead_code)] // each test binary uses part of the harness
//! The harness of the store@ tests: an in-process engine (`ItemEngine`), a fake key@ on a Unix
//! socket served by the kit, and the store service served on a Unix socket too. Every call of
//! a test is a Connect call over the kit's transport; the test's own uid plays every caller, and
//! the table of the kit's test seam says which actor it is for the next call.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use buffa_types::google::protobuf::Timestamp;
use connectrpc::error::ErrorCode;
use connectrpc::{ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal, refusal_reason};
use sluis_proto::sluis::key::v2alpha1::{
    KeyService, KeyServiceExt as _, MacRequest, MacResponse, OpenGrantRequest, OpenGrantResponse,
    OpenRequest, OpenResponse, PublicKeyRequest, PublicKeyResponse, SealGrantRequest,
    SealGrantResponse, SealRequest, SealResponse, SignRequest, SignResponse,
};
use sluis_proto::sluis::port::item::v2alpha1::{
    DriverItem, QueryRequest, QueryResponse, TailLogResponse, TransactRequest, TransactResponse,
    condition::Expect,
};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, GetSignedConfigRequest, GetSignedConfigResponse, ListRequest,
    ListResponse, Operation, StoreServiceClient, StoreServiceExt as _, Verb, WatchRequest,
    WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::{Address, Grant, IndexEntry};
use store::audit::{AuditEvent, AuditSink};
use store::config::ConfigSnapshot;
use store::engine::{EngineError, ItemEngine, LogRows};
use store::grant::KeyOpener;
use store::secret::{Secret, SecretError, SecretSource};
use store::service::{Deps, Service};

pub const T0: u64 = 1_800_000_000;

// ---- the secret source ----

/// A secret source that keeps what it is given and counts the reads that reach it.
#[derive(Default)]
pub struct Secrets {
    pub items: Mutex<HashMap<String, Vec<u8>>>,
    pub down: AtomicBool,
    pub reads: AtomicUsize,
}

impl SecretSource for Secrets {
    fn read<'a>(
        &'a self,
        name: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<Secret>, SecretError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(SecretError::Down);
            }
            let data = self.items.lock().unwrap().get(name).cloned();
            data.map(|data| {
                Arc::new(Secret {
                    data,
                    version: "v1".into(),
                })
            })
            .ok_or(SecretError::Absent)
        })
    }
}

// ---- the engine ----

pub struct MemState {
    /// The test clock, in seconds; the engine uses it for the one rule it must keep: an item past
    /// its expiry does not exist for a condition (the item contract, as the rqlite driver keeps it).
    pub clock: Option<Arc<AtomicU64>>,
    pub items: Mutex<BTreeMap<Vec<u8>, DriverItem>>,
    pub down: AtomicBool,
    pub txs: Mutex<Vec<TransactRequest>>,
    /// The queries the engine was asked, for the tests that check what store@ asks of a driver.
    pub queries: Mutex<Vec<QueryRequest>>,
    /// The change log, as a driver keeps it: it starts with a marker row (sequence 1), so its head is never 0.
    pub log: Mutex<Vec<TailLogResponse>>,
    /// The sequence below which the log was trimmed (rows up to it are gone).
    pub floor: AtomicU64,
    /// The epoch of the log: a log made again has another one.
    pub epoch: AtomicU64,
    /// The keys written with a log row: their expiry is a delete row once swept.
    pub logged: Mutex<std::collections::HashSet<Vec<u8>>>,
}

/// The epoch of the first log of a fake engine; each engine made after it takes the next, so that two engines never share
/// one and a test that names the wrong engine's epoch is refused.
pub const FIRST_EPOCH: u64 = 7_000_001;
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(FIRST_EPOCH);

impl Default for MemState {
    fn default() -> Self {
        MemState {
            clock: None,
            items: Mutex::default(),
            down: AtomicBool::default(),
            txs: Mutex::default(),
            queries: Mutex::default(),
            log: Mutex::new(vec![TailLogResponse {
                sequence: 1,
                ..TailLogResponse::default()
            }]),
            floor: AtomicU64::new(0),
            epoch: AtomicU64::new(NEXT_EPOCH.fetch_add(1000, Ordering::SeqCst)),
            logged: Mutex::default(),
        }
    }
}

/// An engine that keeps what it is given, even past its expiry (a driver hides expired items; this
/// one does not, so the tests show that store@ checks the expiry itself).
#[derive(Clone, Default)]
pub struct Mem(pub Arc<MemState>);

impl Mem {
    pub fn with_clock(clock: Arc<AtomicU64>) -> Self {
        Mem(Arc::new(MemState {
            clock: Some(clock),
            ..MemState::default()
        }))
    }

    /// Whether the item is past its expiry on the test clock.
    fn dead(&self, item: &DriverItem) -> bool {
        let (Some(clock), Some(e)) = (&self.0.clock, item.expires_at.as_option()) else {
            return false;
        };
        e.seconds <= i64::try_from(clock.load(Ordering::SeqCst)).unwrap()
    }

    fn append(&self, key: &[u8], version: u64, deleted: bool) {
        let mut log = self.0.log.lock().unwrap();
        let sequence = log.last().map_or(0, |r| r.sequence) + 1;
        log.push(TailLogResponse {
            sequence,
            key: key.to_vec(),
            version,
            deleted,
            ..TailLogResponse::default()
        });
    }

    /// The newest sequence of the log.
    pub fn head(&self) -> u64 {
        self.0.log.lock().unwrap().last().map_or(0, |r| r.sequence)
    }

    /// One tick of the sweeper: frees the items past their expiry on the test clock and logs the removal of those
    /// that were written with a log row (expiry is a delete to a watcher).
    pub fn sweep(&self) {
        let gone: Vec<(Vec<u8>, u64)> = self
            .0
            .items
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, i)| self.dead(i))
            .map(|(k, i)| (k.clone(), i.version))
            .collect();
        for (key, version) in gone {
            self.0.items.lock().unwrap().remove(&key);
            if self.0.logged.lock().unwrap().remove(&key) {
                self.append(&key, version, true);
            }
        }
    }

    /// The epoch of the log.
    pub fn epoch(&self) -> u64 {
        self.0.epoch.load(Ordering::SeqCst)
    }

    /// Sets the epoch of the log: 0 is an engine out of its contract.
    pub fn set_epoch(&self, epoch: u64) {
        self.0.epoch.store(epoch, Ordering::SeqCst);
    }

    /// Starts a new database, as a restore into one or a reset does: no items, and a log whose sequence begins again at
    /// the marker row, under a new epoch. A restore then writes the items back.
    pub fn remake_log(&self) {
        self.0.items.lock().unwrap().clear();
        self.0.logged.lock().unwrap().clear();
        let mut log = self.0.log.lock().unwrap();
        *log = vec![TailLogResponse {
            sequence: 1,
            ..TailLogResponse::default()
        }];
        self.0.floor.store(0, Ordering::SeqCst);
        self.0.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Trims the change log up to and including `sequence`: a watch from before it has missed rows.
    pub fn trim(&self, sequence: u64) {
        self.0.floor.fetch_max(sequence, Ordering::SeqCst);
        self.0.log.lock().unwrap().retain(|r| r.sequence > sequence);
    }

    pub fn keys(&self) -> Vec<String> {
        self.0
            .items
            .lock()
            .unwrap()
            .keys()
            .map(|k| String::from_utf8(k.clone()).unwrap())
            .collect()
    }
    pub fn item(&self, key: &str) -> Option<DriverItem> {
        self.0.items.lock().unwrap().get(key.as_bytes()).cloned()
    }
    pub fn set_down(&self, down: bool) {
        self.0.down.store(down, Ordering::SeqCst);
    }
    pub fn queries(&self) -> Vec<QueryRequest> {
        self.0.queries.lock().unwrap().clone()
    }
    pub fn transactions(&self) -> Vec<TransactRequest> {
        self.0.txs.lock().unwrap().clone()
    }
}

impl ItemEngine for Mem {
    async fn get(
        &self,
        key: Vec<u8>,
        _linearizable: bool,
    ) -> Result<Option<DriverItem>, EngineError> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(EngineError::Unavailable);
        }
        Ok(self.0.items.lock().unwrap().get(&key).cloned())
    }

    async fn query(&self, q: QueryRequest) -> Result<QueryResponse, EngineError> {
        self.0.queries.lock().unwrap().push(q.clone());
        if self.0.down.load(Ordering::SeqCst) {
            return Err(EngineError::Unavailable);
        }
        let items = self.0.items.lock().unwrap();
        let mut hits: Vec<DriverItem> = items
            .range(q.prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&q.prefix))
            .filter(|(k, _)| q.page_token.is_empty() || **k > q.page_token)
            .filter(|(_, i)| {
                q.index.is_empty()
                    || i.indexes
                        .iter()
                        .any(|e| e.name == q.index && e.value == q.index_value)
            })
            .map(|(_, i)| i.clone())
            .collect();
        let size = usize::try_from(q.page_size).unwrap();
        let more = hits.len() > size;
        hits.truncate(size);
        let next = if more {
            hits.last().map(|i| i.key.clone()).unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(QueryResponse {
            items: hits,
            next_page_token: next,
            log_head: self.head(),
            log_epoch: self.epoch(),
            ..QueryResponse::default()
        })
    }

    async fn transact(&self, tx: TransactRequest) -> Result<TransactResponse, EngineError> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(EngineError::Unavailable);
        }
        self.0.txs.lock().unwrap().push(tx.clone());
        let mut items = self.0.items.lock().unwrap();
        for (i, c) in tx.conditions.iter().enumerate() {
            let held = items
                .get(&c.key)
                .filter(|x| !self.dead(x))
                .map(|x| x.version);
            let ok = match c.expect {
                Some(Expect::Absent(_)) => held.is_none(),
                Some(Expect::Version(v)) => held == Some(v),
                None => true,
            };
            if !ok {
                return Err(EngineError::Aborted(Some(i)));
            }
        }
        let mut written = Vec::new();
        for p in &tx.puts {
            let version = items
                .get(&p.key)
                .filter(|x| !self.dead(x))
                .map_or(1, |x| x.version + 1);
            let item = DriverItem {
                key: p.key.clone(),
                version,
                value: p.value.clone(),
                expires_at: p.expires_at.clone(),
                indexes: p.indexes.clone(),
                ..DriverItem::default()
            };
            items.insert(p.key.clone(), item.clone());
            if p.log {
                self.0.logged.lock().unwrap().insert(p.key.clone());
                self.append(&p.key, version, false);
            } else {
                self.0.logged.lock().unwrap().remove(&p.key);
            }
            written.push(item);
        }
        for d in &tx.deletes {
            let held = items.remove(&d.key);
            let was_logged = self.0.logged.lock().unwrap().remove(&d.key);
            if let (true, Some(old)) = (d.log || was_logged, held) {
                self.append(&d.key, old.version, true);
            }
        }
        Ok(TransactResponse {
            items: written,
            ..TransactResponse::default()
        })
    }

    async fn tail_log(&self, from: u64, epoch: u64) -> Result<LogRows, EngineError> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(EngineError::Unavailable);
        }
        let head = self.head();
        let floor = self.0.floor.load(Ordering::SeqCst);
        let mut last = match from {
            0 => head,
            n if n > head.max(floor) || n < floor || epoch != self.epoch() => {
                return Err(EngineError::SequenceExpired);
            }
            n => n,
        };
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let this = self.clone();
        let followed = self.epoch();
        tokio::spawn(async move {
            loop {
                // The log was made again under the stream: its rows are not the ones this stream follows.
                if this.epoch() != followed {
                    let _ = tx.send(Err(EngineError::SequenceExpired)).await;
                    return;
                }
                let rows: Vec<TailLogResponse> = this
                    .0
                    .log
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|r| r.sequence > last)
                    .cloned()
                    .collect();
                if rows.is_empty() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    if tx.is_closed() {
                        return;
                    }
                    continue;
                }
                for row in rows {
                    last = row.sequence;
                    if tx.send(Ok(row)).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(rx)
    }
}

// ---- key@ ----

/// A key@ that opens the grants a test registered, and nothing else.
#[derive(Default)]
pub struct FakeKey {
    pub grants: Mutex<HashMap<Vec<u8>, Grant>>,
    pub opens: AtomicUsize,
    pub down: AtomicBool,
}

fn not_here() -> ConnectError {
    ConnectError::new(ErrorCode::Unimplemented, "the fake key@ opens grants only")
}

impl KeyService for FakeKey {
    async fn seal(
        &self,
        _c: RequestContext,
        _r: ServiceRequest<'_, SealRequest>,
    ) -> ServiceResult<SealResponse> {
        Err(not_here())
    }
    async fn open(
        &self,
        _c: RequestContext,
        _r: ServiceRequest<'_, OpenRequest>,
    ) -> ServiceResult<OpenResponse> {
        Err(not_here())
    }
    async fn seal_grant(
        &self,
        _c: RequestContext,
        _r: ServiceRequest<'_, SealGrantRequest>,
    ) -> ServiceResult<SealGrantResponse> {
        Err(not_here())
    }
    async fn open_grant(
        &self,
        _c: RequestContext,
        r: ServiceRequest<'_, OpenGrantRequest>,
    ) -> ServiceResult<OpenGrantResponse> {
        if self.down.load(Ordering::SeqCst) {
            return Err(ConnectError::new(ErrorCode::Unavailable, "down"));
        }
        self.opens.fetch_add(1, Ordering::SeqCst);
        let sealed = r.to_owned_message().sealed_grant;
        match self.grants.lock().unwrap().get(&sealed) {
            Some(g) => Response::ok(OpenGrantResponse {
                grant: g.clone().into(),
                ..OpenGrantResponse::default()
            }),
            None => Err(refusal(
                ErrorCode::PermissionDenied,
                "grant",
                "sealed_grant",
            )),
        }
    }
    async fn sign(
        &self,
        _c: RequestContext,
        _r: ServiceRequest<'_, SignRequest>,
    ) -> ServiceResult<SignResponse> {
        Err(not_here())
    }
    async fn mac(
        &self,
        _c: RequestContext,
        _r: ServiceRequest<'_, MacRequest>,
    ) -> ServiceResult<MacResponse> {
        Err(not_here())
    }
    async fn public_key(
        &self,
        _c: RequestContext,
        _r: ServiceRequest<'_, PublicKeyRequest>,
    ) -> ServiceResult<PublicKeyResponse> {
        Err(not_here())
    }
}

// ---- audit and config ----

#[derive(Clone, Default)]
pub struct RecSink {
    pub events: Arc<Mutex<Vec<AuditEvent>>>,
    pub fail: Arc<AtomicBool>,
}

impl AuditSink for RecSink {
    async fn emit(&self, event: AuditEvent) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("spool down".into());
        }
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

#[derive(Default)]
pub struct Docs {
    /// (segment, id) -> bytes
    pub items: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    /// segment -> seq
    pub versions: Mutex<HashMap<String, u64>>,
    /// segment -> the signed document, as a source would give it
    pub signed: Mutex<HashMap<String, Vec<u8>>>,
}

impl ConfigSnapshot for Docs {
    fn get(&self, segment: &str, id: &str) -> Option<Vec<u8>> {
        self.items
            .lock()
            .unwrap()
            .get(&(segment.into(), id.into()))
            .cloned()
    }
    fn list(&self, segment: &str) -> Vec<(String, Vec<u8>)> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|((s, _), _)| s == segment)
            .map(|((_, id), v)| (id.clone(), v.clone()))
            .collect()
    }
    fn version(&self, segment: &str) -> Option<u64> {
        self.versions.lock().unwrap().get(segment).copied()
    }
    fn signed(&self, segment: &str) -> Option<Vec<u8>> {
        self.signed.lock().unwrap().get(segment).cloned()
    }
}

// ---- the fixture ----

pub struct F {
    _dir: tempfile::TempDir,
    pub caller: Arc<Mutex<&'static str>>,
    pub durable: Mem,
    pub temp: Mem,
    pub key: Arc<FakeKey>,
    pub sink: RecSink,
    pub docs: Arc<Docs>,
    pub secrets: Arc<Secrets>,
    pub clock: Arc<AtomicU64>,
    client: StoreServiceClient<sluis_kit::Transport>,
    /// The kit's client of the same socket, for the typed client (`sluis_store::Store`).
    pub kit: sluis_kit::Client,
    next_grant: AtomicUsize,
}

pub async fn wait_for(path: &std::path::Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} did not appear", path.display());
}

impl F {
    pub async fn new() -> F {
        F::new_with(store::watch::BOOKMARK_EVERY).await
    }

    /// A store whose idle watches say their resume point after `bookmark_every`.
    pub async fn new_with(bookmark_every: Duration) -> F {
        let dir = tempfile::tempdir().unwrap();
        let me = rustix::process::geteuid().as_raw();

        // key@, which only store may call.
        let key = Arc::new(FakeKey::default());
        let key_sock = dir.path().join("key.sock");
        let key_ids = Identities::with(0, move |u| (u == me).then_some(("store", 0)));
        tokio::spawn(sluis_kit::serve_with(
            ServerConfig {
                actor: "key",
                boundary: "dev".into(),
                socket: key_sock.clone(),
                mode: 0o660,
                socket_gid: None,
                allow: Allow::Exact("store"),
                default_deadline: Duration::from_secs(5),
            },
            Arc::clone(&key).register(Router::new()),
            std::future::pending(),
            key_ids,
        ));
        wait_for(&key_sock).await;

        let clock = Arc::new(AtomicU64::new(T0));
        let (durable, temp) = (
            Mem::with_clock(Arc::clone(&clock)),
            Mem::with_clock(Arc::clone(&clock)),
        );
        let sink = RecSink::default();
        let docs = Arc::new(Docs::default());
        let secrets = Arc::new(Secrets::default());
        let c = Arc::clone(&clock);
        let svc = Service::new(Deps {
            boundary: "dev".into(),
            durable: durable.clone(),
            temp: temp.clone(),
            grants: KeyOpener::new(&dial(&key_sock)),
            config: Arc::clone(&docs) as Arc<dyn ConfigSnapshot>,
            secrets: Arc::clone(&secrets) as Arc<dyn SecretSource>,
            audit: sink.clone(),
            clock: Arc::new(move || {
                SystemTime::UNIX_EPOCH + Duration::from_secs(c.load(Ordering::SeqCst))
            }),
        })
        .with_watch_timing(bookmark_every, Duration::from_millis(20));

        // store@, called as whichever actor the test says.
        let caller: Arc<Mutex<&'static str>> = Arc::new(Mutex::new("session"));
        let who = Arc::clone(&caller);
        let ids = Identities::with(0, move |u| (u == me).then(|| (*who.lock().unwrap(), 0)));
        let sock = dir.path().join("store.sock");
        tokio::spawn(sluis_kit::serve_with(
            ServerConfig {
                actor: "store",
                boundary: "dev".into(),
                socket: sock.clone(),
                mode: 0o660,
                socket_gid: None,
                allow: Allow::CallGraph,
                default_deadline: Duration::from_secs(5),
            },
            Arc::new(svc).register(Router::new()),
            std::future::pending(),
            ids,
        ));
        wait_for(&sock).await;
        let cl = dial(&sock);
        F {
            _dir: dir,
            caller,
            durable,
            temp,
            key,
            sink,
            docs,
            secrets,
            clock,
            client: StoreServiceClient::new(cl.transport(), cl.config()),
            kit: cl,
            next_grant: AtomicUsize::new(0),
        }
    }

    pub fn as_(&self, name: &'static str) -> &Self {
        *self.caller.lock().unwrap() = name;
        self
    }

    pub fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.clock.load(Ordering::SeqCst))
    }

    pub fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    /// Registers a grant at the fake key@ and returns its sealed bytes. `expires_in` is relative to
    /// the test clock.
    pub fn grant(
        &self,
        holder: &str,
        tenants: &[&str],
        verbs: &[&str],
        expires_in: i64,
    ) -> Vec<u8> {
        let n = self.next_grant.fetch_add(1, Ordering::SeqCst);
        let sealed = format!("sealed-grant-{n}").into_bytes();
        let g = Grant {
            boundary: "dev".into(),
            tenants: tenants.iter().map(|s| (*s).to_owned()).collect(),
            holder: holder.into(),
            store_verbs: verbs.iter().map(|s| (*s).to_owned()).collect(),
            issued_at: Timestamp {
                seconds: i64::try_from(T0).unwrap(),
                ..Timestamp::default()
            }
            .into(),
            expires_at: Timestamp {
                seconds: i64::try_from(self.clock.load(Ordering::SeqCst)).unwrap() + expires_in,
                ..Timestamp::default()
            }
            .into(),
            ..Grant::default()
        };
        self.key.grants.lock().unwrap().insert(sealed.clone(), g);
        sealed
    }

    /// Registers a grant with a field changed by `f`.
    pub fn grant_with(&self, f: impl FnOnce(&mut Grant)) -> Vec<u8> {
        let sealed = self.grant(
            "session",
            &["acme"],
            &["create", "update", "delete", "apply"],
            60,
        );
        f(self.key.grants.lock().unwrap().get_mut(&sealed).unwrap());
        sealed
    }

    pub async fn get(
        &self,
        kind: &str,
        tenant: &str,
        id: &str,
    ) -> Result<GetResponse, ConnectError> {
        self.get_req(GetRequest {
            address: addr(kind, tenant, id).into(),
            ..GetRequest::default()
        })
        .await
    }

    pub async fn get_req(&self, r: GetRequest) -> Result<GetResponse, ConnectError> {
        Ok(self.client.get(r).await?.into_owned())
    }

    pub async fn get_signed_config(
        &self,
        kind: &str,
    ) -> Result<GetSignedConfigResponse, ConnectError> {
        Ok(self
            .client
            .get_signed_config(GetSignedConfigRequest {
                kind: kind.into(),
                ..GetSignedConfigRequest::default()
            })
            .await?
            .into_owned())
    }

    pub async fn list(&self, r: ListRequest) -> Result<ListResponse, ConnectError> {
        Ok(self.client.list(r).await?.into_owned())
    }

    pub async fn write(
        &self,
        ops: Vec<Operation>,
        grant: &[u8],
    ) -> Result<WriteResponse, ConnectError> {
        let r = WriteRequest {
            operations: ops,
            grant: grant.to_vec(),
            ..WriteRequest::default()
        };
        Ok(self.client.write(r).await?.into_owned())
    }

    /// Opens a watch. The refusal of a watch comes as the answer to the call, or as the first thing the stream says;
    /// either way it is the `Err` here.
    pub async fn watch_open(&self, r: WatchRequest) -> Result<Watcher, ConnectError> {
        let mut stream = self.client.watch(r).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let task = tokio::spawn(async move {
            loop {
                let next = match stream.message().await {
                    Ok(Some(m)) => Ok(m.to_owned_message()),
                    Ok(None) => return,
                    Err(e) => Err(e),
                };
                let failed = next.is_err();
                if tx.send(next).await.is_err() || failed {
                    return;
                }
            }
        });
        let mut w = Watcher {
            rx,
            task,
            held: None,
        };
        // A refusal that rides in the stream: wait a moment for it.
        if let Some(Err(e)) = w.peek_error(Duration::from_millis(150)).await {
            return Err(e);
        }
        Ok(w)
    }

    /// The epoch of the log of the engine that holds `kind`: the temp engine for the temp kind of these tests, else the
    /// durable one.
    pub fn epoch_of(&self, kind: &str) -> u64 {
        if kind == "pin-release-request" {
            self.temp.epoch()
        } else {
            self.durable.epoch()
        }
    }

    /// Opens a watch from a resume point of the log as it is now (its epoch is the log's).
    pub async fn watch(
        &self,
        kind: &str,
        tenant: &str,
        resume_point: u64,
    ) -> Result<Watcher, ConnectError> {
        self.watch_in(kind, tenant, resume_point, self.epoch_of(kind))
            .await
    }

    /// Opens a watch from a resume point under the given epoch.
    pub async fn watch_in(
        &self,
        kind: &str,
        tenant: &str,
        resume_point: u64,
        log_epoch: u64,
    ) -> Result<Watcher, ConnectError> {
        self.watch_open(WatchRequest {
            kind: kind.into(),
            tenant: tenant.into(),
            resume_point,
            log_epoch,
            ..WatchRequest::default()
        })
        .await
    }

    pub fn audit(&self) -> Vec<AuditEvent> {
        self.sink.events.lock().unwrap().clone()
    }
}

/// A watch that is open: what it said is read with a bound, so that a test never waits for ever.
pub struct Watcher {
    rx: tokio::sync::mpsc::Receiver<Result<WatchResponse, ConnectError>>,
    task: tokio::task::JoinHandle<()>,
    /// A message that `peek_error` read while it looked for a refusal.
    held: Option<WatchResponse>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Watcher {
    async fn peek_error(&mut self, within: Duration) -> Option<Result<(), ConnectError>> {
        // Only an error is consumed; a message stays for the test (it is put back by reading it again below).
        match tokio::time::timeout(within, self.rx.recv()).await {
            Ok(Some(Err(e))) => Some(Err(e)),
            Ok(Some(Ok(m))) => {
                self.held = Some(m);
                None
            }
            _ => None,
        }
    }

    /// The next message within the bound, or None when the stream is quiet or ended. An error is a message.
    pub async fn next(&mut self, within: Duration) -> Option<Result<WatchResponse, ConnectError>> {
        if let Some(m) = self.held.take() {
            return Some(Ok(m));
        }
        tokio::time::timeout(within, self.rx.recv())
            .await
            .ok()
            .flatten()
    }

    /// The next message, which must come within five seconds and must not be an error.
    pub async fn msg(&mut self) -> WatchResponse {
        self.next(Duration::from_secs(5))
            .await
            .expect("the watch said nothing in five seconds")
            .expect("the watch ended in an error")
    }

    /// The next message, which must come within five seconds and must be an error.
    pub async fn error(&mut self) -> ConnectError {
        self.next(Duration::from_secs(5))
            .await
            .expect("the watch said nothing in five seconds")
            .expect_err("the watch said a message, not an error")
    }

    /// True when the stream says nothing within `within`.
    pub async fn quiet(&mut self, within: Duration) -> bool {
        self.next(within).await.is_none()
    }
}

pub fn addr(kind: &str, tenant: &str, id: &str) -> Address {
    Address {
        kind: kind.into(),
        tenant: tenant.into(),
        id: id.into(),
        ..Address::default()
    }
}

pub fn op(verb: Verb, kind: &str, tenant: &str, id: &str, value: &[u8]) -> Operation {
    Operation {
        verb: verb.into(),
        address: addr(kind, tenant, id).into(),
        value: value.to_vec(),
        ..Operation::default()
    }
}

pub fn with_ttl(mut o: Operation, secs: i64) -> Operation {
    o.ttl = buffa_types::google::protobuf::Duration {
        seconds: secs,
        ..Default::default()
    }
    .into();
    o
}

pub fn with_index(mut o: Operation, name: &str, value: &[u8]) -> Operation {
    o.indexes.push(IndexEntry {
        name: name.into(),
        value: value.to_vec(),
        ..IndexEntry::default()
    });
    o
}

pub fn with_version(mut o: Operation, v: u64) -> Operation {
    o.if_version = v;
    o
}

/// A value with the header and the size of a sealed envelope. store@ never opens it.
pub fn sealed() -> Vec<u8> {
    let mut v = vec![0u8; 41];
    v[0] = 1;
    v[1] = 1;
    v
}

/// The sealed envelope of the kind with the segment `segment`: its purpose byte is `credential` for `StaffPasskey` and
/// `data` for every other kind.
pub fn sealed_for(segment: &str) -> Vec<u8> {
    let mut v = sealed();
    if segment == "staff-passkey" {
        v[1] = 6;
    }
    v
}

pub fn reason(e: &ConnectError) -> String {
    refusal_reason(e).unwrap_or_else(|| "-".into())
}

/// The refusal must be this code with this reason.
#[track_caller]
pub fn refused<T>(r: Result<T, ConnectError>, code: ErrorCode, why: &str) {
    match r {
        Ok(_) => panic!("expected {} / {why}, the call succeeded", code.as_str()),
        Err(e) => assert_eq!((e.code, reason(&e)), (code, why.to_owned()), "{e:?}"),
    }
}

/// The field path of the `Refusal` detail of an error.
pub fn refusal_path(e: &ConnectError) -> String {
    use base64::Engine as _;
    use buffa::Message as _;
    e.details
        .iter()
        .find_map(|d| {
            let raw = d.value.as_deref()?;
            let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(raw)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
                .ok()?;
            sluis_proto::sluis::r#type::v2alpha1::Refusal::decode_from_slice(&bytes)
                .ok()
                .map(|r| r.field_path)
        })
        .unwrap_or_default()
}

/// A KeyRevocation message of a purpose or generation target, with a time: what key@ writes on a declaration.
pub fn revocation(kind: &str, target: &str, reason: &str) -> Vec<u8> {
    use buffa::Message as _;
    sluis_proto::sluis::key::v2alpha1::KeyRevocation {
        target_kind: kind.into(),
        target: target.into(),
        reason_code: reason.into(),
        revoked_at: buffa::MessageField::some(buffa_types::google::protobuf::Timestamp {
            seconds: 1_793_800_000,
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}
