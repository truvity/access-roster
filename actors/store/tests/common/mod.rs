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
    DriverItem, QueryRequest, QueryResponse, TransactRequest, TransactResponse, condition::Expect,
};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, ListRequest, ListResponse, Operation, StoreServiceClient,
    StoreServiceExt as _, Verb, WatchRequest, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::{Address, Grant, IndexEntry};
use store::audit::{AuditEvent, AuditSink};
use store::config::ConfigSnapshot;
use store::engine::{EngineError, ItemEngine};
use store::grant::KeyOpener;
use store::service::{Deps, Service};

pub const T0: u64 = 1_800_000_000;

// ---- the engine ----

#[derive(Default)]
pub struct MemState {
    /// The test clock, in seconds; the engine uses it for the one rule it must keep: an item past
    /// its expiry does not exist for a condition (the item contract, as the rqlite driver keeps it).
    pub clock: Option<Arc<AtomicU64>>,
    pub items: Mutex<BTreeMap<Vec<u8>, DriverItem>>,
    pub down: AtomicBool,
    pub txs: Mutex<Vec<TransactRequest>>,
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
            written.push(item);
        }
        for d in &tx.deletes {
            items.remove(&d.key);
        }
        Ok(TransactResponse {
            items: written,
            ..TransactResponse::default()
        })
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
    pub clock: Arc<AtomicU64>,
    client: StoreServiceClient<sluis_kit::Transport>,
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
        let c = Arc::clone(&clock);
        let svc = Service::new(Deps {
            boundary: "dev".into(),
            durable: durable.clone(),
            temp: temp.clone(),
            grants: KeyOpener::new(&dial(&key_sock)),
            config: Arc::clone(&docs) as Arc<dyn ConfigSnapshot>,
            audit: sink.clone(),
            clock: Arc::new(move || {
                SystemTime::UNIX_EPOCH + Duration::from_secs(c.load(Ordering::SeqCst))
            }),
        });

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
            clock,
            client: StoreServiceClient::new(cl.transport(), cl.config()),
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

    pub async fn watch(&self) -> ConnectError {
        // The error may come with the response head or as the first thing the stream says.
        let mut stream = match self
            .client
            .watch(WatchRequest {
                kind: "person".into(),
                ..WatchRequest::default()
            })
            .await
        {
            Err(e) => return e,
            Ok(s) => s,
        };
        match stream.message().await {
            Err(e) => e,
            Ok(m) => panic!("watch must not be served, got {}", m.is_some()),
        }
    }

    pub fn audit(&self) -> Vec<AuditEvent> {
        self.sink.events.lock().unwrap().clone()
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
