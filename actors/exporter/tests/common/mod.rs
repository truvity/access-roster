#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
#![allow(dead_code)] // each test file uses part of this
//! The world `exporter` runs in under test: an in-process `store@` with a change log and a watch, an audit transport
//! that keeps what it is given, and a place for the sockets. Every call between them is Connect over `proto/`. The
//! stand-ins name the test process as the caller `exporter`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use buffa::Message as _;
use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use exporter::config::Doc;
use exporter::publish::Timing;
use exporter::run::{Engine, EngineConfig, Target};
use serde_json::Value;
use sluis_audit::Config as AuditConfig;
use sluis_destination::Destination;
use sluis_destination::memory::Memory;
use sluis_kit::{Allow, Identities, ServerConfig, refusal};
use sluis_proto::sluis::exporter::v2alpha1::{ExportCursor, ExportManifest, ExportReport};
use sluis_proto::sluis::key::v2alpha1::KeyRevocation;
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};
use sluis_proto::sluis::signer::v2alpha1::{SigningKey, SigningRing};
use sluis_proto::sluis::store::v2alpha1::{
    ChangeType, Consistency, GetRequest, GetResponse, GetSignedConfigRequest,
    GetSignedConfigResponse, Item, ListRequest, ListResponse, StoreService, StoreServiceExt, Verb,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use sluis_store::Backoff;
use tokio::sync::{Notify, oneshot};

// ---------------------------------------------------------------- the stand-in for store@

#[derive(Default)]
struct Inner {
    items: BTreeMap<(String, String), (u64, Vec<u8>)>,
    /// The change log: (sequence, kind, id).
    log: Vec<(u64, String, String)>,
    seq: u64,
    /// The oldest point the log still holds.
    floor: u64,
    /// Every `List`: kind and consistency.
    lists: Vec<(String, Consistency)>,
    /// Every `Get`: kind, id and whether it found the item.
    gets: Vec<(String, String, bool)>,
    /// Every `Watch`: kind and resume point.
    opens: Vec<(String, u64)>,
    /// How many restores the log has had: the epoch is one more.
    restores: u64,
    /// Refuse the watch of a kind (by segment) with `unavailable`.
    watch_down: Vec<String>,
    /// The reports it took, with what the destination had been asked by then.
    report_log: Vec<(String, ExportReport, usize)>,
}

#[derive(Default)]
pub struct FakeStore {
    inner: Mutex<Inner>,
    changed: Notify,
    /// Refuse everything with `unavailable`.
    pub down: AtomicBool,
    /// Refuse the reads of `KeyRevocation` with `unavailable`.
    pub revocations_down: AtomicBool,
    /// Refuse the reads of `SigningRing` (not its watch) with `unavailable`.
    pub ring_down: AtomicBool,
    /// Refuse the writes of reports with `unavailable`.
    pub reports_down: AtomicBool,
    /// Watch calls are counted so a test can wait for one.
    pub watching: AtomicU64,
    /// Shown to the report hook: the destination whose calls are counted.
    pub memory: Mutex<Option<Memory>>,
}

pub fn item(kind: &str, id: &str, version: u64, value: &[u8]) -> Item {
    Item {
        address: Some(Address {
            kind: kind.into(),
            id: id.into(),
            ..Address::default()
        })
        .into(),
        version,
        value: value.to_vec(),
        ..Item::default()
    }
}

impl FakeStore {
    fn put_raw(&self, kind: &str, id: &str, value: Vec<u8>) -> u64 {
        let mut i = self.inner.lock().unwrap();
        let key = (kind.to_owned(), id.to_owned());
        let v = i.items.get(&key).map_or(1, |(v, _)| v + 1);
        i.items.insert(key, (v, value));
        i.seq += 1;
        let seq = i.seq;
        i.log.push((seq, kind.into(), id.into()));
        drop(i);
        self.changed.notify_waiters();
        seq
    }

    /// Sets the ring.
    pub fn set_ring(&self, keys: Vec<SigningKey>) -> u64 {
        self.put_raw(
            "signing-ring",
            "default",
            SigningRing {
                keys,
                ..SigningRing::default()
            }
            .encode_to_vec(),
        )
    }

    /// Lists the key as revoked, as `key@` does when it takes a declaration.
    pub fn revoke(&self, kid: &str) -> u64 {
        self.put_raw(
            "key-revocation",
            &format!("kid/{}", kid.to_lowercase()),
            KeyRevocation {
                target_kind: "kid".into(),
                target: kid.into(),
                reason_code: "compromise".into(),
                ..KeyRevocation::default()
            }
            .encode_to_vec(),
        )
    }

    /// The watch of a kind (segment) is refused until `watch_up`.
    pub fn watch_down(&self, kind: &str) {
        self.inner.lock().unwrap().watch_down.push(kind.to_owned());
        self.changed.notify_waiters();
    }

    pub fn watch_up(&self) {
        self.inner.lock().unwrap().watch_down.clear();
    }

    /// A restore: the change log is now at `point`, behind what a cursor saved.
    pub fn restore_to(&self, point: u64) {
        let mut i = self.inner.lock().unwrap();
        i.seq = point;
        i.log.retain(|(s, _, _)| *s <= point);
        i.restores += 1;
    }

    /// A report put there by something else (an older exporter, a destination since removed).
    pub fn put_report(&self, id: &str, r: &ExportReport) {
        self.put_raw("export-report", id, r.encode_to_vec());
    }

    /// A cursor put there by something else (an exporter from before epochs).
    pub fn put_cursor(&self, id: &str, c: &ExportCursor) {
        self.put_raw("export-cursor", id, c.encode_to_vec());
    }

    pub fn manifest(&self) -> Option<ExportManifest> {
        let i = self.inner.lock().unwrap();
        i.items
            .get(&("export-manifest".to_owned(), "default".to_owned()))
            .map(|(_, b)| ExportManifest::decode_from_slice(b).unwrap())
    }

    pub fn head(&self) -> u64 {
        self.inner.lock().unwrap().seq
    }

    /// The log forgets everything before `point`.
    pub fn forget_before(&self, point: u64) {
        self.inner.lock().unwrap().floor = point;
    }

    pub fn reports(&self) -> BTreeMap<String, ExportReport> {
        let i = self.inner.lock().unwrap();
        i.items
            .iter()
            .filter(|((k, _), _)| k == "export-report")
            .map(|((_, id), (_, b))| (id.clone(), ExportReport::decode_from_slice(b).unwrap()))
            .collect()
    }

    pub fn report(&self, id: &str) -> Option<ExportReport> {
        self.reports().remove(id)
    }

    pub fn report_log(&self) -> Vec<(String, ExportReport, usize)> {
        self.inner.lock().unwrap().report_log.clone()
    }

    pub fn cursor(&self, id: &str) -> Option<ExportCursor> {
        let i = self.inner.lock().unwrap();
        i.items
            .get(&("export-cursor".to_owned(), id.to_owned()))
            .map(|(_, b)| ExportCursor::decode_from_slice(b).unwrap())
    }

    pub fn delete_cursors(&self) {
        self.inner
            .lock()
            .unwrap()
            .items
            .retain(|(k, _), _| k != "export-cursor");
    }

    pub fn lists(&self) -> Vec<(String, Consistency)> {
        self.inner.lock().unwrap().lists.clone()
    }

    pub fn gets(&self) -> Vec<(String, String, bool)> {
        self.inner.lock().unwrap().gets.clone()
    }

    pub fn opens(&self) -> Vec<(String, u64)> {
        self.inner.lock().unwrap().opens.clone()
    }

    pub fn clear_requests(&self) {
        let mut i = self.inner.lock().unwrap();
        i.lists.clear();
        i.gets.clear();
        i.opens.clear();
    }

    fn refused(&self, kind: &str) -> bool {
        self.down.load(Ordering::SeqCst)
            || (kind == "key-revocation" && self.revocations_down.load(Ordering::SeqCst))
            || (kind == "signing-ring" && self.ring_down.load(Ordering::SeqCst))
    }
}

pub struct StoreSvc(pub Arc<FakeStore>);

impl StoreService for StoreSvc {
    async fn get(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        let (kind, id) = (r.address.kind.to_string(), r.address.id.to_string());
        if self.0.refused(&kind) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let mut i = self.0.inner.lock().unwrap();
        let found = i.items.get(&(kind.clone(), id.clone())).cloned();
        i.gets.push((kind.clone(), id.clone(), found.is_some()));
        match found {
            Some((v, b)) => Response::ok(GetResponse {
                item: Some(item(&kind, &id, v, &b)).into(),
                ..GetResponse::default()
            }),
            None => Err(refusal(ErrorCode::NotFound, "absent", "")),
        }
    }

    async fn list(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        let kind = r.kind.to_string();
        if self.0.refused(&kind) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let mut i = self.0.inner.lock().unwrap();
        i.lists
            .push((kind.clone(), r.consistency.as_known().unwrap_or_default()));
        let rows: Vec<Item> = i
            .items
            .iter()
            .filter(|((k, _), _)| *k == kind)
            .map(|((k, id), (v, b))| item(k, id, *v, b))
            .collect();
        Response::ok(ListResponse {
            items: rows,
            resume_point: i.seq,
            log_epoch: 1 + i.restores,
            ..ListResponse::default()
        })
    }

    async fn write(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let req = r.to_owned_message();
        let [op] = req.operations.as_slice() else {
            return Err(refusal(ErrorCode::InvalidArgument, "schema", "operations"));
        };
        let verb = op.verb.as_known();
        if verb != Some(Verb::APPLY) && verb != Some(Verb::DELETE) {
            return Err(refusal(ErrorCode::PermissionDenied, "rule", "verb"));
        }
        let (kind, id) = (op.address.kind.clone(), op.address.id.clone());
        if !matches!(
            kind.as_str(),
            "export-report" | "export-cursor" | "export-manifest"
        ) {
            return Err(refusal(ErrorCode::PermissionDenied, "rule", "kind"));
        }
        if kind == "export-report" && self.0.reports_down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        if verb == Some(Verb::DELETE) {
            let gone = self
                .0
                .inner
                .lock()
                .unwrap()
                .items
                .remove(&(kind.clone(), id.clone()));
            if gone.is_none() {
                return Err(refusal(ErrorCode::NotFound, "absent", ""));
            }
            self.0.changed.notify_waiters();
            return Response::ok(WriteResponse::default());
        }
        if kind == "export-report" {
            let calls = self
                .0
                .memory
                .lock()
                .unwrap()
                .as_ref()
                .map_or(0, |m| m.calls().len());
            let report = ExportReport::decode_from_slice(&op.value).unwrap();
            self.0
                .inner
                .lock()
                .unwrap()
                .report_log
                .push((id.clone(), report, calls));
        }
        let v = {
            let mut i = self.0.inner.lock().unwrap();
            let key = (kind.clone(), id.clone());
            let v = i.items.get(&key).map_or(1, |(v, _)| v + 1);
            i.items.insert(key, (v, op.value.clone()));
            v
        };
        Response::ok(WriteResponse {
            items: vec![item(&kind, &id, v, &op.value)],
            ..WriteResponse::default()
        })
    }

    async fn get_signed_config(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, GetSignedConfigRequest>,
    ) -> ServiceResult<GetSignedConfigResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }

    async fn watch(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        let (kind, from, epoch_asked) = (r.kind.to_string(), r.resume_point, r.log_epoch);
        if self.0.refused(&kind) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        {
            let mut i = self.0.inner.lock().unwrap();
            i.opens.push((kind.clone(), from));
            if i.watch_down.contains(&kind) {
                return Err(refusal(ErrorCode::Unavailable, "engine", ""));
            }
            if from != 0 && (epoch_asked != 1 + i.restores || from < i.floor || from > i.seq) {
                return Err(refusal(
                    ErrorCode::FailedPrecondition,
                    "resume_point_expired",
                    "resume_point",
                ));
            }
        }
        self.0.watching.fetch_add(1, Ordering::SeqCst);
        let store = Arc::clone(&self.0);
        let epoch = 1 + store.inner.lock().unwrap().restores;
        let stream = futures::stream::unfold((store, from), move |(store, mut at)| {
            let kind = kind.clone();
            async move {
                loop {
                    if store.down.load(Ordering::SeqCst)
                        || store.inner.lock().unwrap().watch_down.contains(&kind)
                    {
                        // The store goes away: the stream breaks.
                        return Some((
                            Err(refusal(ErrorCode::Unavailable, "engine", "")),
                            (store, at),
                        ));
                    }
                    let watched = Arc::clone(&store);
                    let notified = watched.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    let next = {
                        let i = store.inner.lock().unwrap();
                        i.log
                            .iter()
                            .find(|(s, k, _)| *s > at && *k == kind)
                            .cloned()
                            .map(|(s, k, id)| {
                                let (v, b) =
                                    i.items.get(&(k.clone(), id.clone())).cloned().unwrap();
                                (s, item(&k, &id, v, &b))
                            })
                    };
                    if let Some((seq, it)) = next {
                        at = seq;
                        let m = WatchResponse {
                            resume_point: seq,
                            log_epoch: epoch,
                            r#type: ChangeType::CHANGE_TYPE_PUT.into(),
                            item: Some(it).into(),
                            ..WatchResponse::default()
                        };
                        return Some((Ok(m), (store, at)));
                    }
                    // Nothing to say: wait for a change, and say a bookmark now and then.
                    if tokio::time::timeout(Duration::from_millis(300), notified)
                        .await
                        .is_err()
                    {
                        let head = store.inner.lock().unwrap().seq;
                        let m = WatchResponse {
                            resume_point: head.max(at),
                            log_epoch: epoch,
                            r#type: ChangeType::CHANGE_TYPE_BOOKMARK.into(),
                            ..WatchResponse::default()
                        };
                        return Some((Ok(m), (store, at)));
                    }
                }
            }
        });
        Response::ok(Box::pin(stream) as ServiceStream<WatchResponse>)
    }
}

// ---------------------------------------------------------------- the stand-in for the audit transport

#[derive(Default)]
pub struct FakeSpool {
    pub emitted: Mutex<Vec<Value>>,
}

impl FakeSpool {
    pub fn records(&self) -> Vec<Value> {
        self.emitted.lock().unwrap().clone()
    }

    /// The records of one action.
    pub fn of(&self, action: &str) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["metadata"]["event_code"] == action)
            .collect()
    }
}

pub struct SpoolSvc(pub Arc<FakeSpool>);

impl TransportService for SpoolSvc {
    async fn emit(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        let rec: Value = serde_json::from_slice(r.message.record).unwrap();
        self.0.emitted.lock().unwrap().push(rec);
        Response::ok(EmitResponse::default())
    }
    async fn receive(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ReceiveRequest>,
    ) -> ServiceResult<ServiceStream<ReceiveResponse>> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn ack(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, AckRequest>,
    ) -> ServiceResult<AckResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
}

// ---------------------------------------------------------------- the world

fn me_as(name: &'static str) -> Identities {
    let me = rustix::process::geteuid().as_raw();
    Identities::with(0, move |u| (u == me).then_some((name, 0)))
}

fn fake_server(socket: &Path, actor: &'static str, router: Router) -> oneshot::Sender<()> {
    let cfg = ServerConfig {
        actor,
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o660,
        socket_gid: None,
        allow: Allow::Exact("exporter"),
        default_deadline: Duration::from_secs(5),
    };
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        me_as("exporter"),
    ));
    tx
}

pub struct World {
    pub store: Arc<FakeStore>,
    pub spool: Arc<FakeSpool>,
    pub dir: tempfile::TempDir,
    stops: Vec<oneshot::Sender<()>>,
}

impl World {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeStore::default());
        let spool = Arc::new(FakeSpool::default());
        let stops = vec![
            fake_server(
                &dir.path().join("store.sock"),
                "store",
                Arc::clone(&store).pipe_store(),
            ),
            fake_server(
                &dir.path().join("emit.sock"),
                "transport",
                Arc::new(SpoolSvc(Arc::clone(&spool))).register(Router::new()),
            ),
        ];
        for n in ["store.sock", "emit.sock"] {
            for _ in 0..200 {
                if dir.path().join(n).exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        Self {
            store,
            spool,
            dir,
            stops,
        }
    }

    /// An engine for these destinations with test timings: a budget of a second or two and short waits.
    pub fn engine<D: Destination + 'static>(
        &self,
        targets: Vec<Target<D>>,
        tweak: impl FnOnce(&mut EngineConfig<D>),
    ) -> Engine<D> {
        let mut c = EngineConfig {
            boundary: "dev".into(),
            store: self.dir.path().join("store.sock"),
            audit: AuditConfig {
                actor: "exporter".into(),
                boundary: "dev".into(),
                release: "0.0.0-test".into(),
                transport_socket: self.dir.path().join("emit.sock"),
                key_socket: None,
                now: None,
            },
            targets,
            refused: Vec::new(),
            reconcile: Duration::from_secs(3600),
            retry: Duration::from_millis(150),
            timing: Timing {
                budget: Duration::from_secs(2),
                initial: Duration::from_millis(20),
                max: Duration::from_millis(100),
                call: Duration::from_secs(2),
                alert_every: Duration::from_millis(300),
            },
            backoff: Backoff {
                initial: Duration::from_millis(20),
                max: Duration::from_millis(100),
            },
            now: std::time::SystemTime::now,
        };
        tweak(&mut c);
        Engine::new(c).unwrap()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        for s in self.stops.drain(..) {
            let _ = s.send(());
        }
    }
}

trait PipeStore {
    fn pipe_store(self) -> Router;
}
impl PipeStore for Arc<FakeStore> {
    fn pipe_store(self) -> Router {
        Arc::new(StoreSvc(self)).register(Router::new())
    }
}

/// An engine running in the background; `stop` ends it and returns its result.
pub struct Running {
    stop: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

pub fn spawn<D: Destination + 'static>(e: Engine<D>) -> Running {
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(e.run(async move {
        let _ = rx.await;
    }));
    Running {
        stop: Some(tx),
        handle: Some(handle),
    }
}

impl Running {
    pub async fn stop(mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .expect("the engine stops")
                .unwrap();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

/// Waits until `f` is true, up to `secs`.
pub async fn until(secs: u64, what: &str, f: impl FnMut() -> bool) {
    until_saying(secs, what, f, String::new).await;
}

/// As [`until`], and on a timeout `state` says what was there instead.
pub async fn until_saying(
    secs: u64,
    what: &str,
    mut f: impl FnMut() -> bool,
    state: impl Fn() -> String,
) {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for: {what}; {}", state());
}

// ---------------------------------------------------------------- keys

/// A P-384 key made for the test: the ring entry, and a way to sign with it.
pub struct TestKey {
    pub pair: EcdsaKeyPair,
    pub key: SigningKey,
}

pub fn test_key(kid: &str, state: &str) -> TestKey {
    let pair = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
    let mut spki = vec![
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
    ];
    spki.extend_from_slice(pair.public_key().as_ref());
    TestKey {
        pair,
        key: SigningKey {
            key_id: kid.into(),
            algorithm: "ES384".into(),
            spki_der: spki,
            state: state.into(),
            ..SigningKey::default()
        },
    }
}

pub fn doc() -> Doc {
    Doc {
        name: "jwks".into(),
        address: "jwks".into(),
        content_type: "application/json".into(),
        cache_control: "public, max-age=300".into(),
        public_address: None,
    }
}

pub fn public_doc(base: &str) -> Doc {
    Doc {
        public_address: Some(format!("{base}/jwks")),
        ..doc()
    }
}

/// The kids a key set document lists.
pub fn kids(body: &[u8]) -> Vec<String> {
    let v: Value = serde_json::from_slice(body).expect("a key set is JSON");
    v["keys"]
        .as_array()
        .expect("a key set has keys")
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------- a destination that hangs

/// A destination that answers as `inner` does until `hang` is set, and then never answers at all (a driver that is
/// wedged, an edge whose API accepts the connection and says nothing).
#[derive(Clone)]
pub struct Hang<D> {
    pub inner: D,
    pub hang: Arc<AtomicBool>,
}

impl<D> Hang<D> {
    pub fn new(inner: D) -> Self {
        Self {
            inner,
            hang: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn stuck(&self) {
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    }
}

impl<D: Destination> Destination for Hang<D> {
    async fn put(
        &self,
        doc: sluis_destination::Document,
    ) -> Result<sluis_destination::Written, sluis_destination::Error> {
        self.stuck().await;
        self.inner.put(doc).await
    }
    async fn delete(&self, address: &str) -> Result<bool, sluis_destination::Error> {
        self.stuck().await;
        self.inner.delete(address).await
    }
    async fn list(
        &self,
        prefix: &str,
        page: Option<&str>,
        page_size: usize,
    ) -> Result<sluis_destination::Page, sluis_destination::Error> {
        self.stuck().await;
        self.inner.list(prefix, page, page_size).await
    }
    async fn purge(
        &self,
        addresses: &[String],
    ) -> Result<sluis_destination::Purged, sluis_destination::Error> {
        self.stuck().await;
        self.inner.purge(addresses).await
    }
    async fn read_back(
        &self,
        address: &str,
    ) -> Result<sluis_destination::Fetched, sluis_destination::Error> {
        self.stuck().await;
        self.inner.read_back(address).await
    }
}

// ---------------------------------------------------------------- a put that lands and says it did not

/// A destination whose `put`, while `lose_answer` is set, takes the document and then fails: the call timed out after the
/// document had landed, which the caller cannot tell from a call that never arrived.
#[derive(Clone)]
pub struct Lossy<D> {
    pub inner: D,
    pub lose_answer: Arc<AtomicBool>,
}

impl<D> Lossy<D> {
    pub fn new(inner: D) -> Self {
        Self {
            inner,
            lose_answer: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl<D: Destination> Destination for Lossy<D> {
    async fn put(
        &self,
        doc: sluis_destination::Document,
    ) -> Result<sluis_destination::Written, sluis_destination::Error> {
        let done = self.inner.put(doc).await?;
        if self.lose_answer.load(Ordering::SeqCst) {
            return Err(sluis_destination::Error::Unavailable(
                "the call timed out".into(),
            ));
        }
        Ok(done)
    }
    async fn delete(&self, address: &str) -> Result<bool, sluis_destination::Error> {
        self.inner.delete(address).await
    }
    async fn list(
        &self,
        prefix: &str,
        page: Option<&str>,
        page_size: usize,
    ) -> Result<sluis_destination::Page, sluis_destination::Error> {
        self.inner.list(prefix, page, page_size).await
    }
    async fn purge(
        &self,
        addresses: &[String],
    ) -> Result<sluis_destination::Purged, sluis_destination::Error> {
        self.inner.purge(addresses).await
    }
    async fn read_back(
        &self,
        address: &str,
    ) -> Result<sluis_destination::Fetched, sluis_destination::Error> {
        self.inner.read_back(address).await
    }
}
