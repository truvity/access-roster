//! Test support: a log made as the writer makes it (actors/writer/internal/writerd), stand-ins for the
//! services the indexer calls, and the real index driver behind its real sockets. All test code; every
//! call between the indexer and the others is Connect over `proto/`.

#![allow(refining_impl_trait)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use buffa::Message as _;
use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult};
use indexer::entry::{self, TILE};
use indexer::merkle;
use indexer::ports::Sockets;
use indexer::run::Settings;
use serde_json::{Value, json};
use sluis_driver_indexer_sqlite::Index;
use sluis_driver_indexer_sqlite::service::{Read, Write};
use sluis_kit::{Allow, Identities, ServerConfig, dial, refusal};
use sluis_proto::sluis::config::v2alpha1::{AuditLog, LogDecl};
use sluis_proto::sluis::key::v2alpha1::{
    KeyService, KeyServiceExt, MacRequest, MacResponse, OpenGrantRequest, OpenGrantResponse,
    OpenRequest, OpenResponse, PublicKeyRequest, PublicKeyResponse, SealGrantRequest,
    SealGrantResponse, SealRequest, SealResponse, SignRequest, SignResponse,
};
use sluis_proto::sluis::policy::v2alpha1::{
    DecideRequest, DecideResponse, Decision, PolicyService, PolicyServiceExt,
};
use sluis_proto::sluis::port::blob::v2alpha1::{
    BlobGetRequest, BlobGetResponse, BlobListRequest, BlobListResponse, BlobService,
    BlobServiceExt, CreateRequest, CreateResponse, PutRequest, PutResponse,
};
use sluis_proto::sluis::port::index::v2alpha1::{
    IndexReadServiceClient, IndexReadServiceExt, IndexServiceExt, Partition, Row, SearchRequest,
};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, Item, ListRequest, ListResponse, StoreService, StoreServiceExt,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use tokio::sync::oneshot;

pub const BOUNDARY: &str = "dev";
pub const PROJECT: &str = "sluis";
pub const LOG: &str = "main";
pub const ORIGIN: &str = "sluis.local.test/dev/sluis/audit/main";
pub const PREFIX: &str = "audit/main/";

/// The fixed prefix of a P-384 `SubjectPublicKeyInfo`.
const SPKI_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

// ---------------------------------------------------------------- the log, as the writer makes it

/// A log key and the log written below `root`/audit/main/.
pub struct TestLog {
    pub root: PathBuf,
    pub key: EcdsaKeyPair,
    pub origin: String,
    pub entries: Vec<Vec<u8>>,
    /// The key that seals the records (the stand-in for the tenants' evidence keys).
    pub seal: Arc<RandomizedNonceKey>,
    /// The verifier key text, when the log was made by another program than this one.
    pub vkey_text: Option<String>,
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    b
}

pub fn new_key() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING).unwrap()
}

impl TestLog {
    pub fn new(root: &Path) -> Self {
        Self::with_key(root, new_key())
    }

    pub fn with_key(root: &Path, key: EcdsaKeyPair) -> Self {
        Self {
            root: root.to_path_buf(),
            key,
            origin: ORIGIN.into(),
            entries: Vec::new(),
            seal: Arc::new(RandomizedNonceKey::new(&AES_256_GCM, &rand_bytes::<32>()).unwrap()),
            vkey_text: None,
        }
    }

    fn spki(&self) -> Vec<u8> {
        [&SPKI_PREFIX[..], self.key.public_key().as_ref()].concat()
    }

    /// The verifier key text: `name+hex(key hash)+base64(0x02 || SubjectPublicKeyInfo)`.
    pub fn vkey(&self) -> String {
        if let Some(t) = &self.vkey_text {
            return t.clone();
        }
        vkey_of(&self.origin, &self.spki())
    }

    fn put(&self, rel: &str, data: &[u8]) {
        let p = self.root.join(PREFIX).join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    /// The signed note of a checkpoint of this log at (size, root).
    pub fn note(&self, origin: &str, size: u64, root: &[u8; 32]) -> Vec<u8> {
        let body = format!("{origin}\n{size}\n{}\n", STANDARD.encode(root));
        let sig = self
            .key
            .sign(&SystemRandom::new(), body.as_bytes())
            .unwrap();
        let spki = self.spki();
        let sum = digest::digest(&digest::SHA256, &spki);
        let line = STANDARD.encode([&sum.as_ref()[..4], sig.as_ref()].concat());
        format!("{body}\n\u{2014} {origin} {line}\n").into_bytes()
    }

    /// The root of the entries by the definition of RFC 6962, independent of the indexer's range.
    pub fn root_of(entries: &[Vec<u8>]) -> [u8; 32] {
        mth(&entries
            .iter()
            .map(|e| merkle::leaf_hash(e))
            .collect::<Vec<_>>())
    }

    /// Appends a batch as the writer does: the bundles (the full ones and the partial tail), then the
    /// checkpoint in `checkpoints/<size>`, then the pointer.
    pub fn append(&mut self, batch: Vec<Vec<u8>>) {
        let old = self.entries.len() as u64;
        self.entries.extend(batch);
        let size = self.entries.len() as u64;
        for n in old / TILE..=(size - 1) / TILE {
            let lo = (n * TILE) as usize;
            let hi = ((n + 1) * TILE).min(size) as usize;
            let mut b = Vec::new();
            for e in &self.entries[lo..hi] {
                b.extend_from_slice(&u16::try_from(e.len()).unwrap().to_be_bytes());
                b.extend_from_slice(e);
            }
            self.put(&entry::bundle_path(n, (hi - lo) as u64), &b);
        }
        let note = self.note(&self.origin, size, &Self::root_of(&self.entries));
        self.put(&format!("checkpoints/{size}"), &note);
        self.put("checkpoint", &note);
    }

    /// Writes a pointer of any content.
    pub fn set_pointer(&self, note: &[u8]) {
        self.put("checkpoint", note);
    }

    pub fn checkpoint_note(&self, size: u64) -> Vec<u8> {
        std::fs::read(self.root.join(PREFIX).join(format!("checkpoints/{size}"))).unwrap()
    }

    pub fn remove(&self, rel: &str) {
        std::fs::remove_file(self.root.join(PREFIX).join(rel)).unwrap();
    }

    pub fn read(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.root.join(PREFIX).join(rel)).unwrap()
    }

    pub fn write(&self, rel: &str, data: &[u8]) {
        self.put(rel, data);
    }

    /// The sealed record entry for a record, as the writer builds it.
    pub fn record_entry(&self, rec: &Rec) -> Vec<u8> {
        let tenant = rec
            .routed
            .as_deref()
            .or(rec.tenant.as_deref())
            .unwrap_or("acme");
        let record = rec.bytes();
        let envelope = seal(&self.seal, tenant, &rec.seal_id(), &record);
        let v = json!({
            "entry": "record",
            "time": rec.envelope_time.unwrap_or(rec.time),
            "class_uid": 6003, "activity_id": 99, "status_id": 1,
            "actor": {"user": {"type_id": 3}},
            "metadata": {"uid": rec.uid, "tenant_uid": tenant},
            "sealed": STANDARD.encode(envelope),
            "writer": {"instance": "node-1", "recorded_at": rec.time + 5},
        });
        serde_json::to_vec(&v).unwrap()
    }

    pub fn seal_entry(&self, records: usize) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "entry": "seal", "records": records, "duplicates": 0, "refused": 0,
            "clock": {"observed": false}, "writer": {"instance": "node-1", "recorded_at": 1}
        }))
        .unwrap()
    }

    /// Appends a batch of records and the seal entry that ends it.
    pub fn append_records(&mut self, recs: &[Rec]) {
        let mut batch: Vec<Vec<u8>> = recs.iter().map(|r| self.record_entry(r)).collect();
        batch.push(self.seal_entry(recs.len()));
        self.append(batch);
    }
}

pub fn vkey_of(name: &str, spki: &[u8]) -> String {
    let sum = digest::digest(&digest::SHA256, spki);
    let hex: String = sum.as_ref()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "{name}+{hex}+{}",
        STANDARD.encode([&[0x02u8][..], spki].concat())
    )
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    let node = |l: &[u8; 32], r: &[u8; 32]| {
        let mut c = digest::Context::new(&digest::SHA256);
        c.update(&[1]);
        c.update(l);
        c.update(r);
        let mut o = [0u8; 32];
        o.copy_from_slice(c.finish().as_ref());
        o
    };
    match leaves.len() {
        0 => merkle::empty_root(),
        1 => leaves[0],
        n => {
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            node(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// The additional data the stand-in for key@ binds, as the Go stand-in of the writer does.
fn aad(tenant: &str, kind: &str, id: &str) -> Vec<u8> {
    format!("{tenant}|{kind}|{id}").into_bytes()
}

fn seal(key: &RandomizedNonceKey, tenant: &str, id: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut buf = plaintext.to_vec();
    let nonce = key
        .seal_in_place_append_tag(Aad::from(aad(tenant, entry::SEAL_KIND, id)), &mut buf)
        .unwrap();
    [nonce.as_ref().as_slice(), &buf].concat()
}

/// A record, as the emitter makes it.
#[derive(Clone)]
pub struct Rec {
    pub uid: String,
    pub tenant: Option<String>,
    pub action: String,
    pub time: i64,
    pub status_code: String,
    pub trace: String,
    /// The tenant the writer routed it to, when the record names none or the test lies.
    pub routed: Option<String>,
    /// A time the envelope states that the record does not.
    pub envelope_time: Option<i64>,
    pub boundary: String,
}

impl Rec {
    pub fn new(n: u32, tenant: &str, action: &str) -> Self {
        Self {
            uid: format!("0194d000-0000-7000-8000-{n:012}"),
            tenant: Some(tenant.into()),
            action: action.into(),
            time: 1_700_000_000_000 + i64::from(n) * 1000,
            status_code: "ok".into(),
            trace: format!("trace-{n}"),
            routed: None,
            envelope_time: None,
            boundary: BOUNDARY.into(),
        }
    }

    /// The record, canonical JSON: keys sorted, integers only (RFC 8785 for this subset).
    pub fn bytes(&self) -> Vec<u8> {
        let mut md = json!({
            "uid": self.uid, "event_code": self.action, "log_name": self.boundary,
            "product": {"name": PROJECT, "version": "0.0.0"},
            "correlation_uid": self.trace,
        });
        if let Some(t) = &self.tenant {
            md["tenant_uid"] = json!(t);
        }
        let v = json!({
            "time": self.time, "class_uid": 6003, "activity_id": 99, "status_id": 1,
            "status_code": self.status_code,
            "actor": {"user": {"uid": "signer@dev", "type_id": 3}},
            "metadata": md,
        });
        serde_json::to_vec(&v).unwrap()
    }

    pub fn seal_id(&self) -> String {
        entry::seal_id(PROJECT, "audit", LOG, &self.uid)
    }
}

// ---------------------------------------------------------------- the stand-ins

fn identities(me_is: &'static str) -> Identities {
    let me = rustix::process::geteuid().as_raw();
    Identities::with(0, move |uid| (uid == me).then_some((me_is, 0)))
}

fn serve(
    socket: &Path,
    actor: &'static str,
    router: Router,
    allow: Allow,
    me_is: &'static str,
) -> oneshot::Sender<()> {
    let cfg = ServerConfig {
        actor,
        boundary: BOUNDARY.into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow,
        default_deadline: std::time::Duration::from_secs(20),
    };
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        identities(me_is),
    ));
    tx
}

async fn up(socket: &Path) {
    for _ in 0..500 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no socket {}", socket.display());
}

/// The blob port over the directory the log was written to: Get and List only (the indexer reads).
struct BlobSvc(PathBuf);

impl BlobService for BlobSvc {
    async fn create(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, CreateRequest>,
    ) -> ServiceResult<CreateResponse> {
        Err(refusal(ErrorCode::PermissionDenied, "rule", "path"))
    }
    async fn put(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, PutRequest>,
    ) -> ServiceResult<PutResponse> {
        Err(refusal(ErrorCode::PermissionDenied, "rule", "path"))
    }
    async fn get(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, BlobGetRequest>,
    ) -> ServiceResult<BlobGetResponse> {
        let path = r.path.to_string();
        assert!(!path.contains(".."), "the indexer asked for {path}");
        match std::fs::read(self.0.join(&path)) {
            Ok(data) => Response::ok(BlobGetResponse {
                data,
                etag: "x".into(),
                ..BlobGetResponse::default()
            }),
            Err(_) => Err(refusal(ErrorCode::NotFound, "absent", "path")),
        }
    }
    async fn list(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, BlobListRequest>,
    ) -> ServiceResult<BlobListResponse> {
        let prefix = r.prefix.to_string();
        let mut paths = Vec::new();
        walk(&self.0, &self.0, &mut paths);
        paths.retain(|p| p.starts_with(&prefix));
        paths.sort();
        Response::ok(BlobListResponse {
            paths,
            ..BlobListResponse::default()
        })
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(root, &p, out);
        } else {
            out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
        }
    }
}

/// What the stand-ins saw and how they behave.
#[derive(Default)]
pub struct Control {
    /// Every question put to policy.
    pub decides: Mutex<Vec<DecideRequest>>,
    /// policy answers DENY.
    pub deny: AtomicBool,
    /// policy is down.
    pub policy_down: AtomicBool,
    /// key@ is down.
    pub key_down: AtomicBool,
    /// The number of Open calls key@ took.
    pub opens: AtomicUsize,
    /// The number of Open items key@ opened.
    pub opened: AtomicUsize,
    /// key@ refuses the first grant it sees as expired.
    pub expire_first_grant: AtomicBool,
    /// The grants key@ saw, in order.
    pub grants: Mutex<Vec<Vec<u8>>>,
    /// The number of grants policy made.
    pub made: AtomicUsize,
    /// The addresses key@ was asked to open.
    pub addresses: Mutex<Vec<Address>>,
    /// What key@ opens, by sealed envelope, for a log made by another program (the Go writer's fixture).
    pub table: Mutex<Option<Vec<Opened>>>,
}

/// What the writer's own stand-in for key@ opened an entry to, at its address.
#[derive(Clone)]
pub struct Opened {
    pub envelope: Vec<u8>,
    pub tenant: String,
    pub kind: String,
    pub id: String,
    pub plaintext: Vec<u8>,
}

struct PolicySvc(Arc<Control>);

impl PolicyService for PolicySvc {
    async fn decide(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, DecideRequest>,
    ) -> ServiceResult<DecideResponse> {
        self.0.decides.lock().unwrap().push(r.to_owned_message());
        if self.0.policy_down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        if self.0.deny.load(Ordering::SeqCst) {
            return Response::ok(DecideResponse {
                decision: Decision::DENY.into(),
                ..DecideResponse::default()
            });
        }
        let n = self.0.made.fetch_add(1, Ordering::SeqCst);
        Response::ok(DecideResponse {
            decision: Decision::ALLOW.into(),
            sealed_grant: format!("grant:{}:{n}", r.tenant).into_bytes(),
            decision_id: "d".into(),
            ..DecideResponse::default()
        })
    }
}

struct KeySvc {
    c: Arc<Control>,
    seal: Arc<RandomizedNonceKey>,
}

fn unimplemented<T>() -> ServiceResult<T> {
    Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
}

impl KeyService for KeySvc {
    async fn open(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, OpenRequest>,
    ) -> ServiceResult<OpenResponse> {
        let req = r.to_owned_message();
        self.c.opens.fetch_add(1, Ordering::SeqCst);
        if self.c.key_down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        // key@ checks the grant first: it must be one policy made for every tenant (the question asked for "*").
        let first = {
            let mut g = self.c.grants.lock().unwrap();
            g.push(req.grant.clone());
            g.len() == 1
        };
        if !req.grant.starts_with(b"grant:*:")
            || (first && self.c.expire_first_grant.load(Ordering::SeqCst))
        {
            return Err(refusal(ErrorCode::PermissionDenied, "grant", "grant"));
        }
        if req.items.is_empty() || req.items.len() > 64 {
            return Err(refusal(ErrorCode::InvalidArgument, "bound", "items"));
        }
        let mut plaintexts = Vec::new();
        for it in &req.items {
            let a = it.address.as_option().cloned().unwrap_or_default();
            self.c.addresses.lock().unwrap().push(a.clone());
            if it.purpose != "evidence" || a.kind != entry::SEAL_KIND {
                return Err(refusal(ErrorCode::InvalidArgument, "purpose", "items"));
            }
            if let Some(table) = self.c.table.lock().unwrap().as_ref() {
                let hit = table.iter().find(|t| t.envelope == it.envelope);
                match hit {
                    Some(t) if (&t.tenant, &t.kind, &t.id) == (&a.tenant, &a.kind, &a.id) => {
                        plaintexts.push(t.plaintext.clone());
                        continue;
                    }
                    _ => return Err(refusal(ErrorCode::PermissionDenied, "open", "")),
                }
            }
            let (nonce, ct) = it.envelope.split_at(12.min(it.envelope.len()));
            let mut buf = ct.to_vec();
            let opened = Nonce::try_assume_unique_for_key(nonce).ok().and_then(|n| {
                self.seal
                    .open_in_place(n, Aad::from(aad(&a.tenant, &a.kind, &a.id)), &mut buf)
                    .ok()
                    .map(|p| p.to_vec())
            });
            match opened {
                Some(p) => plaintexts.push(p),
                None => return Err(refusal(ErrorCode::PermissionDenied, "open", "")),
            }
        }
        self.c.opened.fetch_add(plaintexts.len(), Ordering::SeqCst);
        Response::ok(OpenResponse {
            plaintexts,
            ..OpenResponse::default()
        })
    }
    async fn seal(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SealRequest>,
    ) -> ServiceResult<SealResponse> {
        unimplemented()
    }
    async fn seal_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SealGrantRequest>,
    ) -> ServiceResult<SealGrantResponse> {
        unimplemented()
    }
    async fn open_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, OpenGrantRequest>,
    ) -> ServiceResult<OpenGrantResponse> {
        unimplemented()
    }
    async fn sign(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, SignRequest>,
    ) -> ServiceResult<SignResponse> {
        unimplemented()
    }
    async fn mac(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, MacRequest>,
    ) -> ServiceResult<MacResponse> {
        unimplemented()
    }
    async fn public_key(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, PublicKeyRequest>,
    ) -> ServiceResult<PublicKeyResponse> {
        unimplemented()
    }
}

struct StoreSvc(Vec<u8>);

impl StoreService for StoreSvc {
    async fn get(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        if r.address.kind != "audit-log" || r.address.id != "default" {
            return Err(refusal(ErrorCode::NotFound, "absent", ""));
        }
        Response::ok(GetResponse {
            item: Some(Item {
                address: Some(Address {
                    kind: "audit-log".into(),
                    id: "default".into(),
                    ..Address::default()
                })
                .into(),
                version: 1,
                value: self.0.clone(),
                ..Item::default()
            })
            .into(),
            ..GetResponse::default()
        })
    }
    async fn list(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        unimplemented()
    }
    async fn write(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        unimplemented()
    }
    async fn watch(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<WatchResponse>> {
        unimplemented()
    }
}

// ---------------------------------------------------------------- the environment

/// Everything a test needs: the log, the stand-ins, the real index driver and the settings.
pub struct Env {
    pub log: TestLog,
    pub control: Arc<Control>,
    pub settings: Settings,
    pub index: Index,
    pub reader: IndexReadServiceClient<sluis_kit::Transport>,
    _stops: Vec<oneshot::Sender<()>>,
    _dirs: Vec<tempfile::TempDir>,
}

impl Env {
    pub async fn new() -> Self {
        let blob_root = tempfile::tempdir().unwrap();
        let log = TestLog::new(blob_root.path());
        Self::with_log(log, blob_root).await
    }

    /// The log the merged Go writer made (testdata/go-writer): its blob copied to a directory, its verifier
    /// key, and what the writer's stand-in for key@ opened each entry to.
    pub async fn go_writer() -> Self {
        let from = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/go-writer");
        let dir = tempfile::tempdir().unwrap();
        copy_dir(&from.join("audit"), &dir.path().join("audit"));
        let mut log = TestLog::new(dir.path());
        log.vkey_text = Some(
            std::fs::read_to_string(from.join("vkey"))
                .unwrap()
                .trim()
                .to_owned(),
        );
        let table: Vec<Value> =
            serde_json::from_slice(&std::fs::read(from.join("opened.json")).unwrap()).unwrap();
        let table = table
            .iter()
            .map(|t| {
                let s = |k: &str| t[k].as_str().unwrap().to_owned();
                Opened {
                    envelope: STANDARD.decode(s("Envelope")).unwrap(),
                    tenant: s("Tenant"),
                    kind: s("Kind"),
                    id: s("ID"),
                    plaintext: STANDARD.decode(s("Plaintext")).unwrap(),
                }
            })
            .collect();
        let env = Self::with_log(log, dir).await;
        *env.control.table.lock().unwrap() = Some(table);
        env
    }

    pub async fn with_log(log: TestLog, blob_root: tempfile::TempDir) -> Self {
        let socks = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(keys.path().join(format!("{LOG}.vkey")), log.vkey()).unwrap();

        let s = socks.path();
        let sockets = Sockets {
            blob: s.join("blob.sock"),
            key: s.join("key.sock"),
            policy: s.join("policy.sock"),
            index: s.join("index.sock"),
            store: s.join("store.sock"),
        };
        let ro = s.join("index-ro.sock");
        let control = Arc::new(Control::default());
        let index = Index::open(state.path()).unwrap();

        let doc = AuditLog {
            project: PROJECT.into(),
            logs: vec![
                LogDecl {
                    kind: "audit".into(),
                    id: LOG.into(),
                    origin: ORIGIN.into(),
                    ..LogDecl::default()
                },
                LogDecl {
                    kind: "usage".into(),
                    id: LOG.into(),
                    origin: "x/usage".into(),
                    ..LogDecl::default()
                },
            ],
            lock_mode: "none".into(),
            ..AuditLog::default()
        };
        let mut stops = vec![
            serve(
                &sockets.blob,
                "driver-writer-fs",
                Arc::new(BlobSvc(blob_root.path().to_path_buf())).register(Router::new()),
                Allow::Exact("indexer"),
                "indexer",
            ),
            serve(
                &sockets.key,
                "key",
                Arc::new(KeySvc {
                    c: control.clone(),
                    seal: log.seal.clone(),
                })
                .register(Router::new()),
                Allow::Exact("indexer"),
                "indexer",
            ),
            serve(
                &sockets.policy,
                "policy",
                Arc::new(PolicySvc(control.clone())).register(Router::new()),
                Allow::Exact("indexer"),
                "indexer",
            ),
            serve(
                &sockets.store,
                "store",
                Arc::new(StoreSvc(doc.encode_to_vec())).register(Router::new()),
                Allow::Exact("indexer"),
                "indexer",
            ),
            serve(
                &sockets.index,
                "driver-indexer-sqlite",
                Arc::new(Write(index.clone())).register(Router::new()),
                Allow::OwnerOnly("indexer"),
                "indexer",
            ),
            serve(
                &ro,
                "driver-indexer-sqlite",
                Arc::new(Read(index.clone())).register(Router::new()),
                Allow::Exact("reader"),
                "reader",
            ),
        ];
        for p in [
            &sockets.blob,
            &sockets.key,
            &sockets.policy,
            &sockets.store,
            &sockets.index,
            &ro,
        ] {
            up(p).await;
        }
        let c = dial(&ro);
        let reader = IndexReadServiceClient::new(c.transport(), c.config());
        let settings = Settings {
            boundary: BOUNDARY.into(),
            sockets,
            key_dir: keys.path().to_path_buf(),
            poll: std::time::Duration::from_millis(50),
        };
        stops.shrink_to_fit();
        Self {
            log,
            control,
            settings,
            index,
            reader,
            _stops: stops,
            _dirs: vec![blob_root, socks, keys, state],
        }
    }

    /// All rows of the audit partition for the tenants, newest first, over the reader's socket.
    pub async fn search(&self, tenants: &[&str], q: &str) -> Vec<Row> {
        let mut out = Vec::new();
        let mut token = Vec::new();
        loop {
            let page = self
                .reader
                .search(SearchRequest {
                    partitions: vec![Partition {
                        project: PROJECT.into(),
                        kind: "audit".into(),
                        ..Partition::default()
                    }],
                    tenants: tenants.iter().map(|t| (*t).into()).collect(),
                    q: q.into(),
                    page_size: 200,
                    page_token: token,
                    ..SearchRequest::default()
                })
                .await
                .unwrap()
                .into_owned();
            out.extend(page.rows);
            if page.next_page_token.is_empty() {
                return out;
            }
            token = page.next_page_token;
        }
    }

    pub fn cursor_size(&self) -> i64 {
        use sluis_proto::sluis::port::index::v2alpha1::{GetCursorRequest, LogRef};
        self.index
            .get_cursor(&GetCursorRequest {
                log: ::buffa::MessageField::some(LogRef {
                    project: PROJECT.into(),
                    kind: "audit".into(),
                    log: LOG.into(),
                    ..LogRef::default()
                }),
                ..GetCursorRequest::default()
            })
            .unwrap()
            .cursor
            .as_option()
            .map_or(0, |c| c.size)
    }
}

pub fn by_tenant(rows: &[Row]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for r in rows {
        *m.entry(r.tenant.clone()).or_default() += 1;
    }
    m
}

pub fn value(row: &Row) -> Value {
    serde_json::from_slice(&row.record).unwrap()
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let (p, t) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}
