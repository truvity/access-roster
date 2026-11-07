#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `signer` over its real Unix socket, against in-process stand-ins for `store@`, `key@` and the
//! audit transport (test code only; every call between them is Connect over `proto/`). The
//! stand-ins name the test process as the caller `signer`, and the signer under test names it as
//! the caller the test chooses, through the kit's test identities.
//!
//! The stand-in for `key@` signs ES384 with a key made for the test and applies the content rule of
//! the real `key@` to what it signs (`actors/key/internal/content`: the header holds exactly `alg`,
//! `kid` and `typ`, the payload is an object with `iss`, `aud`, `iat` and `exp`). A token is checked
//! with go-jose, through the compiled test of `actors/signer/tests/gojose`, against the key set that
//! `signer` publishes from the `SigningRing` in the stand-in for `store@`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use buffa::Message as _;
use buffa_types::google::protobuf::{Duration as PbDuration, Timestamp};
use connectrpc::error::ErrorCode;
use connectrpc::{
    ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream,
};
use serde_json::{Value, json};
use signer::ring::Timing;
use signer::{Config, Sockets};
use sluis_kit::{Allow, Identities, ServerConfig, refusal, refusal_reason};
use sluis_proto::sluis::config::v2alpha1::{Boundary, InstallationClient, TokenLifetime};
use sluis_proto::sluis::exporter::v2alpha1::ExportReport;
use sluis_proto::sluis::key::v2alpha1::{
    KeyRevocation, KeyService, KeyServiceExt, PublicKeyRequest, PublicKeyResponse, SignRequest,
    SignResponse,
};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};
use sluis_proto::sluis::signer::v2alpha1::{
    KeySetRequest, SignTokenRequest, SignTokenResponse, SignerServiceClient,
};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, GetSignedConfigRequest, GetSignedConfigResponse, Item, ListRequest,
    ListResponse, StoreService, StoreServiceExt, Verb, WatchRequest, WatchResponse, WriteRequest,
    WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use sluis_store::revocation::{kid_item_id, target_index_value};
use tempfile::TempDir;
use tokio::sync::oneshot;

const ISSUER: &str = "https://sluis.dev.local.test";

// ---------------------------------------------------------------- the stand-in for store@

/// (kind, id) to the (name, value) index entries of the item.
type IndexEntries = HashMap<(String, String), Vec<(String, Vec<u8>)>>;

/// (kind segment, id) to (version, value).
type Items = HashMap<(String, String), (u64, Vec<u8>)>;

#[derive(Default)]
struct FakeStore {
    items: Mutex<Items>,
    /// The writes it took: verb and kind.
    writes: Mutex<Vec<(&'static str, String)>>,
    /// Refuse every read with `unavailable`.
    down: AtomicBool,
    /// Refuse every read of `KeyRevocation` with `unavailable`.
    revocations_down: AtomicBool,
    /// Never answer a `Get` or a `List` of `KeyRevocation`.
    revocation_get_hangs: AtomicBool,
    /// How many `Get`s of `KeyRevocation` found nothing. store@ audits each as a refusal (ADR 0005), so a caller that asks
    /// for an item it expects to be absent writes one record for every ask (REQ-AUDIT-180).
    revocation_gets_absent: AtomicUsize,
    /// Refuse every read of `ExportManifest` and `ExportReport` with `unavailable` (a store@ that has not got the kinds
    /// yet, a timeout, a missing grant).
    publication_down: AtomicBool,
    /// Every `List`: kind and whether it asked for a linearizable read.
    lists: Mutex<Vec<(String, bool)>>,
    /// The index entries of the items a writer gave them: (kind, id) to (name, value).
    indexes: Mutex<IndexEntries>,
    /// Every `List` of `KeyRevocation`: the index it followed (empty for the kind) and the page token it presented.
    revocation_lists: Mutex<Vec<(String, String)>>,
    /// Answer every page of `KeyRevocation` with a next page, for ever.
    revocation_pages_never_end: AtomicBool,
}

impl FakeStore {
    fn put(&self, kind: &str, id: &str, value: Vec<u8>) {
        self.items
            .lock()
            .unwrap()
            .insert((kind.into(), id.into()), (1, value));
    }

    /// Lists the key as revoked, as `key@` does when it takes a declaration.
    fn revoke(&self, kid: &str) {
        let id = kid_item_id(kid).unwrap();
        self.put(
            "key-revocation",
            &id,
            KeyRevocation {
                target_kind: "kid".into(),
                target: kid.into(),
                reason_code: "compromise".into(),
                ..KeyRevocation::default()
            }
            .encode_to_vec(),
        );
        // key@ gives every item the entry of the index by_target.
        self.indexes.lock().unwrap().insert(
            ("key-revocation".into(), id),
            vec![("by_target".into(), target_index_value("kid", kid))],
        );
    }

    /// An item of `KeyRevocation` that an earlier key@ wrote: no entry in the index.
    fn revoke_without_index(&self, kid: &str) {
        self.revoke(kid);
        self.indexes.lock().unwrap().clear();
    }

    fn ring(&self) -> Option<(u64, sluis_proto::sluis::signer::v2alpha1::SigningRing)> {
        let items = self.items.lock().unwrap();
        let (v, bytes) = items.get(&("signing-ring".into(), "default".into()))?;
        Some((
            *v,
            sluis_proto::sluis::signer::v2alpha1::SigningRing::decode_from_slice(bytes).unwrap(),
        ))
    }
}

fn address(kind: &str, id: &str) -> Address {
    Address {
        kind: kind.into(),
        id: id.into(),
        ..Address::default()
    }
}

fn item(kind: &str, id: &str, version: u64, value: &[u8]) -> Item {
    Item {
        address: Some(address(kind, id)).into(),
        version,
        value: value.to_vec(),
        ..Item::default()
    }
}

struct StoreSvc(Arc<FakeStore>);

impl StoreService for StoreSvc {
    async fn get(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, GetRequest>,
    ) -> ServiceResult<GetResponse> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let (kind, id) = (r.address.kind.to_string(), r.address.id.to_string());
        if kind == "key-revocation" && self.0.revocations_down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        if kind == "key-revocation" && self.0.revocation_get_hangs.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        let items = self.0.items.lock().unwrap();
        match items.get(&(kind.clone(), id.clone())) {
            Some((v, bytes)) => Response::ok(GetResponse {
                item: Some(item(&kind, &id, *v, bytes)).into(),
                ..GetResponse::default()
            }),
            None => {
                if kind == "key-revocation" {
                    self.0.revocation_gets_absent.fetch_add(1, Ordering::SeqCst);
                }
                Err(refusal(ErrorCode::NotFound, "absent", ""))
            }
        }
    }
    async fn list(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        self.0.lists.lock().unwrap().push((
            r.kind.to_string(),
            r.consistency.as_known()
                == Some(sluis_proto::sluis::store::v2alpha1::Consistency::LINEARIZABLE),
        ));
        if r.kind == "key-revocation" && self.0.revocation_get_hangs.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        if self.0.down.load(Ordering::SeqCst)
            || (r.kind == "key-revocation" && self.0.revocations_down.load(Ordering::SeqCst))
            || (matches!(r.kind, "export-manifest" | "export-report")
                && self.0.publication_down.load(Ordering::SeqCst))
        {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
        let kind = r.kind.to_string();
        if kind == "key-revocation" {
            self.0
                .revocation_lists
                .lock()
                .unwrap()
                .push((r.index.to_string(), r.page_token.to_string()));
            if self.0.revocation_pages_never_end.load(Ordering::SeqCst) {
                return Response::ok(ListResponse {
                    next_page_token: "more".into(),
                    ..ListResponse::default()
                });
            }
        }
        let items = self.0.items.lock().unwrap();
        let indexes = self.0.indexes.lock().unwrap();
        let mut rows: Vec<_> = items
            .iter()
            .filter(|((k, id), _)| {
                *k == kind
                    && (r.index.is_empty()
                        || indexes.get(&(k.clone(), id.clone())).is_some_and(|e| {
                            e.iter()
                                .any(|(n, v)| n == r.index && v.as_slice() == r.index_value)
                        }))
            })
            .collect();
        rows.sort_by(|a, b| a.0.1.cmp(&b.0.1));
        // Pages of 100 at most, as store@ gives by default; the token is the offset of the next page.
        let size = if r.page_size > 0 {
            r.page_size as usize
        } else {
            100
        }
        .min(100);
        let from: usize = r.page_token.parse().unwrap_or(0);
        let upto = (from + size).min(rows.len());
        Response::ok(ListResponse {
            items: rows[from..upto]
                .iter()
                .map(|((k, id), (v, bytes))| item(k, id, *v, bytes))
                .collect(),
            next_page_token: if upto < rows.len() {
                upto.to_string()
            } else {
                String::new()
            },
            ..ListResponse::default()
        })
    }
    async fn write(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, WriteRequest>,
    ) -> ServiceResult<WriteResponse> {
        let req = r.to_owned_message();
        let [op] = req.operations.as_slice() else {
            return Err(refusal(ErrorCode::InvalidArgument, "schema", "operations"));
        };
        let (kind, id) = (op.address.kind.clone(), op.address.id.clone());
        let verb = match op.verb.as_known() {
            Some(Verb::CREATE) => "create",
            Some(Verb::UPDATE) => "update",
            _ => return Err(refusal(ErrorCode::InvalidArgument, "schema", "verb")),
        };
        let mut items = self.0.items.lock().unwrap();
        let key = (kind.clone(), id.clone());
        let next = match (verb, items.get(&key)) {
            ("create", Some(_)) => return Err(refusal(ErrorCode::AlreadyExists, "exists", "")),
            ("create", None) => 1,
            ("update", None) => return Err(refusal(ErrorCode::NotFound, "absent", "")),
            ("update", Some((v, _))) if *v != op.if_version => {
                return Err(refusal(ErrorCode::Aborted, "version", ""));
            }
            (_, Some((v, _))) => v + 1,
            _ => unreachable!(),
        };
        items.insert(key, (next, op.value.clone()));
        self.0.writes.lock().unwrap().push((verb, kind.clone()));
        Response::ok(WriteResponse {
            items: vec![item(&kind, &id, next, &op.value)],
            ..WriteResponse::default()
        })
    }
    async fn get_signed_config(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, GetSignedConfigRequest>,
    ) -> ServiceResult<GetSignedConfigResponse> {
        Err(connectrpc::ConnectError::new(
            connectrpc::error::ErrorCode::Unimplemented,
            "not served by this fake",
        ))
    }

    async fn watch(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ServiceStream<WatchResponse>> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
}

// ---------------------------------------------------------------- the stand-in for key@

struct Material {
    pair: EcdsaKeyPair,
    spki: Vec<u8>,
    kid: String,
}

fn material() -> Arc<Material> {
    let pair = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
    // The SubjectPublicKeyInfo of a P-384 key (RFC 5480): the fixed prefix, then the point.
    let mut spki = vec![
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
    ];
    spki.extend_from_slice(pair.public_key().as_ref());
    let kid = signer::jwks::thumbprint(&spki).unwrap();
    Arc::new(Material { pair, spki, kid })
}

/// A key whose `kid` begins with `first`. A thumbprint is base64url, so it begins with `-` or `_` once in 32 times, and
/// a test that draws its keys at random meets one only now and then.
fn material_beginning_with(first: char) -> Arc<Material> {
    loop {
        let m = material();
        if m.kid.starts_with(first) {
            return m;
        }
    }
}

struct FakeKey {
    current: Mutex<Arc<Material>>,
    /// The signing inputs it signed.
    signed: Mutex<Vec<String>>,
    /// Calls to Sign, refused or not.
    calls: AtomicUsize,
    /// Refuse Sign with `unavailable`.
    down: AtomicBool,
    /// Return a signature with a flipped bit.
    corrupt: AtomicBool,
}

fn b64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// The content rule of key@ for a token (actors/key/internal/content, JWSSigningInput).
fn key_accepts(content: &[u8], kid: &str) -> bool {
    let Ok(s) = std::str::from_utf8(content) else {
        return false;
    };
    let Some((head, payload)) = s.split_once('.') else {
        return false;
    };
    if payload.contains('.') {
        return false;
    }
    let (Ok(h), Ok(p)) = (
        URL_SAFE_NO_PAD.decode(head),
        URL_SAFE_NO_PAD.decode(payload),
    ) else {
        return false;
    };
    let (Ok(Value::Object(h)), Ok(Value::Object(p))) = (
        serde_json::from_slice::<Value>(&h),
        serde_json::from_slice::<Value>(&p),
    ) else {
        return false;
    };
    h.len() == 3
        && h.get("alg") == Some(&json!("ES384"))
        && h.get("kid") == Some(&json!(kid))
        && matches!(h.get("typ"), Some(t) if t == "JWT" || t == "at+jwt")
        && p.get("iss").is_some_and(Value::is_string)
        && p.get("aud").is_some_and(Value::is_string)
        && matches!((p.get("iat").and_then(Value::as_i64), p.get("exp").and_then(Value::as_i64)), (Some(i), Some(e)) if e > i)
}

struct KeySvc(Arc<FakeKey>);

impl KeyService for KeySvc {
    async fn seal(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, sluis_proto::sluis::key::v2alpha1::SealRequest>,
    ) -> ServiceResult<sluis_proto::sluis::key::v2alpha1::SealResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn open(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, sluis_proto::sluis::key::v2alpha1::OpenRequest>,
    ) -> ServiceResult<sluis_proto::sluis::key::v2alpha1::OpenResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn seal_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, sluis_proto::sluis::key::v2alpha1::SealGrantRequest>,
    ) -> ServiceResult<sluis_proto::sluis::key::v2alpha1::SealGrantResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn open_grant(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, sluis_proto::sluis::key::v2alpha1::OpenGrantRequest>,
    ) -> ServiceResult<sluis_proto::sluis::key::v2alpha1::OpenGrantResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn mac(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, sluis_proto::sluis::key::v2alpha1::MacRequest>,
    ) -> ServiceResult<sluis_proto::sluis::key::v2alpha1::MacResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
    }
    async fn public_key(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, PublicKeyRequest>,
    ) -> ServiceResult<PublicKeyResponse> {
        assert_eq!(
            r.purpose, "token-signing",
            "signer asks for no other purpose"
        );
        let m = self.0.current.lock().unwrap().clone();
        Response::ok(PublicKeyResponse {
            spki_der: m.spki.clone(),
            key_id: m.kid.clone(),
            algorithm: "ES384".into(),
            ..PublicKeyResponse::default()
        })
    }
    async fn sign(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, SignRequest>,
    ) -> ServiceResult<SignResponse> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(r.purpose, "token-signing");
        assert_eq!(r.algorithm, "ES384");
        if self.0.down.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "audit", ""));
        }
        let m = self.0.current.lock().unwrap().clone();
        if !key_accepts(r.content, &m.kid) {
            return Err(refusal(ErrorCode::InvalidArgument, "content", "content"));
        }
        self.0
            .signed
            .lock()
            .unwrap()
            .push(String::from_utf8(r.content.to_vec()).unwrap());
        let sig = m.pair.sign(&SystemRandom::new(), r.content).unwrap();
        let mut raw = sig.as_ref().to_vec();
        assert_eq!(raw.len(), 96);
        if self.0.corrupt.load(Ordering::SeqCst) {
            raw[10] ^= 1;
        }
        Response::ok(SignResponse {
            signature_raw: raw,
            key_id: m.kid.clone(),
            ..SignResponse::default()
        })
    }
}

// ---------------------------------------------------------------- the stand-in for the transport

#[derive(Default)]
struct FakeSpool {
    emitted: Mutex<Vec<Value>>,
    /// When set the transport refuses every emit, as a full spool does, after noting the record.
    full: std::sync::atomic::AtomicBool,
}

impl FakeSpool {
    fn records(&self, action: &str) -> Vec<Value> {
        self.emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["metadata"]["event_code"] == action)
            .cloned()
            .collect()
    }
    fn text(&self) -> String {
        serde_json::to_string(&*self.emitted.lock().unwrap()).unwrap()
    }
}

struct SpoolSvc(Arc<FakeSpool>);

impl TransportService for SpoolSvc {
    async fn emit(
        &self,
        _: RequestContext,
        r: ServiceRequest<'_, EmitRequest>,
    ) -> ServiceResult<EmitResponse> {
        if self.0.full.load(Ordering::SeqCst) {
            return Err(refusal(ErrorCode::Unavailable, "engine", ""));
        }
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

/// The clock of the test, in seconds since the epoch; the signer reads it through `Config::now`.
#[derive(Clone)]
struct Clock(Arc<AtomicU64>);

impl Clock {
    fn secs(&self) -> i64 {
        i64::try_from(self.0.load(Ordering::SeqCst)).unwrap()
    }
    fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

struct World {
    dir: TempDir,
    store: Arc<FakeStore>,
    key: Arc<FakeKey>,
    spool: Arc<FakeSpool>,
    clock: Clock,
    cfg: Config,
    stops: Mutex<Vec<oneshot::Sender<()>>>,
}

async fn wait_for(path: &Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("socket {} did not appear", path.display());
}

/// This process as `name` in uid block `block`, on a server of the uid block `own`.
fn me_as(name: &'static str, block: u32, own: u32) -> Identities {
    let me = rustix::process::geteuid().as_raw();
    Identities::with(own, move |u| (u == me).then_some((name, block)))
}

fn fake_server(socket: &Path, actor: &'static str, router: Router) -> oneshot::Sender<()> {
    let cfg = ServerConfig {
        actor,
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o660,
        socket_gid: None,
        allow: Allow::Exact("signer"),
        default_deadline: Duration::from_secs(5),
    };
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(sluis_kit::serve_with(
        cfg,
        router,
        async move {
            let _ = rx.await;
        },
        me_as("signer", 0, 0),
    ));
    tx
}

fn new_fake_key() -> Arc<FakeKey> {
    Arc::new(FakeKey {
        current: Mutex::new(material()),
        signed: Mutex::default(),
        calls: AtomicUsize::new(0),
        down: AtomicBool::new(false),
        corrupt: AtomicBool::new(false),
    })
}

fn minutes(m: i64) -> Option<PbDuration> {
    Some(PbDuration {
        seconds: m * 60,
        ..PbDuration::default()
    })
}

impl World {
    /// The three stand-ins are up, the config is in the store, and no signer runs yet.
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let sockets = Sockets {
            store: d.join("store.sock"),
            key: d.join("key.sock"),
            audit: d.join("emit.sock"),
        };
        let store = Arc::new(FakeStore::default());
        store.put(
            "boundary",
            "default",
            Boundary {
                name: "dev".into(),
                issuer: ISSUER.into(),
                ..Boundary::default()
            }
            .encode_to_vec(),
        );
        store.put(
            "token-lifetime",
            "default",
            TokenLifetime {
                id_token: minutes(10).into(),
                access_token: minutes(10).into(),
                ..TokenLifetime::default()
            }
            .encode_to_vec(),
        );
        for (id, cap) in [("sluis-cli", 0), ("example-app", 0), ("short-app", 5)] {
            store.put(
                "installation-client",
                id,
                InstallationClient {
                    id: id.into(),
                    kind: "public".into(),
                    ttl_cap: (cap != 0).then(|| minutes(cap)).flatten().into(),
                    ..InstallationClient::default()
                }
                .encode_to_vec(),
            );
        }
        let key = new_fake_key();
        let spool = Arc::new(FakeSpool::default());
        let stops = vec![
            fake_server(
                &sockets.store,
                "store",
                Arc::new(StoreSvc(store.clone())).register(Router::new()),
            ),
            fake_server(
                &sockets.key,
                "key",
                Arc::new(KeySvc(key.clone())).register(Router::new()),
            ),
            fake_server(
                &sockets.audit,
                "transport",
                Arc::new(SpoolSvc(spool.clone())).register(Router::new()),
            ),
        ];
        for s in [&sockets.store, &sockets.key, &sockets.audit] {
            wait_for(s).await;
        }
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let clock = Clock(Arc::new(AtomicU64::new(base)));
        let c = clock.clone();
        let cfg = Config {
            boundary: "dev".into(),
            socket: d.join("signer.sock"),
            socket_gid: None,
            sockets,
            release: "0.0.0-test".into(),
            node: "node-a".into(),
            timing: Timing::DEFAULT,
            start_timeout: Duration::from_secs(5),
            now: Some(Arc::new(move || {
                UNIX_EPOCH + Duration::from_secs(c.0.load(Ordering::SeqCst))
            })),
        };
        Self {
            dir,
            store,
            key,
            spool,
            clock,
            cfg,
            stops: Mutex::new(stops),
        }
    }

    /// Starts a signer that sees this process as `caller` in uid block `block`, on the socket
    /// `name`, and returns a client of it.
    async fn signer_as(
        &self,
        name: &str,
        caller: &'static str,
        block: u32,
    ) -> SignerServiceClient<sluis_kit::Transport> {
        self.signer_on(name, caller, block, "node-a", &self.cfg.sockets.key.clone())
            .await
    }

    /// As [`signer_as`](Self::signer_as), on the node `node`, whose key@ is on `key_socket`.
    async fn signer_on(
        &self,
        name: &str,
        caller: &'static str,
        block: u32,
        node: &str,
        key_socket: &Path,
    ) -> SignerServiceClient<sluis_kit::Transport> {
        let socket = self.dir.path().join(format!("{name}.sock"));
        let mut cfg = self.cfg.clone();
        cfg.socket = socket.clone();
        cfg.node = node.into();
        cfg.sockets.key = key_socket.to_path_buf();
        let (tx, rx) = oneshot::channel::<()>();
        self.stops.lock().unwrap().push(tx);
        tokio::spawn(signer::serve_with(
            cfg,
            async move {
                let _ = rx.await;
            },
            me_as(caller, block, 0),
        ));
        wait_for(&socket).await;
        let c = sluis_kit::dial(&socket);
        SignerServiceClient::new(c.transport(), c.config())
    }

    /// The key@ of another board: its own stand-in, with a key of its own, on a socket of its own.
    async fn another_key(&self, name: &str) -> (Arc<FakeKey>, PathBuf) {
        let socket = self.dir.path().join(format!("{name}.sock"));
        let key = new_fake_key();
        let stop = fake_server(
            &socket,
            "key",
            Arc::new(KeySvc(key.clone())).register(Router::new()),
        );
        self.stops.lock().unwrap().push(stop);
        wait_for(&socket).await;
        (key, socket)
    }

    async fn signer(&self) -> SignerServiceClient<sluis_kit::Transport> {
        self.signer_as("signer", "exchange", 0).await
    }

    fn claims(&self, typ: &str, aud: &str, lifetime: i64) -> Vec<u8> {
        self.claims_at(typ, aud, self.clock.secs(), lifetime)
    }

    fn claims_at(&self, typ: &str, aud: &str, iat: i64, lifetime: i64) -> Vec<u8> {
        let mut c = json!({
            "iss": ISSUER, "sub": "p-0001", "aud": aud, "iat": iat, "exp": iat + lifetime,
            "groups": ["dev:app:admin"],
        });
        if typ == "at+jwt" {
            c["jti"] = json!("j-0001");
            c["client_id"] = json!("sluis-cli");
        } else {
            c["nonce"] = json!("n-0001");
        }
        serde_json::to_vec(&c).unwrap()
    }
}

type Client = SignerServiceClient<sluis_kit::Transport>;

async fn sign(c: &Client, typ: &str, claims: Vec<u8>) -> Result<SignTokenResponse, ConnectError> {
    c.sign_token(SignTokenRequest {
        typ: typ.into(),
        claims_json: claims,
        ..SignTokenRequest::default()
    })
    .await
    .map(connectrpc::client::UnaryResponse::into_owned)
}

async fn key_set(c: &Client) -> Vec<u8> {
    c.key_set(KeySetRequest::default())
        .await
        .unwrap()
        .into_owned()
        .jwks_json
}

fn reason(e: &ConnectError) -> String {
    refusal_reason(e).unwrap_or_default()
}

// ---------------------------------------------------------------- go-jose

fn repo_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    assert!(
        root.join("actors/signer/tests/gojose/gojose_test.go")
            .exists(),
        "actors/signer/tests/gojose is missing: it is the Go side of the test"
    );
    root
}

/// The go-jose verifier: the Go test of `actors/signer/tests/gojose`, compiled once. The Go side is
/// in this repository, so a missing Go toolchain is a failure, never a skip.
fn gojose() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let bin = Path::new(env!("CARGO_TARGET_TMPDIR")).join("gojose.test");
        let out = Command::new("go")
            .current_dir(repo_root())
            .args(["test", "-c", "-o"])
            .arg(&bin)
            .arg("./actors/signer/tests/gojose")
            .output()
            .expect("go test -c: is Go on the PATH (devbox)?");
        assert!(
            out.status.success(),
            "go test -c of the verifier failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        bin
    })
}

/// Verifies a token with go-jose against a key set. `Ok(kid)` when it verifies, `Err(reason)` when it
/// does not.
fn verify(w: &World, jwks: &[u8], token: &str, aud: &str, typ: &str) -> Result<String, String> {
    verify_at(w, jwks, token, aud, typ, w.clock.secs())
}

/// [`verify`] as a relying party would at the Unix time `at`. The Go test prints `kid=<kid>` when it
/// verified; a run that skips exits 0 and prints no kid, which is a failure here.
fn verify_at(
    w: &World,
    jwks: &[u8],
    token: &str,
    aud: &str,
    typ: &str,
    at: i64,
) -> Result<String, String> {
    let file = w.dir.path().join("jwks.json");
    std::fs::write(&file, jwks).unwrap();
    let out = Command::new(gojose())
        .args(["-test.run", "^TestToken$", "-test.v", "-test.count=1"])
        .env("SLUIS_SIGNER_JWKS", &file)
        .env("SLUIS_SIGNER_TOKEN", token)
        .env("SLUIS_SIGNER_ISSUER", ISSUER)
        .env("SLUIS_SIGNER_AUDIENCE", aud)
        .env("SLUIS_SIGNER_TYP", typ)
        .env("SLUIS_SIGNER_NOW", at.to_string())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let kid = stdout
        .lines()
        .find_map(|l| l.strip_prefix("kid="))
        .map(str::to_owned);
    match (out.status.success(), kid) {
        (true, Some(kid)) => Ok(kid),
        _ => Err(format!("{stdout}{}", String::from_utf8_lossy(&out.stderr))),
    }
}

// ---------------------------------------------------------------- tests

/// verifies: REQ-TOKEN-001, REQ-TOKEN-017, REQ-TOKEN-019
#[tokio::test]
async fn a_token_signed_through_key_verifies_with_go_jose_against_the_published_key_set() {
    let w = World::new().await;
    let c = w.signer().await;
    let jwks = key_set(&c).await;
    for (typ, aud) in [("at+jwt", "example-app"), ("JWT", "sluis-cli")] {
        let got = sign(&c, typ, w.claims(typ, aud, 600)).await.unwrap();
        let kid = verify(&w, &jwks, &got.token, aud, typ).unwrap();
        assert_eq!(
            kid, got.key_id,
            "go-jose found the key by the kid of the response"
        );
        assert_eq!(got.token.split('.').count(), 3);
    }
    // The signing input key@ saw: exactly the header it checks for, and the claims that were asked for.
    let seen = w.key.signed.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    let head: Value = serde_json::from_slice(&b64(seen[0].split('.').next().unwrap())).unwrap();
    assert_eq!(head.as_object().unwrap().len(), 3);
    assert_eq!(head["alg"], "ES384");
    assert_eq!(head["typ"], "at+jwt");

    // The check has teeth: a bad signature, another audience, another type and an empty key set fail.
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    let mut bad = got.token.clone();
    bad.pop();
    bad.push(if got.token.ends_with('A') { 'B' } else { 'A' });
    assert!(verify(&w, &jwks, &bad, "example-app", "at+jwt").is_err());
    assert!(verify(&w, &jwks, &got.token, "sluis-cli", "at+jwt").is_err());
    assert!(verify(&w, &jwks, &got.token, "example-app", "JWT").is_err());
    assert!(verify(&w, br#"{"keys":[]}"#, &got.token, "example-app", "at+jwt").is_err());

    // Each token is an audit fact of its own, naming the audience and never the token.
    let facts = w.spool.records("signer.sign");
    assert_eq!(facts.len(), 3);
    assert_eq!(
        facts[0]["unmapped"]["sluis"]["token"]["audience"],
        "example-app"
    );
    assert_eq!(facts[0]["unmapped"]["sluis"]["caller"], "exchange");
    assert!(!w.spool.text().contains(&got.token));
    assert!(
        !w.spool.text().contains("p-0001"),
        "a subject is not in the record"
    );
}

/// The algorithm of the ID token that `signer` makes, and of every key in its key set, is one that the discovery document
/// lists in `id_token_signing_alg_values_supported`: the golden file of `entry`'s tests, which `entry` serves.
///
/// verifies: REQ-AUTHN-006
#[tokio::test]
async fn the_algorithm_of_an_id_token_and_of_the_key_set_is_what_discovery_lists() {
    let golden: Value =
        serde_json::from_str(include_str!("../../entry/tests/testdata/discovery.json")).unwrap();
    let listed: Vec<&str> = golden["id_token_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    assert!(!listed.is_empty());
    let w = World::new().await;
    let c = w.signer().await;
    let got = sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    let head: Value = serde_json::from_slice(&b64(got.token.split('.').next().unwrap())).unwrap();
    assert!(listed.contains(&head["alg"].as_str().unwrap()), "{head}");
    let set: Value = serde_json::from_slice(&key_set(&c).await).unwrap();
    let keys = set["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    for k in keys {
        assert!(listed.contains(&k["alg"].as_str().unwrap()), "{k}");
    }
}

/// verifies: REQ-ISO-028
#[tokio::test]
async fn a_wrong_issuer_an_unregistered_audience_and_a_lifetime_past_the_cap_are_refused_alike() {
    let w = World::new().await;
    let c = w.signer().await;
    let now = w.clock.secs();

    let mut wrong_iss: Value = serde_json::from_slice(&w.claims("JWT", "sluis-cli", 600)).unwrap();
    wrong_iss["iss"] = json!("https://sluis.elsewhere.test");
    let cases = [
        ("claims.iss", serde_json::to_vec(&wrong_iss).unwrap()),
        ("claims.aud", w.claims("JWT", "nobody-registered-this", 600)),
        // The issuer's lifetime is 10 minutes: one second more is refused.
        ("claims.exp", w.claims("JWT", "sluis-cli", 601)),
    ];
    let mut errors = Vec::new();
    for (path, claims) in &cases {
        let e = sign(&c, "JWT", claims.clone()).await.unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::InvalidArgument, "claims"),
            "{path}"
        );
        errors.push(e);
    }
    // The same code, reason and message: nothing tells the three apart but the path inside sluis.
    assert!(errors.iter().all(|e| e.message == errors[0].message));
    let all = format!("{errors:?}");
    for value in ["elsewhere", "nobody-registered-this", ISSUER, "p-0001"] {
        assert!(!all.contains(value), "a refusal shows {value}");
    }
    assert_eq!(
        w.key.calls.load(Ordering::SeqCst),
        0,
        "a refused request never reaches key@"
    );

    // Every one of them is an audit fact, with the path and no value.
    let facts = w.spool.records("signer.refused");
    assert_eq!(facts.len(), 3);
    for (f, (path, _)) in facts.iter().zip(&cases) {
        assert_eq!(f["status_id"], 2);
        assert_eq!(f["status_code"], "claims");
        assert_eq!(f["unmapped"]["sluis"]["path"], *path);
        assert_eq!(f["unmapped"]["sluis"]["caller"], "exchange");
        assert_eq!(f["unmapped"]["sluis"]["method"], "SignToken");
    }
    let text = w.spool.text();
    for value in ["elsewhere", "nobody-registered-this", "p-0001", "n-0001"] {
        assert!(!text.contains(value), "an audit record shows {value}");
    }

    // The edges: the cap itself passes; a client's ttl_cap lowers it; the same for an access token;
    // a window that is not now is refused.
    sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    sign(&c, "JWT", w.claims("JWT", "short-app", 300))
        .await
        .unwrap();
    for (typ, aud, life) in [
        ("JWT", "short-app", 301),
        ("at+jwt", "example-app", 601),
        ("at+jwt", "example-app", 0),
    ] {
        let e = sign(&c, typ, w.claims(typ, aud, life)).await.unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::InvalidArgument, "claims"),
            "{typ} {aud} {life}"
        );
    }
    for iat in [now - 120, now + 120] {
        let e = sign(&c, "JWT", w.claims_at("JWT", "sluis-cli", iat, 600))
            .await
            .unwrap_err();
        assert_eq!(reason(&e), "claims", "iat {iat}");
    }
    // A client_id nobody registered, a claim outside the set, a bound token, a type that is not issued.
    let extra = |k: &str, v: Value, typ: &str, aud: &str| {
        let mut m: Value = serde_json::from_slice(&w.claims(typ, aud, 600)).unwrap();
        m[k] = v;
        serde_json::to_vec(&m).unwrap()
    };
    let refused = [
        (
            "at+jwt",
            extra(
                "client_id",
                json!("not-registered"),
                "at+jwt",
                "example-app",
            ),
        ),
        ("JWT", extra("scope", json!("admin"), "JWT", "sluis-cli")),
        (
            "at+jwt",
            extra("cnf", json!({"jkt": "x"}), "at+jwt", "example-app"),
        ),
        (
            "JWT",
            extra("groups", json!(["*:app:admin"]), "JWT", "sluis-cli"),
        ),
    ];
    for (typ, claims) in refused {
        let e = sign(&c, typ, claims).await.unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::InvalidArgument, "claims")
        );
    }
    for typ in ["", "jwt", "secevent+jwt", "ES384"] {
        let e = sign(&c, typ, w.claims("JWT", "sluis-cli", 600))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::InvalidArgument, "typ")
        );
    }
    let e = sign(&c, "JWT", b"[1,2]".to_vec()).await.unwrap_err();
    assert_eq!(reason(&e), "claims");
    // Only the two accepted tokens above reached key@; each refusal above was an audit fact too.
    assert_eq!(w.key.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        w.spool.records("signer.refused").len(),
        3 + 3 + 2 + 4 + 4 + 1
    );
}

#[tokio::test]
async fn only_the_callers_the_registry_allows_may_ask() {
    let w = World::new().await;
    for (name, caller) in [("a", "exchange"), ("b", "session")] {
        let c = w.signer_as(name, caller, 0).await;
        sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
            .await
            .unwrap_or_else(|e| panic!("{caller}: {e:?}"));
        key_set(&c).await;
    }
    // Callers the call graph does not name, and a caller of another boundary's uid block.
    for (name, caller, block, why) in [
        ("c", "entry", 0, "call_graph"),
        ("d", "policy", 0, "call_graph"),
        ("e", "key", 0, "call_graph"),
        ("f", "exchange", 1, "caller"),
    ] {
        let c = w.signer_as(name, caller, block).await;
        let e = sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::PermissionDenied, why),
            "{caller}"
        );
        let e = c.key_set(KeySetRequest::default()).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{caller}");
    }
    assert_eq!(
        w.key.calls.load(Ordering::SeqCst),
        2,
        "only the two allowed callers reached key@"
    );
}

#[tokio::test]
async fn the_ring_is_created_once_per_boundary_even_when_two_instances_start_together() {
    let w = World::new().await;
    // Two instances, one store: the second one's create loses and it reads the first one's ring.
    let (a, b) = (
        w.signer_as("one", "exchange", 0),
        w.signer_as("two", "exchange", 0),
    );
    let (a, _b) = tokio::join!(a, b);
    let (version, ring) = w.store.ring().unwrap();
    assert_eq!(version, 1, "one create, no update");
    assert_eq!(ring.keys.len(), 1);
    assert_eq!(
        ring.keys[0].state, "active",
        "the first key of a boundary signs at once"
    );
    assert_eq!(ring.keys[0].algorithm, "ES384");
    assert_eq!(ring.keys[0].key_id, w.key.current.lock().unwrap().kid);
    assert!(ring.keys[0].added_at.as_option().is_some());
    assert_eq!(
        *w.store.writes.lock().unwrap(),
        [("create", "signing-ring".to_owned())]
    );
    assert_eq!(
        w.spool.records("signer.ring.add").len(),
        1,
        "one fact for one key"
    );
    let fact = &w.spool.records("signer.ring.add")[0];
    assert_eq!(fact["unmapped"]["sluis"]["state"], "active");
    assert_eq!(fact["unmapped"]["sluis"]["key_id"], ring.keys[0].key_id);
    // A restart changes nothing.
    let c = w.signer_as("three", "exchange", 0).await;
    assert_eq!(w.store.ring().unwrap().0, 1);
    sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    drop(a);
    assert_eq!(w.store.writes.lock().unwrap().len(), 1);
}

/// verifies: REQ-KEYS-076, REQ-KEYS-078
#[tokio::test]
async fn a_new_key_is_published_before_it_signs_and_an_old_one_stays_while_its_tokens_live() {
    let w = World::new().await;
    let c = w.signer().await;
    let old_kid = w.key.current.lock().unwrap().kid.clone();
    let issued_at = w.clock.secs();
    let old = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();

    // key@ now signs with a new key. The ring learns it within ten seconds, and publishes it at once.
    let new = material();
    let new_kid = new.kid.clone();
    *w.key.current.lock().unwrap() = new;
    w.clock.advance(11);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "key_set"),
        "not yet its turn"
    );
    let (_, ring) = w.store.ring().unwrap();
    let states: Vec<_> = ring
        .keys
        .iter()
        .map(|k| (k.key_id.clone(), k.state.clone()))
        .collect();
    assert_eq!(
        states,
        [
            (old_kid.clone(), "active".into()),
            (new_kid.clone(), "pre-published".into())
        ]
    );
    let jwks: Value = serde_json::from_slice(&key_set(&c).await).unwrap();
    assert_eq!(
        jwks["keys"].as_array().unwrap().len(),
        2,
        "both are published"
    );
    assert_eq!(
        w.key.calls.load(Ordering::SeqCst),
        1,
        "key@ signed nothing with the unpublished key"
    );

    // Just short of 30 minutes after it was published it still does not sign; a little after, it does.
    // (The ring is looked at again when the last look is ten seconds old, so a key signs at most ten
    // seconds after its window; the exact second is the test of `ring::plan`.)
    w.clock.advance(30 * 60 - 20);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set", "short of the window");
    w.clock.advance(21);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, new_kid);
    let jwks = key_set(&c).await;
    assert_eq!(
        verify(&w, &jwks, &got.token, "example-app", "at+jwt").unwrap(),
        new_kid
    );
    // The token the old key signed before still verifies against the key set, when a relying party
    // checks it within its life: the old key is retiring, not gone.
    let ring = w.store.ring().unwrap().1;
    assert_eq!(
        ring.keys
            .iter()
            .find(|k| k.key_id == old_kid)
            .unwrap()
            .state,
        "retiring"
    );
    assert_eq!(
        verify_at(
            &w,
            &jwks,
            &old.token,
            "example-app",
            "at+jwt",
            issued_at + 1
        )
        .unwrap(),
        old_kid
    );

    // After the token lifetime plus the skew, the old key leaves the key set.
    w.clock.advance(65 * 60);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, new_kid);
    let jwks = key_set(&c).await;
    let v: Value = serde_json::from_slice(&jwks).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    assert!(
        verify_at(
            &w,
            &jwks,
            &old.token,
            "example-app",
            "at+jwt",
            issued_at + 1
        )
        .is_err()
    );
    // Every change is an audit fact: add, add, activate, retire, drop.
    assert_eq!(w.spool.records("signer.ring.add").len(), 2);
    assert_eq!(w.spool.records("signer.ring.change").len(), 2);
    assert_eq!(w.spool.records("signer.ring.drop").len(), 1);
}

/// Where a destination with a public address reports the static key set, a new key waits for the report through the
/// store: `unverified` keeps it pre-published past the lead time, and once a report says `published` and lists the kid,
/// it signs after the lead time counted from the read back (REQ-KEYS-116, REQ-KEYS-085).
///
/// verifies: REQ-KEYS-116
#[tokio::test]
async fn a_new_key_waits_for_the_report_of_the_static_key_set() {
    let w = World::new().await;
    let c = w.signer().await;
    let new = material();
    let new_kid = new.kid.clone();
    *w.key.current.lock().unwrap() = new;
    let report = |state: &str, read_back: Option<i64>| {
        ExportReport {
            state: state.into(),
            kind: "SigningRing".into(),
            public: true,
            kids: vec![new_kid.clone()],
            read_back_at: read_back
                .map(|s| Timestamp {
                    seconds: s,
                    ..Timestamp::default()
                })
                .into(),
            ..ExportReport::default()
        }
        .encode_to_vec()
    };
    w.store.put("export-manifest", "default", manifest("edge"));
    w.store
        .put("export-report", "edge/jwks", report("unverified", None));
    w.clock.advance(11);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set");
    // Forty minutes later, long past the lead time counted from the write, the report still does not let it sign.
    w.clock.advance(40 * 60);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        "key_set",
        "an unverified report must keep the key pre-published"
    );
    // Read back now: it signs after the lead time from the read back, not before.
    w.store.put(
        "export-report",
        "edge/jwks",
        report("published", Some(w.clock.secs())),
    );
    w.clock.advance(30 * 60 - 20);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        "key_set",
        "short of the lead time since the read back"
    );
    w.clock.advance(21);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, new_kid);
}

/// The manifest of an `exporter@` that publishes the key set to `destination`, with a public address.
fn manifest(destination: &str) -> Vec<u8> {
    use sluis_proto::sluis::exporter::v2alpha1::{ExportManifest, export_manifest::Entry};
    ExportManifest {
        entries: vec![Entry {
            destination: destination.into(),
            document: "jwks".into(),
            kind: "SigningRing".into(),
            public: true,
            ..Entry::default()
        }],
        ..ExportManifest::default()
    }
    .encode_to_vec()
}

/// A store@ that cannot answer for the manifest or the reports (no such kind yet during an upgrade, a timeout, a missing
/// grant) does not stop signing: the ring and the key that signs are kept, a new key is held until the answer is back,
/// and the answer is asked for only when a key is about to become active. An installation with no exporter reads
/// nothing of it.
///
/// verifies: REQ-KEYS-116
#[tokio::test]
async fn an_unreadable_manifest_or_report_holds_a_new_key_and_never_stops_signing() {
    let w = World::new().await;
    let c = w.signer().await;
    // The first key becomes active when it joins: the answer is asked for once, and there is no manifest.
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    w.store.lists.lock().unwrap().clear();
    w.store.publication_down.store(true, Ordering::SeqCst);
    w.clock.advance(11);
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert!(
        w.store
            .lists
            .lock()
            .unwrap()
            .iter()
            .all(|(k, _)| k != "export-manifest" && k != "export-report"),
        "read before a key was about to become active"
    );

    // key@ now signs with a new key; it joins the ring pre-published, and nothing is read yet.
    let new = material();
    let new_kid = new.kid.clone();
    *w.key.current.lock().unwrap() = new;
    w.clock.advance(11);
    let old = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600)).await;
    assert_eq!(reason(&old.unwrap_err()), "key_set");
    // Past the lead time the key is about to become active: the answer is asked for, cannot be had, and holds it. The
    // reconcile goes on, and key@'s old key stays in the ring; the call is refused for the new key, not for the store.
    w.clock.advance(31 * 60);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set", "a doubt must hold the key");
    let (_, ring) = w.store.ring().unwrap();
    assert!(
        ring.keys
            .iter()
            .any(|k| k.key_id == new_kid && k.state == "pre-published"),
        "the new key stays pre-published"
    );
    assert!(
        ring.keys.iter().any(|k| k.state == "active"),
        "the key that signs stays in the ring"
    );
    let lists = w.store.lists.lock().unwrap().clone();
    assert!(
        lists.iter().any(|(k, lin)| k == "export-manifest" && *lin),
        "the manifest is read linearizably: {lists:?}"
    );
    drop(lists);

    // The store answers again, with no manifest: the key is released as it was before exporter existed.
    w.store.publication_down.store(false, Ordering::SeqCst);
    w.clock.advance(11);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, new_kid);
}

/// A manifest that names a public destination with no report holds a new key; the report of a destination the
/// manifest does not name is not read, whatever it says.
///
/// verifies: REQ-KEYS-116
#[tokio::test]
async fn a_missing_report_holds_a_key_and_the_report_of_a_removed_destination_is_ignored() {
    let w = World::new().await;
    let c = w.signer().await;
    let new = material();
    let new_kid = new.kid.clone();
    *w.key.current.lock().unwrap() = new;
    w.store.put("export-manifest", "default", manifest("edge"));
    // The removed destination's report is stale and says unverified: it must not matter.
    let stale = sluis_proto::sluis::exporter::v2alpha1::ExportReport {
        state: "unverified".into(),
        kind: "SigningRing".into(),
        public: true,
        ..Default::default()
    };
    w.store
        .put("export-report", "old/jwks", stale.encode_to_vec());
    w.clock.advance(11);
    w.clock.advance(2 * 3600);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set", "no report of `edge` yet: held");
    // Five minutes later the report of `edge` arrives, published and read back just now.
    w.clock.advance(5 * 60);
    let report = sluis_proto::sluis::exporter::v2alpha1::ExportReport {
        state: "published".into(),
        kind: "SigningRing".into(),
        public: true,
        kids: vec![new_kid.clone()],
        read_back_at: Timestamp {
            seconds: w.clock.secs(),
            ..Timestamp::default()
        }
        .into(),
        ..Default::default()
    };
    w.store
        .put("export-report", "edge/jwks", report.encode_to_vec());
    // The lead time counts from the read back, not from the moment the key joined.
    w.clock.advance(30 * 60 - 20);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set");
    w.clock.advance(21);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(
        got.key_id, new_kid,
        "the stale report of a removed destination held nothing"
    );
}

/// The rows of a ring in an order that does not depend on the made-up key ids.
fn sorted<const N: usize>(rows: [(String, String, String); N]) -> Vec<(String, String, String)> {
    let mut v = rows.to_vec();
    v.sort();
    v
}

#[tokio::test]
async fn two_boards_share_one_ring_without_flapping_and_every_new_key_waits_for_the_window() {
    let w = World::new().await;
    let (key_b, socket_b) = w.another_key("key-b").await;
    let a = w
        .signer_on("one", "exchange", 0, "node-a", &w.cfg.sockets.key.clone())
        .await;
    let b = w.signer_on("two", "exchange", 0, "node-b", &socket_b).await;
    let kid_a = w.key.current.lock().unwrap().kid.clone();
    let kid_b = key_b.current.lock().unwrap().kid.clone();
    let writes_at_start = w.store.writes.lock().unwrap().len();
    let ring = || w.store.ring().unwrap().1;
    let states = |r: &sluis_proto::sluis::signer::v2alpha1::SigningRing| {
        r.keys
            .iter()
            .map(|k| (k.node.clone(), k.key_id.clone(), k.state.clone()))
            .collect::<Vec<_>>()
    };
    // The first deploy: both boards' first keys are active at once, each named for its node.
    let mut start = states(&ring());
    start.sort();
    assert_eq!(
        start,
        sorted([
            ("node-a".into(), kid_a.clone(), "active".into()),
            ("node-b".into(), kid_b.clone(), "active".into())
        ])
    );
    let first = sign(&a, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    let second = sign(&b, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(
        (first.key_id.as_str(), second.key_id.as_str()),
        (kid_a.as_str(), kid_b.as_str())
    );
    let jwks = key_set(&a).await;
    verify(&w, &jwks, &first.token, "example-app", "at+jwt").unwrap();
    verify(&w, &jwks, &second.token, "example-app", "at+jwt").unwrap();

    // Two hours of both signers asking every eleven seconds: the ring is not written again, and
    // every token verifies against the key set.
    for _ in 0..650 {
        w.clock.advance(11);
        for (c, kid) in [(&a, &kid_a), (&b, &kid_b)] {
            let t = sign(c, "JWT", w.claims("JWT", "sluis-cli", 600))
                .await
                .unwrap();
            assert_eq!(&t.key_id, kid);
        }
    }
    assert_eq!(
        w.store.writes.lock().unwrap().len(),
        writes_at_start,
        "no change, no write"
    );

    // Board B rotates its key. Its new key is published, and board A's key is not touched.
    let new_b = material();
    let kid_b2 = new_b.kid.clone();
    *key_b.current.lock().unwrap() = new_b;
    let rotated_at = w.clock.secs();
    let calls_b = key_b.calls.load(Ordering::SeqCst);
    // The first look adds the key (eleven seconds on); the last is thirty seconds short of its window.
    for advance in [11u64, 5 * 60, 10 * 60, 30 * 60 - 30 - 15 * 60] {
        w.clock.advance(advance);
        // B refuses: its new key has not been published for the window. A signs throughout.
        let e = sign(&b, "JWT", w.claims("JWT", "sluis-cli", 600))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::Unavailable, "key_set")
        );
        let t = sign(&a, "JWT", w.claims("JWT", "sluis-cli", 600))
            .await
            .unwrap();
        assert_eq!(t.key_id, kid_a);
        let mut now = states(&ring());
        now.sort();
        assert_eq!(
            now,
            sorted([
                ("node-a".into(), kid_a.clone(), "active".into()),
                ("node-b".into(), kid_b.clone(), "active".into()),
                ("node-b".into(), kid_b2.clone(), "pre-published".into()),
            ]),
            "after {} s",
            w.clock.secs() - rotated_at
        );
    }
    assert_eq!(
        key_b.calls.load(Ordering::SeqCst),
        calls_b,
        "key@ of B signed nothing with the unpublished key"
    );
    // The unpublished key is in the key set the whole time.
    let v: Value = serde_json::from_slice(&key_set(&a).await).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 3);

    // After the window it signs; B's old key retires; A's key is still active.
    w.clock.advance(60);
    let t = sign(&b, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    assert_eq!(t.key_id, kid_b2);
    let mut now = states(&ring());
    now.sort();
    assert_eq!(
        now,
        sorted([
            ("node-a".into(), kid_a.clone(), "active".into()),
            ("node-b".into(), kid_b.clone(), "retiring".into()),
            ("node-b".into(), kid_b2.clone(), "active".into()),
        ])
    );
    let jwks = key_set(&a).await;
    verify(&w, &jwks, &t.token, "sluis-cli", "JWT").unwrap();
    // A keeps signing, and its signer never wrote a change of another node's key.
    let t = sign(&a, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    assert_eq!(t.key_id, kid_a);
}

#[tokio::test]
async fn it_fails_closed_when_key_store_or_the_signature_is_not_what_it_should_be() {
    let w = World::new().await;
    let c = w.signer().await;
    // key@ refuses (as it does when the audit fact cannot be made durable).
    w.key.down.store(true, Ordering::SeqCst);
    let e = sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "key")
    );
    w.key.down.store(false, Ordering::SeqCst);
    // key@ returns a signature that does not verify: nothing is returned.
    w.key.corrupt.store(true, Ordering::SeqCst);
    let e = sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Internal, "signature")
    );
    w.key.corrupt.store(false, Ordering::SeqCst);
    sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    // store@ is down: the config cannot be read, and the key set cannot be served.
    w.store.down.store(true, Ordering::SeqCst);
    w.clock.advance(11);
    let e = sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "store")
    );
    let e = c.key_set(KeySetRequest::default()).await.unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "store")
    );
    // Each of those is an audit fact, and none shows a value.
    assert_eq!(w.spool.records("signer.refused").len(), 4);
    w.store.down.store(false, Ordering::SeqCst);
    sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    // A boundary with no issuer in its config is not served.
    w.store
        .put("boundary", "default", Boundary::default().encode_to_vec());
    w.clock.advance(11);
    let e = sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "config")
    );
}

#[tokio::test]
async fn the_executable_checks_its_sockets_and_prints_its_version() {
    let w = World::new().await;
    let signer = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_signer"))
            .args(args)
            .output()
            .unwrap()
    };
    // The layout of PLAN.md: <run-dir>/store/<boundary>.sock, key/<boundary>/signer/key.sock,
    // audit/<boundary>/emit.sock. None of them exists in an empty directory.
    let empty = tempfile::tempdir().unwrap();
    let o = signer(&[
        "check",
        "--boundary",
        "dev",
        "--run-dir",
        empty.path().to_str().unwrap(),
    ]);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(3), "{err}");
    for part in ["store@", "key@", "audit transport"] {
        assert!(err.contains(part), "{part} is not named: {err}");
    }
    // With the three sockets in place it passes, so the check does not fail on nothing.
    let run = tempfile::tempdir().unwrap();
    let s = Sockets::under(run.path(), "dev");
    let mut listeners = Vec::new();
    for p in [&s.store, &s.key, &s.audit] {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        listeners.push(std::os::unix::net::UnixListener::bind(p).unwrap());
    }
    let o = signer(&[
        "check",
        "--boundary",
        "dev",
        "--run-dir",
        run.path().to_str().unwrap(),
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        signer(&["serve"]).status.code(),
        Some(1),
        "serve needs a boundary"
    );
    let o = signer(&["version"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(!o.stdout.is_empty());
    drop((w, listeners));
}

#[test]
fn the_sockets_are_where_plan_md_puts_them() {
    let s = Sockets::under(Path::new("/run/sluis"), "dev");
    assert_eq!(s.store, Path::new("/run/sluis/store/dev.sock"));
    assert_eq!(s.key, Path::new("/run/sluis/key/dev/signer/key.sock"));
    assert_eq!(s.audit, Path::new("/run/sluis/audit/dev/emit.sock"));
}

/// The audit table's `ident` pattern took a `kid` that began with `-` or `_` for no identifier until #1610, so the fact of
/// every change of the ring, and of every signature, for such a key was refused and lost: about one key in 32, which a
/// test with random keys met as a failure now and then. The keys here begin with each of them.
#[tokio::test]
async fn the_facts_of_a_key_whose_id_begins_with_a_dash_or_an_underscore_are_kept() {
    let w = World::new().await;
    let (dash, under) = (material_beginning_with('-'), material_beginning_with('_'));
    *w.key.current.lock().unwrap() = dash.clone();
    let c = w.signer().await;
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, dash.kid);
    assert_eq!(w.spool.records("signer.ring.add").len(), 1);
    assert_eq!(w.spool.records("signer.sign").len(), 1);
    // The replacement begins with `_`; it joins pre-published and then takes over.
    *w.key.current.lock().unwrap() = under.clone();
    w.clock.advance(11);
    let _ = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600)).await;
    assert_eq!(
        w.spool.records("signer.ring.add").len(),
        2,
        "{}",
        w.spool.text()
    );
    w.clock.advance(30 * 60 + 10);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, under.kid);
    assert_eq!(w.spool.records("signer.ring.change").len(), 2);
    w.clock.advance(65 * 60);
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(w.spool.records("signer.ring.drop").len(), 1);
}

/// A key that left the key set after its retention is not a new key when key@ presents it again: `signer` does not add
/// it, publish it or sign with it, a day later or a month later, and the key that replaced it goes on signing.
///
/// verifies: REQ-KEYS-079
#[tokio::test]
async fn a_key_that_left_the_key_set_does_not_return_when_key_presents_it_again() {
    let w = World::new().await;
    let c = w.signer().await;
    let old = w.key.current.lock().unwrap().clone();
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    let new = material();
    *w.key.current.lock().unwrap() = new.clone();
    w.clock.advance(11);
    let _ = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600)).await;
    w.clock.advance(30 * 60 + 10);
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    w.clock.advance(65 * 60);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, new.kid);
    let v: Value = serde_json::from_slice(&key_set(&c).await).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1, "the old key left");
    let adds = w.spool.records("signer.ring.add").len();
    let writes = w.store.writes.lock().unwrap().len();

    // key@ is back on the old key, whether by a restore of its state or a card that was swapped.
    *w.key.current.lock().unwrap() = old.clone();
    for later in [11, 3600, 24 * 3600, 30 * 24 * 3600] {
        w.clock.advance(later);
        let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::Unavailable, "key_set"),
            "{later} s after"
        );
        let v: Value = serde_json::from_slice(&key_set(&c).await).unwrap();
        let kids: Vec<_> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(kids, std::slice::from_ref(&new.kid), "{later} s after");
    }
    assert_eq!(
        w.spool.records("signer.ring.add").len(),
        adds,
        "not added again"
    );
    assert_eq!(
        w.store.writes.lock().unwrap().len(),
        writes,
        "the ring was not written"
    );
    let (_, ring) = w.store.ring().unwrap();
    let k = ring.keys.iter().find(|k| k.key_id == old.kid).unwrap();
    assert_eq!(k.state, "dropped");
    assert!(
        k.spki_der.is_empty() && k.x5c.is_empty(),
        "a tombstone holds no key"
    );
    // The replacement is untouched: key@ goes back to it and it signs.
    *w.key.current.lock().unwrap() = new.clone();
    w.clock.advance(11);
    assert_eq!(
        sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
            .await
            .unwrap()
            .key_id,
        new.kid
    );
}

/// store@ audits every refusal, a `Get` of an item that is not there among them (ADR 0005), and an idle board writes at
/// most 60 audit records an hour (REQ-AUDIT-180): signing must not ask for the revocation of its key by address, which
/// would write one record for every token. It reads the kind as a list.
#[tokio::test]
async fn signing_asks_for_no_revocation_that_is_absent() {
    let w = World::new().await;
    let c = w.signer().await;
    for _ in 0..5 {
        sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
            .await
            .unwrap();
    }
    assert_eq!(
        w.store.revocation_gets_absent.load(Ordering::SeqCst),
        0,
        "a Get of a revocation that is not there is a refusal that store@ audits"
    );
    // And the stop is as prompt: the list is read at every sign, so a revocation that appears is seen at once.
    let kid = w.key.current.lock().unwrap().kid.clone();
    w.store.revoke(&kid);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_revoked");
}

/// A thumbprint as long and as random as the real ones, so that the ids sort and the first character is any of the 64.
fn random_kid() -> String {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    URL_SAFE_NO_PAD.encode(b)
}

/// A key whose revocation item sorts after at least `others` random ones, so that it is on a late page of a listing.
fn material_with_a_late_id() -> Arc<Material> {
    loop {
        let m = material();
        if kid_item_id(&m.kid).unwrap().starts_with("kid/y")
            || kid_item_id(&m.kid).unwrap().starts_with("kid/z")
        {
            return m;
        }
    }
}

/// `KeyRevocation` is a kind that only grows. A list of more than a page (100 items) is read to its end, and an item on a
/// later page is found, by the listing that builds the key set and by the one that refreshes the snapshot; the check
/// of every token asks the index and reads one page, however long the kind is.
///
/// verifies: REQ-KEYS-106, REQ-KEYS-107
#[tokio::test]
async fn a_revocation_on_a_later_page_is_found_and_a_token_asks_for_one_page() {
    let w = World::new().await;
    let mine = material_with_a_late_id();
    *w.key.current.lock().unwrap() = mine.clone();
    let mine_id = kid_item_id(&mine.kid).unwrap();
    let mut others = 0;
    while others < 250 {
        let other = random_kid();
        if kid_item_id(&other).unwrap() < mine_id {
            w.store.revoke(&other);
            others += 1;
        }
    }
    let c = w.signer().await;
    // Not revoked: it signs, and every look at the kind for the token is the index, one page.
    w.store.revocation_lists.lock().unwrap().clear();
    for _ in 0..5 {
        sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
            .await
            .unwrap();
    }
    let lists = w.store.revocation_lists.lock().unwrap().clone();
    assert_eq!(lists.len(), 5, "{lists:?}");
    assert!(
        lists
            .iter()
            .all(|(index, page)| index == "by_target" && page.is_empty()),
        "a token reads the index, from the first page: {lists:?}"
    );
    // Revoked by an earlier key@, with no entry in the index: the listing of the snapshot, which is read to its end,
    // finds it on the third page, and the key leaves the key set.
    w.store.revoke_without_index(&mine.kid);
    w.clock.advance(11);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_revoked");
    let pages = w
        .store
        .revocation_lists
        .lock()
        .unwrap()
        .iter()
        .filter(|(index, page)| index.is_empty() && !page.is_empty())
        .count();
    assert!(pages >= 2, "the listing went past the first page: {pages}");
    let v: Value = serde_json::from_slice(&key_set(&c).await).unwrap();
    assert!(v["keys"].as_array().unwrap().is_empty());
}

/// A listing that does not end is a store@ that is not answering as it should: the pages are counted, the listing stops
/// at 1000 of them and the sign, the snapshot and the key set are refused (fail closed), not run for ever.
///
/// verifies: REQ-KEYS-106
#[tokio::test]
async fn a_listing_of_key_revocation_that_never_ends_refuses_and_stops() {
    let w = World::new().await;
    let c = w.signer().await;
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    w.store
        .revocation_pages_never_end
        .store(true, Ordering::SeqCst);
    w.store.revocation_lists.lock().unwrap().clear();
    let started = std::time::Instant::now();
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "store")
    );
    let e = c.key_set(KeySetRequest::default()).await.unwrap_err();
    assert_eq!(reason(&e), "store");
    let asked = w.store.revocation_lists.lock().unwrap().len();
    assert!(
        (1000..=3000).contains(&asked),
        "the walk stops at 1000 pages for each of the sign and the key set: {asked}"
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    w.store
        .revocation_pages_never_end
        .store(false, Ordering::SeqCst);
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
}

/// verifies: REQ-KEYS-106, REQ-KEYS-107
#[tokio::test]
async fn a_revoked_key_signs_nothing_more_and_leaves_the_key_set_at_once() {
    let w = World::new().await;
    let c = w.signer().await;
    let kid = w.key.current.lock().unwrap().kid.clone();
    let issued_at = w.clock.secs();
    let before = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    let jwks = key_set(&c).await;
    assert_eq!(
        verify(&w, &jwks, &before.token, "example-app", "at+jwt").unwrap(),
        kid
    );
    let calls = w.key.calls.load(Ordering::SeqCst);

    // An operator's declaration reaches store@. No time passes: the next call is refused, and the key
    // set that the very next fetch gets lacks the kid, with no wait for the ring's look every ten seconds.
    w.store.revoke(&kid);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "key_revoked")
    );
    assert_eq!(
        w.key.calls.load(Ordering::SeqCst),
        calls,
        "key@ was not asked to sign with the revoked key"
    );
    assert_eq!(w.spool.records("signer.refused").len(), 1);
    let jwks = key_set(&c).await;
    let v: Value = serde_json::from_slice(&jwks).unwrap();
    assert!(v["keys"].as_array().unwrap().is_empty());
    assert!(
        verify_at(
            &w,
            &jwks,
            &before.token,
            "example-app",
            "at+jwt",
            issued_at + 1
        )
        .is_err(),
        "a token it signed fails against the set"
    );
}

/// verifies: REQ-KEYS-079, REQ-KEYS-106
#[tokio::test]
async fn the_owner_node_of_a_revoked_key_cannot_make_it_active_or_sign_with_it() {
    let w = World::new().await;
    let c = w.signer().await;
    let first = w.key.current.lock().unwrap().kid.clone();
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();

    // key@ moves to a new key, which the ring publishes. It is revoked before its window ends.
    let new = material();
    let new_kid = new.kid.clone();
    *w.key.current.lock().unwrap() = new;
    w.clock.advance(11);
    let _ = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600)).await;
    let (_, ring) = w.store.ring().unwrap();
    assert!(
        ring.keys
            .iter()
            .any(|k| k.key_id == new_kid && k.state == "pre-published")
    );
    w.store.revoke(&new_kid);
    let calls = w.key.calls.load(Ordering::SeqCst);

    // The window is over, and the loop and the next call look at the ring: nothing is promoted.
    w.clock.advance(31 * 60);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "key_revoked"),
        "revoked, so not asked of key@"
    );
    let (_, ring) = w.store.ring().unwrap();
    let state = |id: &str| {
        ring.keys
            .iter()
            .find(|k| k.key_id == id)
            .map(|k| k.state.clone())
    };
    assert_eq!(state(&new_kid).as_deref(), Some("pre-published"));
    assert_eq!(state(&first).as_deref(), Some("active"));
    assert_eq!(w.key.calls.load(Ordering::SeqCst), calls);
    let v: Value = serde_json::from_slice(&key_set(&c).await).unwrap();
    let kids: Vec<_> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(kids, [first], "the new key is revoked and not published");
}

/// verifies: REQ-KEYS-089, REQ-KEYS-106, REQ-KEYS-107
#[tokio::test]
async fn the_replacement_of_a_revoked_only_key_signs_at_once_with_its_key_set_published() {
    let w = World::new().await;
    let c = w.signer().await;
    let first = w.key.current.lock().unwrap().kid.clone();
    // Long after the first deploy: no shortcut of a young ring helps the replacement.
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    w.clock.advance(3 * 3600);
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();

    // The only key is revoked: nothing signs.
    w.store.revoke(&first);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "key_revoked")
    );

    // key@ moves to a new key. Within the ring's look every ten seconds the ring lists it, active and
    // with no lead time. It signs nothing yet: `entry` keeps its built key set for a few seconds, and
    // no token is signed before that key set can list the key.
    let new = material();
    let new_kid = new.kid.clone();
    *w.key.current.lock().unwrap() = new;
    w.clock.advance(11);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "key_set"),
        "held until entry's key set can list the key"
    );
    let (_, ring) = w.store.ring().unwrap();
    assert!(
        ring.keys
            .iter()
            .any(|k| k.key_id == new_kid && k.state == "active"),
        "in the ring, active, before its first token"
    );
    let hold = signer::ring::KEY_SET_HOLD;
    assert_eq!(hold, sluis_store::KEY_SET_CACHE + Duration::from_secs(1));
    w.clock.advance(hold.as_secs() - 1);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set", "short of the hold");
    w.clock.advance(1);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, new_kid);
    let jwks = key_set(&c).await;
    let v: Value = serde_json::from_slice(&jwks).unwrap();
    let kids: Vec<_> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        kids,
        std::slice::from_ref(&new_kid),
        "the revoked kid is not published"
    );
    assert_eq!(
        verify(&w, &jwks, &got.token, "example-app", "at+jwt").unwrap(),
        new_kid
    );
    let (_, ring) = w.store.ring().unwrap();
    let state = |id: &str| {
        ring.keys
            .iter()
            .find(|k| k.key_id == id)
            .map(|k| k.state.clone())
    };
    assert_eq!(state(&new_kid).as_deref(), Some("active"));
    // The audit fact says why the lead time was skipped; the first key of the deploy says nothing.
    let adds = w.spool.records("signer.ring.add");
    assert_eq!(adds.len(), 2);
    assert!(adds[0]["unmapped"]["sluis"].get("reason").is_none());
    assert_eq!(adds[1]["unmapped"]["sluis"]["key_id"], new_kid);
    assert_eq!(adds[1]["unmapped"]["sluis"]["state"], "active");
    assert_eq!(adds[1]["unmapped"]["sluis"]["reason"], "no_active_key");
}

/// verifies: REQ-KEYS-089, REQ-KEYS-076
#[tokio::test]
async fn a_revoked_spare_and_a_normal_rotation_still_wait_for_the_window() {
    let w = World::new().await;
    let c = w.signer().await;
    let first = w.key.current.lock().unwrap().kid.clone();
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    w.clock.advance(3 * 3600);

    // A normal rotation: the old key is active and not revoked, so the new key is only published.
    let new = material();
    let new_kid = new.kid.clone();
    *w.key.current.lock().unwrap() = new;
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set", "published, not yet signing");
    let (_, ring) = w.store.ring().unwrap();
    assert!(
        ring.keys
            .iter()
            .any(|k| k.key_id == new_kid && k.state == "pre-published")
    );

    // An unrelated revocation changes nothing: the key that signs is still not revoked.
    w.store.revoke(&material().kid);
    w.clock.advance(11);
    let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "key_set");

    // Once the old key is revoked, the key that waited signs at once, without the rest of the window.
    w.store.revoke(&first);
    w.clock.advance(11);
    let got = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    assert_eq!(got.key_id, new_kid);
    let changes = w.spool.records("signer.ring.change");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["unmapped"]["sluis"]["state"], "active");
    assert_eq!(changes[0]["unmapped"]["sluis"]["reason"], "no_active_key");
}

/// verifies: REQ-KEYS-089, REQ-KEYS-106
#[tokio::test]
async fn an_unreadable_revocation_or_ring_never_lets_an_unfamiliar_key_in_or_sign() {
    let w = World::new().await;
    let c = w.signer().await;
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    let (version, _) = w.store.ring().unwrap();
    let writes = w.store.writes.lock().unwrap().len();

    // key@ has moved to a key the ring does not know, and the snapshot is stale. Whatever the shortcut
    // would decide, it is not decided on a revocation list or a ring that could not be read.
    let new = material();
    *w.key.current.lock().unwrap() = new;
    let calls = w.key.calls.load(Ordering::SeqCst);
    for fault in ["revocations", "ring"] {
        w.clock.advance(11);
        match fault {
            "revocations" => w.store.revocations_down.store(true, Ordering::SeqCst),
            _ => w.store.down.store(true, Ordering::SeqCst),
        }
        let e = sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::Unavailable, "store"),
            "{fault}"
        );
        w.store.revocations_down.store(false, Ordering::SeqCst);
        w.store.down.store(false, Ordering::SeqCst);
        assert_eq!(w.store.ring().unwrap().0, version, "{fault}: unchanged");
        assert_eq!(w.store.writes.lock().unwrap().len(), writes, "{fault}");
        assert_eq!(w.key.calls.load(Ordering::SeqCst), calls, "{fault}");
    }
}

/// verifies: REQ-KEYS-089, REQ-KEYS-077
#[tokio::test]
async fn two_nodes_with_every_key_revoked_end_with_one_active_replacement() {
    let w = World::new().await;
    let (key_b, socket_b) = w.another_key("key-b").await;
    let a = w
        .signer_on("one", "exchange", 0, "node-a", &w.cfg.sockets.key.clone())
        .await;
    let b = w.signer_on("two", "exchange", 0, "node-b", &socket_b).await;
    let kid_a = w.key.current.lock().unwrap().kid.clone();
    let kid_b = key_b.current.lock().unwrap().kid.clone();
    w.clock.advance(3 * 3600);

    // Both boards' keys are revoked, and both key@s move on. Both signers look at the same moment;
    // the store's version guard lets one write first, and the other plans again on the ring it wrote.
    w.store.revoke(&kid_a);
    w.store.revoke(&kid_b);
    let (new_a, new_b) = (material(), material());
    let (kid_a2, kid_b2) = (new_a.kid.clone(), new_b.kid.clone());
    *w.key.current.lock().unwrap() = new_a;
    *key_b.current.lock().unwrap() = new_b;
    w.clock.advance(11);
    let _ = tokio::join!(
        sign(&a, "JWT", w.claims("JWT", "sluis-cli", 600)),
        sign(&b, "JWT", w.claims("JWT", "sluis-cli", 600)),
    );
    let (_, ring) = w.store.ring().unwrap();
    let state = |id: &str| {
        ring.keys
            .iter()
            .find(|k| k.key_id == id)
            .map(|k| k.state.clone())
            .unwrap()
    };
    let mut got = [state(&kid_a2), state(&kid_b2)];
    got.sort();
    assert_eq!(
        got,
        ["active", "pre-published"],
        "exactly one skips the window"
    );
    let adds = w.spool.records("signer.ring.add");
    let skipped = adds
        .iter()
        .filter(|f| f["unmapped"]["sluis"]["reason"] == "no_active_key")
        .count();
    assert_eq!(skipped, 1, "the audit names one");
}

/// verifies: REQ-KEYS-106, REQ-KEYS-107
#[tokio::test]
async fn it_fails_closed_when_key_revocation_cannot_be_read() {
    let w = World::new().await;
    let c = w.signer().await;
    sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    w.store.revocations_down.store(true, Ordering::SeqCst);
    let e = sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "store")
    );
    let e = c.key_set(KeySetRequest::default()).await.unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "store")
    );
    w.store.revocations_down.store(false, Ordering::SeqCst);
    sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
}

/// verifies: REQ-KEYS-106
/// The id is the one of the shared vectors (`tests/testdata/keyrevocation/ids.json`), written out here and not derived:
/// a reader that derived another id would not find the item that `key@` writes. The kid is the thumbprint of the public
/// key below (a key made for the vectors; only its public half is here). The stand-in for key@ names it as its key and
/// signs nothing, which the test shows before the item exists.
#[tokio::test]
async fn a_revocation_under_the_id_of_the_shared_vectors_stops_the_key() {
    const KID: &str = "skxjhT7RqwZwTBg1_6Z4ktQKu73fjoKvrNHjlHn9ToA";
    const ID: &str = "kid/wjgghbj62gvqm4cmda277jtyslkavo5536hifl5m2hrzi6p5j2aa";
    const SPKI_HEX: &str = "3076301006072a8648ce3d020106052b81040022036200049a7eeb5771cd7e01b4796199b19a265536aec25d597f925bda74cff1d5bd59985d9ef53cbb7a83311fced8d6f013bf1f7959d68415909a39af3f99e8d48eb76357245c55c4507b26f4082d33d343bd149f7cc73231da8ab59a5fe1c9b8f1a144";
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/testdata/keyrevocation/ids.json"
    ))
    .unwrap();
    assert!(
        vectors["ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["target_kind"] == "kid" && r["target"] == KID && r["id"] == ID),
        "the literals are a row of the shared vectors"
    );
    let spki: Vec<u8> = (0..SPKI_HEX.len() / 2)
        .map(|i| u8::from_str_radix(&SPKI_HEX[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    assert_eq!(
        signer::jwks::thumbprint(&spki).as_deref(),
        Some(KID),
        "the public key is the one the row names"
    );
    let w = World::new().await;
    // The pair is another key's: nothing is signed with it, because key@ is never asked to sign.
    *w.key.current.lock().unwrap() = Arc::new(Material {
        pair: EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap(),
        spki,
        kid: KID.into(),
    });
    let c = w.signer().await;
    let claims = || w.claims("at+jwt", "example-app", 600);
    // Not revoked yet: key@ is asked, and its signature does not verify under the key it names.
    let e = sign(&c, "at+jwt", claims()).await.unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Internal, "signature")
    );
    let calls = w.key.calls.load(Ordering::SeqCst);
    assert_eq!(calls, 1);
    w.store.put(
        "key-revocation",
        ID,
        KeyRevocation {
            target_kind: "kid".into(),
            target: KID.into(),
            reason_code: "compromise".into(),
            ..KeyRevocation::default()
        }
        .encode_to_vec(),
    );
    // key@ gives the item the entry of by_target, whose value the vectors give too.
    let vectors_index = vectors["ids"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["target_kind"] == "kid" && r["target"] == KID)
        .unwrap()["index_value"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(target_index_value("kid", KID), vectors_index.as_bytes());
    w.store.indexes.lock().unwrap().insert(
        ("key-revocation".into(), ID.into()),
        vec![("by_target".into(), vectors_index.into_bytes())],
    );
    let e = sign(&c, "at+jwt", claims()).await.unwrap_err();
    assert_eq!(
        (e.code, reason(&e).as_str()),
        (ErrorCode::Unavailable, "key_revoked")
    );
    assert_eq!(
        w.key.calls.load(Ordering::SeqCst),
        calls,
        "key@ was not asked"
    );
    let v: Value = serde_json::from_slice(&key_set(&c).await).unwrap();
    assert!(v["keys"].as_array().unwrap().is_empty());
}

/// verifies: REQ-KEYS-106
/// A read of `KeyRevocation` that never answers refuses the sign and the key set after the call's time, and queues nobody:
/// two signs and a key set at once finish together, none behind another.
#[tokio::test]
async fn a_hung_key_revocation_read_refuses_the_sign_and_blocks_no_one() {
    let w = World::new().await;
    let c = w.signer().await;
    sign(&c, "at+jwt", w.claims("at+jwt", "example-app", 600))
        .await
        .unwrap();
    w.store.revocation_get_hangs.store(true, Ordering::SeqCst);
    let claims = w.claims("at+jwt", "example-app", 600);
    let started = std::time::Instant::now();
    let (a, b, set) = tokio::join!(
        sign(&c, "at+jwt", claims.clone()),
        sign(&c, "at+jwt", claims),
        c.key_set(KeySetRequest::default()),
    );
    // A key set that might list a revoked key is not served either.
    for e in [a.unwrap_err(), b.unwrap_err(), set.unwrap_err()] {
        assert_eq!(
            (e.code, reason(&e).as_str()),
            (ErrorCode::Unavailable, "store")
        );
    }
    // One wait of the call's time, not three behind each other.
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
}

/// A change of the ring is a tightening: it stands when the spool refuses its fact, because a full spool never blocks it
/// (REQ-AUDIT-015), and the loss is counted, so the next fact the signer gets through says one fact was lost
/// (REQ-AUDIT-186).
///
/// verifies: REQ-AUDIT-015, REQ-AUDIT-186, REQ-AUDIT-187
#[tokio::test]
async fn a_ring_change_stands_when_the_spool_is_full_and_the_loss_is_counted_in_the_next_fact() {
    let w = World::new().await;
    w.spool.full.store(true, Ordering::SeqCst);
    let c = w.signer_as("one", "exchange", 0).await;
    let (_, ring) = w.store.ring().unwrap();
    assert_eq!(
        ring.keys.len(),
        1,
        "the ring change was undone because its fact was refused"
    );
    assert!(w.spool.records("signer.ring.add").is_empty());

    w.spool.full.store(false, Ordering::SeqCst);
    sign(&c, "JWT", w.claims("JWT", "sluis-cli", 600))
        .await
        .unwrap();
    let facts = w.spool.records("signer.sign");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0]["unmapped"]["sluis"]["lost"]["total"], 1);
}
