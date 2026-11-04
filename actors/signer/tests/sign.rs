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
//! with go-jose, built from `actors/signer/tests/gojose`, against the key set that `signer`
//! publishes from the `SigningRing` in the stand-in for `store@`.

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
use buffa_types::google::protobuf::Duration as PbDuration;
use connectrpc::error::ErrorCode;
use connectrpc::{
    ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream,
};
use serde_json::{Value, json};
use signer::ring::Timing;
use signer::{Config, Sockets};
use sluis_kit::{Allow, Identities, ServerConfig, refusal, refusal_reason};
use sluis_proto::sluis::config::v2alpha1::{Boundary, InstallationClient, TokenLifetime};
use sluis_proto::sluis::key::v2alpha1::{
    KeyService, KeyServiceExt, PublicKeyRequest, PublicKeyResponse, SignRequest, SignResponse,
};
use sluis_proto::sluis::port::transport::v2alpha1::{
    AckRequest, AckResponse, EmitRequest, EmitResponse, ReceiveRequest, ReceiveResponse,
    TransportService, TransportServiceExt,
};
use sluis_proto::sluis::signer::v2alpha1::{
    KeySetRequest, SignTokenRequest, SignTokenResponse, SignerServiceClient,
};
use sluis_proto::sluis::store::v2alpha1::{
    GetRequest, GetResponse, Item, ListRequest, ListResponse, StoreService, StoreServiceExt, Verb,
    WatchRequest, WatchResponse, WriteRequest, WriteResponse,
};
use sluis_proto::sluis::r#type::v2alpha1::Address;
use tempfile::TempDir;
use tokio::sync::oneshot;

const ISSUER: &str = "https://sluis.dev.local.test";

// ---------------------------------------------------------------- the stand-in for store@

/// (kind segment, id) to (version, value).
type Items = HashMap<(String, String), (u64, Vec<u8>)>;

#[derive(Default)]
struct FakeStore {
    items: Mutex<Items>,
    /// The writes it took: verb and kind.
    writes: Mutex<Vec<(&'static str, String)>>,
    /// Refuse every read with `unavailable`.
    down: AtomicBool,
}

impl FakeStore {
    fn put(&self, kind: &str, id: &str, value: Vec<u8>) {
        self.items
            .lock()
            .unwrap()
            .insert((kind.into(), id.into()), (1, value));
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
        let items = self.0.items.lock().unwrap();
        match items.get(&(kind.clone(), id.clone())) {
            Some((v, bytes)) => Response::ok(GetResponse {
                item: Some(item(&kind, &id, *v, bytes)).into(),
                ..GetResponse::default()
            }),
            None => Err(refusal(ErrorCode::NotFound, "absent", "")),
        }
    }
    async fn list(
        &self,
        _: RequestContext,
        _: ServiceRequest<'_, ListRequest>,
    ) -> ServiceResult<ListResponse> {
        Err(refusal(ErrorCode::Unimplemented, "unsupported", ""))
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
        let key = Arc::new(FakeKey {
            current: Mutex::new(material()),
            signed: Mutex::default(),
            calls: AtomicUsize::new(0),
            down: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
        });
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
        let socket = self.dir.path().join(format!("{name}.sock"));
        let mut cfg = self.cfg.clone();
        cfg.socket = socket.clone();
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
        root.join("actors/signer/tests/gojose/main.go").exists(),
        "actors/signer/tests/gojose is missing: it is the Go side of the test"
    );
    root
}

/// The go-jose verifier, built once. The Go side is in this repository, so a missing Go toolchain
/// is a failure, never a skip.
fn gojose() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let bin = Path::new(env!("CARGO_TARGET_TMPDIR")).join("gojose");
        let out = Command::new("go")
            .current_dir(repo_root())
            .args(["build", "-o"])
            .arg(&bin)
            .arg("./actors/signer/tests/gojose")
            .output()
            .expect("go build: is Go on the PATH (devbox)?");
        assert!(
            out.status.success(),
            "go build of the verifier failed:\n{}{}",
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

/// [`verify`] as a relying party would at the Unix time `at`.
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
        .arg(&file)
        .args([token, ISSUER, aud, typ])
        .arg(at.to_string())
        .output()
        .unwrap();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

// ---------------------------------------------------------------- tests

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

    // Just short of 15 minutes after it was published it still does not sign; a little after, it does.
    // (The ring is looked at again when the last look is ten seconds old, so a key signs at most ten
    // seconds after its window; the exact second is the test of `ring::plan`.)
    w.clock.advance(15 * 60 - 20);
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
