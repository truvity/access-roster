//! What the config tests share: a pipeline that signs documents with a key made for the test, the
//! `file` driver served on a socket in a temporary directory, and the local installation's
//! config sources.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)] // each test file uses some of it

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connectrpc::Router;
use serde_json::json;
use sluis_kit::{Allow, Identities, ServerConfig};
use sluis_proto::sluis::port::source::v2alpha1::SourceServiceExt as _;
use store::bootstrap::{Bootstrap, Destination, Publisher};

/// The prefix of a P-384 SubjectPublicKeyInfo (RFC 5480), before the 97-byte point.
const SPKI_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

/// The config sources of the local installation, by kind segment.
pub const LOCAL: [(&str, &str); 8] = [
    (
        "boundary",
        include_str!("../../../../tests/installations/local/config/boundary.yaml"),
    ),
    (
        "key-plan",
        include_str!("../../../../tests/installations/local/config/key-plan.yaml"),
    ),
    (
        "token-lifetime",
        include_str!("../../../../tests/installations/local/config/token-lifetime.yaml"),
    ),
    (
        "grant-vocabulary",
        include_str!("../../../../tests/installations/local/config/grant-vocabulary.yaml"),
    ),
    (
        "audit-log",
        include_str!("../../../../tests/installations/local/config/audit-log.yaml"),
    ),
    (
        "audit-catalogue",
        include_str!("../../../../tests/installations/local/config/audit-catalogue.yaml"),
    ),
    (
        "upstream",
        include_str!("../../../../tests/installations/local/config/upstream.yaml"),
    ),
    (
        "installation-client",
        include_str!("../../../../tests/installations/local/config/installation-client.yaml"),
    ),
];

/// A publisher: a key pair made for the test, which signs documents.
pub struct Pipeline {
    key: EcdsaKeyPair,
    pub kid: String,
}

impl Pipeline {
    pub fn new(kid: &str) -> Self {
        Self {
            key: EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap(),
            kid: kid.into(),
        }
    }

    /// The entry the bootstrap file pins for this key.
    pub fn publisher(&self, co_signs: &[&str]) -> Publisher {
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(self.key.public_key().as_ref());
        Publisher {
            kid: self.kid.clone(),
            spki_der: der,
            spki_sha384: String::new(),
            co_signs: co_signs.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// The signature object of `payload` at `seq`.
    pub fn signature(&self, payload: &[u8], seq: u64) -> serde_json::Value {
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg": "ES384", "kid": self.kid, "seq": seq})).unwrap(),
        );
        let input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(payload));
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        json!({"protected": protected, "signature": URL_SAFE_NO_PAD.encode(sig.as_ref())})
    }

    /// A document of `payload` at `seq`, signed by this key alone.
    pub fn sign(&self, payload: &[u8], seq: u64) -> Vec<u8> {
        document(payload, &[self.signature(payload, seq)])
    }
}

/// A document of several signatures.
pub fn document(payload: &[u8], signatures: &[serde_json::Value]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "payload": URL_SAFE_NO_PAD.encode(payload),
        "signatures": signatures,
    }))
    .unwrap()
}

/// Writes (or replaces, by a rename) the document of a kind.
pub fn put(dir: &Path, segment: &str, doc: &[u8]) {
    let next = dir.join(".next");
    std::fs::write(&next, doc).unwrap();
    std::fs::rename(next, dir.join(format!("{segment}.jws"))).unwrap();
}

/// Signs every local source at `seq` into `dir`.
pub fn write_local(dir: &Path, p: &Pipeline, seq: u64) {
    for (segment, text) in LOCAL {
        put(dir, segment, &p.sign(text.as_bytes(), seq));
    }
}

/// A bootstrap file for the boundary `dev` that pins `publishers`; the sockets are placeholders,
/// the loader reads only the config source's, which the caller dials.
pub fn bootstrap(publishers: Vec<Publisher>) -> Bootstrap {
    let d = |name: &str| Destination {
        driver: "file".into(),
        socket: PathBuf::from(format!("/nonexistent/{name}.sock")),
    };
    Bootstrap {
        boundary: "dev".into(),
        start_timeout: Duration::from_secs(5),
        config_source: d("config-source"),
        secret_source: d("secret-source"),
        durable: d("durable"),
        temp: d("temp"),
        publishers,
    }
}

/// Serves the `file` driver over `dir` on `socket`, with this process as `store`.
pub fn serve_driver(socket: &Path, dir: &Path) -> tokio::sync::oneshot::Sender<()> {
    let me = rustix::process::geteuid().as_raw();
    let ids = Identities::with(0, move |uid| (uid == me).then_some(("store", 0)));
    let cfg = ServerConfig {
        actor: "driver-store-file",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        socket_gid: None,
        allow: Allow::OwnerOnly("store"),
        default_deadline: Duration::from_secs(10),
    };
    let router = Arc::new(sluis_file::service::Service(
        sluis_file::Dir::open(dir).unwrap(),
    ))
    .register(Router::new());
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

pub async fn up(socket: &Path) {
    for _ in 0..300 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no socket");
}
