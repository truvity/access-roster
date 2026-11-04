//! `sluis.signer.v2alpha1.SignerService`: `SignToken` and `KeySet`.
//!
//! The caller is the peer the kit named from the transport (peer uid, through the registry's uid
//! map); no request field says who it is, and the call graph of the registry decides who may call at
//! all: `session` and `exchange`. A request names no boundary: the boundary is the connection.

// The generated trait returns `impl Encodable`; a concrete type is fine.
#![allow(refining_impl_trait)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connectrpc::error::ErrorCode;
use connectrpc::{ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult};
use serde_json::json;
use sluis_kit::{Allow, ServerConfig, dial, refusal};
use sluis_proto::sluis::signer::v2alpha1::{
    KeySetRequest, KeySetResponse, SignTokenRequest, SignTokenResponse, SignerService,
    SignerServiceExt as _,
};

use crate::audit::Auditor;
use crate::claims::{self, Bad, Typ};
use crate::config::{self, Unreadable};
use crate::jwks::jwks;
use crate::keys::{KeyAt, KeyError};
use crate::ring::{RingError, RingKeeper, Timing};

/// The clock. Production passes `SystemTime::now`.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The deadline of a call that carries none (contracts.md "Every call").
const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);
/// How often the loop looks at the ring when nobody asks for a token.
const LOOP: Duration = Duration::from_secs(30);
/// The pause between attempts while `serve` waits for key@ and store@.
const START_PAUSE: Duration = Duration::from_millis(500);

/// The sockets of the actors `signer` calls (PLAN.md "Socket layout"; each only where the registry's
/// call graph allows it).
#[derive(Clone, Debug)]
pub struct Sockets {
    /// `store@`.
    pub store: PathBuf,
    /// `key@`, the socket that only `signer` may open.
    pub key: PathBuf,
    /// The audit transport's emit socket.
    pub audit: PathBuf,
}

impl Sockets {
    /// The sockets under `run_dir` (`/run/sluis`) for a boundary.
    #[must_use]
    pub fn under(run_dir: &Path, boundary: &str) -> Self {
        Self {
            store: run_dir.join("store").join(format!("{boundary}.sock")),
            key: run_dir
                .join("key")
                .join(boundary)
                .join("signer")
                .join("key.sock"),
            audit: run_dir.join("audit").join(boundary).join("emit.sock"),
        }
    }
}

/// What one `signer` instance needs.
#[derive(Clone)]
pub struct Config {
    /// The boundary.
    pub boundary: String,
    /// Where it listens (`/run/sluis/signer/<boundary>.sock`).
    pub socket: PathBuf,
    /// The group of the socket file, when it is not `signer`'s own; 0 is refused.
    pub socket_gid: Option<u32>,
    /// The actors it calls.
    pub sockets: Sockets,
    /// The release, for the audit record (`sluis_version`).
    pub release: String,
    /// How long a key is published before it signs, and after it stopped.
    pub timing: Timing,
    /// How long `serve` waits for key@ and store@ before it gives up.
    pub start_timeout: Duration,
    /// The clock; `None` is the system clock. A test injects one.
    pub now: Option<Clock>,
}

/// A refusal in the making: the Connect code, the reason of the list in the crate docs, and the path
/// of the field at fault.
#[derive(Debug, PartialEq, Eq)]
struct Refuse {
    code: ErrorCode,
    reason: &'static str,
    path: &'static str,
}

const fn refuse(code: ErrorCode, reason: &'static str, path: &'static str) -> Refuse {
    Refuse { code, reason, path }
}

impl From<Bad> for Refuse {
    fn from(b: Bad) -> Self {
        // The same code and reason for every claim that does not fit, so that a wrong issuer, an
        // audience nobody registered and a lifetime past the cap look alike (contracts.md "Uniform
        // refusals at the edge"). The path says which field, to the caller inside sluis only.
        refuse(ErrorCode::InvalidArgument, "claims", b.0)
    }
}

impl From<Unreadable> for Refuse {
    fn from(u: Unreadable) -> Self {
        match u {
            Unreadable::Store => refuse(ErrorCode::Unavailable, "store", ""),
            Unreadable::Config => refuse(ErrorCode::Unavailable, "config", ""),
        }
    }
}

impl From<RingError> for Refuse {
    fn from(e: RingError) -> Self {
        match e {
            RingError::Store => refuse(ErrorCode::Unavailable, "store", ""),
            RingError::Key(_) => refuse(ErrorCode::Unavailable, "key", ""),
            RingError::NotActive => refuse(ErrorCode::Unavailable, "key_set", ""),
        }
    }
}

impl From<KeyError> for Refuse {
    fn from(e: KeyError) -> Self {
        match e {
            KeyError::Unavailable => refuse(ErrorCode::Unavailable, "key", ""),
            KeyError::Inconsistent => refuse(ErrorCode::Internal, "signature", ""),
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The signer.
pub struct Signer {
    config: config::Config,
    ring: RingKeeper,
    key: Arc<KeyAt>,
    audit: Arc<Auditor>,
    clock: Clock,
}

impl Signer {
    /// Builds the signer; nothing is dialled until the first call.
    ///
    /// # Errors
    ///
    /// When the audit emitter's configuration is refused, or a kind is not in the registry.
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let clock: Clock = cfg.now.clone().unwrap_or_else(|| Arc::new(SystemTime::now));
        let audit = Arc::new(Auditor::new(sluis_audit::Config {
            actor: "signer".into(),
            boundary: cfg.boundary.clone(),
            release: cfg.release.clone(),
            transport_socket: cfg.sockets.audit.clone(),
            // signer names no person, so it needs no pseudonym key.
            key_socket: None,
            now: None,
        })?);
        let key = Arc::new(KeyAt::new(&cfg.sockets.key));
        let store = dial(&cfg.sockets.store);
        let ring = RingKeeper::new(
            &store,
            Arc::clone(&key),
            Arc::clone(&audit),
            Arc::clone(&clock),
            cfg.timing,
        )
        .map_err(|e| anyhow::anyhow!("SigningRing: {e}"))?;
        let config = config::Config::new(&store, Arc::clone(&clock))
            .map_err(|e| anyhow::anyhow!("config kinds: {e}"))?;
        Ok(Self {
            config,
            ring,
            key,
            audit,
            clock,
        })
    }

    fn now_secs(&self) -> i64 {
        (self.clock)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    /// Checks the claims against the config, and signs them through key@.
    async fn sign(
        &self,
        m: &SignTokenRequest,
    ) -> Result<(SignTokenResponse, Typ, claims::Shaped), Refuse> {
        let typ = Typ::parse(&m.typ).ok_or(refuse(ErrorCode::InvalidArgument, "typ", "typ"))?;
        let c = claims::shape(typ, &m.claims_json)?;
        let issuer = self.config.issuer().await?;
        claims::check_issuer(&c, &issuer.url)?;
        let audience = self
            .config
            .client(&c.audience)
            .await?
            .ok_or(Bad("claims.aud"))?;
        if let Some(id) = &c.client_id {
            self.config
                .client(id)
                .await?
                .ok_or(Bad("claims.client_id"))?;
        }
        let cap = claims::cap_secs(issuer.lifetime_secs(typ), audience.ttl_cap_secs);
        claims::check_time(&c, self.now_secs(), cap)?;

        let key = self.ring.signing_key().await?;
        let header =
            json!({ "alg": crate::keys::ALGORITHM, "kid": key.key_id, "typ": typ.header() });
        let input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&header).unwrap_or_default()),
            b64(&c.payload())
        );
        let sig = self.key.sign(input.as_bytes(), &key).await?;
        let token = format!("{input}.{}", b64(&sig));
        Ok((
            SignTokenResponse {
                token,
                key_id: key.key_id,
                ..SignTokenResponse::default()
            },
            typ,
            c,
        ))
    }

    /// The caller, from the transport. The guard of the kit set it before the message was decoded.
    fn caller(ctx: &RequestContext) -> Result<&'static str, ConnectError> {
        sluis_kit::peer(ctx.extensions())
            .map(|p| p.name)
            .ok_or_else(|| refusal(ErrorCode::PermissionDenied, "caller", ""))
    }

    async fn failed(&self, caller: &str, method: &str, r: Refuse) -> ConnectError {
        self.audit.refused(caller, method, r.reason, r.path).await;
        refusal(r.code, r.reason, r.path)
    }
}

impl SignerService for Signer {
    async fn sign_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SignTokenRequest>,
    ) -> ServiceResult<SignTokenResponse> {
        let caller = Self::caller(&ctx)?;
        match self.sign(&request.to_owned_message()).await {
            Ok((resp, typ, c)) => {
                self.audit
                    .signed(caller, typ.header(), &resp.key_id, &c.audience)
                    .await;
                Response::ok(resp)
            }
            Err(r) => Err(self.failed(caller, "SignToken", r).await),
        }
    }

    async fn key_set(
        &self,
        ctx: RequestContext,
        _: ServiceRequest<'_, KeySetRequest>,
    ) -> ServiceResult<KeySetResponse> {
        let caller = Self::caller(&ctx)?;
        match self.ring.read().await {
            Ok(ring) => Response::ok(KeySetResponse {
                jwks_json: jwks(&ring),
                ..KeySetResponse::default()
            }),
            Err(e) => Err(self.failed(caller, "KeySet", e.into()).await),
        }
    }
}

fn server_config(cfg: &Config) -> ServerConfig {
    ServerConfig {
        actor: "signer",
        boundary: cfg.boundary.clone(),
        socket: cfg.socket.clone(),
        mode: 0o660,
        socket_gid: cfg.socket_gid,
        allow: Allow::CallGraph,
        default_deadline: DEFAULT_DEADLINE,
    }
}

/// Builds the signer, waits for the ring to be in order, and starts the loop that keeps it so.
async fn assemble(cfg: &Config) -> anyhow::Result<(Router, tokio::task::JoinHandle<()>)> {
    let signer = Arc::new(Signer::new(cfg)?);
    // A cold start refuses on any failure: key@ and store@ get start_timeout to come up.
    let deadline = Instant::now() + cfg.start_timeout;
    loop {
        match signer.ring.reconcile().await {
            Ok(()) => break,
            Err(e) if Instant::now() >= deadline => {
                bail!(
                    "the key set is not in order within {}s: {e:?}",
                    cfg.start_timeout.as_secs()
                );
            }
            Err(_) => tokio::time::sleep(START_PAUSE).await,
        }
    }
    let background = tokio::spawn({
        let signer = Arc::clone(&signer);
        async move {
            loop {
                tokio::time::sleep(LOOP).await;
                if let Err(e) = signer.ring.reconcile().await {
                    tracing::warn!(error = ?e, "the key set could not be brought in order");
                }
            }
        }
    });
    Ok((signer.register(Router::new()), background))
}

/// Serves until `shutdown` resolves.
///
/// # Errors
///
/// Fails when key@ and store@ do not come up within the start timeout, when the process does not run
/// as a uid of the registry, or when the socket cannot be made.
pub async fn serve(cfg: Config, shutdown: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
    let (router, background) = assemble(&cfg).await.context("start")?;
    let served = sluis_kit::serve(server_config(&cfg), router, shutdown).await;
    background.abort();
    served
}

/// [`serve`] with a uid table of a test's own. Test builds only.
///
/// # Errors
///
/// As [`serve`], except for the uid of the process.
#[cfg(feature = "test-identities")]
pub async fn serve_with(
    cfg: Config,
    shutdown: impl Future<Output = ()> + Send,
    identities: sluis_kit::Identities,
) -> anyhow::Result<()> {
    let (router, background) = assemble(&cfg).await.context("start")?;
    let served = sluis_kit::serve_with(server_config(&cfg), router, shutdown, identities).await;
    background.abort();
    served
}
