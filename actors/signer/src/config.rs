//! What `signer` reads of the boundary's config, through store@ (ADR 0005 "Configuration loading"):
//!
//! - `Boundary`: the issuer URL, the value `iss` must have (ADR 0017 "Issuers").
//! - `TokenLifetime`: the lifetime of an issuer's tokens, under the built-in maximum (ADR 0020
//!   "Lifetimes").
//! - `InstallationClient`: the registered clients. An audience is exactly one registered client id
//!   (ADR 0017 "Audiences"), and a client may lower its tokens' lifetime with `ttl_cap`.
//!
//! The tenant kinds (`TenantClient`, `TokenLifetimeTenant`) are not read: the first working version
//! has no `Tenant` items (D-4), so every client is one of the installation.
//!
//! `Boundary` and `TokenLifetime` are kept for ten seconds. A client is read for each token, because
//! a registration must not be believed after it ended.

use std::sync::Arc;
use std::time::Duration;

use buffa_types::google::protobuf::Duration as PbDuration;
use sluis_kit::Client;
use sluis_proto::sluis::config::v2alpha1::{Boundary, InstallationClient, TokenLifetime};
use sluis_store::{Error as StoreError, Kind, Store};
use tokio::sync::Mutex;

use crate::claims::Typ;
use crate::service::Clock;

/// The singleton id of a singleton config kind (PLAN.md D-17).
const ID: &str = "default";
/// How long `Boundary` and `TokenLifetime` are kept.
const KEEP: Duration = Duration::from_secs(10);
/// How long one read may take.
const READ: Duration = Duration::from_secs(5);

struct BoundaryKind;
impl Kind for BoundaryKind {
    type Id = &'static str;
    type Value = Boundary;
    const NAME: &'static str = "Boundary";
}

struct LifetimeKind;
impl Kind for LifetimeKind {
    type Id = &'static str;
    type Value = TokenLifetime;
    const NAME: &'static str = "TokenLifetime";
}

struct ClientKind;
impl Kind for ClientKind {
    type Id = String;
    type Value = InstallationClient;
    const NAME: &'static str = "InstallationClient";
}

/// Why the config could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// store@ could not be reached or refused.
    Store,
    /// The boundary has no usable issuer.
    Config,
}

/// What the issuer's config says.
#[derive(Debug, Clone)]
pub struct Issuer {
    /// The issuer URL of the boundary.
    pub url: String,
    /// The lifetime of an ID token, in seconds, when the config sets one.
    pub id_token_secs: Option<i64>,
    /// The lifetime of an access token, in seconds, when the config sets one.
    pub access_token_secs: Option<i64>,
}

impl Issuer {
    /// The lifetime that the config sets for a type of token.
    #[must_use]
    pub fn lifetime_secs(&self, typ: Typ) -> Option<i64> {
        match typ {
            Typ::Id => self.id_token_secs,
            Typ::Access => self.access_token_secs,
        }
    }
}

/// A registered client.
#[derive(Debug, Clone, Copy)]
pub struct Registered {
    /// The longest token lifetime the client may get, in seconds, when it sets one.
    pub ttl_cap_secs: Option<i64>,
}

fn secs(d: Option<&PbDuration>) -> Option<i64> {
    d.map(|d| d.seconds).filter(|s| *s > 0)
}

/// The reader of the config.
pub struct Config {
    boundary: Store<BoundaryKind>,
    lifetime: Store<LifetimeKind>,
    clients: Store<ClientKind>,
    kept: Mutex<Option<(std::time::SystemTime, Arc<Issuer>)>>,
    clock: Clock,
}

impl Config {
    /// A reader over store@'s socket.
    ///
    /// # Errors
    ///
    /// When a kind is not in the registry.
    pub fn new(store: &Client, clock: Clock) -> Result<Self, StoreError> {
        Ok(Self {
            boundary: Store::new(store.clone())?,
            lifetime: Store::new(store.clone())?,
            clients: Store::new(store.clone())?,
            kept: Mutex::new(None),
            clock,
        })
    }

    /// The issuer of the boundary and its lifetimes.
    ///
    /// # Errors
    ///
    /// [`Unreadable`]: `signer` fails closed and signs nothing.
    pub async fn issuer(&self) -> Result<Arc<Issuer>, Unreadable> {
        // The lock is held across the reads: concurrent callers wait for one read, not make many.
        let mut kept = self.kept.lock().await;
        let now = (self.clock)();
        if let Some((at, i)) = kept.as_ref()
            && now.duration_since(*at).is_ok_and(|age| age < KEEP)
        {
            return Ok(Arc::clone(i));
        }
        let (b, l) = tokio::join!(
            tokio::time::timeout(READ, self.boundary.get("", ID)),
            tokio::time::timeout(READ, self.lifetime.get("", ID)),
        );
        let b = b.map_err(|_| Unreadable::Store)?.map_err(|e| match e {
            StoreError::NotFound => Unreadable::Config,
            _ => Unreadable::Store,
        })?;
        // No TokenLifetime means the built-in maximum alone (ADR 0020 "Lifetimes").
        let l = match l.map_err(|_| Unreadable::Store)? {
            Ok(item) => Some(item.value),
            Err(StoreError::NotFound) => None,
            Err(_) => return Err(Unreadable::Store),
        };
        let url = b.value.issuer;
        if url.is_empty() {
            return Err(Unreadable::Config);
        }
        let issuer = Arc::new(Issuer {
            url,
            id_token_secs: l.as_ref().and_then(|l| secs(l.id_token.as_option())),
            access_token_secs: l.as_ref().and_then(|l| secs(l.access_token.as_option())),
        });
        *kept = Some((now, Arc::clone(&issuer)));
        Ok(issuer)
    }

    /// The registration of a client id, or `None` when nobody registered it. An id that cannot be an
    /// address of the store is a client nobody registered.
    ///
    /// # Errors
    ///
    /// [`Unreadable::Store`].
    pub async fn client(&self, id: &str) -> Result<Option<Registered>, Unreadable> {
        match tokio::time::timeout(READ, self.clients.get("", id)).await {
            Ok(Ok(item)) => Ok(Some(Registered {
                ttl_cap_secs: secs(item.value.ttl_cap.as_option()),
            })),
            Ok(Err(StoreError::NotFound | StoreError::Address(_))) => Ok(None),
            _ => Err(Unreadable::Store),
        }
    }
}
