//! The store's half of the two independent checks (ADR 0007 "Two independent checks"): a write to
//! a tenant-scoped address carries a sealed grant, key@ opens it, and store@ refuses unless the
//! grant is for this boundary and this caller, names the address's tenant, allows the verb and has
//! not expired. store@ never opens a grant itself.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::SystemTime;

use aws_lc_rs::digest;
use buffa_types::google::protobuf::Timestamp;
use connectrpc::error::ErrorCode;
use sluis_kit::{Client, Transport};
use sluis_proto::sluis::key::v2alpha1::{KeyServiceClient, OpenGrantRequest};
use sluis_proto::sluis::r#type::v2alpha1::Grant;

/// Why a sealed grant did not open.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// key@ refused it: not a grant, not of this boundary, or tampered with.
    Refused,
    /// key@ is down or slow: store@ fails closed.
    Unavailable,
}

/// key@'s `OpenGrant`, as store@ calls it.
pub trait GrantOpener: Send + Sync + 'static {
    /// Opens a sealed grant.
    fn open(&self, sealed: &[u8]) -> impl Future<Output = Result<Grant, OpenError>> + Send;
}

/// key@ on its socket for store@ (`/run/sluis/key/<boundary>/store/key.sock`).
pub struct KeyOpener {
    client: KeyServiceClient<Transport>,
}

impl KeyOpener {
    /// A client of key@ at the socket of `client`.
    #[must_use]
    pub fn new(client: &Client) -> Self {
        Self {
            client: KeyServiceClient::new(client.transport(), client.config()),
        }
    }
}

impl GrantOpener for KeyOpener {
    async fn open(&self, sealed: &[u8]) -> Result<Grant, OpenError> {
        let req = OpenGrantRequest {
            sealed_grant: sealed.to_vec(),
            ..OpenGrantRequest::default()
        };
        match self.client.open_grant(req).await {
            Ok(r) => r
                .into_owned()
                .grant
                .into_option()
                .ok_or(OpenError::Unavailable),
            Err(e)
                if matches!(
                    e.code,
                    ErrorCode::Unavailable
                        | ErrorCode::DeadlineExceeded
                        | ErrorCode::Internal
                        | ErrorCode::Unknown
                ) =>
            {
                tracing::warn!(code = e.code.as_str(), "key@ did not open the grant");
                Err(OpenError::Unavailable)
            }
            // permission_denied, invalid_argument, ...: the grant is not good.
            Err(_) => Err(OpenError::Refused),
        }
    }
}

/// The opened grants, by the SHA-384 of the sealed bytes, until their expiry, so a batch (or the
/// next write of the same request) costs one open. A grant is never stored anywhere else.
pub struct GrantCache<G> {
    opener: G,
    cache: Mutex<HashMap<[u8; 48], Grant>>,
}

/// More than this many live grants are not cached (a grant lives about 60 s).
const CACHE_MAX: usize = 4096;

impl<G: GrantOpener> GrantCache<G> {
    #[must_use]
    pub fn new(opener: G) -> Self {
        Self {
            opener,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The opened grant for these sealed bytes, from the cache while it has not expired.
    ///
    /// # Errors
    ///
    /// [`OpenError`] from key@.
    pub async fn open(&self, sealed: &[u8], now: SystemTime) -> Result<Grant, OpenError> {
        let mut id = [0u8; 48];
        id.copy_from_slice(digest::digest(&digest::SHA384, sealed).as_ref());
        if let Some(g) = self.lock().get(&id)
            && expiry(g).is_some_and(|e| e > now)
        {
            return Ok(g.clone());
        }
        let grant = self.opener.open(sealed).await?;
        if expiry(&grant).is_some_and(|e| e > now) {
            let mut cache = self.lock();
            if cache.len() >= CACHE_MAX {
                cache.retain(|_, g| expiry(g).is_some_and(|e| e > now));
            }
            if cache.len() < CACHE_MAX {
                cache.insert(id, grant.clone());
            }
        }
        Ok(grant)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 48], Grant>> {
        // A panic while the lock was held cannot leave a half-written entry: inserts are whole.
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// When a grant expires; None when it carries no valid expiry (then it never passes).
#[must_use]
pub fn expiry(g: &Grant) -> Option<SystemTime> {
    g.expires_at.as_option().and_then(to_system_time)
}

/// A protobuf timestamp as a `SystemTime`.
#[must_use]
pub fn to_system_time(t: &Timestamp) -> Option<SystemTime> {
    let secs = u64::try_from(t.seconds).ok()?;
    let nanos = u32::try_from(t.nanos).ok().filter(|n| *n < 1_000_000_000)?;
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(secs, nanos))
}

/// A `SystemTime` as a protobuf timestamp.
#[must_use]
pub fn from_system_time(t: SystemTime) -> Timestamp {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        ..Timestamp::default()
    }
}

/// Whether an opened grant lets `holder` run `verb` on an address of `tenant` in `boundary` at
/// `now` (ADR 0007 "Sealed grants"; ADR 0005 "Rules").
///
/// `*` (every tenant) is for audit reads and is never accepted for a write: a grant that lists it
/// is refused whole.
#[must_use]
pub fn allows(
    g: &Grant,
    boundary: &str,
    holder: &str,
    tenant: &str,
    verb: &str,
    now: SystemTime,
) -> bool {
    g.boundary == boundary
        && g.holder == holder
        && !g.tenants.iter().any(|t| t == "*")
        && !tenant.is_empty()
        && g.tenants.iter().any(|t| t == tenant)
        && g.store_verbs.iter().any(|v| v == verb)
        && expiry(g).is_some_and(|e| e > now)
}
