//! The secret source of store@ (ADR 0005, "Secret sources"; store-api.md "The source contract").
//!
//! A secret is fetched on first use and then held in memory: it is never written to disk, an audit fact, a log
//! line or a span, and nothing here has a `Debug` that prints it.
//!
//! The cache has no expiry. The only secret driver the bootstrap file accepts today is `credential`, whose
//! capability is `NONE`: a systemd credential does not change under a running service, so a changed secret takes a
//! restart of store@ (the unit reloads its credentials on restart). A driver that can change a value, such as `ssm`,
//! gives its capability and a `poll_after`, and its arrival is when the cache learns to expire; that is why
//! `serve` refuses any other driver today.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use connectrpc::error::ErrorCode;
use sluis_kit::{Client, Transport};
use sluis_proto::sluis::port::source::v2alpha1::{ReadRequest, SourceServiceClient};

/// How long one call to the secret source may take.
const CALL: Duration = Duration::from_secs(10);

/// A secret as the source holds it. It has no `Debug`, so it cannot reach a log by accident.
pub struct Secret {
    pub data: Vec<u8>,
    /// The source's label of the bytes (never a hash of the value).
    pub version: String,
}

/// Why a read gave no secret. It names no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The source has no secret of this name.
    Absent,
    /// The source did not answer, or refused: store@ fails closed.
    Down,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where store@ reads secrets from.
pub trait SecretSource: Send + Sync {
    /// The secret named `name`.
    fn read<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Arc<Secret>, SecretError>>;
}

/// No secret source: every read is `Down`. For tests of the service that read no secret kind.
pub struct NoSecrets;

impl SecretSource for NoSecrets {
    fn read<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Arc<Secret>, SecretError>> {
        Box::pin(async { Err(SecretError::Down) })
    }
}

/// The secret source driver on its socket, with the cache of what it has given.
pub struct SourceSecrets {
    source: SourceServiceClient<Transport>,
    cache: Mutex<HashMap<String, Arc<Secret>>>,
}

impl SourceSecrets {
    #[must_use]
    pub fn new(client: &Client) -> Self {
        Self {
            source: SourceServiceClient::new(client.transport(), client.config()),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, name: &str) -> Option<Arc<Secret>> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }
}

impl SecretSource for SourceSecrets {
    fn read<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Arc<Secret>, SecretError>> {
        Box::pin(async move {
            if let Some(s) = self.cached(name) {
                return Ok(s);
            }
            let read = self.source.read(ReadRequest {
                name: name.to_owned(),
                ..ReadRequest::default()
            });
            let got = match tokio::time::timeout(CALL, read).await {
                Ok(Ok(r)) => r.into_owned(),
                Ok(Err(e)) if e.code == ErrorCode::NotFound => return Err(SecretError::Absent),
                Ok(Err(e)) => {
                    // The code only: the driver's refusals name a field, and nothing here names a value.
                    tracing::warn!(code = e.code.as_str(), "secret source failed");
                    return Err(SecretError::Down);
                }
                Err(_) => {
                    tracing::warn!("secret source timed out");
                    return Err(SecretError::Down);
                }
            };
            if got.unchanged {
                // Nothing was held to be unchanged: a driver that says so is wrong.
                return Err(SecretError::Down);
            }
            let secret = Arc::new(Secret {
                data: got.data,
                version: got.version,
            });
            // Two first uses at once both read; the later write replaces an equal value.
            self.cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(name.to_owned(), Arc::clone(&secret));
            Ok(secret)
        })
    }
}
