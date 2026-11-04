//! Where the policy comes from: the config kinds `Policy` and `GrantVocabulary`, read through
//! store@ (ADR 0007 "Cedar in a Rust actor"), and the reload that swaps a new set in.
//!
//! store@ has verified the signature of each config document before it serves it (ADR 0005
//! "Configuration loading"). `policy` validates what it is given again against the schema, and
//! refuses a set as a whole: a set that fails leaves the one in force in force.
//!
//! The first working version has no `Watch` (decision D-18), so a reload is a poll: the kinds are
//! read again every [`RELOAD_EVERY`] and the set is rebuilt only when what was read changed.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sluis_kit::Client;
use sluis_proto::sluis::config::v2alpha1 as pb;
use sluis_store::{Error, Kind, Store};

use crate::audit;
use crate::engine::{Engine, Inputs, LoadError, PolicyDoc};
use crate::service::Service;

/// How often the config kinds are read again.
pub const RELOAD_EVERY: Duration = Duration::from_secs(30);
/// The most pages of the `Policy` kind that are read: a kind of more is not a policy, it is a fault.
const PAGES_MAX: usize = 64;

/// The config kind `Policy`: one Cedar file, the id is the file's id.
pub struct PolicyKind;

impl Kind for PolicyKind {
    type Id = String;
    type Value = pb::Policy;
    const NAME: &'static str = "Policy";
}

/// The config kind `GrantVocabulary`: one item, `default`.
pub struct VocabularyKind;

impl Kind for VocabularyKind {
    type Id = String;
    type Value = pb::GrantVocabulary;
    const NAME: &'static str = "GrantVocabulary";
}

/// Why the kinds could not be read: store@ is down, has no such document, or answered something
/// that is not the kind. Never a decision to run without.
#[derive(Debug)]
pub struct Unavailable(pub String);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unavailable {}

/// The store, as `policy` reads the policy documents from it.
pub struct StoreSource {
    boundary: String,
    policies: Store<PolicyKind>,
    vocabulary: Store<VocabularyKind>,
}

fn failed(what: &str, e: &Error) -> Unavailable {
    Unavailable(format!("{what}: {e}"))
}

impl StoreSource {
    /// A source over store@ at the socket of `client`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownKind`] when the registry lacks a kind: a build whose registry changed.
    pub fn new(client: &Client, boundary: &str) -> Result<Self, Error> {
        Ok(Self {
            boundary: boundary.to_owned(),
            policies: Store::new(client.clone())?,
            vocabulary: Store::new(client.clone())?,
        })
    }

    /// Reads the vocabulary and every `Policy` item.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when store@ does not serve them. A boundary with no `Policy` item is a set of
    /// the built-in layer alone, which is valid; a boundary with no vocabulary is not.
    pub async fn fetch(&self) -> Result<Inputs, Unavailable> {
        let vocab = self
            .vocabulary
            .get("", "default")
            .await
            .map_err(|e| failed("GrantVocabulary", &e))?;
        let mut policies = Vec::new();
        let mut page = None;
        for _ in 0..PAGES_MAX {
            let (items, next) = self
                .policies
                .list("", page.take())
                .await
                .map_err(|e| failed("Policy", &e))?;
            policies.extend(items.into_iter().map(|i| PolicyDoc {
                file: i.id,
                cedar: i.value.cedar,
            }));
            match next {
                Some(t) => page = Some(t),
                None => {
                    return Ok(Inputs {
                        boundary: self.boundary.clone(),
                        policies,
                        vocabulary: vocab.value.document,
                        // planned: the links of the operator and tenant layers (PolicyLink,
                        // PredefinedPolicyLink) come with their first writer, exchange (#892).
                        links: Vec::new(),
                    });
                }
            }
        }
        Err(Unavailable("Policy: more pages than a policy has".into()))
    }
}

/// What one pass of the reload did.
#[derive(Debug)]
pub enum Reloaded {
    /// What was read is what is in force, or what was already refused.
    Unchanged,
    /// A new set is in force, with this digest.
    Applied(String),
    /// The set was refused; the one in force stays.
    Refused(LoadError),
    /// The kinds could not be read; the set in force stays.
    Unavailable(Unavailable),
}

/// Keeps the service's engine current.
pub struct Reloader {
    source: StoreSource,
    service: Arc<Service>,
    /// The fingerprint of the inputs last built or last refused, so a bad set is reported once.
    last: Mutex<String>,
}

impl Reloader {
    /// A reloader for a service that started with `started` as its inputs.
    #[must_use]
    pub fn new(source: StoreSource, service: Arc<Service>, started: &Inputs) -> Self {
        Self {
            source,
            service,
            last: Mutex::new(started.fingerprint()),
        }
    }

    /// One pass: read, and if it changed, build and swap, or refuse.
    pub async fn once(&self) -> Reloaded {
        let inputs = match self.source.fetch().await {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(why = %e, "the policy could not be read again; the set in force stays");
                return Reloaded::Unavailable(e);
            }
        };
        let fp = inputs.fingerprint();
        if *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == fp
        {
            return Reloaded::Unchanged;
        }
        let count = inputs.policies.len();
        let outcome = match Engine::build_on_stack(&inputs).await {
            Ok(engine) => {
                let digest = engine.digest().to_owned();
                self.service.swap(engine);
                if let Err(e) = self
                    .service
                    .emitter()
                    .emit(audit::reloaded(&digest, count))
                    .await
                {
                    tracing::error!(code = e.code.as_str(), "the reload could not be audited");
                }
                Reloaded::Applied(digest)
            }
            Err(why) => {
                let in_force = self.service.engine().digest().to_owned();
                tracing::error!(faults = %why, "a policy set was refused; the set in force stays");
                if let Err(e) = self
                    .service
                    .emitter()
                    .emit(audit::reload_refused(&in_force, &why))
                    .await
                {
                    tracing::error!(code = e.code.as_str(), "the refusal could not be audited");
                }
                Reloaded::Refused(why)
            }
        };
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = fp;
        outcome
    }

    /// Reads again every `every`, for ever.
    pub async fn run(&self, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let _ = self.once().await;
        }
    }
}
