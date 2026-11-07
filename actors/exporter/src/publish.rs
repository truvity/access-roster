//! The publication of one document (ADR 0009, "The order and the time"): after a change, in this order,
//!
//! 1. **write** the new document to the destination, whole (not at all when the destination already holds the same
//!    bytes with the same headers);
//! 2. **purge** its public address, so that the edge does not fill again with the old document;
//! 3. **read back** the public address the way a verifier does: it must answer 200 with the digest written;
//! 4. **report** by setting the temp kind `ExportReport` (REQ-EXPORT-021, REQ-EXPORT-022).
//!
//! A step that fails is tried again with a backoff until the budget of 60 seconds from the moment the change was seen
//! (REQ-EXPORT-028) is spent; past it the state is `purge-pending` (the document is written, the public address does
//! not show it yet) or `unverified` (the write itself failed), an alarm is raised once, and the caller tries again.
//! The state is `published` only when the read back returned the written digest, and `written` when the destination
//! has no public address to read back from.
//!
//! When the key set cannot be built because a kind cannot be read, nothing is written: the published object stays as it
//! is, an alarm is raised and the report says `unverified` (REQ-EXPORT-024).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use sluis_destination::{Destination, Document, Error, Purged, sha256_hex};
use sluis_proto::sluis::exporter::v2alpha1::ExportReport;

use crate::audit::{Auditor, Written};
use crate::config::Doc;
use crate::keyset;
use crate::state::{Read, Reports, stamp};

/// The time budget and the backoff of the steps.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// The write, the purge and the read back finish within this long of the moment the change was seen
    /// (REQ-EXPORT-028).
    pub budget: Duration,
    /// The first wait after a failed step.
    pub initial: Duration,
    /// The longest wait.
    pub max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(60),
            initial: Duration::from_millis(500),
            max: Duration::from_secs(8),
        }
    }
}

/// The state of a report (ADR 0009).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The read back from the public address returned the written digest.
    Published,
    /// Written, and the purge or the read back is being retried.
    PurgePending,
    /// Written, and the destination cannot read back.
    Written,
    /// `exporter` could not tell what the destination holds.
    Unverified,
}

impl State {
    /// The word of the report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::PurgePending => "purge-pending",
            Self::Written => "written",
            Self::Unverified => "unverified",
        }
    }
}

/// What a publication came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The state reported, or `None` when there was nothing to publish (no ring yet) or nothing changed.
    pub state: Option<State>,
    /// Whether the caller should try again soon.
    pub retry: bool,
}

#[derive(Clone, Debug)]
struct Last {
    state: State,
    sha256: String,
    written_at: Option<SystemTime>,
    purged_at: Option<SystemTime>,
}

/// What the publication needs besides the destination.
pub struct Publisher {
    reports: Reports,
    audit: Auditor,
    now: fn() -> SystemTime,
    timing: Timing,
    last: Mutex<HashMap<String, Last>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Publisher {
    /// A publisher.
    #[must_use]
    pub fn new(reports: Reports, audit: Auditor, now: fn() -> SystemTime, timing: Timing) -> Self {
        Self {
            reports,
            audit,
            now,
            timing,
            last: Mutex::new(HashMap::new()),
        }
    }

    /// Tries `op` again after a failure that may pass, with a doubling wait, until `deadline`.
    async fn retry<T, F, Fut>(&self, deadline: Instant, mut op: F) -> Result<T, Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, Error>>,
    {
        let mut wait = self.timing.initial;
        loop {
            match op().await {
                Ok(v) => return Ok(v),
                // What a retry cannot cure.
                Err(e @ (Error::Unsupported | Error::Invalid(_))) => return Err(e),
                Err(e) => {
                    if Instant::now() + wait >= deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(self.timing.max);
                }
            }
        }
    }

    /// The document at the destination, if it holds one.
    async fn find<D: Destination>(
        driver: &D,
        address: &str,
    ) -> Result<Option<sluis_destination::Listed>, Error> {
        let mut token: Option<String> = None;
        for _ in 0..100 {
            let page = driver.list(address, token.as_deref(), 0).await?;
            if let Some(d) = page.documents.into_iter().find(|d| d.address == address) {
                return Ok(Some(d));
            }
            match page.next {
                Some(t) => token = Some(t),
                None => return Ok(None),
            }
        }
        Err(Error::Unavailable("a listing that does not end".into()))
    }

    /// Publishes `doc` to the destination from what was read. `seen` is when the change that caused it was seen, and
    /// `force` runs the purge, the read back and the report even when nothing changed (the start and the daily
    /// reconcile).
    pub async fn publish<D: Destination>(
        &self,
        destination: &str,
        driver: &D,
        doc: &Doc,
        read: &Read,
        seen: Instant,
        force: bool,
    ) -> Outcome {
        let key = format!("{destination}/{}", doc.name);
        let snapshot = match read {
            Read::NoRing => {
                return Outcome {
                    state: None,
                    retry: false,
                };
            }
            Read::Unreadable(what) => {
                return self.unverified(destination, doc, &key, what, force).await;
            }
            Read::Snapshot(s) => s,
        };
        let built = keyset::build(&snapshot.ring, &snapshot.revoked);
        let sha256 = sha256_hex(&built.body);
        let deadline = seen + self.timing.budget;
        let before = lock(&self.last).get(&key).cloned();

        // 1. Write.
        let current = match self
            .retry(deadline, || Self::find(driver, &doc.address))
            .await
        {
            Ok(c) => c,
            Err(e) => {
                return self
                    .failed(destination, doc, &key, "list", &e, &sha256)
                    .await;
            }
        };
        let needs = current.as_ref().is_none_or(|c| {
            c.sha256 != sha256
                || c.content_type != doc.content_type
                || c.cache_control != doc.cache_control
        });
        let mut written_at = before.as_ref().and_then(|b| b.written_at);
        if needs {
            let put = || {
                driver.put(Document {
                    address: doc.address.clone(),
                    content_type: doc.content_type.clone(),
                    cache_control: doc.cache_control.clone(),
                    body: built.body.clone(),
                })
            };
            if let Err(e) = self.retry(deadline, put).await {
                return self
                    .failed(destination, doc, &key, "put", &e, &sha256)
                    .await;
            }
            written_at = Some((self.now)());
            self.audit
                .written(&Written {
                    destination,
                    document: &doc.name,
                    address: &doc.address,
                    sha256: &sha256,
                    kids: built.kids.len(),
                    replaced: current.is_some(),
                })
                .await;
        }
        let pending = before
            .as_ref()
            .is_some_and(|b| b.state == State::PurgePending || b.sha256 != sha256);
        if !needs && !force && !pending && before.is_some() {
            // Nothing changed and nothing is owed: an idle exporter writes nothing.
            return Outcome {
                state: None,
                retry: false,
            };
        }

        // 2 and 3. Purge the public address, read it back, and again until it shows the document or the budget ends.
        let mut purged_at = if needs {
            None
        } else {
            before.as_ref().and_then(|b| b.purged_at)
        };
        let mut read_back_at = None;
        let mut unsupported = doc.public_address.is_none();
        if let Some(url) = &doc.public_address {
            let mut wait = self.timing.initial;
            loop {
                match driver.purge(std::slice::from_ref(url)).await {
                    Ok(Purged::Purged) => purged_at = Some((self.now)()),
                    Ok(Purged::None) | Err(Error::Unsupported) => {}
                    Err(e) => {
                        tracing::warn!(destination, document = %doc.name, why = %e, "the purge failed; trying again")
                    }
                }
                match driver.read_back(url).await {
                    Ok(f) if f.status == 200 && sha256_hex(&f.body) == sha256 => {
                        read_back_at = Some((self.now)());
                        break;
                    }
                    Err(Error::Unsupported) => {
                        unsupported = true;
                        break;
                    }
                    Ok(f) => {
                        tracing::info!(destination, document = %doc.name, status = f.status, cache_state = %f.cache_state, "the public address does not show the document yet")
                    }
                    Err(e) => {
                        tracing::warn!(destination, document = %doc.name, why = %e, "the read back failed; trying again")
                    }
                }
                if Instant::now() + wait >= deadline {
                    break;
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(self.timing.max);
            }
        }
        let state = if unsupported {
            State::Written
        } else if read_back_at.is_some() {
            State::Published
        } else {
            State::PurgePending
        };
        if state == State::PurgePending
            && before
                .as_ref()
                .is_none_or(|b| b.state != State::PurgePending)
        {
            // ADR 0009: a step that is still failing past the budget raises an alarm.
            tracing::error!(alert = "exporter.publication_late", destination, document = %doc.name, state = state.as_str(), "the document is written and its public address does not show it");
        }
        let report = ExportReport {
            state: state.as_str().into(),
            address: doc.address.clone(),
            public_address: doc.public_address.clone().unwrap_or_default(),
            sha256: sha256.clone(),
            kids: built.kids,
            written_at: written_at.map(stamp).into(),
            purged_at: purged_at.map(stamp).into(),
            read_back_at: read_back_at.map(stamp).into(),
            public: doc.public_address.is_some() && state != State::Written,
            kind: crate::config::SIGNING_RING.into(),
            reported_at: stamp((self.now)()).into(),
            ..ExportReport::default()
        };
        let ok = self.set(destination, doc, &report).await;
        lock(&self.last).insert(
            key,
            Last {
                state,
                sha256,
                written_at,
                purged_at,
            },
        );
        Outcome {
            state: Some(state),
            retry: state == State::PurgePending || !ok,
        }
    }

    /// The key set could not be built: the object stays as it is, an alarm is raised, the report says `unverified`.
    async fn unverified(
        &self,
        destination: &str,
        doc: &Doc,
        key: &str,
        what: &str,
        force: bool,
    ) -> Outcome {
        let was = lock(&self.last).get(key).map(|l| l.state);
        if was != Some(State::Unverified) {
            tracing::error!(alert = "exporter.unverified", destination, document = %doc.name, unreadable = what, "a kind cannot be read: the published document is left as it is");
        }
        if was != Some(State::Unverified) || force {
            self.report_unverified(destination, doc, key).await;
        }
        Outcome {
            state: Some(State::Unverified),
            retry: true,
        }
    }

    /// A step failed past the budget and `exporter` cannot tell what the destination holds.
    async fn failed(
        &self,
        destination: &str,
        doc: &Doc,
        key: &str,
        step: &str,
        e: &Error,
        _sha: &str,
    ) -> Outcome {
        let was = lock(&self.last).get(key).map(|l| l.state);
        if was != Some(State::Unverified) {
            tracing::error!(alert = "exporter.publication_late", destination, document = %doc.name, step, why = %e, "the destination did not take the document within the budget");
        }
        self.report_unverified(destination, doc, key).await;
        Outcome {
            state: Some(State::Unverified),
            retry: true,
        }
    }

    /// Sets an `unverified` report and remembers it.
    pub async fn report_unverified(&self, destination: &str, doc: &Doc, key: &str) {
        let report = ExportReport {
            state: State::Unverified.as_str().into(),
            address: doc.address.clone(),
            public_address: doc.public_address.clone().unwrap_or_default(),
            public: doc.public_address.is_some(),
            kind: crate::config::SIGNING_RING.into(),
            reported_at: stamp((self.now)()).into(),
            ..ExportReport::default()
        };
        self.set(destination, doc, &report).await;
        lock(&self.last).insert(
            key.to_owned(),
            Last {
                state: State::Unverified,
                sha256: String::new(),
                written_at: None,
                purged_at: None,
            },
        );
    }

    /// Reports `unverified` for every document of a destination whose watch is interrupted (a change might go unseen).
    pub async fn watch_lost(&self, destination: &str, docs: &[Doc]) {
        for doc in docs {
            let key = format!("{destination}/{}", doc.name);
            let was = lock(&self.last).get(&key).map(|l| l.state);
            if was != Some(State::Unverified) {
                tracing::error!(alert = "exporter.unverified", destination, document = %doc.name, unreadable = "watch", "a change might go unseen: the published document is left as it is");
                self.report_unverified(destination, doc, &key).await;
            }
        }
    }

    async fn set(&self, destination: &str, doc: &Doc, r: &ExportReport) -> bool {
        match self.reports.set(destination, &doc.name, r).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(destination, document = %doc.name, why = %e, "the report could not be written; trying again");
                false
            }
        }
    }
}
