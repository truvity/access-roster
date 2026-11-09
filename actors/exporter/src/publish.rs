//! The publication of one document (ADR 0009, "The order and the time"): after a change, in this order,
//!
//! 1. **write** the new document to the destination, whole (not at all when the destination already holds the same
//!    bytes with the same headers);
//! 2. **purge** its public address, so that the edge does not fill again with the old document;
//! 3. **read back** the public address the way a verifier does: it must answer 200 with the digest written;
//! 4. **report** by setting the temp kind `ExportReport` (REQ-EXPORT-021, REQ-EXPORT-022).
//!
//! A step that fails is tried again with a backoff until the budget of 60 seconds from the moment the change arrived
//! (REQ-EXPORT-028) is spent; past it the state is `purge-pending` (the document is written, the public address does
//! not show it yet) or `unverified` (the write itself failed), and the caller tries again. The state is `published` only
//! when the purge was accepted (or there is no edge to purge) **and** the read back then returned the written digest: a
//! read back after a purge that failed proves nothing about the other copies of the edge. It is `written` when the
//! destination has no public address to read back from.
//!
//! When the key set cannot be built because a kind cannot be read, the published object is left as it is and the report
//! says `unverified` (REQ-EXPORT-024). The one change made then is a **removal**: a `kid` that a `KeyRevocation` event
//! has just named is taken out of the last good document, because removal is monotone (no revocation can put a key
//! back), so it needs nothing that cannot be read. The state stays `unverified`, as the rest of the list is unknown.
//!
//! `unverified` and `purge-pending` are alarms: an error line that repeats every `alert_every` while they last (a
//! revoked key may still be published, and a log line that was written once at the start of a long outage is read by no
//! one), with the number of documents in that state, and one audit fact for each transition into and out of it.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use sluis_destination::{Destination, Document, Error, Purged, sha256_hex};
use sluis_proto::sluis::exporter::v2alpha1::ExportReport;

use crate::audit::{Auditor, Written};
use crate::config::Doc;
use crate::keyset::{self, Built};
use crate::state::{Read, Reports, stamp};

/// The time budget and the backoff of the steps.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// The write, the purge and the read back finish within this long of the moment the change arrived
    /// (REQ-EXPORT-028).
    pub budget: Duration,
    /// The first wait after a failed step.
    pub initial: Duration,
    /// The longest wait.
    pub max: Duration,
    /// The longest one call to the destination may take: a driver that hangs is an error like any other, and does not
    /// hold the publication past its budget.
    pub call: Duration,
    /// How often the alarm of a document that stays `unverified` or `purge-pending` is raised again.
    pub alert_every: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(60),
            initial: Duration::from_millis(500),
            max: Duration::from_secs(8),
            call: Duration::from_secs(20),
            alert_every: Duration::from_secs(300),
        }
    }
}

/// The state of a report (ADR 0009).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The purge was accepted (or there is no edge) and the read back then returned the written digest.
    Published,
    /// Written, and the purge or the read back is being retried.
    PurgePending,
    /// Written, and the destination has no public address to read back from.
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
    /// The report was stored. A report that could not be stored is owed, whatever else is unchanged.
    reported: bool,
}

/// A document a failed `put` was to write, and what the destination held before it.
#[derive(Clone, Debug)]
struct Unanswered {
    sha256: String,
    content_type: String,
    cache_control: String,
    kids: usize,
    /// The destination held a document at the address.
    replaced: bool,
}

/// What the publication needs besides the destination.
pub struct Publisher {
    reports: Reports,
    audit: Auditor,
    now: fn() -> SystemTime,
    timing: Timing,
    last: Mutex<HashMap<String, Last>>,
    /// The last document known to be at the destination, by `<destination>/<document>`: what a removal trims.
    good: Mutex<HashMap<String, Vec<u8>>>,
    /// Every kid this process has been told is revoked, by a listing or by an event, and never forgotten: a trim subtracts
    /// all of them from the last good document, which may be older than the destination (a `put` that timed out may have
    /// landed), so that it cannot bring back a key that an earlier cycle took out.
    revoked: Mutex<HashSet<String>>,
    /// What a `put` that failed was to write, by `<destination>/<document>`: the call may have landed though its answer did
    /// not come (a timeout). When a later pass finds all of it at the destination (the digest and both headers, none of
    /// which the destination held before) the write is made a fact then, also when the pass is about to write over it, so
    /// that no write is left without one.
    unanswered: Mutex<HashMap<String, Unanswered>>,
    /// When the alarm of a document was last raised.
    alerted: Mutex<HashMap<String, Instant>>,
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
            good: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
            unanswered: Mutex::new(HashMap::new()),
            alerted: Mutex::new(HashMap::new()),
        }
    }

    /// How many documents are `unverified` now: the gauge behind the repeated alarm.
    #[must_use]
    pub fn unverified_documents(&self) -> usize {
        lock(&self.last)
            .values()
            .filter(|l| l.state == State::Unverified)
            .count()
    }

    /// Whether the alarm of this document is due: at the first time, and then every `alert_every`.
    fn alert_due(&self, key: &str) -> bool {
        let mut a = lock(&self.alerted);
        let now = Instant::now();
        match a.get(key) {
            Some(t) if now.duration_since(*t) < self.timing.alert_every => false,
            _ => {
                a.insert(key.to_owned(), now);
                true
            }
        }
    }

    fn alert_over(&self, key: &str) {
        lock(&self.alerted).remove(key);
    }

    /// One call to the destination, bounded by [`Timing::call`].
    async fn call<T>(&self, f: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
        tokio::time::timeout(self.timing.call, f)
            .await
            .unwrap_or_else(|_| Err(Error::Unavailable("the call timed out".into())))
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
        &self,
        driver: &D,
        address: &str,
    ) -> Result<Option<sluis_destination::Listed>, Error> {
        let mut token: Option<String> = None;
        for _ in 0..100 {
            let page = self.call(driver.list(address, token.as_deref(), 0)).await?;
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

    /// Records what is now known of a document, and makes the audit fact of a transition into or out of `unverified`
    /// (one for each, never for a repeat).
    async fn remember(&self, destination: &str, doc: &Doc, key: &str, new: Last, reason: &str) {
        let now = new.state;
        let prev = lock(&self.last).insert(key.to_owned(), new);
        let was = prev.is_some_and(|l| l.state == State::Unverified);
        if now == State::Unverified && !was {
            self.audit
                .unverified(destination, &doc.name, Some(reason))
                .await;
        } else if now != State::Unverified && was {
            self.audit.unverified(destination, &doc.name, None).await;
        }
    }

    /// Publishes `doc` to the destination from what was read. `seen` is when the change that caused it arrived, `force`
    /// runs the purge, the read back and the report even when nothing changed (the start and the daily reconcile), and
    /// `removed` are the kids a `KeyRevocation` event named that the caller has not seen in a listing yet: they are all
    /// that is done when the listings cannot be read.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish<D: Destination>(
        &self,
        destination: &str,
        driver: &D,
        doc: &Doc,
        read: &Read,
        removed: &HashSet<String>,
        seen: Instant,
        force: bool,
    ) -> Outcome {
        let key = format!("{destination}/{}", doc.name);
        {
            let mut known = lock(&self.revoked);
            known.extend(removed.iter().cloned());
            match read {
                Read::Snapshot(s) => known.extend(s.revoked.iter().cloned()),
                Read::Unreadable(_, r) => known.extend(r.iter().cloned()),
                Read::NoRing => {}
            }
        }
        match read {
            Read::NoRing => Outcome {
                state: None,
                retry: false,
            },
            Read::Unreadable(what, _) => {
                self.unreadable(destination, driver, doc, &key, what, seen, force)
                    .await
            }
            Read::Snapshot(snapshot) => {
                let built = keyset::build(&snapshot.ring, &snapshot.revoked);
                self.deliver(destination, driver, doc, &key, &built, seen, force, None)
                    .await
            }
        }
    }

    /// The listings cannot be read. If the last good document lists a kid that this process knows to be revoked (named by
    /// an event, or seen in a listing at any time), that one document is written without it; otherwise nothing is written. Either way the state is `unverified`.
    #[allow(clippy::too_many_arguments)]
    async fn unreadable<D: Destination>(
        &self,
        destination: &str,
        driver: &D,
        doc: &Doc,
        key: &str,
        what: &'static str,
        seen: Instant,
        force: bool,
    ) -> Outcome {
        let removed = lock(&self.revoked).clone();
        if !removed.is_empty() {
            let good = lock(&self.good).get(key).cloned();
            if let Some(trimmed) = good.and_then(|g| keyset::without_kids(&g, &removed)) {
                tracing::error!(destination, document = %doc.name, removed = removed.len(), unreadable = what, "a revoked key is taken out of the published document; the rest cannot be read");
                return self
                    .deliver(
                        destination,
                        driver,
                        doc,
                        key,
                        &trimmed,
                        seen,
                        true,
                        Some(what),
                    )
                    .await;
            }
        }
        self.unverified(destination, doc, key, what, force).await
    }

    /// Writes `built` to the destination if it is not there, purges, reads back and reports. With `degraded` the
    /// document is delivered the same way and the state is `unverified` at the end, for the reason named.
    #[allow(clippy::too_many_arguments)]
    async fn deliver<D: Destination>(
        &self,
        destination: &str,
        driver: &D,
        doc: &Doc,
        key: &str,
        built: &Built,
        seen: Instant,
        force: bool,
        degraded: Option<&'static str>,
    ) -> Outcome {
        let sha256 = sha256_hex(&built.body);
        let deadline = seen + self.timing.budget;
        let before = lock(&self.last).get(key).cloned();

        // 1. Write.
        let current = match self
            .retry(deadline, || self.find(driver, &doc.address))
            .await
        {
            Ok(c) => c,
            Err(e) => {
                return self.failed(destination, doc, key, "list", &e).await;
            }
        };
        let needs = current.as_ref().is_none_or(|c| {
            c.sha256 != sha256
                || c.content_type != doc.content_type
                || c.cache_control != doc.cache_control
        });
        let mut written_at = before.as_ref().and_then(|b| b.written_at);
        // A put that failed to answer and had landed is a write: the fact is made now that the destination shows it.
        // What the destination shows must be all of what the put was to write: the digest and the headers (a put that
        // changes only a header leaves the digest as it was), and `needs` was true when it was tried, so the destination
        // did not show it then.
        let landed = lock(&self.unanswered).remove(key).filter(|u| {
            current.as_ref().is_some_and(|c| {
                c.sha256 == u.sha256
                    && c.content_type == u.content_type
                    && c.cache_control == u.cache_control
            })
        });
        if let Some(u) = &landed {
            self.audit
                .written(&Written {
                    destination,
                    document: &doc.name,
                    address: &doc.address,
                    sha256: &u.sha256,
                    kids: u.kids,
                    replaced: u.replaced,
                })
                .await;
        }
        if needs {
            let put = || {
                self.call(driver.put(Document {
                    address: doc.address.clone(),
                    content_type: doc.content_type.clone(),
                    cache_control: doc.cache_control.clone(),
                    body: built.body.clone(),
                }))
            };
            if let Err(e) = self.retry(deadline, put).await {
                lock(&self.unanswered).insert(
                    key.to_owned(),
                    Unanswered {
                        sha256: sha256.clone(),
                        content_type: doc.content_type.clone(),
                        cache_control: doc.cache_control.clone(),
                        kids: built.kids.len(),
                        replaced: current.is_some(),
                    },
                );
                return self.failed(destination, doc, key, "put", &e).await;
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
        } else if landed.is_some() {
            // The destination shows the very document an earlier put wrote without an answer.
            written_at = Some((self.now)());
        }
        // The destination holds this document now: it is what a later removal trims.
        lock(&self.good).insert(key.to_owned(), built.body.clone());
        // Owed: a purge or a read back that is not over, a document that is not the one last reported, a report that was
        // not stored, and a state of `unverified`, which only a pass that reads everything again ends (a document that
        // was trimmed to a revoked kid has the digest of the whole one when nothing else changed).
        let pending = before.as_ref().is_some_and(|b| {
            matches!(b.state, State::PurgePending | State::Unverified)
                || b.sha256 != sha256
                || !b.reported
        });
        if !needs && !force && !pending && degraded.is_none() && before.is_some() {
            // Nothing changed and nothing is owed: an idle exporter writes nothing.
            return Outcome {
                state: None,
                retry: false,
            };
        }

        // 2 and 3. Purge the public address, read it back, and again until it shows the document or the budget ends. A
        // read back counts only after a purge that was accepted (or where there is no edge): one that failed leaves the
        // other copies of the edge unchecked.
        let mut purged_at = if needs {
            None
        } else {
            before.as_ref().and_then(|b| b.purged_at)
        };
        let mut read_back_at = None;
        let mut read_back_unsupported = false;
        if let Some(url) = &doc.public_address {
            let mut wait = self.timing.initial;
            loop {
                let purged = match self.call(driver.purge(std::slice::from_ref(url))).await {
                    Ok(Purged::Purged) => {
                        purged_at = Some((self.now)());
                        true
                    }
                    Ok(Purged::None) | Err(Error::Unsupported) => true,
                    Err(e) => {
                        tracing::warn!(destination, document = %doc.name, why = %e, "the purge failed; trying again");
                        false
                    }
                };
                if purged {
                    match self.call(driver.read_back(url)).await {
                        Ok(f) if f.status == 200 && sha256_hex(&f.body) == sha256 => {
                            read_back_at = Some((self.now)());
                            break;
                        }
                        Err(Error::Unsupported) => {
                            read_back_unsupported = true;
                            break;
                        }
                        Ok(f) => {
                            tracing::info!(destination, document = %doc.name, status = f.status, cache_state = %f.cache_state, "the public address does not show the document yet");
                        }
                        Err(e) => {
                            tracing::warn!(destination, document = %doc.name, why = %e, "the read back failed; trying again");
                        }
                    }
                }
                if Instant::now() + wait >= deadline {
                    break;
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(self.timing.max);
            }
        }
        let (state, reason) = if let Some(why) = degraded {
            (State::Unverified, why)
        } else if doc.public_address.is_none() {
            (State::Written, "")
        } else if read_back_unsupported {
            // The check refuses this pairing; a driver that answers so anyway is a fault to see, not a state to trust.
            (State::Unverified, "read_back_unsupported")
        } else if read_back_at.is_some() {
            (State::Published, "")
        } else {
            (State::PurgePending, "")
        };
        match state {
            State::PurgePending | State::Unverified => {
                if self.alert_due(key) {
                    tracing::error!(alert = if state == State::Unverified { "exporter.unverified" } else { "exporter-publication-late" }, destination, document = %doc.name, state = state.as_str(), reason, unverified_documents = self.unverified_documents() + usize::from(state == State::Unverified), "the published document may not be what a verifier gets");
                }
            }
            State::Published | State::Written => self.alert_over(key),
        }
        let report = ExportReport {
            state: state.as_str().into(),
            address: doc.address.clone(),
            public_address: doc.public_address.clone().unwrap_or_default(),
            sha256: sha256.clone(),
            kids: built.kids.clone(),
            written_at: written_at.map(stamp).into(),
            purged_at: purged_at.map(stamp).into(),
            read_back_at: read_back_at.map(stamp).into(),
            public: doc.public_address.is_some(),
            kind: crate::config::SIGNING_RING.into(),
            reported_at: stamp((self.now)()).into(),
            ..ExportReport::default()
        };
        let ok = self.set(destination, doc, &report).await;
        self.remember(
            destination,
            doc,
            key,
            Last {
                state,
                sha256,
                written_at,
                purged_at,
                reported: ok,
            },
            reason,
        )
        .await;
        Outcome {
            state: Some(state),
            retry: matches!(state, State::PurgePending | State::Unverified) || !ok,
        }
    }

    /// The key set could not be built: the object stays as it is, an alarm is raised (and again while it lasts), the
    /// report says `unverified`.
    async fn unverified(
        &self,
        destination: &str,
        doc: &Doc,
        key: &str,
        what: &'static str,
        force: bool,
    ) -> Outcome {
        let was = lock(&self.last).get(key).map(|l| (l.state, l.reported));
        if self.alert_due(key) {
            tracing::error!(alert = "exporter.unverified", destination, document = %doc.name, unreadable = what, unverified_documents = self.unverified_documents(), "a kind cannot be read: the published document is left as it is");
        }
        let owed = !matches!(was, Some((State::Unverified, true)));
        if owed || force {
            self.report_unverified(destination, doc, key, what).await;
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
        step: &'static str,
        e: &Error,
    ) -> Outcome {
        if self.alert_due(key) {
            tracing::error!(alert = "exporter-publication-late", destination, document = %doc.name, step, why = %e, unverified_documents = self.unverified_documents(), "the destination did not take the document within the budget");
        }
        let was = lock(&self.last).get(key).map(|l| (l.state, l.reported));
        if !matches!(was, Some((State::Unverified, true))) {
            self.report_unverified(destination, doc, key, step).await;
        }
        Outcome {
            state: Some(State::Unverified),
            retry: true,
        }
    }

    /// Sets an `unverified` report. The state is remembered only when the report was stored: until then it is still owed,
    /// and a `published` report that stayed in the store would say something that is no longer known to be true. Returns
    /// whether it was stored.
    pub async fn report_unverified(
        &self,
        destination: &str,
        doc: &Doc,
        key: &str,
        reason: &str,
    ) -> bool {
        let report = ExportReport {
            state: State::Unverified.as_str().into(),
            address: doc.address.clone(),
            public_address: doc.public_address.clone().unwrap_or_default(),
            public: doc.public_address.is_some(),
            kind: crate::config::SIGNING_RING.into(),
            reported_at: stamp((self.now)()).into(),
            ..ExportReport::default()
        };
        if !self.set(destination, doc, &report).await {
            return false;
        }
        self.remember(
            destination,
            doc,
            key,
            Last {
                state: State::Unverified,
                sha256: String::new(),
                written_at: None,
                purged_at: None,
                reported: true,
            },
            reason,
        )
        .await;
        true
    }

    /// Reports `unverified` for every document of a destination whose watch is interrupted (a change might go unseen).
    /// Returns whether every report was stored; the caller tries again until it was.
    pub async fn watch_lost(&self, destination: &str, docs: &[Doc]) -> bool {
        let mut all = true;
        for doc in docs {
            let key = format!("{destination}/{}", doc.name);
            let was = lock(&self.last).get(&key).map(|l| (l.state, l.reported));
            if self.alert_due(&key) {
                tracing::error!(alert = "exporter.unverified", destination, document = %doc.name, unreadable = "watch", unverified_documents = self.unverified_documents(), "a change might go unseen: the published document is left as it is");
            }
            if !matches!(was, Some((State::Unverified, true)))
                && !self
                    .report_unverified(destination, doc, &key, "watch")
                    .await
            {
                all = false;
            }
        }
        all
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
