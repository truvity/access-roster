//! The loop and the command line of `exporter`: `serve`, `check`, `version` (cli.md).
//!
//! `exporter` serves no socket. It follows `SigningRing` and `KeyRevocation` in two tasks (the watch helper of the
//! store client, from the resume point in `ExportCursor`) and a **dispatcher** turns what they say into one nudge to a
//! **worker for each destination**. A worker reads both kinds linearizably, for itself, and publishes its destination's
//! documents ([`crate::publish`]). One task for each destination keeps a destination that hangs from delaying a
//! revocation reaching a healthy one: each reads what is true when it wakes, and each has its own budget of 60 seconds
//! counted from the moment the change *arrived* at the dispatcher (REQ-EXPORT-028), not from the moment a busy loop got
//! to it. Events are coalesced: any number of them while a worker is busy are one more round. The events say *when*,
//! never *what*: a missed or repeated event cannot make the document wrong, only late, and the daily reconcile bounds
//! how late.
//!
//! - **Start.** Write the manifest (what is configured, for `signer`), remove the reports of what is not configured any
//!   more, then reconcile at once: read, compare with the destination, write what differs, purge, read back, report.
//! - **A change.** The same, as soon as the event arrives.
//! - **Watch.** The helper's positions are used as it gives them: a point goes to `ExportCursor` as the helper delivered
//!   it, and the start from it is the helper's `from`. A `Resync` *replaces* the held point (a restore can take the log
//!   back), a change only moves it forward. A point is the pair of the epoch of the log and the sequence in it, saved whole in `ExportCursor`; a cursor without an epoch is no point and the kind is listed again. A point the store no longer holds
//!   is a `Resync` and a full read, so a stale cursor costs a reconcile and never a skipped change. The document never
//!   comes from the watch's state, only from the linearizable listings read after it, so a watch that is behind can
//!   delay a publication and cannot make one wrong. The cursor is saved only while both follows are confirmed.
//! - **A watch that breaks.** A change might go unseen: the documents are reported `unverified` (until the report is
//!   stored), and the watch reconnects by itself. Each kind is confirmed again by its own caught-up claim or resync, and by
//!   nothing weaker: a change or a bookmark of a stream that is still catching up says nothing about the rows still to
//!   come. The other kind's events say nothing about it.
//! - **A kid in an event.** A revocation event names the kid. If the listings cannot be read, that kid is still taken out
//!   of the last good document (removal is monotone), and nothing else is changed.
//! - **A step that fails.** Tried again every `retry` until it passes; the report says `purge-pending` or `unverified`.
//! - **Once a day.** A full reconcile, which also refreshes the reports so that none expires while `exporter` runs.
//! - **Stop.** A stop is not held up by a call that hangs: every worker is cancelled, and a document is only ever
//!   replaced whole by the driver.

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::bail;
use clap::{Arg, Command};
use sluis_audit::Config as AuditConfig;
use sluis_destination::Destination;
use sluis_destination::rpc::Client as DriverClient;
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Client, dial};
use sluis_proto::sluis::exporter::v2alpha1::export_manifest::Entry;
use sluis_store::{Backoff, Event, Kind, ResumePoint, Watch, WatchOpts};
use tokio::sync::{Notify, mpsc, watch};

use crate::audit::Auditor;
use crate::config::{self, Doc, Refused as DocRefused, Sockets};
use crate::publish::{Publisher, Timing};
use crate::state::{Cursors, Manifest, Points, Read, Reports, Source, usable};

/// The default time between full reconciles.
pub const RECONCILE: Duration = Duration::from_secs(24 * 60 * 60);
/// The default wait before a publication that is not finished is tried again.
pub const RETRY: Duration = Duration::from_secs(15);
/// How long a watch that ended with an error waits before it starts again (and lists again).
const RESTART: Duration = Duration::from_secs(5);
/// How long one attempt to reach a socket may take.
const REACH: Duration = Duration::from_secs(2);
/// How long the workers get to stop after a stop was asked for.
const STOP: Duration = Duration::from_secs(5);

/// A destination with its driver.
pub struct Target<D> {
    /// Its name.
    pub name: String,
    /// The driver.
    pub driver: D,
    /// The documents to publish to it.
    pub documents: Vec<Doc>,
}

/// What an [`Engine`] needs.
pub struct EngineConfig<D> {
    /// The boundary.
    pub boundary: String,
    /// store@'s socket.
    pub store: PathBuf,
    /// The audit emitter.
    pub audit: AuditConfig,
    /// The destinations.
    pub targets: Vec<Target<D>>,
    /// The documents the check refused.
    pub refused: Vec<DocRefused>,
    /// The time between full reconciles.
    pub reconcile: Duration,
    /// The wait before an unfinished publication is tried again.
    pub retry: Duration,
    /// The budget and backoff of a publication.
    pub timing: Timing,
    /// The backoff of the watches.
    pub backoff: Backoff,
    /// The clock.
    pub now: fn() -> SystemTime,
}

/// What a watch tells the dispatcher.
#[derive(Debug)]
enum Sig {
    /// The kind was listed again (the start, or a point the store no longer holds): the point *replaces* the held one.
    /// The kids are those of every item of a revocation listing.
    Resync(ResumePoint, Vec<String>),
    /// A change, with the kid it names if it is a revocation.
    Change(ResumePoint, Vec<String>),
    /// An idle stream.
    Bookmark,
    /// The stream is caught up (the first claim, or a renewal): the state holds what was committed before it.
    CaughtUp,
    /// The stream broke and will reconnect.
    Interrupted(String, u32),
    /// The watch ended with an error and will start again.
    Ended(String),
}

#[derive(Debug)]
enum Msg {
    Ring(Sig),
    Revocation(Sig),
}

/// The kid a revocation item names, if it names one.
fn revoked_kid(v: &sluis_proto::sluis::key::v2alpha1::KeyRevocation) -> Option<String> {
    (v.target_kind == sluis_store::revocation::TARGET_KID && !v.target.is_empty())
        .then(|| v.target.clone())
}

fn sig<K: Kind>(ev: Event<K>, kid: fn(&K::Value) -> Option<String>) -> Sig {
    match ev {
        Event::Resync {
            resume_point,
            items,
            ..
        } => Sig::Resync(
            resume_point,
            items.iter().filter_map(|i| kid(&i.value)).collect(),
        ),
        Event::Put {
            resume_point, item, ..
        } => Sig::Change(resume_point, kid(&item.value).into_iter().collect()),
        Event::Delete { resume_point, .. } => Sig::Change(resume_point, Vec::new()),
        Event::Bookmark { .. } => Sig::Bookmark,
        Event::CaughtUp { .. } => Sig::CaughtUp,
        Event::Interrupted { reason, attempt } => Sig::Interrupted(reason, attempt),
    }
}

/// Follows one kind until the receiver is gone, starting the watch again after an error that ended it.
async fn follow<K: Kind + Send + 'static>(
    make: impl Fn(Option<ResumePoint>) -> Result<Watch<K>, sluis_store::Error> + Send + 'static,
    from: Option<ResumePoint>,
    tx: mpsc::Sender<Msg>,
    wrap: fn(Sig) -> Msg,
    kid: fn(&K::Value) -> Option<String>,
) where
    K::Value: Send,
{
    let mut from = from;
    loop {
        let mut w = match make(from.take()) {
            Ok(w) => w,
            Err(e) => {
                if tx.send(wrap(Sig::Ended(e.to_string()))).await.is_err() {
                    return;
                }
                tokio::time::sleep(RESTART).await;
                continue;
            }
        };
        loop {
            match w.next().await {
                Ok(ev) => {
                    if tx.send(wrap(sig(ev, kid))).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    if tx.send(wrap(Sig::Ended(e.to_string()))).await.is_err() {
                        return;
                    }
                    break;
                }
            }
        }
        tokio::time::sleep(RESTART).await;
    }
}

/// What the dispatcher has asked of a worker since it last looked.
#[derive(Default)]
struct Ask {
    /// A round is wanted.
    dirty: bool,
    /// The round also purges, reads back and reports when nothing changed.
    force: bool,
    /// When the earliest change not yet served arrived.
    seen: Option<Instant>,
    /// A watch broke: report `unverified`.
    lost: bool,
    /// Kids named by revocation events.
    removed: HashSet<String>,
}

/// The nudge to one worker: what was asked, and a wake-up. `Notify` keeps one permit, so a nudge made while the worker
/// is busy is not lost, and many are one.
#[derive(Default)]
struct Wake {
    ask: Mutex<Ask>,
    bell: Notify,
}

impl Wake {
    /// `look` asks for a round (a change, a confirmed watch, the reconcile); without it the nudge only carries the rest, as
    /// a watch that broke does: it says nothing about what is published, so nothing is read for it.
    fn poke(&self, look: bool, force: bool, lost: bool, removed: &[String]) {
        {
            let mut a = self
                .ask
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if look && !a.dirty {
                a.dirty = true;
                a.seen = Some(Instant::now());
            }
            a.force |= force;
            a.lost |= lost;
            a.removed.extend(removed.iter().cloned());
        }
        self.bell.notify_one();
    }

    fn take(&self) -> Ask {
        std::mem::take(
            &mut *self
                .ask
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// What the dispatcher and the workers share.
#[derive(Default)]
struct Shared {
    points: Mutex<Points>,
    /// For each kind (the ring, then the revocations): the follow is not confirmed since it broke.
    unconfirmed: [AtomicBool; 2],
}

impl Shared {
    fn points(&self) -> Points {
        *self
            .points
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn any_unconfirmed(&self) -> bool {
        self.unconfirmed.iter().any(|u| u.load(Ordering::SeqCst))
    }
}

struct Inner<D> {
    targets: Vec<Target<D>>,
    refused: Vec<DocRefused>,
    audit: Auditor,
    source: Source,
    cursors: Cursors,
    reports: Reports,
    manifest: Manifest,
    publisher: Publisher,
    reconcile: Duration,
    retry: Duration,
    now: fn() -> SystemTime,
    shared: Shared,
}

/// The engine: the follow, the dispatcher, a worker for each destination, over any destination driver.
pub struct Engine<D> {
    store: Client,
    backoff: Backoff,
    inner: Arc<Inner<D>>,
}

/// Moves a held point to the one of a change: forward inside an epoch, never back; a point of another epoch is not ordered
/// against the held one (a sequence means something only inside its epoch), and it is the log the stream is on now.
fn advance(held: &mut ResumePoint, p: ResumePoint) {
    if p.epoch != held.epoch || p.sequence > held.sequence {
        *held = p;
    }
}

/// Resolves when a stop was asked for, or the sender is gone.
async fn stopped(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

impl<D: Destination + 'static> Engine<D> {
    /// Builds the engine; nothing is dialled until the first call.
    ///
    /// # Errors
    ///
    /// When a kind is not in the registry or the emitter is refused.
    pub fn new(c: EngineConfig<D>) -> anyhow::Result<Self> {
        let store = dial(&c.store);
        let audit = Auditor::new(c.audit)?;
        let map = |e: sluis_store::Error| anyhow::anyhow!("{e}");
        let reports = Reports::new(&store).map_err(map)?;
        let inner = Inner {
            source: Source::new(&store).map_err(map)?,
            cursors: Cursors::new(&store).map_err(map)?,
            manifest: Manifest::new(&store).map_err(map)?,
            publisher: Publisher::new(reports.clone(), audit.clone(), c.now, c.timing),
            reports,
            targets: c.targets,
            refused: c.refused,
            audit,
            reconcile: c.reconcile,
            retry: c.retry,
            now: c.now,
            shared: Shared::default(),
        };
        Ok(Self {
            store,
            backoff: c.backoff,
            inner: Arc::new(inner),
        })
    }

    /// Runs until `shutdown` resolves.
    ///
    /// # Errors
    ///
    /// When a watch cannot be built at all.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
        tokio::pin!(shutdown);
        let inner = Arc::clone(&self.inner);
        let documents: usize = inner.targets.iter().map(|t| t.documents.len()).sum();
        inner
            .audit
            .started(inner.targets.len(), documents, inner.refused.len())
            .await;
        for r in &inner.refused {
            tracing::error!(alert = "exporter.refused", destination = %r.destination, document = %r.document, reason = r.reason, "a document is not published");
            inner
                .audit
                .refused(&r.destination, &r.document, r.reason)
                .await;
        }

        // What is configured, for `signer`, and no report of anything else: also when nothing is configured, so that a
        // destination that was removed stops being waited for.
        let sync = tokio::spawn({
            let inner = Arc::clone(&inner);
            async move { inner.sync_manifest().await }
        });

        if inner.targets.is_empty() {
            // Nothing to publish (no --destinations, or none left): no watch to hold open and nothing to read.
            tracing::info!("no destination: exporter waits and does nothing");
            shutdown.await;
            sync.abort();
            return Ok(());
        }
        let (ring_from, rev_from) = inner.saved().await;
        let (tx, mut rx) = mpsc::channel::<Msg>(64);
        let backoff = self.backoff;
        let opts = move |p: Option<ResumePoint>| WatchOpts {
            from: p.and_then(usable),
            backoff,
            ..WatchOpts::default()
        };
        let ring_store = inner.source.ring_store().clone();
        let revocations = sluis_store::revocation::KeyRevocations::new(&self.store)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut tasks = vec![
            sync,
            tokio::spawn(follow(
                move |from| ring_store.watch_with("", opts(from)),
                ring_from,
                tx.clone(),
                Msg::Ring,
                |_| None,
            )),
            tokio::spawn(follow(
                move |from| revocations.watch_with(opts(from)),
                rev_from,
                tx.clone(),
                Msg::Revocation,
                revoked_kid,
            )),
        ];
        drop(tx);

        *inner
            .shared
            .points
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Points {
            signing_ring: ring_from.unwrap_or_default(),
            key_revocation: rev_from.unwrap_or_default(),
        };
        let (stop_tx, stop_rx) = watch::channel(false);
        let wakes: Vec<Arc<Wake>> = inner.targets.iter().map(|_| Arc::default()).collect();
        let mut workers = Vec::new();
        for (i, w) in wakes.iter().enumerate() {
            // The first round of each is the start: everything is read and compared, and reported.
            w.poke(true, true, false, &[]);
            workers.push(tokio::spawn(Arc::clone(&inner).work(
                i,
                Arc::clone(w),
                stop_rx.clone(),
            )));
        }
        let out = inner.dispatch(&mut rx, &wakes, &mut shutdown).await;
        let _ = stop_tx.send(true);
        for w in workers {
            // They stop at once: a call in flight is dropped. A document is replaced whole by the driver, so a call
            // dropped half way leaves the old one or the new one.
            if tokio::time::timeout(STOP, w).await.is_err() {
                tracing::warn!("a worker did not stop in time");
            }
        }
        for t in tasks.drain(..) {
            t.abort();
        }
        out
    }
}

impl<D: Destination + 'static> Inner<D> {
    /// The resume points to watch from, for the ring and for the revocations: the lowest sequence each destination saved,
    /// when all of them saved a point of the same epoch for the kind. A destination with none, a cursor from before
    /// epochs (epoch 0) and points of different epochs are not ordered, and give `None`: the kind is listed again,
    /// which costs a reconcile and loses nothing.
    async fn saved(&self) -> (Option<ResumePoint>, Option<ResumePoint>) {
        let mut all = Vec::new();
        for t in &self.targets {
            match self.cursors.load(&t.name).await {
                Ok(Some(p)) => all.push(p),
                Ok(None) => return (None, None),
                Err(e) => {
                    tracing::warn!(why = %e, "the cursor could not be read; starting without it");
                    return (None, None);
                }
            }
        }
        let lowest = |pick: fn(&Points) -> ResumePoint| {
            let mut it = all.iter().map(|p| usable(pick(p)));
            let first = it.next()??;
            it.try_fold(first, |low, p| {
                let p = p?;
                (p.epoch == low.epoch).then_some(ResumePoint {
                    epoch: low.epoch,
                    sequence: low.sequence.min(p.sequence),
                })
            })
        };
        (lowest(|p| p.signing_ring), lowest(|p| p.key_revocation))
    }

    /// Writes the manifest and removes the reports of what is not configured, until both are done.
    async fn sync_manifest(&self) {
        let entries: Vec<Entry> = self
            .targets
            .iter()
            .flat_map(|t| {
                t.documents.iter().map(|d| Entry {
                    destination: t.name.clone(),
                    document: d.name.clone(),
                    kind: config::SIGNING_RING.into(),
                    public: d.public_address.is_some(),
                    ..Entry::default()
                })
            })
            .collect();
        let expected: HashSet<String> = entries
            .iter()
            .map(|e| format!("{}/{}", e.destination, e.document))
            .collect();
        loop {
            let done = async {
                self.manifest
                    .set(entries.clone(), (self.now)())
                    .await
                    .map_err(|e| format!("the manifest: {e}"))?;
                for id in self
                    .reports
                    .ids()
                    .await
                    .map_err(|e| format!("the reports: {e}"))?
                {
                    if !expected.contains(&id) {
                        self.reports
                            .remove(&id)
                            .await
                            .map_err(|e| format!("the report {id}: {e}"))?;
                    }
                }
                Ok::<(), String>(())
            }
            .await;
            match done {
                Ok(()) => return,
                Err(why) => {
                    tracing::warn!(why, "the manifest is not written yet; trying again");
                    tokio::time::sleep(self.retry).await;
                }
            }
        }
    }

    /// Turns the watches into nudges. It never publishes and never waits for a destination.
    async fn dispatch(
        &self,
        rx: &mut mpsc::Receiver<Msg>,
        wakes: &[Arc<Wake>],
        shutdown: &mut (impl Future<Output = ()> + Unpin),
    ) -> anyhow::Result<()> {
        let poke = |look: bool, force: bool, lost: bool, removed: &[String]| {
            for w in wakes {
                w.poke(look, force, lost, removed);
            }
        };
        let mut ended = [0u32; 2];
        let mut next_full = Instant::now() + self.reconcile;
        loop {
            tokio::select! {
                () = &mut *shutdown => return Ok(()),
                m = rx.recv() => {
                    let Some(m) = m else { bail!("the watches ended") };
                    let (k, s) = match m { Msg::Ring(s) => (0, s), Msg::Revocation(s) => (1, s) };
                    let name = if k == 0 { "SigningRing" } else { "KeyRevocation" };
                    match s {
                        Sig::Resync(p, kids) => {
                            {
                                let mut pts = self.shared.points.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                // The listing replaces what was held: after a restore the log can be behind the saved point.
                                if k == 0 { pts.signing_ring = p } else { pts.key_revocation = p }
                            }
                            ended[k] = 0;
                            self.shared.unconfirmed[k].store(false, Ordering::SeqCst);
                            poke(true, false, false, &kids);
                        }
                        Sig::Change(p, kids) => {
                            {
                                let mut pts = self.shared.points.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                // Never back inside an epoch: the helper delivers each sequence once, in order. A point of
                                // another epoch is not ordered against the held one; it is the log the stream is on now.
                                let slot = if k == 0 { &mut pts.signing_ring } else { &mut pts.key_revocation };
                                advance(slot, p);
                            }
                            ended[k] = 0;
                            // Not a confirmation: the first change of a reconnect may be the first of many rows still to
                            // come. Only the caught-up claim (or a listing) confirms.
                            poke(true, false, false, &kids);
                        }
                        Sig::Bookmark => {
                            // An idle stream proves nothing about the rows it may not have delivered: it does not confirm.
                        }
                        Sig::CaughtUp => {
                            // The stream has delivered everything committed before it: the follow is confirmed, and the
                            // state is looked at once.
                            if self.shared.unconfirmed[k].swap(false, Ordering::SeqCst) {
                                poke(true, false, false, &[]);
                            }
                        }
                        Sig::Interrupted(why, attempt) => {
                            if !self.shared.unconfirmed[k].swap(true, Ordering::SeqCst) {
                                tracing::error!(alert = "exporter-watch-interrupted", kind = name, why = %why, "a change might go unseen: the published document is left as it is");
                                poke(false, false, true, &[]);
                            } else if attempt % 20 == 0 {
                                tracing::warn!(attempt, why = %why, "the watch is still interrupted");
                            }
                        }
                        Sig::Ended(why) => {
                            // One error when it breaks; then a line a minute while it keeps ending (it restarts every 5 s).
                            ended[k] += 1;
                            if !self.shared.unconfirmed[k].swap(true, Ordering::SeqCst) {
                                tracing::error!(alert = "exporter-watch-ended", kind = name, why = %why, "the watch ended; it starts again and lists");
                                poke(false, false, true, &[]);
                            } else if ended[k] % 12 == 0 {
                                tracing::warn!(kind = name, times = ended[k], why = %why, "the watch keeps ending");
                            }
                        }
                    }
                }
                () = tokio::time::sleep_until(next_full.into()) => {
                    next_full = Instant::now() + self.reconcile;
                    poke(true, true, false, &[]);
                }
            }
        }
    }

    /// One destination: waits for a nudge or for its retry, reads, publishes its documents, saves its cursor.
    async fn work(self: Arc<Self>, i: usize, wake: Arc<Wake>, mut stop: watch::Receiver<bool>) {
        let t = &self.targets[i];
        let mut retry_at: Option<Instant> = None;
        let mut removed: HashSet<String> = HashSet::new();
        let mut lost_pending = false;
        // A publication is owed again (a step failed, a purge is pending): the next timer runs a round. A report of a
        // lost watch that could not be stored is a different debt and runs no round, or it would undo what it reports.
        let mut publish_owed = false;
        let mut stored: Option<Points> = None;
        loop {
            let retry_sleep = async {
                match retry_at {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            };
            let retried = tokio::select! {
                () = stopped(&mut stop) => return,
                () = wake.bell.notified() => false,
                () = retry_sleep => true,
            };
            let ask = wake.take();
            let round = async {
                if ask.lost || lost_pending {
                    lost_pending = !self.publisher.watch_lost(&t.name, &t.documents).await;
                }
                removed.extend(ask.removed);
                if !(ask.dirty || (retried && publish_owed)) {
                    publish_owed = publish_owed && retry_at.is_some();
                    return (lost_pending || publish_owed).then_some(());
                }
                let seen = ask.seen.unwrap_or_else(Instant::now);
                let at = self.shared.points();
                let read = self.source.read().await;
                let mut retry = false;
                for d in &t.documents {
                    let o = self
                        .publisher
                        .publish(&t.name, &t.driver, d, &read, &removed, seen, ask.force)
                        .await;
                    retry |= o.retry;
                }
                let settled = matches!(read, Read::Snapshot(_) | Read::NoRing);
                if matches!(read, Read::Snapshot(_)) {
                    // A listing that was read after every event so far is the whole truth: nothing is owed by the kids.
                    removed.clear();
                }
                // The cursor moves only while both follows are confirmed: after a break it stays where it was until the
                // watch is back (see "Watch" in the module docs).
                if settled
                    && !retry
                    && !self.shared.any_unconfirmed()
                    && at.known()
                    && stored != Some(at)
                {
                    match self.cursors.save(&t.name, at, (self.now)()).await {
                        Ok(()) => stored = Some(at),
                        Err(e) => tracing::warn!(why = %e, "the cursor could not be saved"),
                    }
                }
                publish_owed = retry;
                (retry || lost_pending).then_some(())
            };
            let again = tokio::select! {
                () = stopped(&mut stop) => return,
                r = round => r,
            };
            retry_at = again.map(|()| Instant::now() + self.retry);
        }
    }
}

/// What the command line says.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The boundary.
    pub boundary: String,
    /// The sockets.
    pub sockets: Sockets,
    /// The destinations file, if one was given.
    pub destinations: Option<PathBuf>,
    /// The time between full reconciles.
    pub reconcile: Duration,
}

fn load(file: Option<&Path>) -> anyhow::Result<config::Loaded> {
    match file {
        Some(f) => config::load(f).map_err(|e| Refused(e.to_string()).into()),
        None => {
            tracing::info!("no --destinations: nothing to publish");
            Ok(config::Loaded::default())
        }
    }
}

/// Serves until `shutdown` resolves.
///
/// # Errors
///
/// When the destinations file is not usable, or the engine cannot be built.
pub async fn serve(s: Settings, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let loaded = load(s.destinations.as_deref())?;
    let targets = loaded
        .destinations
        .into_iter()
        .map(|d| Target {
            driver: DriverClient::new(&dial(&s.sockets.driver(&d.dtype))),
            name: d.name,
            documents: d.documents,
        })
        .collect();
    let engine = Engine::new(EngineConfig {
        audit: AuditConfig {
            actor: "exporter".into(),
            boundary: s.boundary.clone(),
            release: sluis_version::VERSION.to_owned(),
            transport_socket: s.sockets.audit.clone(),
            key_socket: None,
            now: None,
        },
        boundary: s.boundary,
        store: s.sockets.store,
        targets,
        refused: loaded.refused,
        reconcile: s.reconcile,
        retry: RETRY,
        timing: Timing::default(),
        backoff: Backoff::default(),
        now: SystemTime::now,
    })?;
    tracing::info!("following SigningRing and KeyRevocation");
    engine.run(shutdown).await
}

/// The flags of `exporter` beyond the global ones of the kit.
#[must_use]
pub fn extra(c: Command) -> Command {
    let path = |name: &'static str, help: &'static str| {
        Arg::new(name)
            .long(name)
            .value_name("PATH")
            .global(true)
            .help(help)
    };
    c.arg(
        Arg::new("run-dir")
            .long("run-dir")
            .value_name("DIR")
            .default_value("/run/sluis")
            .global(true)
            .help("The directory of the sockets of the actors"),
    )
    .arg(path("store-socket", "store@'s socket; <run-dir>/store/<boundary>.sock by default"))
    .arg(path(
        "transport-socket",
        "the audit transport's emit socket; <run-dir>/audit/<boundary>/emit.sock by default",
    ))
    .arg(path(
        "driver-dir",
        "the directory of the destination drivers' sockets, <type>.sock each; <run-dir>/exporter/<boundary> by default",
    ))
    .arg(path("destinations", "the file of ExportDestination items (JSON); without it exporter has no destination"))
    .arg(
        Arg::new("reconcile-secs")
            .long("reconcile-secs")
            .value_name("SECONDS")
            .default_value("86400")
            .global(true)
            .help("The time between full reconciles, from 60 seconds to a day"),
    )
}

/// `exporter`.
pub struct Exporter;

fn settings(f: &Flags) -> anyhow::Result<Settings> {
    if f.boundary.is_empty() {
        bail!("--boundary is needed");
    }
    let one = |name: &str| f.matches.get_one::<String>(name).filter(|s| !s.is_empty());
    let run = one("run-dir").map_or_else(|| PathBuf::from("/run/sluis"), PathBuf::from);
    let mut sockets = Sockets::under(&run, &f.boundary);
    for (name, slot) in [
        ("store-socket", &mut sockets.store),
        ("transport-socket", &mut sockets.audit),
        ("driver-dir", &mut sockets.drivers),
    ] {
        if let Some(p) = one(name) {
            *slot = PathBuf::from(p);
        }
    }
    // Without a file there is no destination: `exporter` runs, follows nothing it has to publish, and says so.
    let destinations = one("destinations").map(PathBuf::from);
    let secs = one("reconcile-secs")
        .map_or(Ok(RECONCILE.as_secs()), |s| s.parse::<u64>())
        .ok()
        .filter(|s| (60..=RECONCILE.as_secs()).contains(s))
        .ok_or_else(|| anyhow::anyhow!("--reconcile-secs: a number of seconds from 60 to 86400"))?;
    Ok(Settings {
        boundary: f.boundary.clone(),
        sockets,
        destinations,
        reconcile: Duration::from_secs(secs),
    })
}

async fn reach(path: &Path) -> Result<(), String> {
    match tokio::time::timeout(REACH, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{:?}", e.kind())),
        Err(_) => Err("timed out".into()),
    }
}

impl Commands for Exporter {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        serve(settings(&f)?, shutdown_signal()).await
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(check(&f).await)
    }
}

async fn check(f: &Flags) -> anyhow::Result<()> {
    let s = settings(f)?;
    let loaded = load(s.destinations.as_deref())?;
    let mut missing = Vec::new();
    let mut sockets = vec![
        ("store@".to_owned(), s.sockets.store.clone()),
        ("audit transport".to_owned(), s.sockets.audit.clone()),
    ];
    for d in &loaded.destinations {
        sockets.push((
            format!("the {} driver", d.dtype),
            s.sockets.driver(&d.dtype),
        ));
    }
    for (name, path) in &sockets {
        if let Err(why) = reach(path).await {
            missing.push(format!("{name}: {} unreachable ({why})", path.display()));
        }
    }
    if !loaded.refused.is_empty() {
        missing.push(format!(
            "{} document(s) refused by the check",
            loaded.refused.len()
        ));
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Refused(missing.join("; ")).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(epoch: u64, sequence: u64) -> ResumePoint {
        ResumePoint { epoch, sequence }
    }

    /// A point moves forward inside its epoch and never back, and a sequence of another epoch is not compared with it:
    /// a lower number in a new epoch is the new log, a higher one in an old epoch is not.
    ///
    /// verifies: REQ-EXPORT-015
    #[test]
    fn a_held_point_moves_forward_inside_its_epoch_only() {
        let mut held = rp(1, 10);
        advance(&mut held, rp(1, 12));
        assert_eq!(held, rp(1, 12));
        advance(&mut held, rp(1, 11));
        assert_eq!(held, rp(1, 12), "never back inside an epoch");
        advance(&mut held, rp(2, 3));
        assert_eq!(
            held,
            rp(2, 3),
            "a lower sequence of a new epoch is the new log"
        );
        advance(&mut held, rp(2, 2));
        assert_eq!(held, rp(2, 3));
    }

    /// A nudge made while a worker is busy is not lost: it leaves a permit, the worker's next wait returns at once, and
    /// what it carries (the earliest arrival, the force, the kids) is taken. Many nudges are one more round, not many.
    ///
    /// verifies: REQ-EXPORT-028
    #[tokio::test]
    async fn a_nudge_made_while_a_worker_is_busy_is_one_more_round() {
        use std::time::Duration;
        let w = Wake::default();
        w.poke(true, false, false, &[]);
        tokio::time::timeout(Duration::from_millis(50), w.bell.notified())
            .await
            .expect("a nudge with nobody waiting is kept");
        let first = w.take();
        assert!(first.dirty && first.seen.is_some());

        // The worker is busy with that round; two nudges arrive.
        w.poke(true, false, false, &["kid-x".into()]);
        w.poke(true, true, false, &[]);
        tokio::time::timeout(Duration::from_millis(50), w.bell.notified())
            .await
            .expect("a nudge made while busy is not lost");
        let second = w.take();
        assert!(second.dirty && second.force && second.removed.contains("kid-x"));
        assert!(second.seen.is_some_and(|s| s >= first.seen.unwrap()));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), w.bell.notified())
                .await
                .is_err(),
            "two nudges are one round"
        );
        assert!(!w.take().dirty);

        // A nudge that only says the watch broke asks for no round.
        w.poke(false, false, true, &[]);
        tokio::time::timeout(Duration::from_millis(50), w.bell.notified())
            .await
            .unwrap();
        let lost = w.take();
        assert!(lost.lost && !lost.dirty);
    }
}
