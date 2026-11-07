//! The loop and the command line of `exporter`: `serve`, `check`, `version` (cli.md).
//!
//! `exporter` serves no socket. It follows `SigningRing` and `KeyRevocation` in two tasks (the watch helper of the
//! store client, from the resume point in `ExportCursor`) and does one thing when the follow says "look": it reads both
//! kinds linearizably and publishes ([`crate::publish`]). The events say *when*, never *what*: a missed or repeated
//! event cannot make the document wrong, only late, and the daily reconcile bounds how late.
//!
//! - **Start.** Reconcile at once: read, compare with the destination, write what differs, purge, read back, report.
//! - **A change.** The same, as soon as the event arrives, with the 60 seconds of REQ-EXPORT-028 counted from it.
//! - **A watch that breaks.** A change might go unseen: the documents are reported `unverified` once, and the watch
//!   reconnects by itself (an alarm per interruption would be a stream of its own). The first event after it is a
//!   reason to reconcile.
//! - **A step that fails.** Tried again every `retry` until it passes; the report says `purge-pending` or `unverified`.
//! - **Once a day.** A full reconcile, which also refreshes the reports so that none expires while `exporter` runs.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::bail;
use clap::{Arg, Command};
use sluis_audit::Config as AuditConfig;
use sluis_destination::Destination;
use sluis_destination::rpc::Client as DriverClient;
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Client, dial};
use sluis_store::{Backoff, Event, Kind, Watch, WatchOpts};
use tokio::sync::mpsc;

use crate::audit::Auditor;
use crate::config::{self, Doc, Refused as DocRefused, Sockets};
use crate::publish::{Publisher, Timing};
use crate::state::{Cursors, Points, Reports, Source};

/// The default time between full reconciles.
pub const RECONCILE: Duration = Duration::from_secs(24 * 60 * 60);
/// The default wait before a publication that is not finished is tried again.
pub const RETRY: Duration = Duration::from_secs(15);
/// How long a watch that ended with an error waits before it starts again (and lists again).
const RESTART: Duration = Duration::from_secs(5);
/// How long one attempt to reach a socket may take.
const REACH: Duration = Duration::from_secs(2);

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

/// What a watch tells the loop.
#[derive(Debug)]
enum Sig {
    /// The kind was listed again (the start, or a point the store no longer holds).
    Resync(u64),
    /// A change.
    Change(u64),
    /// An idle stream.
    Bookmark,
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

fn sig<K: Kind>(ev: Event<K>) -> Sig {
    match ev {
        Event::Resync { resume_point, .. } => Sig::Resync(resume_point),
        Event::Put { resume_point, .. } | Event::Delete { resume_point, .. } => {
            Sig::Change(resume_point)
        }
        Event::Bookmark { .. } => Sig::Bookmark,
        Event::Interrupted { reason, attempt } => Sig::Interrupted(reason, attempt),
    }
}

/// Follows one kind until the receiver is gone, starting the watch again after an error that ended it.
async fn follow<K: Kind + Send + 'static>(
    make: impl Fn(Option<u64>) -> Result<Watch<K>, sluis_store::Error> + Send + 'static,
    from: Option<u64>,
    tx: mpsc::Sender<Msg>,
    wrap: fn(Sig) -> Msg,
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
                    if tx.send(wrap(sig(ev))).await.is_err() {
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

/// The engine: the follow, the reconcile and the publication, over any destination driver.
pub struct Engine<D> {
    store: Client,
    targets: Vec<Target<D>>,
    refused: Vec<DocRefused>,
    audit: Auditor,
    source: Source,
    cursors: Cursors,
    publisher: Publisher,
    reconcile: Duration,
    retry: Duration,
    backoff: Backoff,
    now: fn() -> SystemTime,
}

impl<D: Destination> Engine<D> {
    /// Builds the engine; nothing is dialled until the first call.
    ///
    /// # Errors
    ///
    /// When a kind is not in the registry or the emitter is refused.
    pub fn new(c: EngineConfig<D>) -> anyhow::Result<Self> {
        let store = dial(&c.store);
        let audit = Auditor::new(c.audit)?;
        let map = |e: sluis_store::Error| anyhow::anyhow!("{e}");
        Ok(Self {
            source: Source::new(&store).map_err(map)?,
            cursors: Cursors::new(&store).map_err(map)?,
            publisher: Publisher::new(
                Reports::new(&store).map_err(map)?,
                audit.clone(),
                c.now,
                c.timing,
            ),
            store,
            targets: c.targets,
            refused: c.refused,
            audit,
            reconcile: c.reconcile,
            retry: c.retry,
            backoff: c.backoff,
            now: c.now,
        })
    }

    /// The resume points to watch from: the lowest each destination saved, or none when a destination has none.
    async fn saved(&self) -> Option<Points> {
        let mut out: Option<Points> = None;
        for t in &self.targets {
            let p = match self.cursors.load(&t.name).await {
                Ok(Some(p)) => p,
                Ok(None) => return None,
                Err(e) => {
                    tracing::warn!(why = %e, "the cursor could not be read; starting without it");
                    return None;
                }
            };
            out = Some(match out {
                None => p,
                Some(o) => Points {
                    signing_ring: o.signing_ring.min(p.signing_ring),
                    key_revocation: o.key_revocation.min(p.key_revocation),
                },
            });
        }
        out
    }

    /// Runs until `shutdown` resolves.
    ///
    /// # Errors
    ///
    /// When a watch cannot be built at all.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
        tokio::pin!(shutdown);
        let documents: usize = self.targets.iter().map(|t| t.documents.len()).sum();
        self.audit
            .started(self.targets.len(), documents, self.refused.len())
            .await;
        for r in &self.refused {
            tracing::error!(alert = "exporter.refused", destination = %r.destination, document = %r.document, reason = r.reason, "a document is not published");
            self.audit
                .refused(&r.destination, &r.document, r.reason)
                .await;
        }

        let saved = self.saved().await;
        let (tx, mut rx) = mpsc::channel::<Msg>(64);
        let backoff = self.backoff;
        let opts = move |p: Option<u64>| WatchOpts {
            from: p.filter(|p| *p != 0),
            backoff,
            ..WatchOpts::default()
        };
        let ring_store = self.source.ring_store().clone();
        let ring_from = saved.map(|p| p.signing_ring);
        let revocations = sluis_store::revocation::KeyRevocations::new(&self.store)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let rev_from = saved.map(|p| p.key_revocation);
        let tasks = [
            tokio::spawn(follow(
                move |from| ring_store.watch_with("", opts(from)),
                ring_from,
                tx.clone(),
                Msg::Ring,
            )),
            tokio::spawn(follow(
                move |from| revocations.watch_with(opts(from)),
                rev_from,
                tx.clone(),
                Msg::Revocation,
            )),
        ];
        drop(tx);
        let out = self.lead(&mut rx, saved, &mut shutdown).await;
        for t in tasks {
            t.abort();
        }
        out
    }

    async fn lead(
        &self,
        rx: &mut mpsc::Receiver<Msg>,
        saved: Option<Points>,
        shutdown: &mut (impl Future<Output = ()> + Unpin),
    ) -> anyhow::Result<()> {
        let mut points = saved.unwrap_or_default();
        let mut stored = saved;
        let (mut dirty, mut force) = (true, true);
        let mut seen = Instant::now();
        let mut unconfirmed = false;
        let mut next_full = Instant::now() + self.reconcile;
        let mut retry_at: Option<Instant> = None;
        loop {
            if dirty {
                dirty = false;
                let at = points;
                let read = self.source.read().await;
                let mut retry = false;
                for t in &self.targets {
                    for d in &t.documents {
                        let o = self
                            .publisher
                            .publish(&t.name, &t.driver, d, &read, seen, force)
                            .await;
                        retry |= o.retry;
                    }
                }
                force = false;
                let settled = matches!(
                    read,
                    crate::state::Read::Snapshot(_) | crate::state::Read::NoRing
                );
                if settled && !retry && stored != Some(at) {
                    let mut all = true;
                    for t in &self.targets {
                        if let Err(e) = self.cursors.save(&t.name, at, (self.now)()).await {
                            tracing::warn!(why = %e, "the cursor could not be saved");
                            all = false;
                        }
                    }
                    if all {
                        stored = Some(at);
                    }
                }
                retry_at = retry.then(|| Instant::now() + self.retry);
            }
            let retry_sleep = async {
                match retry_at {
                    Some(t) => tokio::time::sleep_until(t.into()).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = &mut *shutdown => return Ok(()),
                m = rx.recv() => {
                    let Some(m) = m else { bail!("the watches ended") };
                    let (ring, s) = match m { Msg::Ring(s) => (true, s), Msg::Revocation(s) => (false, s) };
                    match s {
                        Sig::Resync(p) | Sig::Change(p) => {
                            // Never back: the helper delivers each sequence once, in order.
                            let slot = if ring { &mut points.signing_ring } else { &mut points.key_revocation };
                            *slot = (*slot).max(p);
                            if !dirty { seen = Instant::now(); }
                            dirty = true;
                            unconfirmed = false;
                        }
                        Sig::Bookmark => {
                            if unconfirmed {
                                // The stream is back and has nothing more to say: look.
                                if !dirty { seen = Instant::now(); }
                                dirty = true;
                                unconfirmed = false;
                            }
                        }
                        Sig::Interrupted(why, attempt) => {
                            if !unconfirmed {
                                unconfirmed = true;
                                tracing::error!(alert = "exporter.watch_interrupted", kind = if ring { "SigningRing" } else { "KeyRevocation" }, why = %why, "a change might go unseen: the published document is left as it is");
                                for t in &self.targets {
                                    self.publisher.watch_lost(&t.name, &t.documents).await;
                                }
                            } else if attempt % 20 == 0 {
                                tracing::warn!(attempt, why = %why, "the watch is still interrupted");
                            }
                        }
                        Sig::Ended(why) => {
                            tracing::error!(alert = "exporter.watch_ended", kind = if ring { "SigningRing" } else { "KeyRevocation" }, why = %why, "the watch ended; it starts again and lists");
                            if !unconfirmed {
                                unconfirmed = true;
                                for t in &self.targets {
                                    self.publisher.watch_lost(&t.name, &t.documents).await;
                                }
                            }
                        }
                    }
                }
                () = tokio::time::sleep_until(next_full.into()) => {
                    next_full = Instant::now() + self.reconcile;
                    seen = Instant::now();
                    dirty = true;
                    force = true;
                }
                () = retry_sleep => {
                    retry_at = None;
                    seen = Instant::now();
                    dirty = true;
                }
            }
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
