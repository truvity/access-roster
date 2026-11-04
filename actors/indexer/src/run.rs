//! The command line and the loop of `indexer`: `serve`, `check`, `version` (cli.md).
//!
//! The indexer serves no socket. It polls: every `--poll-secs` it reads `AuditLog`, and takes each audit
//! log of the boundary from its cursor to the newest verified checkpoint (see [`crate::follow`]). 0028
//! says notifications only wake it; there is no notification source yet, so the poll is the whole
//! trigger, and the index lags the log by the seal interval plus the poll.
//!
//! A log that fails verification is halted for the life of the process and an alert is logged, at
//! error level, with the closed word and the position (`alert = "indexer.halted"`); it is repeated every
//! five minutes. The other logs go on. A restart tries the log again from its cursor.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::bail;
use clap::{Arg, Command};
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::dial;

use crate::config::Config;
use crate::follow::{Follower, Log, Progress};
use crate::ports::{Failure, Ports, Sockets};

/// How often a halted log repeats its alert.
const REPEAT_ALERT: Duration = Duration::from_secs(300);
/// The default poll, in seconds.
const POLL_SECS: u64 = 5;
/// How long one attempt to reach a socket may take.
const REACH: Duration = Duration::from_secs(2);

/// What the indexer needs to run.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The boundary.
    pub boundary: String,
    /// The sockets it calls.
    pub sockets: Sockets,
    /// The directory of the verifier keys of the logs.
    pub key_dir: PathBuf,
    /// The time between rounds.
    pub poll: Duration,
}

/// One round over every log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Round {
    /// Steps that moved a cursor.
    pub steps: usize,
    /// Logs that stopped this round for a cause that may pass.
    pub transient: usize,
    /// Logs that are halted (including from earlier rounds).
    pub halted: usize,
}

/// The loop's state: the follower and the logs it has halted.
pub struct Runner {
    follower: Follower,
    config: Config,
    key_dir: PathBuf,
    halted: HashMap<String, Instant>,
}

impl Runner {
    /// A runner for the settings; nothing is dialled until the first round.
    ///
    /// # Errors
    ///
    /// When the config kind is not in the registry.
    pub fn new(s: &Settings) -> anyhow::Result<Self> {
        let store = dial(&s.sockets.store);
        Ok(Self {
            follower: Follower::new(&s.boundary, Ports::new(&s.sockets)),
            config: Config::new(&store).map_err(|e| anyhow::anyhow!("{e}"))?,
            key_dir: s.key_dir.clone(),
            halted: HashMap::new(),
        })
    }

    /// Takes every log from its cursor to its newest verified checkpoint.
    pub async fn round(&mut self) -> Round {
        let mut out = Round::default();
        let logs = match self.config.logs(&self.key_dir).await {
            Ok(l) => l,
            Err(Failure::Transient(why)) => {
                tracing::warn!(why = %why, "the audit config could not be read; trying again");
                out.transient += 1;
                return out;
            }
            Err(Failure::Refused(word, at)) => {
                tracing::error!(alert = "indexer.config", word, at = %at, "the audit config is not usable; nothing is indexed");
                out.halted += 1;
                return out;
            }
        };
        for log in &logs {
            self.follow(log, &mut out).await;
        }
        out
    }

    async fn follow(&mut self, log: &Log, out: &mut Round) {
        let name = log.name();
        if let Some(at) = self.halted.get_mut(&name) {
            out.halted += 1;
            if at.elapsed() >= REPEAT_ALERT {
                *at = Instant::now();
                tracing::error!(alert = "indexer.halted", log = %name, "the log is still halted; restart the indexer after the cause is gone");
            }
            return;
        }
        loop {
            match self.follower.pass(log).await {
                Ok(Progress::Idle) => return,
                Ok(Progress::Advanced { size, rows }) => {
                    out.steps += 1;
                    tracing::info!(log = %name, size, rows, "indexed to a verified checkpoint");
                }
                Err(Failure::Transient(why)) => {
                    tracing::warn!(log = %name, why = %why, "the pass stopped; trying again");
                    out.transient += 1;
                    return;
                }
                Err(Failure::Refused(word, at)) => {
                    // 0028: a checkpoint that fails verification stops indexing and raises an alert,
                    // never a skip. The cursor stays where it is.
                    tracing::error!(alert = "indexer.halted", log = %name, word, at = %at, "the log failed verification; indexing of it has stopped");
                    self.halted.insert(name, Instant::now());
                    out.halted += 1;
                    return;
                }
            }
        }
    }
}

/// Runs rounds until `shutdown` resolves.
///
/// # Errors
///
/// When the runner cannot be made.
pub async fn serve(s: Settings, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let mut runner = Runner::new(&s)?;
    tokio::pin!(shutdown);
    tracing::info!(boundary = %s.boundary, "following the audit logs");
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            _ = runner.round() => {}
        }
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            () = tokio::time::sleep(s.poll) => {}
        }
    }
}

/// The flags of `indexer` beyond the global ones of the kit.
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
    .arg(path(
        "store-socket",
        "store@'s socket; <run-dir>/store/<boundary>.sock by default",
    ))
    .arg(path(
        "key-socket",
        "key@'s socket for the indexer; <run-dir>/key/<boundary>/indexer/key.sock by default",
    ))
    .arg(path(
        "policy-socket",
        "policy's socket; <run-dir>/policy/<boundary>.sock by default",
    ))
    .arg(path(
        "blob-socket",
        "the blob driver the indexer reads; <run-dir>/indexer/<boundary>/blob.sock by default",
    ))
    .arg(path(
        "index-socket",
        "the index driver's write socket; <run-dir>/indexer/<boundary>/index.sock by default",
    ))
    .arg(path(
        "verifier-key-dir",
        "the directory of the log verifier keys, <log id>.vkey each",
    ))
    .arg(
        Arg::new("poll-secs")
            .long("poll-secs")
            .value_name("SECONDS")
            .default_value("5")
            .global(true)
            .help("The time between rounds"),
    )
}

/// `indexer`.
pub struct Indexer;

fn settings(f: &Flags) -> anyhow::Result<Settings> {
    if f.boundary.is_empty() {
        bail!("--boundary is needed");
    }
    let one = |name: &str| f.matches.get_one::<String>(name).filter(|s| !s.is_empty());
    let run = one("run-dir").map_or_else(|| PathBuf::from("/run/sluis"), PathBuf::from);
    let mut sockets = Sockets::under(&run, &f.boundary);
    for (name, slot) in [
        ("store-socket", &mut sockets.store),
        ("key-socket", &mut sockets.key),
        ("policy-socket", &mut sockets.policy),
        ("blob-socket", &mut sockets.blob),
        ("index-socket", &mut sockets.index),
    ] {
        if let Some(p) = one(name) {
            *slot = PathBuf::from(p);
        }
    }
    let Some(key_dir) = one("verifier-key-dir") else {
        bail!("--verifier-key-dir is needed");
    };
    let secs = one("poll-secs")
        .map_or(Ok(POLL_SECS), |s| s.parse::<u64>())
        .ok()
        .filter(|s| (1..=3600).contains(s))
        .ok_or_else(|| anyhow::anyhow!("--poll-secs: a number of seconds from 1 to 3600"))?;
    Ok(Settings {
        boundary: f.boundary.clone(),
        sockets,
        key_dir: PathBuf::from(key_dir),
        poll: Duration::from_secs(secs),
    })
}

async fn reach(path: &Path) -> Result<(), String> {
    match tokio::time::timeout(REACH, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{:?}", e.kind())),
        Err(_) => Err("timed out".into()),
    }
}

impl Commands for Indexer {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        serve(settings(&f)?, shutdown_signal()).await
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(check(&f).await)
    }
}

async fn check(f: &Flags) -> anyhow::Result<()> {
    let s = settings(f)?;
    let mut missing = Vec::new();
    for (name, path) in [
        ("store@", &s.sockets.store),
        ("key@", &s.sockets.key),
        ("policy", &s.sockets.policy),
        ("blob driver", &s.sockets.blob),
        ("index driver", &s.sockets.index),
    ] {
        if let Err(why) = reach(path).await {
            missing.push(format!("{name}: {} unreachable ({why})", path.display()));
        }
    }
    if missing.is_empty() {
        // The config is read only when its source is there; the keys are checked with it.
        let config = Config::new(&dial(&s.sockets.store)).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Err(e) = config.logs(&s.key_dir).await {
            missing.push(format!("config: {e:?}"));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Refused(missing.join("; ")).into())
    }
}
