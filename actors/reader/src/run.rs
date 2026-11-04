//! The command line of `reader`: `serve`, `check`, `version` (cli.md "Conventions").

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use clap::{Arg, Command};
use connectrpc::Router;
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig, dial};
use sluis_proto::sluis::reader::v2alpha1::ReaderServiceExt as _;

use crate::config::Config;
use crate::ports::{Ports, Sockets};
use crate::search::Searcher;
use crate::service::Service;

/// The deadline of a call that carries none (contracts.md "Every call").
const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);
/// How long one attempt to reach a socket may take.
const REACH: Duration = Duration::from_secs(2);

/// What the reader needs to run.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The boundary.
    pub boundary: String,
    /// The sockets it calls.
    pub sockets: Sockets,
    /// Its own socket.
    pub service: PathBuf,
    /// The group of its own socket, when it is not the process's.
    pub socket_gid: Option<u32>,
}

/// The flags of `reader` beyond the global ones of the kit.
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
        "key@'s socket for the reader; <run-dir>/key/<boundary>/reader/key.sock by default",
    ))
    .arg(path(
        "policy-socket",
        "policy's socket; <run-dir>/policy/<boundary>.sock by default",
    ))
    .arg(path(
        "blob-socket",
        "the read-only blob driver; <run-dir>/indexer/<boundary>/blob-ro.sock by default",
    ))
    .arg(path(
        "index-socket",
        "the index driver's read socket; <run-dir>/indexer/<boundary>/index-ro.sock by default",
    ))
    .arg(path(
        "transport-socket",
        "the audit transport's emit socket; <run-dir>/audit/<boundary>/emit.sock by default",
    ))
    .arg(
        Arg::new("socket-gid")
            .long("socket-gid")
            .value_name("GID")
            .global(true)
            .help("Give the socket (mode 0660) to this group; the default is the group the process runs as"),
    )
}

fn settings(f: &Flags) -> anyhow::Result<Settings> {
    if f.boundary.is_empty() {
        bail!("--boundary is required");
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
        ("transport-socket", &mut sockets.audit),
    ] {
        if let Some(p) = one(name) {
            *slot = PathBuf::from(p);
        }
    }
    let socket_gid = match one("socket-gid") {
        None => None,
        Some(g) => match g.parse::<u32>() {
            Ok(g) if g != 0 => Some(g),
            _ => bail!("--socket-gid must be a group number other than 0"),
        },
    };
    let service = if f.socket.as_os_str().is_empty() {
        run.join("reader").join(format!("{}.sock", f.boundary))
    } else {
        f.socket.clone()
    };
    Ok(Settings {
        boundary: f.boundary.clone(),
        sockets,
        service,
        socket_gid,
    })
}

async fn reach(path: &Path) -> Result<(), String> {
    match tokio::time::timeout(REACH, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{:?}", e.kind())),
        Err(_) => Err("timed out".into()),
    }
}

/// `reader`.
pub struct Reader;

impl Commands for Reader {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        let s = settings(&f)?;
        let config = Config::new(&dial(&s.sockets.store)).map_err(|e| anyhow::anyhow!("{e}"))?;
        // The reader has no pseudonym to make, so its emitter needs no key@ socket.
        let audit = sluis_audit::Emitter::new(sluis_audit::Config {
            actor: "reader".into(),
            boundary: s.boundary.clone(),
            release: sluis_version::VERSION.into(),
            transport_socket: s.sockets.audit.clone(),
            key_socket: None,
            now: None,
        })
        .map_err(|e| anyhow::anyhow!("the audit emitter: {}", e.code.as_str()))?;
        let searcher = Searcher::new(&s.boundary, Ports::new(&s.sockets), config);
        let svc = Arc::new(Service::new(searcher, audit));
        tracing::info!(boundary = %s.boundary, "serving Search");
        sluis_kit::serve(
            ServerConfig {
                actor: "reader",
                boundary: s.boundary.clone(),
                socket: s.service,
                mode: 0o660,
                socket_gid: s.socket_gid,
                // planned: Allow::CallGraph. The registry lets `console` call the reader and gives `entry` no
                // edge to it, while 0028 "The audit front" has the audit `entry` route to the reader, and the
                // console does not exist yet. Until actors.yaml names the edge, only the audit front's `entry`
                // may call.
                allow: Allow::Exact("entry"),
                default_deadline: DEFAULT_DEADLINE,
            },
            svc.register(Router::new()),
            shutdown_signal(),
        )
        .await
    }

    /// Reaches every dependency and reads the config: what a first Search would need.
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
        ("audit transport", &s.sockets.audit),
    ] {
        if let Err(why) = reach(path).await {
            missing.push(format!("{name}: {} unreachable ({why})", path.display()));
        }
    }
    if missing.is_empty() {
        let config = Config::new(&dial(&s.sockets.store)).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Err(e) = config.logs().await {
            missing.push(format!("config: {}", e.code.as_str()));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Refused(missing.join("; ")).into())
    }
}
