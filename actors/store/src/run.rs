//! The command line of `store`: `serve`, `check`, `version` (ADR 0005, "Drivers"; cli.md).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, bail};
use clap::{Arg, Command};
use connectrpc::Router;
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig, dial};
use sluis_proto::sluis::store::v2alpha1::StoreServiceExt as _;

use crate::audit::LogSink;
use crate::bootstrap::Bootstrap;
use crate::config::NoConfig;
use crate::engine::DriverEngine;
use crate::grant::KeyOpener;
use crate::service::{Deps, Service};

/// The deadline of a call that carries none (contracts.md "Every call").
const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);
/// How long one attempt to reach a socket may take.
const REACH_ATTEMPT: Duration = Duration::from_secs(2);
/// The pause between attempts while `serve` waits for a driver.
const REACH_PAUSE: Duration = Duration::from_millis(250);

/// The flags of `store` beyond the global ones of the kit.
#[must_use]
pub fn extra(c: Command) -> Command {
    c.arg(
        Arg::new("bootstrap")
            .long("bootstrap")
            .global(true)
            .value_name("FILE")
            .help("The bootstrap file, /etc/sluis/bootstrap.d/<boundary>.yaml"),
    )
    .arg(
        Arg::new("key-socket")
            .long("key-socket")
            .global(true)
            .value_name("PATH")
            .help("key@'s socket for store@; default /run/sluis/key/<boundary>/store/key.sock"),
    )
    .arg(
        Arg::new("transport-socket")
            .long("transport-socket")
            .global(true)
            .value_name("PATH")
            .help(
                "The audit transport's emit socket; default /run/sluis/audit/<boundary>/emit.sock",
            ),
    )
}

/// The paths a run uses, from the flags and the boundary of the file.
struct Paths {
    key: PathBuf,
    #[allow(dead_code)] // planned: the emitter of sluis-audit dials it (WP-10)
    transport: PathBuf,
    service: PathBuf,
}

fn paths(f: &Flags, boundary: &str) -> Paths {
    let flag = |name: &str| {
        f.matches
            .get_one::<String>(name)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    Paths {
        key: flag("key-socket")
            .unwrap_or_else(|| format!("/run/sluis/key/{boundary}/store/key.sock").into()),
        transport: flag("transport-socket")
            .unwrap_or_else(|| format!("/run/sluis/audit/{boundary}/emit.sock").into()),
        service: if f.socket.as_os_str().is_empty() {
            format!("/run/sluis/store/{boundary}.sock").into()
        } else {
            f.socket.clone()
        },
    }
}

fn load(f: &Flags) -> anyhow::Result<Bootstrap> {
    let path = f
        .matches
        .get_one::<String>("bootstrap")
        .filter(|s| !s.is_empty())
        .context("--bootstrap FILE is required")?;
    let own = rustix::process::geteuid().as_raw();
    let b = Bootstrap::load(Path::new(path), own).map_err(|e| Refused(e.to_string()))?;
    if !f.boundary.is_empty() && f.boundary != b.boundary {
        return Err(Refused("--boundary is not the boundary of the bootstrap file".into()).into());
    }
    Ok(b)
}

/// Whether something listens on the socket.
async fn reach(path: &Path) -> Result<(), String> {
    match tokio::time::timeout(REACH_ATTEMPT, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{:?}", e.kind())),
        Err(_) => Err("timed out".into()),
    }
}

/// The sockets store@ needs, with the name of each.
fn needed(b: &Bootstrap, key: &Path) -> Vec<(String, PathBuf)> {
    let mut v: Vec<_> = b
        .destinations()
        .into_iter()
        .map(|(port, d)| (format!("{port} ({} driver)", d.driver), d.socket.clone()))
        .collect();
    v.push(("key@".into(), key.to_owned()));
    v
}

/// The unreachable sockets among `wanted`, one line each.
async fn unreachable(wanted: &[(String, PathBuf)]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, path) in wanted {
        if let Err(why) = reach(path).await {
            out.push(format!("{name}: {} unreachable ({why})", path.display()));
        }
    }
    out
}

/// `store`.
pub struct Store;

impl Commands for Store {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        let b = load(&f)?;
        let p = paths(&f, &b.boundary);

        // A cold start refuses on any failure (ADR 0005): wait for the drivers up to start_timeout.
        let wanted = needed(&b, &p.key);
        let deadline = Instant::now() + b.start_timeout;
        loop {
            let missing = unreachable(&wanted).await;
            if missing.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "not started within {}s: {}",
                    b.start_timeout.as_secs(),
                    missing.join("; ")
                );
            }
            tokio::time::sleep(REACH_PAUSE).await;
        }

        let svc = Service::new(Deps {
            boundary: b.boundary.clone(),
            durable: DriverEngine::new(&dial(&b.durable.socket), "durable"),
            temp: DriverEngine::new(&dial(&b.temp.socket), "temp"),
            grants: KeyOpener::new(&dial(&p.key)),
            // planned: the signed config snapshot (WP-11) replaces NoConfig.
            config: Arc::new(NoConfig),
            // planned: the emitter of sluis-audit replaces LogSink (WP-10), on `p.transport`.
            audit: LogSink,
            clock: Arc::new(SystemTime::now),
        });
        svc.announce_start(
            b.destinations()
                .into_iter()
                .map(|(port, d)| (port, d.driver.clone()))
                .collect(),
        )
        .await;
        let router = Arc::new(svc).register(Router::new());
        sluis_kit::serve(
            ServerConfig {
                actor: "store",
                boundary: b.boundary.clone(),
                socket: p.service,
                mode: 0o660,
                allow: Allow::CallGraph,
                default_deadline: DEFAULT_DEADLINE,
            },
            router,
            shutdown_signal(),
        )
        .await
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(self.check_inner(&f).await)
    }
}

impl Store {
    async fn check_inner(&self, f: &Flags) -> anyhow::Result<()> {
        let b = load(f)?;
        let p = paths(f, &b.boundary);
        let missing = unreachable(&needed(&b, &p.key)).await;
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Refused(missing.join("; ")).into())
        }
    }
}
