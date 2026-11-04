//! `rqlite`: the driver of store@ for the durable and the temp port.
//!
//! ```text
//! rqlite serve --socket P --rqlite-url URL --namespace durable|temp [--sweep-interval 30s]
//!              [--changelog-retention 24h] [--basic-auth-file F] [--socket-gid GID]
//! rqlite check --rqlite-url URL --namespace durable|temp [--basic-auth-file F]
//! rqlite conformance --socket P
//! rqlite version
//! ```

use std::time::Duration;

use anyhow::{Context, bail};
use clap::Arg;
use sluis_kit::cli::{self, Commands, Flags, Refused};
use sluis_kit::{Allow, ServerConfig};
use sluis_rqlite::client::Level;
use sluis_rqlite::config::{self, Settings};
use sluis_rqlite::sweeper;

/// The registry name of this driver's user (docs/architecture/actors.yaml, drivers).
const DRIVER: &str = "driver-store-rqlite";
/// How long `serve` waits for rqlite to answer before it gives up.
const READY: Duration = Duration::from_secs(60);

struct Rqlite;

/// The group of the socket (`--socket-gid`), if given. The socket is then 0660 for that group, so that
/// the owner, who joins it, can connect; without it the socket is 0600 for the driver's user alone.
/// The peer check (`OwnerOnly`) still decides who may call.
fn socket_gid(f: &Flags) -> anyhow::Result<Option<u32>> {
    match f.matches.get_one::<String>("socket-gid") {
        None => Ok(None),
        Some(g) => match g.parse::<u32>() {
            Ok(g) if g != 0 => Ok(Some(g)),
            _ => bail!("--socket-gid must be a group number other than 0"),
        },
    }
}

impl Commands for Rqlite {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        anyhow::ensure!(!f.socket.as_os_str().is_empty(), "--socket is required");
        // Checked before rqlite is waited for: a bad flag fails at once.
        let gid = socket_gid(&f)?;
        let settings = Settings::from_flags(&f)?;
        let driver = settings.driver;
        // The unit starts after rqlite, but rqlite may still be electing a leader.
        let started = tokio::time::Instant::now();
        loop {
            match driver.ensure_schema().await {
                Ok(()) => break,
                Err(e) if started.elapsed() < READY => {
                    tracing::info!(error = %format!("{e:#}"), "rqlite is not ready; trying again");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e.context("rqlite did not become ready")),
            }
        }
        // Only store@ may open this socket (0005 "Drivers"): the owner is the registry's, not ours.
        let owner = sluis_registry::driver_owner(DRIVER)
            .with_context(|| format!("{DRIVER} is not a driver of the registry"))?;
        let cfg = ServerConfig {
            actor: DRIVER,
            boundary: f.boundary.clone(),
            socket: f.socket.clone(),
            mode: gid.map_or(0o600, |_| 0o660),
            socket_gid: gid,
            allow: Allow::OwnerOnly(owner),
            default_deadline: Duration::from_secs(30),
        };
        let sweeping = tokio::spawn(sweeper::run(
            driver.clone(),
            settings.sweep_interval,
            settings.retention,
        ));
        let served = sluis_kit::serve(cfg, driver.router(), cli::shutdown_signal()).await;
        sweeping.abort();
        served
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(check(&f).await)
    }

    async fn conformance(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(conformance(&f).await)
    }
}

/// Connects, reads `SELECT 1`-level proof at `linearizable` (the schema version read is one), and
/// verifies the schema version. A failure is a refusal: exit 3.
async fn check(f: &Flags) -> anyhow::Result<()> {
    let settings = Settings::from_flags(f)?;
    settings
        .driver
        .verify_schema(Level::Linearizable)
        .await
        .map_err(|e| Refused(format!("{e:#}")).into())
}

/// Runs the item suite against the driver serving on `--socket`. Any failed case, and no case at
/// all, is a failure.
async fn conformance(f: &Flags) -> anyhow::Result<()> {
    if f.socket.as_os_str().is_empty() {
        bail!("--socket is required");
    }
    let cases = sluis_conformance::item_suite(sluis_kit::dial(&f.socket)).await;
    sluis_conformance::report(&cases, &mut std::io::stdout())
        .map_err(|e| Refused(format!("{e:#}")).into())
}

fn main() {
    cli::main("rqlite", Rqlite, |c| {
        config::flags(c).arg(
            Arg::new("socket-gid")
                .long("socket-gid")
                .value_name("GID")
                .global(true)
                .help("Open the socket (mode 0660) to this group; the default is 0600"),
        )
    })
}
