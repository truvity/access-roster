//! The `file` driver of store@.
//!
//! ```text
//! file serve       --socket PATH --dir DIR
//! file check       --dir DIR
//! file conformance                 # the source suite over a temporary directory
//! file version
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Arg;
use connectrpc::Router;
use sluis_file::Dir;
use sluis_file::service::Service;
use sluis_kit::cli::{self, Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig};
use sluis_proto::sluis::port::source::v2alpha1::SourceServiceExt;

/// The registry name of this driver's user (docs/architecture/actors.yaml, drivers).
const DRIVER: &str = "driver-store-file";

struct File;

fn dir(f: &Flags) -> anyhow::Result<PathBuf> {
    match f.matches.get_one::<String>("dir") {
        Some(d) if !d.is_empty() => Ok(PathBuf::from(d)),
        _ => bail!("--dir is required"),
    }
}

impl Commands for File {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        if f.socket.as_os_str().is_empty() {
            bail!("--socket is required");
        }
        // The directory is checked before the socket exists: no directory, no service.
        let dir = Dir::open(&dir(&f)?)?;
        // Only store@ may open this socket (0005 "Drivers"): the owner is the registry's.
        let owner = sluis_registry::driver_owner(DRIVER)
            .with_context(|| format!("{DRIVER} is not a driver of the registry"))?;
        let cfg = ServerConfig {
            actor: DRIVER,
            boundary: f.boundary,
            socket: f.socket,
            mode: 0o600,
            allow: Allow::OwnerOnly(owner),
            default_deadline: Duration::from_secs(30),
        };
        let router = Arc::new(Service(dir)).register(Router::new());
        sluis_kit::serve(cfg, router, shutdown_signal()).await
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        let r = dir(&f).and_then(|d| Dir::open(&d));
        Some(r.map(|_| ()).map_err(|e| Refused(format!("{e:#}")).into()))
    }

    async fn conformance(&self, _f: Flags) -> Option<anyhow::Result<()>> {
        Some(sluis_file::suite::run_temp().context("the source suite"))
    }
}

fn main() {
    cli::main("file", File, |c| {
        c.arg(
            Arg::new("dir")
                .long("dir")
                .value_name("DIR")
                .global(true)
                .help("The directory of signed config documents, /etc/sluis/config/<boundary>"),
        )
    });
}
