//! The `fs` blob driver of the writer.
//!
//! ```text
//! driver-writer-fs serve       --socket PATH --root DIR
//! driver-writer-fs check       --root DIR
//! driver-writer-fs conformance          # the port suite over a temporary directory
//! driver-writer-fs version
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Arg;
use connectrpc::Router;
use sluis_driver_writer_fs::service::Service;
use sluis_driver_writer_fs::{Fs, suite};
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig};
use sluis_proto::sluis::port::blob::v2alpha1::BlobServiceExt;

/// The registry name of this driver's user and the actor that owns it (PLAN.md "Socket layout").
const NAME: &str = "driver-writer-fs";
const OWNER: &str = "writer";

struct Fsd;

fn root(f: &Flags) -> anyhow::Result<PathBuf> {
    match f.matches.get_one::<String>("root") {
        Some(r) if !r.is_empty() => Ok(PathBuf::from(r)),
        _ => bail!("--root is required"),
    }
}

impl Commands for Fsd {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        if f.socket.as_os_str().is_empty() {
            bail!("--socket is required");
        }
        // The root is checked before the socket exists: no socket, no service.
        let fs = Fs::open(&root(&f)?)?;
        // A crash can leave temporary files; serve is the one command that may remove them.
        let swept = fs.sweep()?;
        tracing::info!(swept, "temporary files of an earlier run removed");
        let cfg = ServerConfig {
            actor: NAME,
            boundary: f.boundary,
            socket: f.socket,
            mode: 0o600,
            allow: Allow::OwnerOnly(OWNER),
            default_deadline: Duration::from_secs(30),
        };
        let router = Arc::new(Service(fs)).register(Router::new());
        sluis_kit::serve(cfg, router, shutdown_signal()).await
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        let r = root(&f).and_then(|r| Fs::open(&r));
        Some(r.map(|_| ()).map_err(|e| Refused(format!("{e:#}")).into()))
    }

    async fn conformance(&self, _f: Flags) -> Option<anyhow::Result<()>> {
        Some(suite::run_temp().context("the blob port suite"))
    }
}

fn main() {
    sluis_kit::cli::main(NAME, Fsd, |c| {
        c.arg(
            Arg::new("root")
                .long("root")
                .value_name("DIR")
                .global(true)
                .help("The blob directory"),
        )
    });
}
