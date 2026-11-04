//! The `spool` audit transport driver of the writer.
//!
//! ```text
//! driver-writer-spool serve   --boundary B --socket-dir DIR --root DIR [--socket-gid GID] [--limit-bytes N] [--segment-bytes N]
//! driver-writer-spool check   --root DIR
//! driver-writer-spool conformance          # the transport suite over a temporary directory
//! driver-writer-spool version
//! ```
//!
//! `serve` listens on `DIR/emit.sock` (every emitting actor of the call graph) and
//! `DIR/receive.sock` (the writer only), mode 0600, or 0660 for the group of `--socket-gid`: the guard
//! of the kit decides by peer uid, the mode is the second wall.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Arg;
use connectrpc::Router;
use sluis_driver_writer_spool::service::{Consume, Emit};
use sluis_driver_writer_spool::{Config, Spool, check_root, suite};
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig};
use sluis_proto::sluis::port::transport::v2alpha1::TransportServiceExt;

/// The registry name of this driver's user (PLAN.md "Socket layout").
const NAME: &str = "driver-writer-spool";
/// The callee the call graph knows the audit transport by.
const CALLEE: &str = "transport";
/// The group of both sockets (`--socket-gid`), if given. The sockets are then 0660 for that group, so
/// that the emitters and the writer, who join it, can connect; without it they are 0600 for the
/// driver's user alone. The peer check still decides who may call.
fn socket_gid(f: &Flags) -> anyhow::Result<Option<u32>> {
    match f.matches.get_one::<String>("socket-gid") {
        None => Ok(None),
        Some(g) => match g.parse::<u32>() {
            Ok(g) if g != 0 => Ok(Some(g)),
            _ => bail!("--socket-gid must be a group number other than 0"),
        },
    }
}

/// A consumer stream lives for as long as the writer wants; it reconnects when this ends.
const STREAM_DEADLINE: Duration = Duration::from_secs(24 * 3600);

struct Spoold;

fn root(f: &Flags) -> anyhow::Result<PathBuf> {
    match f.matches.get_one::<String>("root") {
        Some(r) if !r.is_empty() => Ok(PathBuf::from(r)),
        _ => bail!("--root is required"),
    }
}

fn config(f: &Flags) -> Config {
    let d = Config::default();
    Config {
        limit: f
            .matches
            .get_one::<u64>("limit-bytes")
            .copied()
            .unwrap_or(d.limit),
        segment: f
            .matches
            .get_one::<u64>("segment-bytes")
            .copied()
            .unwrap_or(d.segment),
    }
}

impl Commands for Spoold {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        let Some(dir) = f
            .matches
            .get_one::<String>("socket-dir")
            .filter(|d| !d.is_empty())
        else {
            bail!("--socket-dir is required");
        };
        let dir = PathBuf::from(dir);
        let gid = socket_gid(&f)?;
        // The directory is recovered before a socket exists: no socket, no service.
        let spool = Spool::open(&root(&f)?, config(&f))?;
        tracing::info!(
            depth = spool.depth(),
            bytes = spool.bytes(),
            "spool recovered"
        );
        let cfg = |socket: &str, allow, default_deadline| ServerConfig {
            actor: CALLEE,
            boundary: f.boundary.clone(),
            socket: dir.join(socket),
            mode: gid.map_or(0o600, |_| 0o660),
            socket_gid: gid,
            allow,
            default_deadline,
        };
        let emit = Arc::new(Emit {
            spool: spool.clone(),
            boundary: f.boundary.clone(),
        })
        .register(Router::new());
        let consume = Arc::new(Consume(spool.clone())).register(Router::new());
        let a = sluis_kit::serve(
            cfg("emit.sock", Allow::CallGraph, Duration::from_secs(30)),
            emit,
            spool.closed(),
        );
        let b = sluis_kit::serve(
            cfg("receive.sock", Allow::Exact("writer"), STREAM_DEADLINE),
            consume,
            spool.closed(),
        );
        let stop = async {
            shutdown_signal().await;
            spool.close();
            Ok(())
        };
        tokio::try_join!(a, b, stop).map(|_| ())
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        // A check does not recover: recovery cuts a torn tail, and a check changes nothing.
        let r = root(&f).and_then(|r| check_root(&r));
        Some(r.map_err(|e| Refused(format!("{e:#}")).into()))
    }

    async fn conformance(&self, _f: Flags) -> Option<anyhow::Result<()>> {
        Some(suite::run_temp().context("the transport suite"))
    }
}

fn main() {
    sluis_kit::cli::main(NAME, Spoold, |c| {
        c.arg(
            Arg::new("root")
                .long("root")
                .value_name("DIR")
                .global(true)
                .help("The spool directory"),
        )
        .arg(
            Arg::new("socket-dir")
                .long("socket-dir")
                .value_name("DIR")
                .global(true)
                .help("Where emit.sock and receive.sock are made"),
        )
        .arg(
            Arg::new("limit-bytes")
                .long("limit-bytes")
                .value_name("N")
                .global(true)
                .value_parser(clap::value_parser!(u64))
                .help("The most bytes the spool holds; past it emits are refused"),
        )
        .arg(
            Arg::new("segment-bytes")
                .long("segment-bytes")
                .value_name("N")
                .global(true)
                .value_parser(clap::value_parser!(u64))
                .help("The size at which a segment is closed"),
        )
    });
}
