//! The `sqlite` index driver of the indexer.
//!
//! ```text
//! driver-indexer-sqlite serve       --socket PATH --ro-socket PATH --state-dir DIR [--socket-gid GID] [--ro-socket-gid GID]
//! driver-indexer-sqlite check       --state-dir DIR
//! driver-indexer-sqlite conformance          # the index port suite over a temporary directory
//! driver-indexer-sqlite version
//! ```
//!
//! `--socket` is `index.sock`, for the indexer: the write side. `--ro-socket` is `index-ro.sock`, for the
//! reader: the read side, which has no way to write (PLAN.md "Socket layout").

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Arg;
use connectrpc::Router;
use sluis_driver_indexer_sqlite::service::{Read, Write};
use sluis_driver_indexer_sqlite::{Index, suite};
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig};
use sluis_proto::sluis::port::index::v2alpha1::{IndexReadServiceExt, IndexServiceExt};

/// The registry name of this driver's user and the actors that may call it (PLAN.md "Socket layout").
const NAME: &str = "driver-indexer-sqlite";
const WRITER: &str = "indexer";
const READER: &str = "reader";

struct Sqlite;

fn state_dir(f: &Flags) -> anyhow::Result<PathBuf> {
    match f.matches.get_one::<String>("state-dir") {
        Some(r) if !r.is_empty() => Ok(PathBuf::from(r)),
        _ => bail!("--state-dir is required"),
    }
}

/// A group flag: the socket is then 0660 for that group, so that the caller, who joins it, can
/// connect; without it the socket is 0600 for the driver's user alone. The peer check still decides
/// who may call.
fn gid(f: &Flags, flag: &str) -> anyhow::Result<Option<u32>> {
    match f.matches.get_one::<String>(flag) {
        None => Ok(None),
        Some(g) => match g.parse::<u32>() {
            Ok(g) if g != 0 => Ok(Some(g)),
            _ => bail!("--{flag} must be a group number other than 0"),
        },
    }
}

fn server(f: &Flags, socket: PathBuf, gid: Option<u32>, allow: Allow) -> ServerConfig {
    ServerConfig {
        actor: NAME,
        boundary: f.boundary.clone(),
        socket,
        mode: gid.map_or(0o600, |_| 0o660),
        socket_gid: gid,
        allow,
        default_deadline: Duration::from_secs(30),
    }
}

impl Commands for Sqlite {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        if f.socket.as_os_str().is_empty() {
            bail!("--socket is required");
        }
        let ro = match f.matches.get_one::<String>("ro-socket") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => bail!("--ro-socket is required"),
        };
        if ro == f.socket {
            bail!("--socket and --ro-socket are the same path");
        }
        // The database is checked before a socket exists: no index, no service.
        let index = Index::open(&state_dir(&f)?)?;
        let (wgid, rgid) = (gid(&f, "socket-gid")?, gid(&f, "ro-socket-gid")?);
        let write = server(&f, f.socket.clone(), wgid, Allow::OwnerOnly(WRITER));
        let read = server(&f, ro, rgid, Allow::Exact(READER));
        let wr = Arc::new(Write(index.clone())).register(Router::new());
        let rr = Arc::new(Read(index)).register(Router::new());
        // One signal stops both servers.
        let (stop, _) = tokio::sync::broadcast::channel::<()>(1);
        let (mut a, mut b) = (stop.subscribe(), stop.subscribe());
        let sig = tokio::spawn({
            let stop = stop.clone();
            async move {
                shutdown_signal().await;
                let _ = stop.send(());
            }
        });
        let w = sluis_kit::serve(write, wr, async move {
            let _ = a.recv().await;
        });
        let r = sluis_kit::serve(read, rr, async move {
            let _ = b.recv().await;
        });
        let (w, r) = tokio::join!(
            async {
                let out = w.await;
                let _ = stop.send(()); // a server that ended takes the other with it
                out
            },
            async {
                let out = r.await;
                let _ = stop.send(());
                out
            }
        );
        sig.abort();
        w.and(r)
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        let r = state_dir(&f)
            .and_then(|d| Index::open(&d))
            .and_then(|i| i.ping().map_err(|e| anyhow::anyhow!("{e}")));
        Some(r.map_err(|e| Refused(format!("{e:#}")).into()))
    }

    async fn conformance(&self, _f: Flags) -> Option<anyhow::Result<()>> {
        Some(suite::run_temp().context("the index port suite"))
    }
}

fn main() {
    sluis_kit::cli::main(NAME, Sqlite, |c| {
        c.arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_name("DIR")
                .global(true)
                .help("The directory of the index file"),
        )
        .arg(
            Arg::new("ro-socket")
                .long("ro-socket")
                .value_name("PATH")
                .global(true)
                .help("The read-only socket (index-ro.sock), for the reader"),
        )
        .arg(
            Arg::new("socket-gid")
                .long("socket-gid")
                .value_name("GID")
                .global(true)
                .help("Open --socket (mode 0660) to this group; the default is 0600"),
        )
        .arg(
            Arg::new("ro-socket-gid")
                .long("ro-socket-gid")
                .value_name("GID")
                .global(true)
                .help("Open --ro-socket (mode 0660) to this group; the default is 0600"),
        )
    });
}
