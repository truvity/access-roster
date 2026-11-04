//! The read-only `fs` blob driver of the indexer and the reader.
//!
//! ```text
//! driver-indexer-fs serve       --socket PATH --reader-socket PATH --root DIR [--socket-gid GID] [--reader-socket-gid GID]
//! driver-indexer-fs check       --root DIR
//! driver-indexer-fs conformance          # the read side of the blob port suite over a temporary directory
//! driver-indexer-fs version
//! ```
//!
//! `--socket` is `blob.sock`, for the indexer. `--reader-socket` is `blob-ro.sock`, for the reader. The directory
//! is the one `driver-writer-fs` keeps; the uid that must own it is that driver's uid in this process's own uid
//! block (REQ-ISO-072), taken from the registry, so no number is passed in.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Arg;
use connectrpc::Router;
use sluis_driver_indexer_fs::{NAME, ReadOnly, WRITER_DRIVER, suite};
use sluis_driver_writer_fs::Fs;
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig};
use sluis_proto::sluis::port::blob::v2alpha1::BlobServiceExt;

/// The actors that may call it, one socket each (PLAN.md "Socket layout").
const INDEXER: &str = "indexer";
const READER: &str = "reader";

struct Fsd;

fn root(f: &Flags) -> anyhow::Result<PathBuf> {
    match f.matches.get_one::<String>("root") {
        Some(r) if !r.is_empty() => Ok(PathBuf::from(r)),
        _ => bail!("--root is required"),
    }
}

/// Opens the directory of the writer's driver: it must belong to that driver, in the uid block this process
/// runs in.
fn open(root: &std::path::Path) -> anyhow::Result<Fs> {
    let me = rustix::process::geteuid().as_raw();
    let (name, block) = sluis_registry::name_for_uid(me)
        .with_context(|| format!("own uid {me} is not a uid of the registry"))?;
    if name != NAME {
        bail!("own uid {me} is {name}, not {NAME}");
    }
    let owner = sluis_registry::uid(WRITER_DRIVER, block)
        .with_context(|| format!("{WRITER_DRIVER} has no uid in block {block}"))?;
    Fs::open_read_only(root, owner)
}

/// A group flag: the socket is then 0660 for that group, so that the caller, who joins it, can connect; without
/// it the socket is 0600 for the driver's user alone. The peer check still decides who may call.
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

impl Commands for Fsd {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        if f.socket.as_os_str().is_empty() {
            bail!("--socket is required");
        }
        let ro = match f.matches.get_one::<String>("reader-socket") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => bail!("--reader-socket is required"),
        };
        if ro == f.socket {
            bail!("--socket and --reader-socket are the same path");
        }
        // The root is checked before a socket exists: no directory, no service.
        let fs = open(&root(&f)?)?;
        let (igid, rgid) = (gid(&f, "socket-gid")?, gid(&f, "reader-socket-gid")?);
        let for_indexer = server(&f, f.socket.clone(), igid, Allow::OwnerOnly(INDEXER));
        let for_reader = server(&f, ro, rgid, Allow::Exact(READER));
        let router = || Arc::new(ReadOnly(fs.clone())).register(Router::new());
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
        let i = sluis_kit::serve(for_indexer, router(), async move {
            let _ = a.recv().await;
        });
        let r = sluis_kit::serve(for_reader, router(), async move {
            let _ = b.recv().await;
        });
        let (i, r) = tokio::join!(
            async {
                let out = i.await;
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
        i.and(r)
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        let r = root(&f).and_then(|r| open(&r));
        Some(r.map(|_| ()).map_err(|e| Refused(format!("{e:#}")).into()))
    }

    async fn conformance(&self, _f: Flags) -> Option<anyhow::Result<()>> {
        Some(suite::run_temp().context("the blob port suite, read side"))
    }
}

fn main() {
    sluis_kit::cli::main(NAME, Fsd, |c| {
        c.arg(
            Arg::new("root")
                .long("root")
                .value_name("DIR")
                .global(true)
                .help("The blob directory of driver-writer-fs"),
        )
        .arg(
            Arg::new("reader-socket")
                .long("reader-socket")
                .value_name("PATH")
                .global(true)
                .help("The socket for the reader (blob-ro.sock)"),
        )
        .arg(
            Arg::new("socket-gid")
                .long("socket-gid")
                .value_name("GID")
                .global(true)
                .help("Open --socket (mode 0660) to this group; the default is 0600"),
        )
        .arg(
            Arg::new("reader-socket-gid")
                .long("reader-socket-gid")
                .value_name("GID")
                .global(true)
                .help("Open --reader-socket (mode 0660) to this group; the default is 0600"),
        )
    });
}
