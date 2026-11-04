//! The command line of `signer`: `serve`, `check`, `version` (cli.md).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::bail;
use clap::{Arg, Command};
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};

use crate::ring::Timing;
use crate::service::{Config, Sockets, serve};

/// How long `serve` waits for key@ and store@.
const START_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one attempt to reach a socket may take.
const REACH: Duration = Duration::from_secs(2);

/// The flags of `signer` beyond the global ones of the kit.
#[must_use]
pub fn extra(c: Command) -> Command {
    c.arg(
        Arg::new("run-dir")
            .long("run-dir")
            .value_name("DIR")
            .default_value("/run/sluis")
            .global(true)
            .help("The directory of the sockets of the actors"),
    )
    .arg(
        Arg::new("node")
            .long("node")
            .value_name("NAME")
            .global(true)
            .help("The node (board) this instance runs on; default the host name"),
    )
    .arg(
        Arg::new("socket-gid")
            .long("socket-gid")
            .value_name("GID")
            .global(true)
            .help("The group of the listening socket (not 0)"),
    )
}

/// `signer`.
pub struct Signer;

fn sockets(f: &Flags) -> Sockets {
    let run_dir = f
        .matches
        .get_one::<String>("run-dir")
        .map_or_else(|| PathBuf::from("/run/sluis"), PathBuf::from);
    Sockets::under(&run_dir, &f.boundary)
}

fn boundary(f: &Flags) -> anyhow::Result<&str> {
    if f.boundary.is_empty() {
        bail!("--boundary is needed");
    }
    Ok(&f.boundary)
}

async fn reach(path: &Path) -> Result<(), String> {
    match tokio::time::timeout(REACH, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{:?}", e.kind())),
        Err(_) => Err("timed out".into()),
    }
}

impl Commands for Signer {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        let boundary = boundary(&f)?.to_owned();
        let run_dir = f
            .matches
            .get_one::<String>("run-dir")
            .map_or_else(|| PathBuf::from("/run/sluis"), PathBuf::from);
        let socket = if f.socket.as_os_str().is_empty() {
            run_dir.join("signer").join(format!("{boundary}.sock"))
        } else {
            f.socket.clone()
        };
        let socket_gid = f
            .matches
            .get_one::<String>("socket-gid")
            .map(|g| g.parse::<u32>())
            .transpose()
            .map_err(|_| anyhow::anyhow!("--socket-gid: a numeric group id"))?;
        let node = match f.matches.get_one::<String>("node") {
            Some(n) => n.clone(),
            None => std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|h| h.trim().to_owned())
                .map_err(|e| {
                    anyhow::anyhow!("--node is needed: the host name is unreadable ({e})")
                })?,
        };
        serve(
            Config {
                node,
                sockets: sockets(&f),
                boundary,
                socket,
                socket_gid,
                release: sluis_version::VERSION.to_owned(),
                timing: Timing::DEFAULT,
                start_timeout: START_TIMEOUT,
                now: None,
            },
            shutdown_signal(),
        )
        .await
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(check(&f).await)
    }
}

async fn check(f: &Flags) -> anyhow::Result<()> {
    boundary(f)?;
    let s = sockets(f);
    let mut missing = Vec::new();
    for (name, path) in [
        ("store@", &s.store),
        ("key@", &s.key),
        ("audit transport", &s.audit),
    ] {
        if let Err(why) = reach(path).await {
            missing.push(format!("{name}: {} unreachable ({why})", path.display()));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Refused(missing.join("; ")).into())
    }
}
