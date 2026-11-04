//! The `entry` executable: `serve | check | version | conformance` (cli.md, `sluis-kit::cli`).

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Arg;
use entry::{Config, Front, Sockets};
use sluis_kit::cli::{self, Commands, Flags, shutdown_signal};

struct Entry;

impl Commands for Entry {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        let boundary = f.boundary.clone();
        if boundary.is_empty() {
            bail!("--boundary is needed");
        }
        let run_dir = PathBuf::from(
            f.matches
                .get_one::<String>("run-dir")
                .cloned()
                .unwrap_or_default(),
        );
        let (front, suffix) = match f.matches.get_one::<String>("front").map(String::as_str) {
            Some("audit") => (Front::Audit, "-audit"),
            _ => (Front::Identity, ""),
        };
        let socket = if f.socket.as_os_str().is_empty() {
            run_dir
                .join("entry")
                .join(format!("{boundary}{suffix}.sock"))
        } else {
            f.socket.clone()
        };
        let mode = f
            .matches
            .get_one::<String>("socket-mode")
            .map(|m| u32::from_str_radix(m, 8))
            .transpose()
            .context("--socket-mode: an octal mode such as 660")?
            .unwrap_or(0o660);
        let group = f
            .matches
            .get_one::<String>("socket-group")
            .map(|g| g.parse::<u32>())
            .transpose()
            .context("--socket-group: a numeric group id")?;
        let sockets = Sockets::under(&run_dir, &boundary);
        entry::serve(
            Config {
                boundary,
                front,
                socket,
                socket_mode: mode,
                socket_group: group,
                sockets,
                release: sluis_version::VERSION.to_owned(),
            },
            shutdown_signal(),
        )
        .await
    }
}

fn main() {
    cli::main("entry", Entry, |c| {
        c.arg(
            Arg::new("run-dir")
                .long("run-dir")
                .value_name("DIR")
                .default_value("/run/sluis")
                .global(true)
                .help("The directory of the sockets of the actors"),
        )
        .arg(
            Arg::new("front")
                .long("front")
                .value_parser(["identity", "audit"])
                .default_value("identity")
                .global(true)
                .help("The route set: identity, or audit (the audit front of ADR 0028)"),
        )
        .arg(
            Arg::new("socket-mode")
                .long("socket-mode")
                .value_name("OCTAL")
                .global(true)
                .help("The mode of the listening socket (default 660)"),
        )
        .arg(
            Arg::new("socket-group")
                .long("socket-group")
                .value_name("GID")
                .global(true)
                .help("The group of the listening socket, the forwarder's"),
        )
    })
}
