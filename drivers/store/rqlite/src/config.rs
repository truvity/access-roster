//! The flags of `serve` and `check`, and the duration syntax they share.

use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Arg, Command};
use sluis_kit::cli::Flags;

use crate::client::Rq;
use crate::service::Driver;
use crate::sql::Ns;

/// Adds the driver's flags to the command line. They are global, so `rqlite serve --namespace
/// durable` and `rqlite --namespace durable serve` both work.
pub fn flags(cmd: Command) -> Command {
    // planned: TLS and auth for the rqlite client (D-13)
    let global = |a: Arg| a.global(true);
    cmd.arg(global(
        Arg::new("rqlite-url")
            .long("rqlite-url")
            .value_name("URL")
            .help("rqlite's client API, http://HOST:PORT (loopback on a board, 0005 Engines)"),
    ))
    .arg(global(
        Arg::new("namespace")
            .long("namespace")
            .value_name("NS")
            .value_parser(["durable", "temp"])
            .help("The port this driver serves: durable or temp"),
    ))
    .arg(global(
        Arg::new("sweep-interval")
            .long("sweep-interval")
            .value_name("DURATION")
            .default_value("30s")
            .help("How often the leader's driver frees expired items, e.g. 30s"),
    ))
    .arg(global(
        Arg::new("changelog-retention")
            .long("changelog-retention")
            .value_name("DURATION")
            .default_value("24h")
            .help("How long change-log rows are kept, e.g. 24h"),
    ))
    .arg(global(
        Arg::new("basic-auth-file")
            .long("basic-auth-file")
            .value_name("FILE")
            .help("A file holding user:password for rqlite's basic authentication"),
    ))
}

/// What the flags say.
pub struct Settings {
    /// The driver over rqlite.
    pub driver: Driver,
    /// `--sweep-interval`.
    pub sweep_interval: Duration,
    /// `--changelog-retention`.
    pub retention: Duration,
}

impl Settings {
    /// Reads the flags.
    ///
    /// # Errors
    ///
    /// For a missing or malformed flag, or an unreadable credential file. The error names the
    /// flag, never its value.
    pub fn from_flags(f: &Flags) -> anyhow::Result<Self> {
        let get = |name: &str| f.matches.get_one::<String>(name).cloned();
        let url = get("rqlite-url").context("--rqlite-url is required")?;
        let ns = Ns::new(&get("namespace").context("--namespace is required")?)?;
        let auth = match get("basic-auth-file") {
            Some(path) => {
                Some(std::fs::read_to_string(&path).context("--basic-auth-file: cannot be read")?)
            }
            None => None,
        };
        let duration = |name: &str| -> anyhow::Result<Duration> {
            parse_duration(&get(name).unwrap_or_default()).with_context(|| format!("--{name}"))
        };
        Ok(Self {
            driver: Driver::new(Rq::new(&url, auth.as_deref())?, ns),
            sweep_interval: duration("sweep-interval")?,
            retention: duration("changelog-retention")?,
        })
    }
}

/// A duration such as `200ms`, `30s`, `5m` or `24h`. Zero is refused: no interval and no
/// retention of zero makes sense.
///
/// # Errors
///
/// For anything else.
pub fn parse_duration(text: &str) -> anyhow::Result<Duration> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(split);
    let n: u64 = digits.parse().context("want a number and a unit: 30s")?;
    let d = match unit {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n.saturating_mul(60)),
        "h" => Duration::from_secs(n.saturating_mul(3600)),
        _ => bail!("want a number and a unit (ms, s, m, h): 30s"),
    };
    anyhow::ensure!(!d.is_zero(), "must not be zero");
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("200ms").unwrap(), Duration::from_millis(200));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
        for bad in ["", "s", "30", "30x", "0s", "-1s", "1.5s", "1 s"] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
    }
}
