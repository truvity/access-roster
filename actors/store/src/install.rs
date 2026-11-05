//! The installation a bootstrap file is checked against, and what each driver of store@ declares it fits
//! (ADR 0011, "Runtime kinds"; ADR 0005, "Drivers"; runtimes/index.md "Which drivers fit which runtime").
//!
//! An installation is not a configuration key, so neither file carries its runtime: `sluis config check` is told
//! (`--runtime`). The model is that one fact and the table below; it grows by a row for each driver that arrives
//! and by a field when a rule first needs one (the node count comes with the first driver that cares about it).
//! The table is also the list of drivers that each port of the bootstrap file accepts, so the two cannot differ.

use crate::bootstrap::Bootstrap;
use crate::config::offline::Check;

/// The kind of runtime (ADR 0011, "Runtime kinds").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    BareMetal,
    Serverless,
    Kubernetes,
}

impl Runtime {
    /// The names the flag takes, as the requirements and the runtime pages write them.
    pub const NAMES: [&'static str; 3] = ["bare-metal", "serverless", "kubernetes"];

    /// The runtime of a name, or `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "bare-metal" => Some(Self::BareMetal),
            "serverless" => Some(Self::Serverless),
            "kubernetes" => Some(Self::Kubernetes),
            _ => None,
        }
    }

    /// The name of the runtime.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BareMetal => "bare-metal",
            Self::Serverless => "serverless",
            Self::Kubernetes => "kubernetes",
        }
    }
}

/// What a check knows of the installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Installation {
    pub runtime: Runtime,
}

/// What a driver of store@ declares: the port of the bootstrap file it serves, its name, and the runtimes it fits.
/// A runtime that is not listed lacks something the driver needs: systemd credentials, or a disk and a node that
/// other nodes can reach.
#[derive(Debug)]
pub struct Driver {
    pub port: &'static str,
    pub name: &'static str,
    pub runtimes: &'static [Runtime],
}

const ALL: &[Runtime] = &[Runtime::BareMetal, Runtime::Serverless, Runtime::Kubernetes];
const BARE_METAL: &[Runtime] = &[Runtime::BareMetal];

/// The drivers of store@'s four ports that the first working version accepts (bootstrap-file.md "Drivers").
pub const DRIVERS: &[Driver] = &[
    Driver {
        port: "config_source",
        name: "file",
        runtimes: ALL,
    },
    Driver {
        port: "secret_source",
        name: "credential",
        runtimes: BARE_METAL,
    },
    Driver {
        port: "durable",
        name: "rqlite",
        runtimes: BARE_METAL,
    },
    Driver {
        port: "temp",
        name: "rqlite",
        runtimes: BARE_METAL,
    },
];

/// The driver `name` of `port`, if the port has one by that name.
#[must_use]
pub fn declared(port: &str, name: &str) -> Option<&'static Driver> {
    DRIVERS.iter().find(|d| d.port == port && d.name == name)
}

/// The drivers of the bootstrap file against the installation: one `installation` check for each port, at the path
/// of its `driver` field. A driver that does not fit refuses with the field and the runtime, never the driver's name
/// (REQ-DATA-072, REQ-OPS-009).
#[must_use]
pub fn check_drivers(b: &Bootstrap, i: Installation) -> Vec<Check> {
    b.destinations()
        .iter()
        .map(|(port, d)| {
            let path = format!("{port}.driver");
            // The bootstrap file refuses a driver the table does not list, so a port always finds its row; a port
            // that did not would be a defect of the table, and the check says so rather than pass it.
            match declared(port, &d.driver) {
                Some(row) if row.runtimes.contains(&i.runtime) => Check::ok("installation", &path),
                Some(_) => Check::fail(
                    "installation",
                    &path,
                    format!("the driver does not fit the {} runtime", i.runtime.name()),
                ),
                None => Check::fail("installation", &path, "the driver is not declared"),
            }
        })
        .collect()
}

/// The check that stands in when no runtime was named: the drivers cannot be judged, and a check that cannot run is
/// reported as not run, never as passed.
#[must_use]
pub fn not_run() -> Check {
    Check::not_run_because(
        "installation",
        "",
        "name the runtime with --runtime to check the drivers against it",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../tests/installations/local/bootstrap.yaml");

    /// Each port accepts exactly the drivers the table declares for it, and no driver of another port: the bootstrap
    /// file reads the same table.
    #[test]
    fn each_port_accepts_exactly_the_drivers_declared_for_it() {
        let accepted = |port: &str, driver: &str| declared(port, driver).is_some();
        for port in ["config_source", "secret_source", "durable", "temp"] {
            for driver in ["file", "credential", "rqlite", "dynamodb", ""] {
                let want = matches!(
                    (port, driver),
                    ("config_source", "file")
                        | ("secret_source", "credential")
                        | ("durable" | "temp", "rqlite")
                );
                assert_eq!(accepted(port, driver), want, "{port}: {driver}");
            }
        }
        assert!(Bootstrap::parse(EXAMPLE).is_ok());
        for (from, to, path) in [
            (
                "config_source: { driver: file,",
                "config_source: { driver: rqlite,",
                "config_source.driver",
            ),
            (
                "durable: { driver: rqlite,",
                "durable: { driver: file,",
                "durable.driver",
            ),
            (
                "temp: { driver: rqlite,",
                "temp: { driver: credential,",
                "temp.driver",
            ),
            (
                "secret_source: { driver: credential,",
                "secret_source: { driver: file,",
                "secret_source.driver",
            ),
        ] {
            assert!(EXAMPLE.contains(from), "{from}");
            let e = Bootstrap::parse(&EXAMPLE.replacen(from, to, 1)).unwrap_err();
            assert!(e.0.starts_with(&format!("{path}: ")), "{e}");
        }
    }
}
