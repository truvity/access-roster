//! The command line of `store`: `serve`, `check`, `version` (ADR 0005, "Drivers"; cli.md).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, bail};
use clap::{Arg, Command};
use connectrpc::Router;
use sluis_kit::cli::{Commands, Flags, Refused, Usage, shutdown_signal};
use sluis_kit::{Allow, ServerConfig, dial};
use sluis_proto::sluis::store::v2alpha1::StoreServiceExt as _;

use crate::audit::EmitterSink;
use crate::bootstrap::Bootstrap;
use crate::config::{self, ConfigSnapshot, Loader};
use crate::engine::DriverEngine;
use crate::grant::KeyOpener;
use crate::secret::SourceSecrets;
use crate::service::{Deps, Service};

/// The deadline of a call that carries none (contracts.md "Every call").
const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);
/// How long one attempt to reach a socket may take.
const REACH_ATTEMPT: Duration = Duration::from_secs(2);
/// The pause between attempts while `serve` waits for a driver.
const REACH_PAUSE: Duration = Duration::from_millis(250);

/// The flags of `store` beyond the global ones of the kit.
#[must_use]
pub fn extra(c: Command) -> Command {
    c.arg(
        Arg::new("bootstrap")
            .long("bootstrap")
            .global(true)
            .value_name("FILE")
            .help("The bootstrap file, /etc/sluis/bootstrap.d/<boundary>.yaml"),
    )
    .arg(
        Arg::new("key-socket")
            .long("key-socket")
            .global(true)
            .value_name("PATH")
            .help("key@'s socket for store@; default /run/sluis/key/<boundary>/store/key.sock"),
    )
    .arg(
        Arg::new("validate")
            .long("validate")
            .global(true)
            .value_name("DIR")
            .help(
                "check only: validate the bootstrap file and the signed config documents in DIR offline, \
                 as store@ does at load, and probe no socket (what `sluis config check` runs)",
            ),
    )
    .arg(
        Arg::new("explain")
            .long("explain")
            .global(true)
            .action(clap::ArgAction::SetTrue)
            .requires("validate")
            .conflicts_with("runtime")
            .help(
                "check --validate only: also print what each setting resolves to and where it comes from, \
                 for a set that passes (what `sluis config explain` runs)",
            ),
    )
    .arg(
        Arg::new("against")
            .long("against")
            .global(true)
            .value_name("OLD")
            .requires("validate")
            .conflicts_with("explain")
            .help(
                "check --validate only: the previous bootstrap file; a warning names each setting that \
                 differs from it (what `sluis config check --against` runs)",
            ),
    )
    .arg(
        Arg::new("field")
            .long("field")
            .global(true)
            .value_name("PATH")
            .requires("explain")
            .help("check --validate --explain only: print the settings under PATH"),
    )
    .arg(
        Arg::new("runtime")
            .long("runtime")
            .global(true)
            .value_name("RUNTIME")
            .value_parser(clap::builder::PossibleValuesParser::new(
                crate::install::Runtime::NAMES,
            ))
            .help(
                "check --validate only: the runtime of the installation, bare-metal, serverless or kubernetes; \
                 the drivers of the bootstrap file are checked against it; other commands ignore it",
            ),
    )
    .arg(
        Arg::new("transport-socket")
            .long("transport-socket")
            .global(true)
            .value_name("PATH")
            .help(
                "The audit transport's emit socket; default /run/sluis/audit/<boundary>/emit.sock",
            ),
    )
}

/// The paths a run uses, from the flags and the boundary of the file.
struct Paths {
    key: PathBuf,
    transport: PathBuf,
    service: PathBuf,
}

fn paths(f: &Flags, boundary: &str) -> Paths {
    let flag = |name: &str| {
        f.matches
            .get_one::<String>(name)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    Paths {
        key: flag("key-socket")
            .unwrap_or_else(|| format!("/run/sluis/key/{boundary}/store/key.sock").into()),
        transport: flag("transport-socket")
            .unwrap_or_else(|| format!("/run/sluis/audit/{boundary}/emit.sock").into()),
        service: if f.socket.as_os_str().is_empty() {
            format!("/run/sluis/store/{boundary}.sock").into()
        } else {
            f.socket.clone()
        },
    }
}

fn load(f: &Flags) -> anyhow::Result<Bootstrap> {
    load_as(f, Some(rustix::process::geteuid().as_raw()))
}

/// [`load`], with the owner rule only when `own` is given (see [`Bootstrap::load_with`]).
fn load_as(f: &Flags, own: Option<u32>) -> anyhow::Result<Bootstrap> {
    let path = f
        .matches
        .get_one::<String>("bootstrap")
        .filter(|s| !s.is_empty())
        .context("--bootstrap FILE is required")?;
    let b = Bootstrap::load_with(Path::new(path), own).map_err(|e| Refused(e.to_string()))?;
    if !f.boundary.is_empty() && f.boundary != b.boundary {
        return Err(Refused("--boundary is not the boundary of the bootstrap file".into()).into());
    }
    Ok(b)
}

/// Whether something listens on the socket.
async fn reach(path: &Path) -> Result<(), String> {
    match tokio::time::timeout(REACH_ATTEMPT, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{:?}", e.kind())),
        Err(_) => Err("timed out".into()),
    }
}

/// The sockets store@ needs before it serves, with the name of each.
///
/// key@ is not among them. key@'s `Init` reads its own kinds from store@, so key@ cannot be up
/// before store@ serves: waiting for it here would deadlock the two units. store@ dials key@ at the
/// first use (`KeyOpener`), and a call that needs it answers `unavailable` until it is reachable
/// (ADR 0007 "Sealed grants": store@ fails closed).
fn needed(b: &Bootstrap, transport: &Path) -> Vec<(String, PathBuf)> {
    let mut v: Vec<_> = b
        .destinations()
        .into_iter()
        .map(|(port, d)| (format!("{port} ({} driver)", d.driver), d.socket.clone()))
        .collect();
    v.push(("audit transport".into(), transport.to_owned()));
    v
}

/// The warning for a key@ that does not answer yet, or `None` when it does.
async fn key_warning(key: &Path) -> Option<String> {
    reach(key).await.err().map(|why| {
        format!(
            "key@: {} unreachable ({why}); store@ answers unavailable to a call that needs key@ until it is up",
            key.display()
        )
    })
}

/// The unreachable sockets among `wanted`, one line each.
async fn unreachable(wanted: &[(String, PathBuf)]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, path) in wanted {
        if let Err(why) = reach(path).await {
            out.push(format!("{name}: {} unreachable ({why})", path.display()));
        }
    }
    out
}

/// `store`.
pub struct Store;

impl Commands for Store {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        let b = load(&f)?;
        let p = paths(&f, &b.boundary);

        // A cold start refuses on any failure (ADR 0005): wait for the drivers up to start_timeout.
        let wanted = needed(&b, &p.transport);
        let deadline = Instant::now() + b.start_timeout;
        loop {
            let missing = unreachable(&wanted).await;
            if missing.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "not started within {}s: {}",
                    b.start_timeout.as_secs(),
                    missing.join("; ")
                );
            }
            tokio::time::sleep(REACH_PAUSE).await;
        }

        // key@ may come up after store@, and only after it (key@'s Init reads store@): serve without it.
        if let Some(w) = key_warning(&p.key).await {
            tracing::warn!("{w}");
        }

        // The signed config, loaded as one snapshot. A cold start refuses on any failure.
        let left = deadline.saturating_duration_since(Instant::now());
        let loader = Loader::start(&dial(&b.config_source.socket), &b, left)
            .await
            .map_err(|e| anyhow::anyhow!("config: {e}"))?;

        let svc = Service::new(Deps {
            boundary: b.boundary.clone(),
            durable: DriverEngine::new(&dial(&b.durable.socket), "durable"),
            temp: DriverEngine::new(&dial(&b.temp.socket), "temp"),
            grants: KeyOpener::new(&dial(&p.key)),
            config: Arc::clone(&loader) as Arc<dyn ConfigSnapshot>,
            secrets: Arc::new(SourceSecrets::new(&dial(&b.secret_source.socket))),
            audit: EmitterSink(sluis_audit::Emitter::new(sluis_audit::Config {
                actor: "store".into(),
                boundary: b.boundary.clone(),
                release: sluis_version::VERSION.into(),
                transport_socket: p.transport.clone(),
                // store@ has no pseudonym rule: it names no person.
                key_socket: None,
                now: None,
            })?),
            clock: Arc::new(SystemTime::now),
        });
        svc.announce_start(
            b.destinations()
                .into_iter()
                .map(|(port, d)| (port, d.driver.clone()))
                .collect(),
            loader.snapshot().summaries(),
        )
        .await;
        let svc = Arc::new(svc);
        // A changed document reloads the whole set; a bad one keeps the snapshot in force.
        let reloading = tokio::spawn({
            let (loader, svc) = (Arc::clone(&loader), Arc::clone(&svc));
            async move {
                config::reload::run(loader, |outcome| {
                    let svc = Arc::clone(&svc);
                    async move { svc.announce_reload(&outcome).await }
                })
                .await;
            }
        });
        let router = svc.register(Router::new());
        let served = sluis_kit::serve(
            ServerConfig {
                actor: "store",
                boundary: b.boundary.clone(),
                socket: p.service,
                mode: 0o660,
                socket_gid: None,
                allow: Allow::CallGraph,
                default_deadline: DEFAULT_DEADLINE,
            },
            router,
            shutdown_signal(),
        )
        .await;
        reloading.abort();
        served
    }

    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(self.check_inner(&f).await)
    }
}

impl Store {
    async fn check_inner(&self, f: &Flags) -> anyhow::Result<()> {
        if let Some(dir) = f
            .matches
            .get_one::<String>("validate")
            .filter(|s| !s.is_empty())
        {
            return validate(f, Path::new(dir));
        }
        let b = load(f)?;
        let p = paths(f, &b.boundary);
        let missing = unreachable(&needed(&b, &p.transport)).await;
        // key@ is a warning, not a failure: it starts after store@ (see `needed`).
        if let Some(w) = key_warning(&p.key).await {
            tracing::warn!("{w}");
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Refused(missing.join("; ")).into())
        }
    }
}

/// `store check --validate DIR`: the offline check of the bootstrap file and the config set in `DIR`, with the rules
/// store@ applies at load and the same code (ADR 0012, "The configuration check runs store@'s own rules"). It prints
/// one line per check, or with `--output json` one object `{"checks": [...]}` on standard output; a failed check is a
/// refusal (exit 3). Nothing is printed but kinds, paths and rules: never a value of a document.
fn validate(f: &Flags, dir: &Path) -> anyhow::Result<()> {
    let explain = f.matches.get_flag("explain");
    // The owner of the file is the host's to check (#1419); its mode and content are the file's.
    let mut groups = Vec::new();
    let checks = match load_as(f, None) {
        Ok(b) => {
            let mut c = vec![config::offline::Check {
                name: "bootstrap",
                result: "ok",
                path: String::new(),
                rule: String::new(),
            }];
            // The runtime is the caller's to name: no file carries it (ADR 0011, "Runtime kinds"). `explain` judges
            // no driver, so it runs no `installation` check and says nothing of one.
            if !explain {
                match f
                    .matches
                    .get_one::<String>("runtime")
                    .and_then(|r| crate::install::Runtime::parse(r))
                {
                    Some(runtime) => c.extend(crate::install::check_drivers(
                        &b,
                        crate::install::Installation { runtime },
                    )),
                    None => c.push(crate::install::not_run()),
                }
            }
            if let Some(old) = f.matches.get_one::<String>("against") {
                // The previous file is read as a bootstrap file is, without the owner rule: it often is a copy
                // taken from git.
                match Bootstrap::load_with(Path::new(old), None) {
                    Ok(old) => c.extend(crate::against::compare(&old, &b)),
                    Err(e) => c.push(crate::against::unreadable(&e.to_string())),
                }
            }
            let (set, docs) = config::offline::load_dir(dir, &b, explain);
            c.extend(set);
            // Only a set that passes its checks is one store@ would load, and only that has effective values.
            if explain && set_loads(&c) {
                groups = explained(&b, &docs)?;
            }
            c
        }
        Err(e) => {
            // A refused bootstrap file: its rule (it names a path, never a value); the documents cannot be verified
            // without its publisher keys.
            let rule = e
                .downcast_ref::<Refused>()
                .map_or_else(|| format!("{e:#}"), |r| r.0.clone());
            vec![
                config::offline::Check {
                    name: "bootstrap",
                    result: "fail",
                    path: String::new(),
                    rule,
                },
                config::offline::Check {
                    name: "set",
                    result: "not-run",
                    path: String::new(),
                    rule: String::new(),
                },
            ]
        }
    };
    let explained_set = explain && set_loads(&checks);
    if let Some(scope) = f.matches.get_one::<String>("field") {
        config::explain::retain_within(&mut groups, scope);
        // A path that names no setting is input the command cannot act on. In JSON the caller reads the empty list.
        if explained_set && groups.is_empty() && !f.json {
            return Err(Usage("--field: no setting is at that path".into()).into());
        }
    }
    let mut out = std::io::stdout().lock();
    if f.json {
        let mut o = config::offline::to_json(&checks);
        if explain {
            o["groups"] = config::explain::to_json(&groups);
        }
        writeln!(out, "{o}")?;
    } else if explained_set {
        for g in &groups {
            for x in &g.settings {
                writeln!(
                    out,
                    "{} = {} ({} {} {} {})",
                    config::explain::lossy(&x.path),
                    config::explain::lossy(&x.value),
                    g.class,
                    g.layer,
                    g.version,
                    config::explain::lossy(&g.source)
                )?;
            }
        }
    } else {
        for c in &checks {
            let at = if c.path.is_empty() {
                String::new()
            } else {
                format!(" {}", c.path)
            };
            let why = if c.rule.is_empty() {
                String::new()
            } else {
                format!(": {}", c.rule)
            };
            writeln!(out, "{} {}{at}{why}", c.result, c.name)?;
        }
    }
    let failed: Vec<_> = checks
        .iter()
        .filter(|c| c.result == "fail")
        .map(|c| {
            if c.path.is_empty() {
                c.name.to_owned()
            } else {
                format!("{} {}", c.name, c.path)
            }
        })
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Refused(failed.join("; ")).into())
    }
}

/// Whether the checks leave a set that store@ would load: none failed and the set itself passed.
fn set_loads(checks: &[config::offline::Check]) -> bool {
    checks.iter().all(|c| c.result != "fail")
        && checks.iter().any(|c| c.name == "set" && c.result == "ok")
}

/// The settings of the bootstrap file and of the accepted documents, in that order.
fn explained(
    b: &Bootstrap,
    docs: &[config::snapshot::Document],
) -> anyhow::Result<Vec<config::explain::Group>> {
    let mut groups = config::explain::bootstrap_groups(b, sluis_version::VERSION);
    for d in docs {
        let g = config::explain::document_group(d, b).map_err(anyhow::Error::msg)?;
        // A document that sets nothing (an `ExchangeTrust` that trusts no issuer) has nothing to explain.
        if !g.settings.is_empty() {
            groups.push(g);
        }
    }
    Ok(groups)
}
