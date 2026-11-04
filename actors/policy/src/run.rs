//! The command line of `policy`: `serve`, `check`, `version` (cli.md "Conventions").

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, bail};
use clap::{Arg, Command};
use connectrpc::Router;
use sluis_kit::cli::{Commands, Flags, Refused, shutdown_signal};
use sluis_kit::{Allow, ServerConfig, dial};
use sluis_proto::sluis::key::v2alpha1::KeyServiceClient;
use sluis_proto::sluis::policy::v2alpha1::PolicyServiceExt as _;

use crate::audit;
use crate::engine::{Engine, Inputs};
use crate::service::{Deps, Service};
use crate::source::{RELOAD_EVERY, Reloader, StoreSource};

/// The deadline of a call that carries none (contracts.md "Every call").
const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);
/// How long a cold start waits for store@ to serve the policy.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// The pause between attempts while `serve` waits for store@.
const START_PAUSE: Duration = Duration::from_millis(250);

/// The flags of `policy` beyond the global ones of the kit.
#[must_use]
pub fn extra(c: Command) -> Command {
    let flag = |name: &'static str, value: &'static str, help: &'static str| {
        Arg::new(name)
            .long(name)
            .global(true)
            .value_name(value)
            .help(help)
    };
    c.arg(flag(
        "store-socket",
        "PATH",
        "store@'s socket; default /run/sluis/store/<boundary>.sock",
    ))
    .arg(flag(
        "key-socket",
        "PATH",
        "key@'s socket for policy; default /run/sluis/key/<boundary>/policy/key.sock",
    ))
    .arg(flag(
        "transport-socket",
        "PATH",
        "The audit transport's emit socket; default /run/sluis/audit/<boundary>/emit.sock",
    ))
    .arg(flag(
        "socket-gid",
        "GID",
        "Give the socket (mode 0660) to this group; the default is the group the process runs as",
    ))
}

struct Paths {
    store: PathBuf,
    key: PathBuf,
    transport: PathBuf,
    service: PathBuf,
}

fn paths(f: &Flags) -> anyhow::Result<Paths> {
    if f.boundary.is_empty() {
        bail!("--boundary is required");
    }
    let b = &f.boundary;
    let flag = |name: &str| {
        f.matches
            .get_one::<String>(name)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    Ok(Paths {
        store: flag("store-socket").unwrap_or_else(|| format!("/run/sluis/store/{b}.sock").into()),
        key: flag("key-socket")
            .unwrap_or_else(|| format!("/run/sluis/key/{b}/policy/key.sock").into()),
        transport: flag("transport-socket")
            .unwrap_or_else(|| format!("/run/sluis/audit/{b}/emit.sock").into()),
        service: if f.socket.as_os_str().is_empty() {
            format!("/run/sluis/policy/{b}.sock").into()
        } else {
            f.socket.clone()
        },
    })
}

/// The group of the socket (`--socket-gid`), if given: a group number other than 0.
fn socket_gid(f: &Flags) -> anyhow::Result<Option<u32>> {
    match f.matches.get_one::<String>("socket-gid") {
        None => Ok(None),
        Some(g) => match g.parse::<u32>() {
            Ok(g) if g != 0 => Ok(Some(g)),
            _ => bail!("--socket-gid must be a group number other than 0"),
        },
    }
}

/// Reads the policy from store@, waiting up to `wait` for it to be served.
async fn read(source: &StoreSource, wait: Duration) -> anyhow::Result<Inputs> {
    let deadline = Instant::now() + wait;
    loop {
        match source.fetch().await {
            Ok(i) => return Ok(i),
            Err(e) if Instant::now() >= deadline => bail!("store@ does not serve the policy: {e}"),
            Err(_) => tokio::time::sleep(START_PAUSE).await,
        }
    }
}

/// `policy`.
pub struct Policy;

impl Commands for Policy {
    async fn serve(&self, f: Flags) -> anyhow::Result<()> {
        let p = paths(&f)?;
        let gid = socket_gid(&f)?;
        let source = StoreSource::new(&dial(&p.store), &f.boundary).context("the store client")?;
        // A cold start with a set that fails does not start (ADR 0007).
        let inputs = read(&source, START_TIMEOUT).await?;
        // Cedar recurses: the build runs on a thread with a stack of its own (stack.rs).
        let engine = Engine::build_on_stack(&inputs)
            .await
            .map_err(|e| anyhow::anyhow!("the policy is refused: {e}"))?;
        let (digest, count) = (engine.digest().to_owned(), inputs.policies.len());

        let key = dial(&p.key);
        let audit = sluis_audit::Emitter::new(sluis_audit::Config {
            actor: "policy".into(),
            boundary: f.boundary.clone(),
            release: sluis_version::VERSION.into(),
            transport_socket: p.transport.clone(),
            // policy has the pseudonym rule: a decision about a person names a pseudonym.
            key_socket: Some(p.key.clone()),
            now: None,
        })
        .map_err(|e| anyhow::anyhow!("the audit emitter: {e}"))?;
        let svc = Arc::new(Service::new(Deps {
            engine,
            keys: KeyServiceClient::new(key.transport(), key.config()),
            audit,
            clock: SystemTime::now,
        }));
        if let Err(e) = svc.emitter().emit(audit::start(&digest, count)).await {
            tracing::error!(code = e.code.as_str(), "the start could not be audited");
        }
        let reloader = Arc::new(Reloader::new(source, Arc::clone(&svc), &inputs));
        let reloading = tokio::spawn({
            let r = Arc::clone(&reloader);
            async move { r.run(RELOAD_EVERY).await }
        });
        let served = sluis_kit::serve(
            ServerConfig {
                actor: "policy",
                boundary: f.boundary.clone(),
                socket: p.service,
                mode: 0o660,
                socket_gid: gid,
                allow: Allow::CallGraph,
                default_deadline: DEFAULT_DEADLINE,
            },
            svc.register(Router::new()),
            shutdown_signal(),
        )
        .await;
        reloading.abort();
        served
    }

    /// Reads the policy from store@ and builds the set, without serving: what a cold start would do.
    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        Some(self.check_inner(&f).await)
    }
}

impl Policy {
    async fn check_inner(&self, f: &Flags) -> anyhow::Result<()> {
        let p = paths(f)?;
        let source = StoreSource::new(&dial(&p.store), &f.boundary).context("the store client")?;
        let inputs = read(&source, Duration::ZERO).await?;
        Engine::build_on_stack(&inputs)
            .await
            .map(|_| ())
            .map_err(|e| Refused(e.to_string()).into())
    }
}
