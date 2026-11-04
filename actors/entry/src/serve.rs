//! The listener: one Unix socket, HTTP/1.1 and h2c, with the timeouts and limits of an edge.

use std::future::Future;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::{UnixListener, UnixStream};

use crate::audit::Auditor;
use crate::handler::{State, handle};
use crate::routes::Front;

/// The sockets of the actors `entry` calls (PLAN.md "Socket layout"; each only where the registry's
/// call graph allows it).
#[derive(Clone, Debug)]
pub struct Sockets {
    /// `session`.
    pub session: PathBuf,
    /// `exchange`.
    pub exchange: PathBuf,
    /// `store@`, for the kinds `Boundary` and `SigningRing`.
    pub store: PathBuf,
    /// The audit transport's emit socket.
    pub audit: PathBuf,
}

impl Sockets {
    /// The sockets under `run_dir` (`/run/sluis`) for a boundary.
    #[must_use]
    pub fn under(run_dir: &Path, boundary: &str) -> Self {
        Self {
            session: run_dir.join("session").join(format!("{boundary}.sock")),
            exchange: run_dir.join("exchange").join(format!("{boundary}.sock")),
            store: run_dir.join("store").join(format!("{boundary}.sock")),
            audit: run_dir.join("audit").join(boundary).join("emit.sock"),
        }
    }
}

/// What one `entry` instance needs.
#[derive(Clone, Debug)]
pub struct Config {
    /// The boundary.
    pub boundary: String,
    /// The route set this instance serves.
    pub front: Front,
    /// Where it listens (`/run/sluis/entry/<boundary>.sock`, or `<boundary>-audit.sock`).
    pub socket: PathBuf,
    /// The mode of the socket file: a group mode such as 0o660, or 0o600. A mode that gives
    /// anything to others is refused at start (ADR 0003 "Listeners").
    pub socket_mode: u32,
    /// The group of the socket file: the forwarder's group, when it is not `entry`'s. 0 is refused.
    /// The process must be a member. It decides who may open the socket; the uid check on each
    /// connection decides who is served.
    pub socket_gid: Option<u32>,
    /// The actors it calls.
    pub sockets: Sockets,
    /// The release, for the audit record (`sluis_version`).
    pub release: String,
}

/// Longest wait for the request head, then for an idle connection (docs/reference/sluis/endpoints.md
/// "Hardening": headers 10 s; idle 2 min).
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest header block.
const HEADER_MAX: usize = 64 * 1024;
/// How long a graceful shutdown waits for requests in flight.
const GRACE: Duration = Duration::from_secs(5);

/// The registry name of the only caller `entry` serves: the forwarder that ends TLS.
const FORWARDER: &str = "harness-forwarder";

type Resolve = Arc<dyn Fn(u32) -> Option<(&'static str, u32)> + Send + Sync>;

/// Who may be served: the forwarder's uid in the uid block of this boundary (REQ-ISO-072), read
/// from `SO_PEERCRED` once per connection. A uid of another name or of another boundary's block
/// is refused before a byte is read.
struct Peers {
    resolve: Resolve,
    own_block: u32,
}

impl Peers {
    fn admits(&self, uid: u32) -> bool {
        (self.resolve)(uid) == Some((FORWARDER, self.own_block))
    }
}

/// Serves until `shutdown` resolves, then drains for at most 5 s.
///
/// Each connection must come from the forwarder's uid in this boundary's block: `SO_PEERCRED`
/// is read on accept, any other peer is dropped and audited (ADR 0003 "Listeners").
///
/// # Errors
///
/// Fails when the process does not run as a uid of the registry (it could not tell its own
/// boundary), when the socket cannot be made or its mode is too wide, or when the audit emitter
/// cannot be built.
pub async fn serve(cfg: Config, shutdown: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    let (_, own_block) = sluis_registry::name_for_uid(uid)
        .with_context(|| format!("own uid {uid} is not a uid of the registry"))?;
    serve_inner(
        cfg,
        shutdown,
        Peers {
            resolve: Arc::new(sluis_registry::name_for_uid),
            own_block,
        },
    )
    .await
}

/// [`serve`] with a uid table of a test's own. Test builds only.
///
/// # Errors
///
/// As [`serve`], except for the uid of the process.
#[cfg(feature = "test-identities")]
pub async fn serve_with(
    cfg: Config,
    shutdown: impl Future<Output = ()> + Send,
    own_block: u32,
    resolve: impl Fn(u32) -> Option<(&'static str, u32)> + Send + Sync + 'static,
) -> anyhow::Result<()> {
    serve_inner(
        cfg,
        shutdown,
        Peers {
            resolve: Arc::new(resolve),
            own_block,
        },
    )
    .await
}

async fn serve_inner(
    cfg: Config,
    shutdown: impl Future<Output = ()> + Send,
    peers: Peers,
) -> anyhow::Result<()> {
    let audit = Auditor::new(sluis_audit::Config {
        actor: "entry".into(),
        boundary: cfg.boundary.clone(),
        release: cfg.release.clone(),
        transport_socket: cfg.sockets.audit.clone(),
        // entry names no person, so it needs no pseudonym key.
        key_socket: None,
        now: None,
    })?;
    let state = Arc::new(State::new(cfg.front, &cfg.sockets, audit));
    let peers = Arc::new(peers);
    let listener = listen(&cfg.socket, cfg.socket_mode, cfg.socket_gid)?;
    tracing::info!(actor = "entry", boundary = %cfg.boundary, "listening");

    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => accept(stream, &state, &peers, &graceful),
                Err(e) => break Err(e).context("accept"),
            },
        }
    };
    drop(listener);
    let _ = std::fs::remove_file(&cfg.socket);
    if tokio::time::timeout(GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("requests still running after the grace period");
    }
    result
}

fn accept(stream: UnixStream, state: &Arc<State>, peers: &Peers, graceful: &GracefulShutdown) {
    let state = Arc::clone(state);
    // Without credentials, or from any other uid, the connection is not served.
    let admitted = stream.peer_cred().is_ok_and(|c| peers.admits(c.uid()));
    if !admitted {
        drop(stream);
        tokio::spawn(async move { state.refuse_peer().await });
        return;
    }
    let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
        let state = Arc::clone(&state);
        async move { Ok::<_, std::convert::Infallible>(handle(&state, req).await) }
    });
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(HEADER_MAX);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_header_list_size(u32::try_from(HEADER_MAX).unwrap_or(u32::MAX));
    let conn = builder
        .serve_connection(TokioIo::new(stream), svc)
        .into_owned();
    let conn = graceful.watch(conn);
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "connection ended with an error");
        }
    });
}

/// Makes the listening socket. A stale socket file is replaced; a live listener, a symlink or any
/// other file is refused, and so is a mode that gives anything to others. The socket gets its group
/// and mode before it has its final name, so it is never reachable more widely than asked for.
fn listen(path: &Path, mode: u32, gid: Option<u32>) -> anyhow::Result<UnixListener> {
    // Owner and group only: the world never opens this socket.
    if mode & !0o770 != 0 {
        bail!("the socket mode {mode:o} gives access to others or sets a special bit");
    }
    if gid == Some(0) {
        bail!("the socket group 0 is refused: use None for no group");
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("{}: a symlink is in the way of the socket", path.display())
        }
        Ok(m) if m.file_type().is_socket() => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => bail!(
                "{}: a live listener already serves this socket",
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path).context("remove the stale socket")?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("cannot tell whether the socket is stale; left alone"),
        },
        Ok(_) => bail!("{}: exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("stat the socket path"),
    }
    let parent = path.parent().context("the socket path has no directory")?;
    let name = path.file_name().context("the socket path has no name")?;
    let mut tmp = name.to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = parent.join(tmp);
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).context("bind the socket")?;
    // The group first, then the mode, both before the final name. A failure leaves no socket behind.
    let placed = (|| -> anyhow::Result<()> {
        if let Some(g) = gid {
            std::os::unix::fs::chown(&tmp, None, Some(g)).context("set the socket group")?;
        }
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .context("set the socket mode")
    })();
    if let Err(e) = placed {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).context("put the socket in place")?;
    Ok(listener)
}
