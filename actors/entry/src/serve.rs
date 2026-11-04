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
    /// The mode of the socket file: only the forwarder may connect, so 0o660 with its group, or
    /// 0o600 when it runs as the same user.
    pub socket_mode: u32,
    /// The group of the socket file, when the forwarder's group is not `entry`'s.
    pub socket_group: Option<u32>,
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

/// Serves until `shutdown` resolves, then drains for at most 5 s.
///
/// # Errors
///
/// Fails when the socket cannot be made or the audit emitter cannot be built.
pub async fn serve(cfg: Config, shutdown: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
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
    let listener = listen(&cfg.socket, cfg.socket_mode, cfg.socket_group)?;
    tracing::info!(actor = "entry", boundary = %cfg.boundary, "listening");

    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => accept(stream, &state, &graceful),
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

fn accept(stream: UnixStream, state: &Arc<State>, graceful: &GracefulShutdown) {
    let state = Arc::clone(state);
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
/// other file is refused. The socket gets its mode and group before it has its final name, so it
/// is never reachable more widely than asked for.
fn listen(path: &Path, mode: u32, group: Option<u32>) -> anyhow::Result<UnixListener> {
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
    if let Some(gid) = group {
        std::os::unix::fs::chown(&tmp, None, Some(gid)).context("set the socket group")?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
        .context("set the socket mode")?;
    std::fs::rename(&tmp, path).context("put the socket in place")?;
    Ok(listener)
}
