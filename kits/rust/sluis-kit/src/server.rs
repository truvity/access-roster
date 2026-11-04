//! The server half of the kit: a Unix socket listener, the peer credentials of each connection,
//! and the guard that refuses a caller outside the call graph before the message is decoded.

use std::future::Future;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use connectrpc::error::ErrorCode;
use connectrpc::interceptor::{
    Interceptor, Next, NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest,
    UnaryResponse, async_trait,
};
use connectrpc::{ConnectError, ConnectRpcService, DeadlinePolicy, RequestContext, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::{UnixListener, UnixStream};
use tower::Service;

use crate::correlation_impl::{CorrelationId, INHERITED, Inherited, from_headers};
use crate::identity::{Identities, Peer};
use crate::peercred::{self, ConnPeer};
use crate::refusal_impl::refusal;

/// Who may call this server.
#[derive(Clone, Debug)]
pub enum Allow {
    /// The call graph of the registry: `may_call(caller, actor)`.
    CallGraph,
    /// Only the named owner: a driver's socket answers its owner and nobody else.
    OwnerOnly(&'static str),
    /// Only the named caller: one of `key@`'s per-caller sockets.
    Exact(&'static str),
}

/// The configuration of one server on one socket.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// The callee's registry name, e.g. `store`.
    pub actor: &'static str,
    /// The boundary the server belongs to.
    pub boundary: String,
    /// The absolute path of the socket (PLAN.md "Socket layout").
    pub socket: PathBuf,
    /// The mode of the socket file: 0o660 for an actor, 0o600 for a driver.
    pub mode: u32,
    /// Who may call.
    pub allow: Allow,
    /// The deadline of a call that carries none (contracts.md "Every call").
    pub default_deadline: Duration,
}

/// How long a graceful shutdown waits for calls in flight.
const GRACE: Duration = Duration::from_secs(5);

/// Serves `router` on `cfg.socket` until `shutdown` resolves, then drains for at most 5 s.
///
/// The socket is made fresh: a stale socket file is replaced, a symlink or any other file is
/// refused. Each connection's peer credentials are read once, and every call passes the guard
/// before its message is decoded: a caller the registry does not know, or from another boundary's
/// uid block, is `permission_denied` with the reason `caller`; one the call graph does not allow
/// is `permission_denied` with `call_graph`.
///
/// # Errors
///
/// Fails when the socket cannot be made, or when the process does not run as a uid of the
/// registry (it could not tell its own boundary).
pub async fn serve(
    cfg: ServerConfig,
    router: Router,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    serve_inner(cfg, router, shutdown, Identities::registry()?).await
}

/// [`serve`] with a table of uids of a test's own choosing. Test and example builds only.
///
/// # Errors
///
/// As [`serve`], except for the uid of the process.
#[cfg(feature = "test-identities")]
pub async fn serve_with(
    cfg: ServerConfig,
    router: Router,
    shutdown: impl Future<Output = ()> + Send,
    identities: Identities,
) -> anyhow::Result<()> {
    serve_inner(cfg, router, shutdown, identities).await
}

async fn serve_inner(
    cfg: ServerConfig,
    router: Router,
    shutdown: impl Future<Output = ()> + Send,
    identities: Identities,
) -> anyhow::Result<()> {
    let listener = listen(&cfg.socket, cfg.mode)?;
    let guard = Guard {
        actor: cfg.actor,
        allow: cfg.allow.clone(),
        identities,
    };
    let service = ConnectRpcService::new(router)
        .with_deadline_policy(DeadlinePolicy::new().with_default_timeout(cfg.default_deadline))
        .with_interceptor(guard);
    tracing::info!(actor = cfg.actor, boundary = %cfg.boundary, "listening");

    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => accept(stream, &service, &graceful),
                Err(e) => break Err(e).context("accept"),
            },
        }
    };
    drop(listener);
    // The file is ours: remove it so that the next start finds no stale socket.
    let _ = std::fs::remove_file(&cfg.socket);
    if tokio::time::timeout(GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!(
            actor = cfg.actor,
            "calls still running after the grace period"
        );
    }
    result
}

fn accept(stream: UnixStream, service: &ConnectRpcService, graceful: &GracefulShutdown) {
    let peer = match peercred::read(&stream) {
        Ok(p) => p,
        Err(e) => {
            // Without credentials the connection cannot be named: drop it.
            tracing::warn!(error = %e, "peer credentials unreadable; connection dropped");
            return;
        }
    };
    let service = service.clone();
    let svc = hyper::service::service_fn(move |mut req: http::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(peer);
        let mut service = service.clone();
        async move { service.call(req).await }
    });
    let conn = AutoBuilder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), svc)
        .into_owned();
    let conn = graceful.watch(conn);
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "connection ended with an error");
        }
    });
}

/// Makes the listening socket: a stale file is replaced, a symlink or a non-socket refused, and
/// the mode is set before the socket gets its final name.
fn listen(path: &Path, mode: u32) -> anyhow::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("{}: a symlink is in the way of the socket", path.display())
        }
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).context("remove the stale socket")?;
        }
        Ok(_) => bail!("{}: exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("stat the socket path"),
    }
    let parent = path.parent().context("the socket path has no directory")?;
    let name = path.file_name().context("the socket path has no name")?;
    // Bind under a temporary name, set the mode, then rename: the socket is never reachable at
    // its final name with a wider mode than asked for.
    let mut tmp = name.to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = parent.join(tmp);
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).context("bind the socket")?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
        .context("set the socket mode")?;
    std::fs::rename(&tmp, path).context("put the socket in place")?;
    Ok(listener)
}

/// The interceptor in front of every procedure (contracts.md "Errors"; 0003 "The call graph").
/// It runs after the request head is read and before the message is decoded.
struct Guard {
    actor: &'static str,
    allow: Allow,
    identities: Identities,
}

impl Guard {
    /// Names the caller and decides. On success the caller is in the request's extensions.
    fn check(&self, ctx: &mut RequestContext) -> Result<(), ConnectError> {
        let procedure = ctx.path().unwrap_or("").to_owned();
        let conn = ctx.extensions().get::<ConnPeer>().copied();
        let named = conn.and_then(|c| self.identities.name(c.uid).map(|n| (c, n)));
        let Some((conn, (name, block))) = named else {
            tracing::info!(
                callee = self.actor, procedure = %procedure,
                caller_uid = conn.map(|c| c.uid), "refused: caller unknown"
            );
            return Err(refusal(ErrorCode::PermissionDenied, "caller", ""));
        };
        if block != self.identities.own_block() {
            tracing::info!(
                callee = self.actor, caller = name, procedure = %procedure,
                "refused: caller of another boundary"
            );
            return Err(refusal(ErrorCode::PermissionDenied, "caller", ""));
        }
        let allowed = match &self.allow {
            Allow::CallGraph => sluis_registry::may_call(name, self.actor),
            Allow::OwnerOnly(owner) => name == *owner,
            Allow::Exact(only) => name == *only,
        };
        if !allowed {
            tracing::info!(
                callee = self.actor, caller = name, procedure = %procedure,
                "refused: call graph"
            );
            return Err(refusal(ErrorCode::PermissionDenied, "call_graph", ""));
        }
        let peer = Peer {
            uid: conn.uid,
            gid: conn.gid,
            pid: conn.pid,
            name,
            uid_block: block,
        };
        let correlation = from_headers(ctx.headers());
        let ext = ctx.extensions_mut();
        ext.insert(peer);
        if let Some(id) = correlation {
            ext.insert(CorrelationId(id));
        }
        Ok(())
    }

    fn inherited(ctx: &RequestContext) -> Inherited {
        Inherited {
            correlation: from_headers(ctx.headers()),
            deadline: ctx.deadline(),
        }
    }
}

#[async_trait]
impl Interceptor for Guard {
    async fn intercept_unary(
        &self,
        mut req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        self.check(&mut req.ctx)?;
        let inherited = Self::inherited(&req.ctx);
        INHERITED.scope(inherited, next.run(req)).await
    }

    async fn intercept_streaming(
        &self,
        mut req: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        self.check(&mut req.ctx)?;
        let inherited = Self::inherited(&req.ctx);
        INHERITED.scope(inherited, next.run(req, inbound)).await
    }
}
