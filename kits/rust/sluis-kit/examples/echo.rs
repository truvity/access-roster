//! The Rust side of the cross-language test (rule R9 of ADR 0012), test only:
//!
//! ```text
//! echo serve --socket P     # answers any caller under this process's own uid, as the actor "harness"
//! echo call  --socket P     # checks a server of either language; exits 0 when every case passes
//! ```
//!
//! The Go side is `go run ./kits/conformance/kit/cmd/echo` with the same two commands. The
//! integration test `tests/cross_language.rs` includes this file as a module and runs both.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use connectrpc::client::CallOptions;
use connectrpc::error::ErrorCode;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use sluis_kit::{
    Allow, Identities, ServerConfig, correlation, dial, peer, refusal, refusal_reason,
};
use sluis_kit_echo::sluis::conformance::v2alpha1::{
    CountRequest, CountResponse, EchoRequest, EchoResponse, EchoService, EchoServiceClient,
    EchoServiceExt, RefuseRequest, RefuseResponse,
};

/// The largest `n` a Count call accepts (the Go side has the same bound).
const MAX_COUNT: i32 = 1000;

/// The echo service.
pub struct Server;

impl EchoService for Server {
    async fn echo(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EchoRequest>,
    ) -> ServiceResult<EchoResponse> {
        let left = ctx.time_remaining().map_or(0, |d| {
            i64::try_from(d.as_millis()).unwrap_or(i64::MAX).max(1)
        });
        Response::ok(EchoResponse {
            message: request.message.to_owned(),
            caller: peer(ctx.extensions())
                .map(|p| p.name.to_owned())
                .unwrap_or_default(),
            correlation_id: correlation::get(ctx.extensions()).unwrap_or_default(),
            timeout_ms: left,
            ..EchoResponse::default()
        })
    }

    async fn count(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CountRequest>,
    ) -> ServiceResult<ServiceStream<CountResponse>> {
        let n = request.n;
        if !(0..=MAX_COUNT).contains(&n) {
            return Err(refusal(ErrorCode::InvalidArgument, "count", "n"));
        }
        Response::stream_ok(futures::stream::iter((1..=n).map(|seq| {
            Ok(CountResponse {
                seq,
                ..CountResponse::default()
            })
        })))
    }

    async fn refuse(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RefuseRequest>,
    ) -> ServiceResult<RefuseResponse> {
        let Ok(code) = request.code.parse::<ErrorCode>() else {
            return Err(refusal(ErrorCode::InvalidArgument, "code", "code"));
        };
        Err(refusal(code, request.reason, request.field_path))
    }
}

/// Serves the echo service on `socket` until `shutdown`. Every caller under this process's own
/// uid is the actor `harness`: a test runs both ends as one user, so the pinned uids of the
/// registry do not apply.
pub async fn serve(
    socket: &Path,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let me = rustix::process::geteuid().as_raw();
    let identities = Identities::with(0, move |uid| (uid == me).then_some(("harness", 0)));
    let cfg = ServerConfig {
        actor: "echo",
        boundary: "dev".into(),
        socket: socket.to_path_buf(),
        mode: 0o600,
        allow: Allow::Exact("harness"),
        default_deadline: Duration::from_secs(30),
    };
    let router = Arc::new(Server).register(Router::new());
    sluis_kit::serve_with(cfg, router, shutdown, identities).await
}

/// Checks the server on `socket`, whatever language it is written in; the first difference is
/// the error.
pub async fn call(socket: &Path) -> anyhow::Result<()> {
    let client = dial(socket);
    let c = EchoServiceClient::new(client.transport(), client.config());

    // Unary: the message, the correlation id and the deadline cross the hop.
    const ID: &str = "conformance-0001";
    let opts = CallOptions::default()
        .with_timeout(Duration::from_secs(10))
        .with_header(sluis_kit::HEADER_CORRELATION, ID);
    let res = c
        .echo_with_options(
            EchoRequest {
                message: "hello".into(),
                ..EchoRequest::default()
            },
            opts,
        )
        .await
        .context("echo")?
        .into_owned();
    if res.message != "hello" {
        bail!("echo: message {:?}", res.message);
    }
    if res.correlation_id != ID {
        bail!("echo: correlation id {:?}, want {ID:?}", res.correlation_id);
    }
    if !(1..=10_000).contains(&res.timeout_ms) {
        bail!(
            "echo: deadline {} ms, want within (0, 10000]",
            res.timeout_ms
        );
    }
    if res.caller != "harness" {
        bail!("echo: caller {:?}, want \"harness\"", res.caller);
    }

    // Server stream: 50 messages, in order.
    let mut stream = c
        .count(CountRequest {
            n: 50,
            ..CountRequest::default()
        })
        .await
        .context("count")?;
    let mut next = 1;
    while let Some(m) = stream.message().await.context("count")? {
        let got = m.to_owned_message().seq;
        if got != next {
            bail!("count: message {next} came as {got}");
        }
        next += 1;
    }
    if next != 51 {
        bail!("count: {} messages, want 50", next - 1);
    }

    // Refusal: the code and the Refusal detail survive.
    let err = c
        .refuse(RefuseRequest {
            code: "failed_precondition".into(),
            reason: "bound".into(),
            field_path: "a.b".into(),
            ..RefuseRequest::default()
        })
        .await
        .err()
        .context("refuse: no error")?;
    if err.code != ErrorCode::FailedPrecondition {
        bail!("refuse: code {:?}, want failed_precondition", err.code);
    }
    match refusal_reason(&err).as_deref() {
        Some("bound") => {}
        other => bail!("refuse: reason {other:?}, want bound"),
    }
    Ok(())
}

// A binary for people; `cargo run --example echo -- serve --socket P`.
struct Commands;

impl sluis_kit::cli::Commands for Commands {
    async fn serve(&self, f: sluis_kit::cli::Flags) -> anyhow::Result<()> {
        if f.socket.as_os_str().is_empty() {
            bail!("--socket is required");
        }
        serve(&f.socket, sluis_kit::cli::shutdown_signal()).await
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("call") {
        let socket = argv
            .windows(2)
            .find(|w| w[0] == "--socket")
            .map(|w| w[1].clone())
            .or_else(|| {
                argv.iter()
                    .find_map(|a| a.strip_prefix("--socket=").map(str::to_owned))
            });
        let Some(socket) = socket else {
            eprintln!("usage: echo call --socket PATH");
            std::process::exit(2);
        };
        let Ok(rt) = tokio::runtime::Runtime::new() else {
            std::process::exit(1)
        };
        match rt.block_on(call(Path::new(&socket))) {
            Ok(()) => println!("echo call: ok"),
            Err(e) => {
                eprintln!("echo call: FAIL: {e:#}");
                std::process::exit(1);
            }
        }
        return;
    }
    sluis_kit::cli::main("echo", Commands, |c| c);
}
