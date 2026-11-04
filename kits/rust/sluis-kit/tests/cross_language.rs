#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! Rule R9 of ADR 0012: a Rust client calls the Go `EchoService` server, and the Go client calls a
//! Rust server, over a Unix socket. One unary call, one server stream of 50 messages in order, and
//! a refusal whose `Refusal` detail survives the hop. The Go side is
//! `kits/conformance/kit/cmd/echo` (WP-04), built with `go build -tags sluis_test`; the Rust side is `examples/echo.rs`.
//!
//! The Go side is in this repository, so a missing Go toolchain or source is a failure, never a
//! skip.

#[allow(dead_code)]
#[path = "../examples/echo.rs"]
mod echo;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

fn repo_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    assert!(
        root.join("kits/conformance/kit/cmd/echo/main.go").exists(),
        "kits/conformance/kit/cmd/echo is missing: it is the Go side of the cross-language test"
    );
    root
}

/// The Go echo command, built once with the tag `sluis_test` (the name resolver that makes the
/// process's own uid the actor `harness`; `serve` needs it and `call` does not) into the target
/// directory. It is built, not `go run`, so that killing the server kills the server itself and
/// not only a `go run` parent.
fn go_echo_binary() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let root = repo_root();
        let bin = Path::new(env!("CARGO_TARGET_TMPDIR")).join("go-echo");
        let out = Command::new("go")
            .current_dir(&root)
            .args(["build", "-tags", "sluis_test", "-o"])
            .arg(&bin)
            .arg("./kits/conformance/kit/cmd/echo")
            .output()
            .expect("go build: is Go on the PATH (devbox)?");
        assert!(
            out.status.success(),
            "go build of the echo command failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        bin
    })
}

fn go_echo(command: &str, socket: &Path) -> Command {
    let mut c = Command::new(go_echo_binary());
    c.arg(command).arg("--socket").arg(socket);
    c
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for(path: &Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("socket {} did not appear", path.display());
}

#[tokio::test]
async fn a_rust_client_calls_the_go_server() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("go.sock");
    let _server = Kill(
        go_echo("serve", &socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("go run: is Go on the PATH (devbox)?"),
    );
    wait_for(&socket).await;
    echo::call(&socket)
        .await
        .expect("the Rust client against the Go server");
}

#[tokio::test]
async fn a_go_client_calls_the_rust_server() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rust.sock");
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let s = socket.clone();
    let server = tokio::spawn(async move {
        echo::serve(&s, async move {
            let _ = rx.await;
        })
        .await
    });
    wait_for(&socket).await;
    let out = tokio::task::spawn_blocking(move || go_echo("call", &socket).output())
        .await
        .unwrap()
        .expect("go run: is Go on the PATH (devbox)?");
    let _ = stop.send(());
    server.await.unwrap().unwrap();
    assert!(
        out.status.success(),
        "the Go client against the Rust server failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The Rust side against itself, in this process, over a Unix socket: the same cases as the
/// cross-language test, so a failure here is the Rust side's and not the Go side's.
#[tokio::test]
async fn the_rust_client_and_server_agree() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("self.sock");
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let s = socket.clone();
    let server = tokio::spawn(async move {
        echo::serve(&s, async move {
            let _ = rx.await;
        })
        .await
    });
    wait_for(&socket).await;
    echo::call(&socket).await.expect("the echo cases");
    let _ = stop.send(());
    server.await.unwrap().unwrap();
}
