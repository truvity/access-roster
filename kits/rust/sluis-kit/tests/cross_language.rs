#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! Rule R9 of ADR 0012: a Rust client calls the Go `EchoService` server, and the Go client calls a
//! Rust server, over a Unix socket. One unary call, one server stream of 50 messages in order, and
//! a refusal whose `Refusal` detail survives the hop. The Go side is
//! `go run ./kits/conformance/kit/cmd/echo` (WP-04); the Rust side is `examples/echo.rs`.
//!
//! While WP-04 is not on `main` its sources are absent and each test prints `SKIP: ...` and is
//! not run. Once they are present, a failure of the Go toolchain is a failure of the test.

#[allow(dead_code)]
#[path = "../examples/echo.rs"]
mod echo;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

/// The Go echo command, if WP-04's sources are in this checkout.
fn go_echo_present(test: &str) -> Option<PathBuf> {
    let root = repo_root();
    if root.join("kits/conformance/kit/cmd/echo/main.go").exists() {
        Some(root)
    } else {
        println!(
            "SKIP: {test}: kits/conformance/kit/cmd/echo is not in this checkout (WP-04, the Go kit, is not merged); not run"
        );
        None
    }
}

fn go_echo(root: &Path, args: &[&str], socket: &Path) -> Command {
    let mut c = Command::new("go");
    c.current_dir(root)
        .args(["run", "./kits/conformance/kit/cmd/echo"])
        .args(args)
        .arg("--socket")
        .arg(socket);
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
    // The first `go run` compiles the kit.
    for _ in 0..3000 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("socket {} did not appear", path.display());
}

#[tokio::test]
async fn a_rust_client_calls_the_go_server() {
    let Some(root) = go_echo_present("a_rust_client_calls_the_go_server") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("go.sock");
    let _server = Kill(
        go_echo(&root, &["serve"], &socket)
            .stdout(Stdio::null())
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
    let Some(root) = go_echo_present("a_go_client_calls_the_rust_server") else {
        return;
    };
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
    let out = tokio::task::spawn_blocking(move || go_echo(&root, &["call"], &socket).output())
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
