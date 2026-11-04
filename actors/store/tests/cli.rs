#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The `store` executable: `check` on the example bootstrap file of the local installation, and
//! the exit codes of cli.md.

use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output};

const LOCAL: &str = include_str!("../../../tests/installations/local/bootstrap.yaml");

fn store(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_store"))
        .args(args)
        .output()
        .unwrap()
}

fn write_bootstrap(dir: &Path, text: &str, mode: u32) -> String {
    let path = dir.join("dev.yaml");
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path.to_str().unwrap().to_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn check_exits_3_and_names_each_unreachable_socket() {
    let dir = tempfile::tempdir().unwrap();
    // The example's sockets (/run/sluis/store/dev/...) do not exist where the tests run.
    let file = write_bootstrap(dir.path(), LOCAL, 0o640);
    let key = dir.path().join("no-key.sock");
    let transport = dir.path().join("no-emit.sock");
    let o = store(&[
        "check",
        "--bootstrap",
        &file,
        "--key-socket",
        key.to_str().unwrap(),
        "--transport-socket",
        transport.to_str().unwrap(),
    ]);
    let err = stderr(&o);
    assert_eq!(o.status.code(), Some(3), "{err}");
    for socket in [
        "config-source.sock",
        "secret-source.sock",
        "durable.sock",
        "temp.sock",
        "no-emit.sock",
    ] {
        assert!(err.contains(socket), "{socket} is not named: {err}");
    }
    // key@ starts after store@ (its Init reads store@), so it is a warning here, not a failure.
    assert!(err.contains("WARN") && err.contains("no-key.sock"), "{err}");
    assert!(o.stdout.is_empty());
}

#[test]
fn check_passes_with_a_warning_when_only_key_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let mut text = LOCAL.to_owned();
    let mut _listeners = Vec::new();
    for name in ["config-source", "secret-source", "durable", "temp"] {
        let sock = dir.path().join(format!("{name}.sock"));
        text = text.replace(
            &format!("/run/sluis/store/dev/{name}.sock"),
            sock.to_str().unwrap(),
        );
        _listeners.push(UnixListener::bind(&sock).unwrap());
    }
    let transport = dir.path().join("emit.sock");
    _listeners.push(UnixListener::bind(&transport).unwrap());
    let file = write_bootstrap(dir.path(), &text, 0o600);
    let o = store(&[
        "check",
        "--bootstrap",
        &file,
        "--key-socket",
        dir.path().join("no-key.sock").to_str().unwrap(),
        "--transport-socket",
        transport.to_str().unwrap(),
    ]);
    let err = stderr(&o);
    assert_eq!(o.status.code(), Some(0), "{err}");
    assert!(err.contains("WARN"), "{err}");
    assert!(err.contains("no-key.sock"), "{err}");
}

#[test]
fn check_passes_when_every_socket_answers_so_it_does_not_fail_on_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut text = LOCAL.to_owned();
    let mut _listeners = Vec::new();
    for name in ["config-source", "secret-source", "durable", "temp"] {
        let sock = dir.path().join(format!("{name}.sock"));
        text = text.replace(
            &format!("/run/sluis/store/dev/{name}.sock"),
            sock.to_str().unwrap(),
        );
        _listeners.push(UnixListener::bind(&sock).unwrap());
    }
    let key = dir.path().join("key.sock");
    _listeners.push(UnixListener::bind(&key).unwrap());
    let transport = dir.path().join("emit.sock");
    _listeners.push(UnixListener::bind(&transport).unwrap());
    let file = write_bootstrap(dir.path(), &text, 0o600);
    let o = store(&[
        "check",
        "--bootstrap",
        &file,
        "--key-socket",
        key.to_str().unwrap(),
        "--transport-socket",
        transport.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
}

#[test]
fn check_refuses_a_file_another_uid_can_write_and_a_file_that_is_not_the_schema() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_bootstrap(dir.path(), LOCAL, 0o664);
    let o = store(&["check", "--bootstrap", &file]);
    assert_eq!(o.status.code(), Some(3));
    assert!(
        stderr(&o).contains("mode allows a write by group or others"),
        "{}",
        stderr(&o)
    );

    let bad = LOCAL.replace("boundary: dev", "boundary: dev\nsurprise: 1");
    let file = write_bootstrap(dir.path(), &bad, 0o600);
    let o = store(&["check", "--bootstrap", &file]);
    assert_eq!(o.status.code(), Some(3));
    assert!(stderr(&o).contains("unknown key"), "{}", stderr(&o));
    assert!(
        !stderr(&o).contains("surprise"),
        "an error never shows the value"
    );
}

#[test]
fn check_without_a_file_and_version_and_unknown_commands() {
    let o = store(&["check"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("--bootstrap"));
    let o = store(&["version"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("store "));
    assert_eq!(store(&["frobnicate"]).status.code(), Some(2));
    // A driver's command that store does not have is "not run", never a pass.
    assert_eq!(store(&["conformance"]).status.code(), Some(2));
}

#[test]
fn serve_refuses_to_start_when_a_driver_does_not_come_up() {
    let dir = tempfile::tempdir().unwrap();
    let text = LOCAL.replace("start_timeout: 30s", "start_timeout: 1s");
    let file = write_bootstrap(dir.path(), &text, 0o600);
    let sock = dir.path().join("store.sock");
    let o = store(&[
        "serve",
        "--bootstrap",
        &file,
        "--socket",
        sock.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("not started within 1s"),
        "{}",
        stderr(&o)
    );
    assert!(!sock.exists(), "nothing was served");
}
