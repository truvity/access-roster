#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The command line of `driver-writer-spool`: the flags that the units pass must be declared.

use std::process::{Command, Output};

fn spool(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_driver-writer-spool"))
        .args(args)
        .output()
        .unwrap()
}

/// The unit of the writer's spool passes `--socket-gid`, so that the emitters and the writer, who join
/// the group, can connect. Undeclared, the driver exited with "unexpected argument".
#[test]
fn serve_declares_socket_gid() {
    let o = spool(&["serve", "--help"]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("--socket-gid"), "{out}");
}

/// A group number other than 0 is accepted by the parser: the run goes on past it and does not say
/// "unexpected argument". Under a test the kit then refuses the uid of the test runner, which is not a
/// uid of the registry, so the run ends.
#[test]
fn serve_takes_a_socket_gid_and_goes_on_to_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("no-such-root");
    let o = spool(&[
        "serve",
        "--boundary",
        "dev",
        "--socket-dir",
        dir.path().to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
        "--socket-gid",
        "4242",
    ]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("unexpected argument"), "{err}");
    assert!(!err.contains("--socket-gid must"), "{err}");
}

/// Zero and text are refused by name, before the spool is opened and before a socket exists.
#[test]
fn serve_refuses_a_socket_gid_of_zero_or_text() {
    for gid in ["0", "wheel", ""] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let o = spool(&[
            "serve",
            "--boundary",
            "dev",
            "--socket-dir",
            dir.path().to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--socket-gid",
            gid,
        ]);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(1), "{gid}: {err}");
        assert!(
            err.contains("--socket-gid must be a group number"),
            "{gid}: {err}"
        );
        assert!(!dir.path().join("emit.sock").exists(), "{gid}");
        assert!(!root.exists(), "{gid}: the spool was not opened");
    }
}
