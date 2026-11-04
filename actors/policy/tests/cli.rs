#![allow(refining_impl_trait)] // the generated traits return `impl Encodable`; a concrete type is fine
#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The command line of the `policy` executable: version, check, and the flags of serve.

mod common;

use common::{Around, local_inputs};
use policy::engine::PolicyDoc;

/// Runs the executable without blocking the runtime that serves its fakes.
async fn run(args: Vec<String>) -> (i32, String) {
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_policy"))
            .args(&args)
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).into_owned(),
        )
    })
    .await
    .unwrap()
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

#[tokio::test]
async fn version_prints_the_version() {
    let (code, out) = run(args(&["version"])).await;
    assert_eq!(code, 0);
    assert!(out.starts_with("policy "), "{out}");
}

#[tokio::test]
async fn check_reads_the_policy_from_store_and_builds_it() {
    let a = Around::new().await;
    let store = a.store_socket.to_str().unwrap().to_owned();
    let check = |s: String| args(&["check", "--boundary", "dev", "--store-socket", &s]);

    a.store.set(&local_inputs());
    assert_eq!(run(check(store.clone())).await.0, 0, "a set that loads");

    let mut bad = local_inputs();
    bad.policies.push(PolicyDoc {
        file: "oops".into(),
        cedar: "permit (principal, action, resource);".into(),
    });
    a.store.set(&bad);
    let (code, out) = run(check(store.clone())).await;
    assert_eq!(code, 3, "refused by the check: {out}");
    assert!(out.contains("a policy has no @id"), "{out}");

    let (code, out) = run(check(
        a.dir
            .path()
            .join("nobody.sock")
            .to_str()
            .unwrap()
            .to_owned(),
    ))
    .await;
    assert_eq!(
        code, 1,
        "store@ not reachable is a failure, not a refusal: {out}"
    );
}

#[tokio::test]
async fn serve_refuses_a_missing_boundary_and_a_socket_group_of_zero() {
    let (code, out) = run(args(&["serve"])).await;
    assert_eq!(code, 1);
    assert!(out.contains("--boundary is required"), "{out}");
    for gid in ["0", "wheel", "4294967296"] {
        let (code, out) = run(args(&["serve", "--boundary", "dev", "--socket-gid", gid])).await;
        assert_eq!(code, 1, "{gid}: {out}");
        assert!(
            out.contains("--socket-gid must be a group number other than 0"),
            "{out}"
        );
    }
}
