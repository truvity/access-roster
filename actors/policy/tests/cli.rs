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

/// The arguments of `serve` against the fakes of a rig, with the service socket in the rig's directory.
fn serve_args(a: &Around) -> (Vec<String>, std::path::PathBuf) {
    let socket = a.dir.path().join("policy.sock");
    let path = |p: &std::path::Path| p.to_str().unwrap().to_owned();
    (
        vec![
            "serve".into(),
            "--boundary".into(),
            "dev".into(),
            "--store-socket".into(),
            path(&a.store_socket),
            "--key-socket".into(),
            path(&a.key_socket),
            "--transport-socket".into(),
            path(&a.emit_socket),
            "--socket".into(),
            path(&socket),
        ],
        socket,
    )
}

/// `serve` against a set that fails does not start: it exits with an error that names the offending
/// policy or the offending path of the vocabulary, audits no start and opens no socket. The same
/// command against a good set gets as far as its start fact, so the refusal is the set's and not a
/// wrong flag.
///
/// verifies: REQ-POLICY-005
#[tokio::test]
async fn serve_refuses_to_start_on_a_policy_violation_and_names_the_offending_path() {
    let a = Around::new().await;
    let (serve, socket) = serve_args(&a);

    let with_policy = |file: &str, cedar: &str| {
        let mut i = local_inputs();
        i.policies.push(PolicyDoc {
            file: file.into(),
            cedar: cedar.into(),
        });
        i
    };
    let mut bad_vocabulary = local_inputs();
    bad_vocabulary.vocabulary = b"scopes: {dev: {}}\nthings: {t: {roles: {a: [b]}}}\n".to_vec();
    let cases = [
        (
            "an attribute the schema does not have",
            with_policy(
                "bad-attr",
                "@id(\"bad-attr\")\npermit (principal is Person, action == Action::\"token.issue\", resource is Client)\nwhen { principal.shoe_size == 9 };",
            ),
            vec!["bad-attr", "does not fit the schema"],
        ),
        (
            "a policy with no @id",
            with_policy("no-id", "permit (principal, action, resource);"),
            vec!["a policy has no @id"],
        ),
        (
            "a file that does not parse",
            with_policy(
                "broken-file",
                "permit (principal, action, resource) when {{{",
            ),
            vec!["broken-file: does not parse"],
        ),
        (
            "a vocabulary that does not fit",
            bad_vocabulary,
            vec!["GrantVocabulary: things.t.roles.a.implies[0]"],
        ),
    ];
    for (what, set, names) in cases {
        a.store.set(&set);
        let (code, out) = run(serve.clone()).await;
        assert_eq!(code, 1, "{what}: the start is refused: {out}");
        assert!(out.contains("the policy is refused"), "{what}: {out}");
        for n in names {
            assert!(
                out.contains(n),
                "{what}: the error does not name {n:?}: {out}"
            );
        }
        assert!(!socket.exists(), "{what}: a socket was opened");
        assert!(
            a.spool.records().is_empty(),
            "{what}: a refused start must audit nothing as started"
        );
    }

    // The control: the good set gets past the check. The test process is not a uid of the registry, so
    // the server refuses to listen, but only after the start was audited, which a refused set never
    // reaches. Without this the refusals above could be a wrong flag.
    a.store.set(&local_inputs());
    let (code, out) = run(serve).await;
    assert_eq!(code, 1, "{out}");
    assert!(!out.contains("the policy is refused"), "{out}");
    assert!(out.contains("not a uid of the registry"), "{out}");
    assert_eq!(
        a.spool.of("policy.start").len(),
        1,
        "the good set did not reach its start"
    );
}
