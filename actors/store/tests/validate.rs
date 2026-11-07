#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `store check --validate DIR`, the helper `sluis config check` runs (ADR 0012): the local set passes, each class
//! of rule refuses with its kind and rule, a value of a document is never printed, and the offline check gives the
//! verdict the loader gives on the same documents, because both run the same code.

mod config_support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use config_support::{LOCAL, Pipeline, bootstrap, put, serve_driver, up, write_local};
use serde_json::Value;
use sluis_kit::dial;
use store::config::Loader;
use store::config::offline;

const EXAMPLE: &str = include_str!("../../../tests/installations/local/bootstrap.yaml");

fn source(segment: &str) -> &'static str {
    LOCAL.iter().find(|(s, _)| *s == segment).unwrap().1
}

/// The example bootstrap file of the local installation, pinning this test's publisher key, written with `mode`.
fn write_bootstrap(dir: &Path, p: &Pipeline, mode: u32) -> String {
    let pk = p.publisher(&[]);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        STANDARD.encode(&pk.spki_der)
    );
    let pin = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, &pk.spki_der);
    let mut text = EXAMPLE[..EXAMPLE.find("publishers:").unwrap()].to_owned();
    text.push_str(&format!(
        "publishers:\n  - kid: {}\n    public_key: |\n{}\n    spki_sha384: \"{}\"\n",
        p.kid,
        pem.lines()
            .map(|l| format!("      {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
        store::config::document::hex(pin.as_ref()),
    ));
    let file = dir.join("dev.yaml");
    std::fs::write(&file, text).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
    file.to_str().unwrap().to_owned()
}

fn validate(bootstrap: &str, docs: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_store"))
        .args([
            "check",
            "--output",
            "json",
            "--bootstrap",
            bootstrap,
            "--validate",
        ])
        .arg(docs)
        .args(extra)
        .output()
        .unwrap()
}

/// The exit code, the checks of the JSON object, and everything printed.
fn run(bootstrap: &str, docs: &Path) -> (Option<i32>, Vec<Value>, String) {
    run_with(bootstrap, docs, &[])
}

/// [`run`] with more flags, such as the runtime of the installation.
fn run_with(bootstrap: &str, docs: &Path, extra: &[&str]) -> (Option<i32>, Vec<Value>, String) {
    let o = validate(bootstrap, docs, extra);
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    let all = format!("{stdout}{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {all}"));
    (
        o.status.code(),
        v["checks"].as_array().unwrap().clone(),
        all,
    )
}

fn failures(checks: &[Value]) -> Vec<String> {
    checks
        .iter()
        .filter(|c| c["result"] == "fail")
        .map(|c| {
            format!(
                "{} {}: {}",
                c["name"].as_str().unwrap(),
                c["path"].as_str().unwrap(),
                c["rule"].as_str().unwrap()
            )
        })
        .collect()
}

/// What a case does to the local set before it is checked.
type Break = Box<dyn Fn(&Env)>;

struct Env {
    run: tempfile::TempDir,
    docs: tempfile::TempDir,
    p: Pipeline,
}

fn env() -> Env {
    let e = Env {
        run: tempfile::tempdir().unwrap(),
        docs: tempfile::tempdir().unwrap(),
        p: Pipeline::new("publisher-1"),
    };
    write_local(e.docs.path(), &e.p, 1);
    e
}

impl Env {
    fn sign(&self, segment: &str, text: &str) {
        put(
            self.docs.path(),
            segment,
            &self.p.sign(segment, text.as_bytes(), 2),
        );
    }
    fn bootstrap(&self) -> String {
        write_bootstrap(self.run.path(), &self.p, 0o600)
    }
}

/// verifies: REQ-DATA-090
#[test]
fn the_local_set_passes_every_check_and_exits_0() {
    let e = env();
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(0), "{all}");
    assert!(failures(&checks).is_empty(), "{all}");
    // The bootstrap file, the check that the installation was not named, the Boundary document, the nine kinds it
    // declares, and the set: a sweep over nothing would prove nothing.
    assert_eq!(checks.len(), 13, "{all}");
    let not_run: Vec<_> = checks.iter().filter(|c| c["result"] != "ok").collect();
    assert_eq!(not_run.len(), 1, "{all}");
    assert_eq!(not_run[0]["name"], "installation", "{all}");
    assert_eq!(not_run[0]["result"], "not-run", "{all}");
    assert_eq!(checks.last().unwrap()["name"], "set");
}

/// The KeyPlan's slot map is checked as key@ checks it, on the whole set: two purposes in one slot, an enabled
/// purpose with no slot, a slot that is no slot of a board and a purpose listed twice are each one failed `set` line
/// that names the entry (`default.purposes[2].slot`) and a word, and no slot is printed. A plan that lists none of the
/// purposes of an installation that issues no SSH certificates is accepted (the local set), and so is a spare slot.
///
/// verifies: REQ-PKI-037, REQ-PKI-038, REQ-PKI-042
#[test]
fn a_key_plan_with_a_wrong_slot_map_fails_the_set_and_a_plan_without_ssh_purposes_does_not() {
    let plan = source("key-plan");
    let line = |purpose: &str, alg: &str, slot: &str| {
        format!("    - {{ purpose: {purpose}, algorithm: {alg}, slot: \"{slot}\" }}\n")
    };
    let with = |extra: &str| {
        plan.replace(
            "    - { purpose: data,",
            &format!("{extra}    - {{ purpose: data,"),
        )
    };
    for (name, text, want) in [
        (
            "the token key in the wrapping key's slot",
            plan.replace("slot: 9a", "slot: 9d"),
            "default.purposes[1].slot: shared with wrapping",
        ),
        (
            "an enabled purpose with no slot",
            with(&line("issuance-log", "ES384", "")),
            "default.purposes[3]: no slot",
        ),
        (
            "9e is no board slot",
            with(&line("issuance-log", "ES384", "9e")),
            "default.purposes[3].slot: not a slot of a board",
        ),
        (
            "a purpose listed twice",
            with(&line("wrapping", "ECDH-P384", "88")),
            "default.purposes[3]: listed twice",
        ),
    ] {
        let e = env();
        e.sign("key-plan", &text);
        let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
        assert_eq!(code, Some(3), "{name}: {all}");
        let f = failures(&checks);
        assert_eq!(f.len(), 1, "{name}: {all}");
        assert!(
            f[0].starts_with("set : KeyPlan: card slot map: "),
            "{name}: {f:?}"
        );
        assert!(f[0].contains(want), "{name}: {f:?}");
    }
    // An enabled purpose that the map gives a spare slot, and a plan that lists no SSH purpose, are accepted.
    let e = env();
    e.sign("key-plan", &with(&line("issuance-log", "ES384", "88")));
    let (code, _, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(0), "{all}");
}

fn installation_checks(checks: &[Value]) -> Vec<(String, String)> {
    checks
        .iter()
        .filter(|c| c["name"] == "installation")
        .map(|c| {
            (
                c["path"].as_str().unwrap().to_owned(),
                c["result"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// verifies: REQ-DATA-072, REQ-OPS-009
#[test]
fn the_local_drivers_fit_a_bare_metal_installation() {
    let e = env();
    let (code, checks, all) = run_with(&e.bootstrap(), e.docs.path(), &["--runtime", "bare-metal"]);
    assert_eq!(code, Some(0), "{all}");
    // One check for each of the four ports: a sweep over nothing would prove nothing.
    assert_eq!(
        installation_checks(&checks),
        [
            ("config_source.driver", "ok"),
            ("secret_source.driver", "ok"),
            ("durable.driver", "ok"),
            ("temp.driver", "ok"),
        ]
        .map(|(p, r)| (p.to_owned(), r.to_owned())),
        "{all}"
    );
    assert!(checks.iter().all(|c| c["result"] == "ok"), "{all}");
}

/// verifies: REQ-DATA-072, REQ-OPS-009
#[test]
fn a_driver_that_does_not_fit_the_runtime_is_refused_with_its_field_and_not_its_name() {
    for runtime in ["serverless", "kubernetes"] {
        let e = env();
        let (code, checks, all) = run_with(&e.bootstrap(), e.docs.path(), &["--runtime", runtime]);
        assert_eq!(code, Some(3), "{runtime}: {all}");
        // rqlite and the systemd credentials need a disk and a node; the file driver fits every runtime.
        let want = format!("the driver does not fit the {runtime} runtime");
        assert_eq!(
            failures(&checks),
            [
                format!("installation secret_source.driver: {want}"),
                format!("installation durable.driver: {want}"),
                format!("installation temp.driver: {want}"),
            ],
            "{runtime}"
        );
        assert_eq!(
            installation_checks(&checks)[0],
            ("config_source.driver".to_owned(), "ok".to_owned()),
            "{runtime}"
        );
        // The documents are still checked: one run shows every problem.
        assert_eq!(checks.last().unwrap()["name"], "set", "{runtime}");
        for name in ["rqlite", "credential"] {
            assert!(!all.contains(name), "{runtime}: the output names a driver");
        }
    }
}

#[test]
fn an_unknown_runtime_is_a_usage_error() {
    let e = env();
    let o = validate(&e.bootstrap(), e.docs.path(), &["--runtime", "edge"]);
    assert_eq!(o.status.code(), Some(2));
}

/// verifies: REQ-ISO-073
#[test]
fn a_uid_block_past_the_uid_space_is_refused_with_its_path_and_never_its_value() {
    let b = source("boundary");
    assert!(b.contains("  uid_block: 0\n"));
    // The edge itself is pinned in the registry's own test; here a far block fits and the ends of the range do not.
    for (block, ok) in [(4_000_000, true), (4_294_907, false), (u32::MAX, false)] {
        let e = env();
        e.sign(
            "boundary",
            &b.replace("  uid_block: 0\n", &format!("  uid_block: {block}\n")),
        );
        let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
        if ok {
            assert_eq!(code, Some(0), "block {block}: {all}");
        } else {
            assert_eq!(code, Some(3), "block {block}: {all}");
            assert_eq!(
                failures(&checks),
                [
                    "document Boundary: step 6: default.uid_block: the block gives a pinned name no uid"
                ],
                "block {block}"
            );
            assert!(
                !all.contains(&block.to_string()),
                "block {block}: the value is printed"
            );
        }
    }
}

#[test]
fn a_bootstrap_file_that_others_can_write_is_refused_and_nothing_else_is_run() {
    let e = env();
    let file = write_bootstrap(e.run.path(), &e.p, 0o620);
    let (code, checks, all) = run(&file, e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(checks[0]["name"], "bootstrap");
    assert_eq!(checks[0]["result"], "fail", "{all}");
    assert!(
        checks[1..].iter().all(|c| c["result"] == "not-run"),
        "{all}"
    );
}

#[test]
fn a_bootstrap_file_that_is_a_fifo_is_refused_at_once() {
    let e = env();
    let fifo = e.run.path().join("dev.yaml");
    let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    let (tx, rx) = std::sync::mpsc::channel();
    let (file, docs) = (fifo.to_str().unwrap().to_owned(), e.docs.path().to_owned());
    std::thread::spawn(move || tx.send(run(&file, &docs)).unwrap());
    // A FIFO with no writer would block an open without O_NONBLOCK for ever.
    let (code, checks, all) = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the check hung on a FIFO");
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(checks[0]["result"], "fail", "{all}");
    assert!(
        checks[0]["rule"]
            .as_str()
            .unwrap()
            .contains("not a regular file"),
        "{all}"
    );
}

#[test]
fn each_class_of_rule_refuses_with_its_kind_and_rule() {
    let cases: Vec<(&str, Break, &str)> = vec![
        (
            "structure (step 1)",
            Box::new(|e| put(e.docs.path(), "key-plan", b"not json")),
            "document KeyPlan: step 1",
        ),
        (
            "a key the bootstrap file does not pin (step 4)",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "audit-log",
                    &Pipeline::new("publisher-1").sign(
                        "audit-log",
                        source("audit-log").as_bytes(),
                        1,
                    ),
                );
            }),
            "document AuditLog: step 4: a signature does not verify",
        ),
        (
            "a missing declared document",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("upstream.jws")).unwrap()),
            "document Upstream: the source has no document of the kind",
        ),
        (
            "a payload rule (step 6)",
            Box::new(|e| {
                e.sign(
                    "token-lifetime",
                    &source("token-lifetime").replace("access_token: 10m", "access_token: 2h"),
                );
            }),
            "document TokenLifetime: step 6: default.access_token: above the built-in cap of one hour",
        ),
        (
            "a rule of the set",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary")
                        .replace("environment: development", "environment: production"),
                );
            }),
            "set : Upstream: issuer: must be https outside development",
        ),
    ];
    for (name, break_it, want) in cases {
        let e = env();
        break_it(&e);
        let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
        assert_eq!(code, Some(3), "{name}: {all}");
        let f = failures(&checks);
        assert!(
            f.iter().any(|l| l.starts_with(want)),
            "{name}: want {want}, got {f:?}"
        );
    }
}

/// verifies: REQ-TOKEN-038
#[test]
fn a_token_lifetime_or_a_ttl_cap_above_one_hour_is_refused_with_its_path() {
    let e = env();
    assert!(source("token-lifetime").contains("access_token: 10m"));
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("access_token: 10m", "access_token: 2h"),
    );
    let client = source("installation-client");
    assert!(!client.contains("ttl_cap"));
    e.sign(
        "installation-client",
        &client.replacen("  kind: ", "  ttl_cap: 2h\n  kind: ", 1),
    );
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    let f = failures(&checks).join("\n");
    assert!(
        f.contains("default.access_token: above the built-in cap of one hour"),
        "{f}"
    );
    assert!(
        f.contains(".ttl_cap: above the built-in cap of one hour"),
        "{f}"
    );

    // One hour itself is the cap, not above it.
    let e = env();
    e.sign(
        "installation-client",
        &client.replacen("  kind: ", "  ttl_cap: 1h\n  kind: ", 1),
    );
    let (code, _, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(0), "{all}");
}

/// verifies: REQ-KEYS-039
#[test]
fn a_key_cache_ttl_at_the_maximum_is_accepted_and_one_second_over_is_refused() {
    let plan = source("key-plan");
    assert!(plan.contains("cache_ttl: 15m"));
    for (ttl, ok) in [("3600s", true), ("3601s", false)] {
        let e = env();
        e.sign(
            "key-plan",
            &plan.replace("cache_ttl: 15m", &format!("cache_ttl: {ttl}")),
        );
        let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
        if ok {
            assert_eq!(code, Some(0), "{ttl}: {all}");
        } else {
            assert_eq!(code, Some(3), "{ttl}: {all}");
            assert_eq!(
                failures(&checks),
                [
                    "document KeyPlan: step 6: default.cache_ttl: above the built-in maximum of one hour"
                ],
                "{ttl}"
            );
        }
    }
}

/// verifies: REQ-POLICY-013
#[test]
fn a_set_that_declares_no_grant_vocabulary_is_refused() {
    let e = env();
    let b = source("boundary");
    assert!(b.contains("    - GrantVocabulary\n"));
    e.sign("boundary", &b.replace("    - GrantVocabulary\n", ""));
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(
        failures(&checks),
        ["set : Boundary: declared_kinds: must declare GrantVocabulary"]
    );
}

#[test]
fn no_value_of_a_document_is_printed() {
    // A credential name that breaks the rule, an unknown key and a wrongly typed field each hold a marker: the
    // checks name the paths, never the text.
    let marker = "zq-marker-7f3a";
    let e = env();
    let up = source("upstream");
    assert!(up.contains("secret: upstream-workforce"));
    e.sign(
        "upstream",
        &up.replace(
            "secret: upstream-workforce",
            &format!("secret: \"{marker}/x\""),
        ),
    );
    e.sign(
        "audit-log",
        &format!("{}  {marker}: {marker}\n", source("audit-log")),
    );
    e.sign(
        "token-lifetime",
        &source("token-lifetime")
            .replace("access_token: 10m", &format!("access_token: [{marker}]")),
    );
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(failures(&checks).len(), 3, "{all}");
    assert!(!all.contains(marker), "a value was printed: {all}");
    // The same in text output.
    let o = Command::new(env!("CARGO_BIN_EXE_store"))
        .args(["check", "--bootstrap", &e.bootstrap(), "--validate"])
        .arg(e.docs.path())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(o.status.code(), Some(3), "{text}");
    assert!(
        text.contains("fail document Upstream: step 6: workforce.secret: is not a credential name"),
        "{text}"
    );
    assert!(!text.contains(marker), "a value was printed: {text}");
}

/// `store check --validate --explain`: the exit code, the whole JSON object, and everything printed.
fn explain_with(bootstrap: &str, docs: &Path, extra: &[&str]) -> (Option<i32>, Value, String) {
    let mut args = vec!["--explain"];
    args.extend_from_slice(extra);
    let o = validate(bootstrap, docs, &args);
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    let all = format!("{stdout}{}", String::from_utf8_lossy(&o.stderr));
    let mut v: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {all}"));
    // The helper prints the settings in groups of one provenance; the tests read them one by one, as the CLI writes
    // them (cli.md "JSON output").
    let mut fields = Vec::new();
    for g in v["groups"].as_array().unwrap_or(&Vec::new()) {
        assert!(
            !g["settings"].as_array().unwrap().is_empty(),
            "an empty group: {all}"
        );
        for s in g["settings"].as_array().unwrap() {
            let mut f = s.clone();
            for k in ["class", "layer", "version", "source", "checks"] {
                f[k] = g[k].clone();
            }
            fields.push(f);
        }
    }
    v["fields"] = Value::Array(fields);
    (o.status.code(), v, all)
}

fn field<'a>(v: &'a Value, path: &str) -> &'a Value {
    v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == path)
        .unwrap_or_else(|| panic!("no field {path}"))
}

fn paths(v: &Value) -> Vec<&str> {
    v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect()
}

fn sha384(text: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, text.as_bytes());
    store::config::document::hex(d.as_ref())
}

/// verifies: REQ-OPS-023
#[test]
fn explain_gives_each_setting_its_layer_its_version_and_its_source() {
    let e = env();
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(0), "{all}");
    // The same checks run, so the set is one store@ would load; no installation line, as no runtime was named.
    assert!(
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["result"] == "ok" && c["name"] != "installation"),
        "{all}"
    );

    // A setting of the bootstrap file: no class, no version, the file is the source.
    let f = field(&v, "durable.driver");
    assert_eq!(
        (
            f["value"].as_str(),
            f["layer"].as_str(),
            f["class"].as_str()
        ),
        (Some("rqlite"), Some("bootstrap"), Some("-"))
    );
    assert_eq!(
        (f["version"].as_str(), f["source"].as_str()),
        (Some(""), Some("bootstrap"))
    );
    assert_eq!(
        f["checks"],
        serde_json::json!(["bootstrap", "installation"])
    );
    assert_eq!(field(&v, "start_timeout")["value"], "30s");
    assert_eq!(field(&v, "start_timeout")["layer"], "bootstrap");
    assert_eq!(field(&v, "publishers[0].kid")["value"], "publisher-1");

    // A setting of a signed document: the config class and layer, the seq of the document, and the document as the
    // audit fact of a start names it, with the digest of the payload.
    let f = field(&v, "Boundary.default.environment");
    assert_eq!(f["value"], "development");
    assert_eq!(
        (f["class"].as_str(), f["layer"].as_str()),
        (Some("config"), Some("config"))
    );
    assert_eq!(f["version"], "1");
    assert_eq!(
        f["source"].as_str().unwrap(),
        format!("Boundary:1:{}", sha384(source("boundary")))
    );
    assert_eq!(f["checks"], serde_json::json!(["document", "set"]));
    assert_eq!(
        field(&v, "TokenLifetime.default.access_token")["value"],
        "10m"
    );
    assert_eq!(field(&v, "KeyPlan.default.cache_ttl")["value"], "15m");
    assert_eq!(
        field(&v, "InstallationClient.sluis-cli.redirects[0]")["value"],
        "http://127.0.0.1/callback"
    );

    // A sweep over nothing would prove nothing: the Boundary and every kind it declares that sets something is there
    // (the local ExchangeTrust trusts no issuer, so it sets nothing).
    let kinds: std::collections::BTreeSet<_> = paths(&v)
        .iter()
        .filter(|p| p.chars().next().unwrap().is_ascii_uppercase())
        .map(|p| p.split('.').next().unwrap())
        .collect();
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        [
            "AuditCatalogue",
            "AuditLog",
            "Boundary",
            "GrantVocabulary",
            "InstallationClient",
            "KeyPlan",
            "Policy",
            "TokenLifetime",
            "Upstream",
        ]
    );
}

/// verifies: REQ-OPS-023
#[test]
fn a_start_timeout_the_file_leaves_out_is_a_built_in() {
    let e = env();
    let text = std::fs::read_to_string(e.bootstrap()).unwrap();
    assert!(text.contains("start_timeout: 30s\n"));
    let file = e.run.path().join("default.yaml");
    std::fs::write(&file, text.replace("start_timeout: 30s\n", "")).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (code, v, all) = explain_with(
        file.to_str().unwrap(),
        e.docs.path(),
        &["--field", "start_timeout"],
    );
    assert_eq!(code, Some(0), "{all}");
    let f = field(&v, "start_timeout");
    assert_eq!(f["value"], "30s");
    assert_eq!(f["layer"], "built-in");
    assert_eq!(f["source"], "store@");
    assert_eq!(f["version"], sluis_version::VERSION);
}

/// verifies: REQ-OPS-023
#[test]
fn a_credential_is_shown_as_its_reference_and_marked() {
    let e = env();
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(0), "{all}");
    for path in [
        "InstallationClient.example-app.secret",
        "Upstream.workforce.secret",
    ] {
        assert_eq!(field(&v, path)["secret"], true, "{path}");
    }
    assert_eq!(
        field(&v, "Upstream.workforce.secret")["value"],
        "upstream-workforce"
    );
    // Only a reference is marked: no other setting is.
    let marked: Vec<_> = v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f.get("secret").is_some())
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        marked,
        [
            "Upstream.workforce.secret",
            "InstallationClient.example-app.secret"
        ]
    );
}

/// verifies: REQ-OPS-023
#[test]
fn a_text_or_a_long_value_is_shown_as_its_digest_and_a_public_key_is_not_repeated() {
    let e = env();
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(0), "{all}");
    // Cedar text and the vocabulary are not interpreted by store@: one setting each, identified by the digest of the
    // payload, which `sha384sum` of the reviewed file gives.
    assert_eq!(
        field(&v, "Policy.default.cedar")["value"].as_str().unwrap(),
        format!("sha384:{}", sha384(source("policy")))
    );
    assert_eq!(
        field(&v, "GrantVocabulary.default.document")["value"]
            .as_str()
            .unwrap(),
        format!("sha384:{}", sha384(source("grant-vocabulary")))
    );
    assert!(!all.contains("permit"), "Cedar text was printed");
    // A pin identifies the publisher; the key itself is not printed.
    assert!(!all.contains("BEGIN PUBLIC KEY"));
    assert!(v["fields"].as_array().unwrap().iter().all(|f| {
        let s = f["value"].as_str().unwrap();
        s.len() <= 256 && !s.chars().any(char::is_control)
    }));
}

/// verifies: REQ-OPS-023
#[test]
fn field_limits_the_output_to_a_subtree_at_a_boundary_of_the_path() {
    let e = env();
    let b = e.bootstrap();
    let only = |scope: &str| {
        let (code, v, all) = explain_with(&b, e.docs.path(), &["--field", scope]);
        assert_eq!(code, Some(0), "{scope}: {all}");
        paths(&v).into_iter().map(str::to_owned).collect::<Vec<_>>()
    };
    assert_eq!(only("durable"), ["durable.driver", "durable.socket"]);
    assert_eq!(only("durable.driver"), ["durable.driver"]);
    assert_eq!(only("publishers[0]").len(), 2);
    assert_eq!(
        only("TokenLifetime.default.access_token"),
        ["TokenLifetime.default.access_token"]
    );
    assert_eq!(
        only("Upstream.workforce.scopes"),
        [
            "Upstream.workforce.scopes[0]",
            "Upstream.workforce.scopes[1]",
            "Upstream.workforce.scopes[2]"
        ]
    );
    // `Upstream` is one kind and `Up` is none; a path that names nothing gives no field, which the CLI reports.
    assert!(only("Up").is_empty());
    assert!(only("durabl").is_empty());
    // The checks still ran and are all there.
    let (_, v, _) = explain_with(&b, e.docs.path(), &["--field", "Up"]);
    assert!(!v["checks"].as_array().unwrap().is_empty());
}

/// verifies: REQ-OPS-023
#[test]
fn a_set_that_is_refused_is_not_explained_and_no_value_is_printed() {
    let marker = "zq-marker-7f3a";
    let e = env();
    e.sign(
        "token-lifetime",
        &source("token-lifetime")
            .replace("access_token: 10m", &format!("access_token: [{marker}]")),
    );
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(3), "{all}");
    assert!(v["fields"].as_array().unwrap().is_empty(), "{all}");
    assert_eq!(
        failures(v["checks"].as_array().unwrap()),
        ["document TokenLifetime: step 6: default.access_token: not a duration string"]
    );
    assert!(!all.contains(marker), "a value was printed: {all}");

    // A refused bootstrap file explains nothing either.
    let file = write_bootstrap(e.run.path(), &e.p, 0o620);
    let (code, v, all) = explain_with(&file, e.docs.path(), &[]);
    assert_eq!(code, Some(3), "{all}");
    assert!(v["fields"].as_array().unwrap().is_empty(), "{all}");
}

#[test]
fn explain_takes_no_runtime_and_field_needs_explain() {
    let e = env();
    let o = validate(
        &e.bootstrap(),
        e.docs.path(),
        &["--explain", "--runtime", "bare-metal"],
    );
    assert_eq!(o.status.code(), Some(2));
    let o = validate(&e.bootstrap(), e.docs.path(), &["--field", "boundary"]);
    assert_eq!(o.status.code(), Some(2));
}

/// verifies: REQ-OPS-023
#[test]
fn a_document_duration_is_shown_in_its_largest_whole_unit() {
    let e = env();
    assert!(source("token-lifetime").contains("id_token: 10m"));
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("id_token: 10m", "id_token: 600s"),
    );
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(0), "{all}");
    assert_eq!(field(&v, "TokenLifetime.default.id_token")["value"], "10m");
}

/// verifies: REQ-OPS-023
#[test]
fn a_url_is_shown_without_its_query_and_fragment() {
    let marker = "zq-marker-7f3a";
    let e = env();
    let clients = source("installation-client");
    assert!(clients.contains("https://app.local.test/callback"));
    e.sign(
        "installation-client",
        &clients.replace(
            "https://app.local.test/callback",
            &format!("https://app.local.test/callback?token={marker}#{marker}"),
        ),
    );
    let up = source("upstream");
    e.sign(
        "upstream",
        &up.replace(
            "realms/sluis-test",
            &format!("realms/sluis-test?key={marker}"),
        ),
    );
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(0), "{all}");
    assert_eq!(
        field(&v, "InstallationClient.example-app.redirects[0]")["value"],
        "https://app.local.test/callback?<elided>"
    );
    assert_eq!(
        field(&v, "Upstream.workforce.issuer")["value"],
        "http://127.0.0.1:8180/realms/sluis-test?<elided>"
    );
    assert!(!all.contains(marker), "a query was printed: {all}");
}

/// verifies: REQ-OPS-023
#[test]
fn a_url_with_user_information_is_refused_by_check_and_never_printed() {
    let marker = "zq-marker-7f3a";
    let e = env();
    let up = source("upstream");
    e.sign(
        "upstream",
        &up.replace(
            "http://127.0.0.1:8180",
            &format!("https://{marker}:{marker}@h.example.com/?token={marker}"),
        ),
    );
    let (code, checks, all) = run(&e.bootstrap(), e.docs.path());
    assert_eq!(code, Some(3), "{all}");
    assert_eq!(
        failures(&checks),
        [
            "document Upstream: step 6: workforce.issuer: must not hold user information before the host"
        ]
    );
    assert!(!all.contains(marker), "a value was printed: {all}");
    // And explain explains nothing of it.
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(3), "{all}");
    assert!(v["fields"].as_array().unwrap().is_empty());
    assert!(!all.contains(marker), "a value was printed: {all}");
}

/// verifies: REQ-OPS-023
#[test]
fn an_invisible_format_character_makes_a_value_its_digest_and_it_says_so() {
    let e = env();
    let up = source("upstream");
    // A right-to-left override and a line separator, which a terminal shows as text that is not there.
    for bad in ["a\u{202e}b", "a\u{2028}b", "a\u{200b}b"] {
        e.sign(
            "upstream",
            &up.replace("client_id: sluis-local", &format!("client_id: \"{bad}\"")),
        );
        let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
        assert_eq!(code, Some(0), "{all}");
        let f = field(&v, "Upstream.workforce.client_id");
        assert!(f["value"].as_str().unwrap().starts_with("sha384:"), "{f}");
        assert_eq!(f["digest"], true);
        assert!(
            !all.chars()
                .any(|c| matches!(c, '\u{202e}' | '\u{2028}' | '\u{200b}')),
            "an invisible character was printed"
        );
    }
    // A value that is shown says nothing of a digest.
    let (_, v, _) = explain_with(
        &e.bootstrap(),
        e.docs.path(),
        &["--field", "Upstream.workforce.kind"],
    );
    assert!(field(&v, "Upstream.workforce.kind").get("digest").is_none());
}

/// verifies: REQ-OPS-023
#[test]
fn a_public_key_of_the_slot_map_is_its_pin_and_an_attestation_is_a_digest() {
    let e = env();
    let plan = source("key-plan");
    assert!(plan.contains("  slot_map: []\n"));
    e.sign(
        "key-plan",
        &plan.replace(
            "  slot_map: []\n",
            "  slot_map:\n    - node: n1\n      slots:\n        - slot: \"9a\"\n          purpose: token-signing\n          public_key: AAECAwQ\n          attestation: QUJD\n          attestation_signer: REVG\n",
        ),
    );
    let (code, v, all) = explain_with(&e.bootstrap(), e.docs.path(), &[]);
    assert_eq!(code, Some(0), "{all}");
    let at = |key: &str| format!("KeyPlan.default.slot_map[0].slots[0].{key}");
    assert_eq!(field(&v, &at("slot"))["value"], "9a");
    let pin = |bytes: &[u8]| {
        format!(
            "sha384:{}",
            store::config::document::hex(
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, bytes).as_ref()
            )
        )
    };
    assert_eq!(field(&v, &at("public_key"))["value"], pin(&[0, 1, 2, 3, 4]));
    assert_eq!(field(&v, &at("attestation"))["value"], pin(b"QUJD"));
    for key in ["public_key", "attestation", "attestation_signer"] {
        assert_eq!(field(&v, &at(key))["digest"], true, "{key}");
    }
    assert!(
        !all.contains("AAECAwQ") && !all.contains("QUJD") && !all.contains("REVG"),
        "{all}"
    );
}

/// verifies: REQ-OPS-023
#[test]
fn an_unmatched_field_exits_2_in_text_and_gives_an_empty_list_in_json() {
    let e = env();
    let o = Command::new(env!("CARGO_BIN_EXE_store"))
        .args([
            "check",
            "--explain",
            "--field",
            "Up",
            "--bootstrap",
            &e.bootstrap(),
            "--validate",
        ])
        .arg(e.docs.path())
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.stdout.is_empty());
    // A matched one prints its line.
    let o = Command::new(env!("CARGO_BIN_EXE_store"))
        .args([
            "check",
            "--explain",
            "--field",
            "Upstream.workforce.kind",
            "--bootstrap",
            &e.bootstrap(),
            "--validate",
        ])
        .arg(e.docs.path())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(
        text.starts_with("Upstream.workforce.kind = oidc (config config 1 Upstream:1:"),
        "{text}"
    );
    let (code, v, _) = explain_with(&e.bootstrap(), e.docs.path(), &["--field", "Up"]);
    assert_eq!((code, v["groups"].as_array().unwrap().len()), (Some(0), 0));
}

/// What the explain walk reads out of each fixture document is what the payload decodes into: every text the walk
/// finds is in the decoded message, and every text in the decoded message is one the walk found. The two read the
/// same YAML in two ways, so this is what keeps them from drifting apart (a field one of them reads and the other does
/// not).
///
/// verifies: REQ-OPS-023
#[test]
fn explain_and_the_payload_decoder_read_the_same_texts_from_every_fixture() {
    use buffa::Message as _;
    use sluis_proto::sluis::config::v2alpha1 as pb;
    // The quoted strings of a Debug print, unescaped as Debug escapes them.
    fn quoted(debug: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let mut it = debug.chars();
        while let Some(c) = it.next() {
            if c != '"' {
                continue;
            }
            let mut s = String::new();
            while let Some(c) = it.next() {
                match c {
                    '"' => break,
                    '\\' => s.push(it.next().unwrap_or('\\')),
                    c => s.push(c),
                }
            }
            // A field the file leaves out is the empty string in the message.
            if !s.is_empty() {
                out.insert(s);
            }
        }
        out
    }
    let mut swept = 0;
    for (segment, text) in LOCAL {
        let kind = sluis_registry::kind_by_segment(segment).unwrap();
        if !store::config::payload::readable(kind)
            || matches!(kind.name, "Policy" | "GrantVocabulary")
        {
            continue;
        }
        let leaves = store::config::explain::leaves(kind, text).unwrap();
        // The texts the walk read, except the ones the message does not hold as a string: a duration is a number of
        // seconds there, and the fields that are bytes.
        let walked: std::collections::BTreeSet<String> = leaves
            .iter()
            .filter(|l| l.text)
            .filter(|l| {
                use store::config::explain::Treatment::{Digest, Duration, Pin};
                !matches!(
                    store::config::explain::treatment(kind.name, &l.rel),
                    Duration | Pin | Digest
                )
            })
            .map(|l| l.value.clone())
            .collect();
        let items = store::config::payload::decode(kind, text.as_bytes()).unwrap();
        let mut decoded = std::collections::BTreeSet::new();
        for (_, bytes) in &items {
            let debug = match kind.name {
                "Boundary" => format!("{:?}", pb::Boundary::decode_from_slice(bytes).unwrap()),
                "KeyPlan" => format!("{:?}", pb::KeyPlan::decode_from_slice(bytes).unwrap()),
                "TokenLifetime" => {
                    format!("{:?}", pb::TokenLifetime::decode_from_slice(bytes).unwrap())
                }
                "AuditLog" => format!("{:?}", pb::AuditLog::decode_from_slice(bytes).unwrap()),
                "AuditCatalogue" => format!(
                    "{:?}",
                    pb::AuditCatalogue::decode_from_slice(bytes).unwrap()
                ),
                "ExchangeTrust" => {
                    format!("{:?}", pb::ExchangeTrust::decode_from_slice(bytes).unwrap())
                }
                "Upstream" => format!("{:?}", pb::Upstream::decode_from_slice(bytes).unwrap()),
                "InstallationClient" => format!(
                    "{:?}",
                    pb::InstallationClient::decode_from_slice(bytes).unwrap()
                ),
                other => panic!("no decoder in this test for {other}"),
            };
            decoded.extend(quoted(&debug));
        }
        // The message of a keyed kind holds the id of its item as a string too (its name or id), which the file may
        // leave out.
        let walked: std::collections::BTreeSet<String> =
            if matches!(kind.name, "Upstream" | "InstallationClient") {
                let ids = items.iter().map(|(id, _)| id.clone());
                walked.iter().cloned().chain(ids).collect()
            } else {
                walked
            };
        assert_eq!(
            walked, decoded,
            "{}: the walk and the decoder read different texts",
            kind.name
        );
        swept += walked.len();
    }
    assert!(
        swept >= 60,
        "the sweep covered {swept} texts: a sweep over nothing proves nothing"
    );
}

/// The verdict of the loader on a set: None when it loads, else the kind and the rule of the refusal.
async fn loader_verdict(e: &Env) -> Option<String> {
    let sock = e.run.path().join("config-source.sock");
    let _ = std::fs::remove_file(&sock);
    let _stop = serve_driver(&sock, e.docs.path());
    up(&sock).await;
    match Loader::start(
        &dial(&sock),
        &bootstrap(vec![e.p.publisher(&[])]),
        Duration::from_secs(5),
    )
    .await
    {
        Ok(_) => None,
        Err(err) => Some(err.to_string()),
    }
}

/// The verdict of the offline check: None when every check passes, else the first failure as the loader words it.
fn offline_verdict(e: &Env) -> Option<String> {
    let checks = offline::check_dir(e.docs.path(), &bootstrap(vec![e.p.publisher(&[])]));
    let first = checks.iter().find(|c| c.result == "fail")?;
    Some(if first.path.is_empty() {
        first.rule.clone()
    } else {
        format!("{}: {}", first.path, first.rule)
    })
}

/// verifies: REQ-DATA-090
#[tokio::test(flavor = "multi_thread")]
async fn the_offline_check_and_the_loader_give_the_same_verdict_on_every_set() {
    let cases: Vec<(&str, Break)> = vec![
        ("the local set", Box::new(|_| {})),
        (
            "structure",
            Box::new(|e| put(e.docs.path(), "key-plan", b"{}")),
        ),
        (
            "an unpinned key",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "policy",
                    &Pipeline::new("publisher-1").sign("policy", source("policy").as_bytes(), 1),
                );
            }),
        ),
        (
            "a document under the wrong kind",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "audit-log",
                    &e.p.sign("audit-catalogue", source("audit-catalogue").as_bytes(), 1),
                );
            }),
        ),
        (
            "a missing document",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("exchange-trust.jws")).unwrap()),
        ),
        (
            "a link that leaves the directory",
            Box::new(|e| {
                let outside = e.run.path().join("outside");
                std::fs::create_dir_all(&outside).unwrap();
                put(
                    &outside,
                    "key-plan",
                    &e.p.sign("key-plan", source("key-plan").as_bytes(), 1),
                );
                std::fs::remove_file(e.docs.path().join("key-plan.jws")).unwrap();
                std::os::unix::fs::symlink(
                    outside.join("key-plan.jws"),
                    e.docs.path().join("key-plan.jws"),
                )
                .unwrap();
            }),
        ),
        (
            "a link that stays in the directory",
            Box::new(|e| {
                std::fs::create_dir_all(e.docs.path().join("..data")).unwrap();
                put(
                    &e.docs.path().join("..data"),
                    "key-plan",
                    &e.p.sign("key-plan", source("key-plan").as_bytes(), 1),
                );
                std::fs::remove_file(e.docs.path().join("key-plan.jws")).unwrap();
                std::os::unix::fs::symlink(
                    "..data/key-plan.jws",
                    e.docs.path().join("key-plan.jws"),
                )
                .unwrap();
            }),
        ),
        (
            "a document that is not a regular file",
            Box::new(|e| {
                std::fs::remove_file(e.docs.path().join("audit-log.jws")).unwrap();
                std::fs::create_dir(e.docs.path().join("audit-log.jws")).unwrap();
            }),
        ),
        (
            "a missing boundary",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("boundary.jws")).unwrap()),
        ),
        (
            "a payload type",
            Box::new(|e| e.sign("token-lifetime", "default:\n  id_token: ten minutes\n")),
        ),
        (
            "a ttl_cap above the cap",
            Box::new(|e| {
                e.sign(
                    "installation-client",
                    &source("installation-client").replacen(
                        "  kind: ",
                        "  ttl_cap: 61m\n  kind: ",
                        1,
                    ),
                );
            }),
        ),
        (
            "a cache above the maximum",
            Box::new(|e| {
                e.sign(
                    "key-plan",
                    &source("key-plan").replace("cache_ttl: 15m", "cache_ttl: 2h"),
                )
            }),
        ),
        (
            "another boundary",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("name: dev", "name: other"),
                )
            }),
        ),
        (
            "a kind this build cannot read",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("- KeyPlan", "- RegulatedPartyPolicy"),
                )
            }),
        ),
        (
            "no grant vocabulary",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("    - GrantVocabulary\n", ""),
                )
            }),
        ),
        (
            "production with plain http",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary")
                        .replace("environment: development", "environment: production"),
                );
            }),
        ),
        (
            "one credential name for two kinds",
            Box::new(|e| {
                e.sign(
                    "upstream",
                    &source("upstream")
                        .replace("secret: upstream-workforce", "secret: client-example-app"),
                );
            }),
        ),
    ];
    // The one place where the words differ: a document the file driver refuses. The loader gets that refusal over the
    // wire as a source that did not answer, without the kind it asked for or the driver's reason; the check reads the
    // directory with the driver's own Dir::read, so it names both. The loader's words are still all there, in place.
    let driver_refusals = [
        ("a link that leaves the directory", "KeyPlan"),
        ("a document that is not a regular file", "AuditLog"),
    ];
    let mut refused = 0;
    for (name, break_it) in cases {
        let e = env();
        break_it(&e);
        let (live, offline) = (loader_verdict(&e).await, offline_verdict(&e));
        let want = match driver_refusals.iter().find(|(n, _)| *n == name) {
            Some((_, kind)) => {
                assert_eq!(
                    live.as_deref(),
                    Some("the config source did not answer"),
                    "{name}"
                );
                live.as_ref()
                    .map(|l| format!("{kind}: {l}: the file driver refuses the document (bound)"))
            }
            None => live.clone(),
        };
        assert_eq!(offline, want, "{name}: the loader says {live:?}");
        refused += usize::from(live.is_some());
    }
    assert_eq!(
        refused, 15,
        "every case but the local set and the link inside is refused"
    );
}
