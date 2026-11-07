#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The signed config snapshot (WP-11): the local installation's documents, the payload rules, the
//! cold start that refuses, the reload that keeps the snapshot in force, and the watcher that
//! reloads. The documents are signed here with a key made for the test and read through the real
//! `file` driver on a Unix socket.

mod config_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use buffa::Message as _;
use config_support::{LOCAL, Pipeline, bootstrap, document, put, serve_driver, up, write_local};
use sluis_kit::dial;
use sluis_proto::sluis::config::v2alpha1 as pb;
use store::config::payload;
use store::config::{ConfigSnapshot, Loader, Reloaded};

fn kind(name: &str) -> &'static sluis_registry::Kind {
    sluis_registry::kind_by_name(name).unwrap()
}

fn source(segment: &str) -> &'static str {
    LOCAL.iter().find(|(s, _)| *s == segment).unwrap().1
}

// ---- the documents of the local installation ----

#[test]
fn every_local_document_is_read_into_its_kinds_message() {
    for (segment, text) in LOCAL {
        let k = sluis_registry::kind_by_segment(segment).unwrap();
        let items =
            payload::decode(k, text.as_bytes()).unwrap_or_else(|e| panic!("{segment}: {e}"));
        assert!(!items.is_empty(), "{segment}");
        // A singleton kind has the one item `default`; a keyed kind uses its name (D-17).
        let ids: Vec<_> = items.iter().map(|(i, _)| i.as_str()).collect();
        match segment {
            "upstream" => assert_eq!(ids, ["workforce"]),
            "installation-client" => assert_eq!(ids, ["example-app", "sluis-cli"]),
            _ => assert_eq!(ids, ["default"], "{segment}"),
        }
    }
}

#[test]
fn the_local_values_are_the_ones_the_skeleton_needs() {
    let one = |name: &str| {
        payload::decode(
            kind(name),
            source(sluis_registry::kind_by_name(name).unwrap().segment).as_bytes(),
        )
        .unwrap()
        .remove(0)
        .1
    };
    let b = pb::Boundary::decode_from_slice(&one("Boundary")).unwrap();
    assert_eq!(
        (
            b.name.as_str(),
            b.environment.as_str(),
            b.default_tenant.as_str()
        ),
        ("dev", "development", "acme")
    );
    assert_eq!(b.declared_kinds.len(), 9);
    let u = pb::Upstream::decode_from_slice(&one("Upstream")).unwrap();
    assert_eq!(u.name, "workforce");
    assert_eq!(u.issuer, "http://127.0.0.1:8180/realms/sluis-test");
    assert_eq!(u.subject_claim, "sub");
    // The name of its client secret in the secret source, which store@ serves as UpstreamSecret.
    assert_eq!(u.secret, "upstream-workforce");
    let c = pb::InstallationClient::decode_from_slice(&one("InstallationClient")).unwrap();
    // The items of a keyed kind are in the order of their ids: the audience comes before the command-line client.
    assert_eq!(
        (c.id.as_str(), c.kind.as_str()),
        ("example-app", "confidential")
    );
    let all = payload::decode(
        kind("InstallationClient"),
        source("installation-client").as_bytes(),
    )
    .unwrap();
    let cli = pb::InstallationClient::decode_from_slice(&all[1].1).unwrap();
    assert_eq!(
        (cli.id.as_str(), cli.kind.as_str(), cli.profile.as_str()),
        ("sluis-cli", "public", "native")
    );
    assert!(!cli.requires.is_empty() && !c.requires.is_empty());
    // The config names where a confidential client's secret is, and a public client names none (ADR 0005).
    assert_eq!(
        (c.secret.as_str(), cli.secret.as_str()),
        ("client-example-app", "")
    );
    let t = pb::TokenLifetime::decode_from_slice(&one("TokenLifetime")).unwrap();
    assert_eq!(t.access_token.seconds, 600);
    assert_eq!(t.human_session_absolute.seconds, 12 * 3600);
    let k = pb::KeyPlan::decode_from_slice(&one("KeyPlan")).unwrap();
    assert_eq!((k.cache_ttl.seconds, k.purposes.len()), (900, 4));
    let v = pb::GrantVocabulary::decode_from_slice(&one("GrantVocabulary")).unwrap();
    assert_eq!(v.document, source("grant-vocabulary").as_bytes());
    let a = pb::AuditCatalogue::decode_from_slice(&one("AuditCatalogue")).unwrap();
    assert!(a.actions.iter().any(|x| x == "store.reload.refused"));
    let l = pb::AuditLog::decode_from_slice(&one("AuditLog")).unwrap();
    assert_eq!(l.logs.len(), 2);
}

// ---- the payload rules ----

fn refused(kind_name: &str, text: &str) -> String {
    payload::decode(kind(kind_name), text.as_bytes())
        .expect_err("must be refused")
        .0
}

#[test]
fn the_credential_a_client_names_is_a_name_and_only_a_confidential_client_has_one() {
    let client = |kind: &str, secret: &str| {
        format!(
            "app:\n  kind: {kind}\n  redirects: [\"https://app.example.com/cb\"]\n  requires: [\"dev:app:user\"]\n  secret: {secret}\n"
        )
    };
    assert!(
        payload::decode(
            kind("InstallationClient"),
            client("confidential", "client-app").as_bytes()
        )
        .is_ok()
    );
    let e = refused("InstallationClient", &client("public", "client-app"));
    assert!(
        e.contains("app.secret: a public client has no secret"),
        "{e}"
    );
    // The credential driver's rule (systemd's): letters, digits, `-`, `_` and `.`, starting with a letter or a digit.
    for ok in ["Client_App.1", "client-app", "a"] {
        assert!(
            payload::decode(
                kind("InstallationClient"),
                client("confidential", ok).as_bytes()
            )
            .is_ok(),
            "{ok}"
        );
    }
    let long = "a".repeat(129);
    for bad in [
        "../x",
        "a/b",
        ".hidden",
        "-x",
        "_x",
        "\"has space\"",
        long.as_str(),
    ] {
        let e = refused("InstallationClient", &client("confidential", bad));
        assert!(
            e.contains("app.secret: is not a credential name"),
            "{bad}: {e}"
        );
    }
}

/// verifies: REQ-AUTHN-004
#[test]
fn a_plain_http_redirect_off_loopback_is_refused_for_every_client_kind() {
    let client = |client_kind: &str, redirect: &str| {
        let secret = if client_kind == "public" {
            String::new()
        } else {
            "  secret: client-app\n".to_owned()
        };
        format!(
            "app:\n  kind: {client_kind}\n  redirects: [\"https://app.example.com/cb\", \"{redirect}\"]\n  requires: [\"dev:app:user\"]\n{secret}"
        )
    };
    for ck in ["public", "confidential", "exchange"] {
        // RFC 8252 section 7.3: http on a loopback IP literal, with any port or none.
        for ok in [
            "https://app.example.com/other",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:1/callback",
            "http://127.0.0.1:65535/callback",
            "http://[::1]/callback",
            "http://[::1]:8080/callback",
            "http://127.0.0.1",
        ] {
            assert!(
                payload::decode(kind("InstallationClient"), client(ck, ok).as_bytes()).is_ok(),
                "{ck}: {ok} was refused"
            );
        }
        for bad in [
            "http://app.example.com/callback",
            // A name that may not resolve to loopback (RFC 8252 section 8.3).
            "http://localhost/callback",
            "http://localhost:8080/callback",
            "http://127.0.0.2/callback",
            "http://[::2]/callback",
            "http://192.0.2.1/callback",
            "http://127.0.0.1.example.com/callback",
            "http://127.0.0.1:8080@app.example.com/callback",
            "http://user@127.0.0.1/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:65536/callback",
            "http://127.0.0.1:/callback",
            "http://127.0.0.1:+80/callback",
            "http://[::1]x/callback",
            "ftp://127.0.0.1/callback",
        ] {
            let e = refused("InstallationClient", &client(ck, bad));
            assert!(
                e.contains("app.redirects[1]: must be https, or http on a loopback IP literal")
                    || e.contains("app.redirects[1]: must be an http or https URL")
                    || e.contains(
                        "app.redirects[1]: must not hold user information before the host"
                    ),
                "{ck}: {bad}: {e}"
            );
            assert!(!e.contains(bad), "an error never shows a value: {e}");
        }
    }
}

/// A redirect whose host `entry` cannot name in the `form-action` of a form_post page is refused when the client is
/// registered, because every form_post answer to that client would be a server error (REQ-AUTHN-079): a name in Unicode
/// must be written in its `xn--` form.
///
/// verifies: REQ-AUTHN-004
#[test]
fn a_redirect_host_that_form_action_cannot_name_is_refused_at_registration() {
    let client = |redirect: &str| {
        format!(
            "app:\n  kind: public\n  redirects: [\"https://app.example.com/cb\", \"{redirect}\"]\n  requires: [\"dev:app:user\"]\n"
        )
    };
    for ok in [
        "https://xn--bcher-kva.example/cb",
        "https://app-1.example.com:8443/cb?x=1",
        "https://203.0.113.7/cb",
        "https://[2001:db8::7]:8443/cb",
        "https://app.example.com",
        "https://app.example.com?x=1",
    ] {
        assert!(
            payload::decode(kind("InstallationClient"), client(ok).as_bytes()).is_ok(),
            "{ok} was refused"
        );
    }
    for bad in [
        "https://b\u{fc}cher.example/cb",
        "https://\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.example/cb",
        "https://my_app.example.com/cb",
        "https://app.example.com:/cb",
        "https://app.example.com:0/cb",
        "https://app.example.com:65536/cb",
        "https://app.example.com:80a/cb",
        "https://*.example.com/cb",
        "https://[::1/cb",
        "https://[zz::1]/cb",
        "https:///cb",
    ] {
        let e = refused("InstallationClient", &client(bad));
        assert!(
            e.contains(
                "app.redirects[1]: the host must be an IP literal or a name of ASCII letters"
            ) || e.contains("app.redirects[1]: must be an http or https URL"),
            "{bad}: {e}"
        );
        assert!(!e.contains(bad), "an error never shows a value: {e}");
    }
}

/// A URL with user information is refused wherever the payload takes one, with the path and never the value.
#[test]
fn a_url_with_user_information_is_refused_with_its_path_and_never_its_value() {
    let bad = "https://zq-user:zq-pass@h.example.com/?token=zq-token";
    let cases = [
        (
            "Upstream",
            format!(
                "w:\n  kind: oidc\n  issuer: \"{bad}\"\n  client_id: c\n  subject_claim: sub\n"
            ),
            "w.issuer",
        ),
        (
            "ExchangeTrust",
            format!(
                "default:\n  issuers:\n    - issuer: https://i.example.com\n      proof_kind: jwt\n      jwks_uri: \"{bad}\"\n"
            ),
            "issuers[0].jwks_uri",
        ),
        (
            "ExchangeTrust",
            format!("default:\n  issuers:\n    - issuer: \"{bad}\"\n      proof_kind: jwt\n"),
            "issuers[0].issuer",
        ),
        (
            "InstallationClient",
            format!(
                "app:\n  kind: public\n  redirects: [\"{bad}\"]\n  requires: [\"dev:app:user\"]\n"
            ),
            "app.redirects[0]",
        ),
    ];
    for (kind_name, text, path) in cases {
        let e = refused(kind_name, &text);
        assert!(
            e.contains(&format!(
                "{path}: must not hold user information before the host"
            )),
            "{kind_name}: {e}"
        );
        for secret in ["zq-user", "zq-pass", "zq-token"] {
            assert!(!e.contains(secret), "an error never shows a value: {e}");
        }
    }
    // An `@` after the authority is a path, not user information.
    let ok = "w:\n  kind: oidc\n  issuer: https://h.example.com/@realm?a=b@c\n  client_id: c\n  subject_claim: sub\n";
    assert!(payload::decode(kind("Upstream"), ok.as_bytes()).is_ok());
}

/// verifies: REQ-AUTHN-004
#[tokio::test]
async fn only_a_public_native_clients_loopback_redirect_passes_the_https_floor() {
    // ADR 0011 and ADR 0021: outside development, the one plain-http URL is the loopback redirect
    // of a public client with the native profile (RFC 8252 section 7.3). Every other URL of the
    // set is https, and the local clients stay as they are, so only the added client is at stake.
    let set = |e: &Env, environment: &str, client: &str, redirect: &str| {
        e.sign(
            "boundary",
            &source("boundary")
                .replace(
                    "environment: development",
                    &format!("environment: {environment}"),
                )
                .replace("http://", "https://"),
            1,
        );
        e.sign(
            "upstream",
            &source("upstream").replace("http://", "https://"),
            1,
        );
        e.sign(
            "installation-client",
            &format!(
                "{}probe:\n{client}  redirects: [\"{redirect}\"]\n  requires: [\"dev:example-app:user\"]\n",
                source("installation-client")
            ),
            1,
        );
    };
    let native = "  kind: public\n  profile: native\n";
    let not_native = [
        ("a browser client", "  kind: public\n  profile: browser\n"),
        ("a public client with no profile", "  kind: public\n"),
        (
            "a confidential client",
            "  kind: confidential\n  profile: web\n",
        ),
        (
            "a confidential client that says native",
            "  kind: confidential\n  profile: native\n",
        ),
        ("an exchange client", "  kind: exchange\n"),
    ];
    for environment in ["production", "staging", "development"] {
        for loopback in ["http://127.0.0.1/callback", "http://[::1]:8080/callback"] {
            let e = env().await;
            write_local(e.docs.path(), &e.pipeline, 1);
            set(&e, environment, native, loopback);
            assert!(
                e.start().await.is_ok(),
                "{environment}: a public native client's loopback redirect did not start: {loopback}"
            );
            for (who, client) in not_native {
                let e = env().await;
                write_local(e.docs.path(), &e.pipeline, 1);
                set(&e, environment, client, loopback);
                let started = e.start().await;
                if environment == "development" {
                    assert!(
                        started.is_ok(),
                        "development: {who} with {loopback} did not start"
                    );
                } else {
                    let err = started
                        .err()
                        .unwrap_or_else(|| panic!("{environment}: {who} with {loopback} started"));
                    assert!(
                        err.to_string().contains(
                            "InstallationClient: redirects: must be https outside development"
                        ),
                        "{environment}: {who}: {err}"
                    );
                }
            }
        }
        // Off loopback, refused at step 6, the payload, whatever the client and the environment.
        let e = env().await;
        write_local(e.docs.path(), &e.pipeline, 1);
        set(&e, environment, native, "http://app.example.com/callback");
        let err = e
            .start()
            .await
            .err()
            .unwrap_or_else(|| panic!("{environment}: a plain http redirect started"));
        assert!(
            err.to_string()
                .contains("must be https, or http on a loopback IP literal"),
            "{environment}: {err}"
        );
    }
}

#[test]
fn the_secret_an_upstream_names_is_a_credential_name() {
    let upstream = |secret: &str| {
        format!(
            "workforce:\n  kind: oidc\n  issuer: https://idp.example.com\n  client_id: c\n  subject_claim: sub\n  secret: {secret}\n"
        )
    };
    let u = payload::decode(kind("Upstream"), upstream("upstream-workforce").as_bytes()).unwrap();
    assert_eq!(
        pb::Upstream::decode_from_slice(&u[0].1).unwrap().secret,
        "upstream-workforce"
    );
    for bad in ["../x", "a/b", ".hidden", "\"has space\""] {
        let e = refused("Upstream", &upstream(bad));
        assert!(
            e.contains("workforce.secret: is not a credential name"),
            "{bad}: {e}"
        );
    }
}

/// verifies: REQ-CLIENT-005
#[test]
fn a_client_is_of_exactly_one_type_from_the_closed_set() {
    let client = |kind_line: &str| {
        format!(
            "app:\n{kind_line}  redirects: [\"https://app.example.com/cb\"]\n  requires: [\"dev:app:user\"]\n"
        )
    };
    let decoded = |kind_line: &str| {
        let items =
            payload::decode(kind("InstallationClient"), client(kind_line).as_bytes()).unwrap();
        assert_eq!(items.len(), 1);
        pb::InstallationClient::decode_from_slice(&items[0].1).unwrap()
    };
    // Each type of the set is read, and is the one type of its client.
    for ty in ["public", "confidential", "exchange"] {
        assert_eq!(decoded(&format!("  kind: {ty}\n")).kind, ty);
    }
    // Anything outside the set is refused by the place of `kind`, and its value is never shown: another name, another
    // spelling, a type of another model, an empty value, a number, none at all.
    for (line, want) in [
        (
            "  kind: service\n",
            "app.kind: not one of the values of the schema",
        ),
        (
            "  kind: machine\n",
            "app.kind: not one of the values of the schema",
        ),
        (
            "  kind: Public\n",
            "app.kind: not one of the values of the schema",
        ),
        (
            "  kind: \"public \"\n",
            "app.kind: not one of the values of the schema",
        ),
        ("  kind: \"\"\n", "app.kind: required"),
        ("  kind: 1\n", "app.kind: must be a string"),
        ("", "app.kind: required"),
        // More than one type: a list, or the key written twice.
        (
            "  kind: [public, confidential]\n",
            "app.kind: must be a string",
        ),
        ("  kind: {public: true}\n", "app.kind: must be a string"),
    ] {
        let e = refused("InstallationClient", &client(line));
        assert_eq!(e, want, "{line:?}");
    }
    let twice = refused(
        "InstallationClient",
        &client("  kind: public\n  kind: exchange\n"),
    );
    // The strict profile refuses a key written twice by its line and column, so a second type never reaches the loader.
    assert_eq!(twice, "line 3, column 3: duplicate key");
    let e = refused("InstallationClient", &client("  kind: surprise-type-9\n"));
    assert!(!e.contains("surprise-type-9"), "{e}");
}

/// verifies: REQ-OPS-010
#[test]
fn a_payload_is_refused_by_place_and_an_error_shows_no_value() {
    let e = refused(
        "Upstream",
        "workforce:\n  kind: oidc\n  issuer: https://idp.example.com\n  client_id: c\n  subject_claim: sub\n  surprise-value-1: x\n",
    );
    assert!(e.contains("workforce.<key>: unknown key"), "{e}");
    assert!(
        !e.contains("surprise-value-1"),
        "an error never shows a value: {e}"
    );
    // A retired or unknown field is refused, a type error names the field.
    let e = refused(
        "TokenLifetime",
        "default:\n  id_token: 10m\n  access_token: 600\n",
    );
    assert!(e.contains("default.access_token"), "{e}");
    // The strict profile: a duplicate key, an anchor, a tag.
    for bad in [
        "default:\n  id_token: 1m\n  id_token: 2m\n",
        "default: &a\n  id_token: 1m\n",
        "default: !!map\n  id_token: 1m\n",
    ] {
        assert!(!refused("TokenLifetime", bad).is_empty(), "{bad}");
    }
}

/// verifies: REQ-DATA-044
#[test]
fn durations_follow_the_grammar_and_the_built_in_cap() {
    let doc = |d: &str| {
        format!(
            "default:\n  id_token: 10m\n  access_token: {d}\n  human_session_absolute: 12h\n  refresh_idle: 8h\n"
        )
    };
    for ok in ["30s", "15m", "1h"] {
        assert!(
            payload::decode(kind("TokenLifetime"), doc(ok).as_bytes()).is_ok(),
            "{ok}"
        );
    }
    for bad in ["30", "PT30S", "1.5s", "1h30m", "-1s", "0s"] {
        let e = refused("TokenLifetime", &doc(bad));
        assert!(e.starts_with("default.access_token"), "{bad}: {e}");
    }
    let e = refused("TokenLifetime", &doc("2h"));
    assert!(e.contains("above the built-in cap"), "{e}");
}

#[test]
fn key_plan_recipients_are_thumbprints_listed_once() {
    // The RFC 7638 section 3.1 thumbprint, and one of a P-384 key (both 43 characters of base64url).
    let a = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    let b = "S6so4ozvKppaEWY0wKql5mscesqW7SqnwqkfyQ_fabw";
    let doc = |list: &str| format!("default:\n  cache_ttl: 15m\n  recipients: {list}\n");
    let plan = |text: &[u8]| {
        let items = payload::decode(kind("KeyPlan"), text).unwrap();
        pb::KeyPlan::decode_from_slice(&items[0].1).unwrap()
    };
    let k = plan(doc(&format!("[{a}, {b}]")).as_bytes());
    assert_eq!(k.recipients, vec![a.to_owned(), b.to_owned()]);
    assert!(payload::decode(kind("KeyPlan"), doc("[]").as_bytes()).is_ok());
    // The field may be left out: nobody is listed then.
    assert!(plan(b"default:\n  cache_ttl: 15m\n").recipients.is_empty());
    for (bad, why) in [
        ("[node-1-abcdefghijklmnop]".to_owned(), "a label"),
        (format!("[{}]", &a[..42]), "too short"),
        (format!("[{a}=]"), "padded"),
        // The last character of a canonical encoding of 32 bytes ends in one of 16 values.
        (
            format!("[{}B]", &a[..42]),
            "a last character with bits that are not the key's",
        ),
        (format!("[{a}, {a}]"), "listed twice"),
        (a.to_owned(), "not a list"),
        ("[1]".to_owned(), "not a string"),
    ] {
        let e = refused("KeyPlan", &doc(&bad));
        assert!(e.starts_with("default.recipients"), "{why}: {e}");
        assert!(!e.contains(a), "an error never shows a value: {e}");
    }
}

#[test]
fn a_singleton_has_one_item_default_and_a_keyed_kind_uses_its_name() {
    let k = "default:\n  cache_ttl: 15m\n";
    assert!(payload::decode(kind("KeyPlan"), k.as_bytes()).is_ok());
    for bad in [
        "other:\n  cache_ttl: 15m\n",
        "default:\n  cache_ttl: 15m\nsecond:\n  cache_ttl: 15m\n",
        "{}",
        "- cache_ttl: 15m\n",
        "",
    ] {
        assert!(!refused("KeyPlan", bad).is_empty(), "{bad:?}");
    }
    // The name a message carries is its id.
    let up = |name: &str| {
        format!(
            "workforce:\n  name: {name}\n  kind: oidc\n  issuer: https://idp.example.com\n  client_id: c\n  subject_claim: sub\n"
        )
    };
    assert!(payload::decode(kind("Upstream"), up("workforce").as_bytes()).is_ok());
    assert!(refused("Upstream", &up("other")).contains("workforce.name"));
    // An id is an address part.
    assert!(refused("Upstream", "Work Force:\n  kind: oidc\n").contains("<id>"));
}

#[test]
fn a_kind_this_build_cannot_read_is_refused_not_skipped() {
    for name in ["RegulatedPartyPolicy", "SignInMethods", "FrontHost"] {
        if let Some(k) = sluis_registry::kind_by_name(name) {
            assert!(payload::decode(k, b"default: {}\n").is_err(), "{name}");
        }
    }
    // A non-config kind has no document at all.
    assert!(payload::decode(kind("DataKeyWrap"), b"default: {}\n").is_err());
}

// ---- the loader ----

struct Env {
    docs: tempfile::TempDir,
    _sock: tempfile::TempDir,
    pipeline: Pipeline,
    client: sluis_kit::Client,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn env() -> Env {
    let (docs, sock) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let path = sock.path().join("config-source.sock");
    let stop = serve_driver(&path, docs.path());
    up(&path).await;
    Env {
        docs,
        _sock: sock,
        pipeline: Pipeline::new("publisher-1"),
        client: dial(&path),
        _stop: stop,
    }
}

impl Env {
    async fn start(&self) -> Result<Arc<Loader>, store::config::LoadError> {
        Loader::start(
            &self.client,
            &bootstrap(vec![self.pipeline.publisher(&[])]),
            Duration::from_millis(300),
        )
        .await
    }

    fn sign(&self, segment: &str, text: &str, seq: u64) {
        put(
            self.docs.path(),
            segment,
            &self.pipeline.sign(segment, text.as_bytes(), seq),
        );
    }
}

/// verifies: REQ-DATA-099
/// the signed document the snapshot holds is the one in force, byte for byte as the source gave it.
#[tokio::test]
async fn req_data_099_the_snapshot_holds_the_signed_bytes_of_the_document_in_force() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 3);
    let loader = e.start().await.unwrap();
    let on_disk =
        |segment: &str| std::fs::read(e.docs.path().join(format!("{segment}.jws"))).unwrap();
    assert_eq!(loader.signed("key-plan"), Some(on_disk("key-plan")));
    assert_eq!(loader.signed("no-such-kind"), None);

    // A refused reload keeps the document in force, signed bytes included.
    let before = on_disk("key-plan");
    e.sign("key-plan", source("key-plan"), 2);
    let (err, _) = refused_reload(loader.reload().await);
    assert!(err.to_string().contains("step 5"), "{err}");
    assert_eq!(loader.signed("key-plan"), Some(before));

    // A reload that takes a newer one serves the newer bytes.
    e.sign("key-plan", source("key-plan"), 4);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.signed("key-plan"), Some(on_disk("key-plan")));
}

#[tokio::test]
async fn a_cold_start_loads_the_set_and_serves_it_read_only() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 7);
    let loader = e.start().await.unwrap();

    assert_eq!(loader.version("boundary"), Some(7));
    assert_eq!(loader.version("upstream"), Some(7));
    // Every kind the boundary declares has its document in the snapshot, ExchangeTrust (declared, no issuer) among them.
    assert_eq!(loader.version("exchange-trust"), Some(7));
    assert!(loader.get("exchange-trust", "default").is_some());

    let b = pb::Boundary::decode_from_slice(&loader.get("boundary", "default").unwrap()).unwrap();
    assert_eq!(b.name, "dev");
    let ups = loader.list("upstream");
    assert_eq!(ups.len(), 1);
    assert_eq!(ups[0].0, "workforce");
    assert!(loader.get("upstream", "nope").is_none());

    // The audit fact names each document's kind, seq and the SHA-384 of its payload.
    let summaries = loader.snapshot().summaries();
    assert_eq!(summaries.len(), 10);
    let up = summaries.iter().find(|s| s.kind == "Upstream").unwrap();
    assert_eq!(up.seq, 7);
    assert_eq!(up.sha384.len(), 96);
    let digest =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, source("upstream").as_bytes());
    assert_eq!(up.sha384, store::config::document::hex(digest.as_ref()));
}

/// The `Kind` to `{seq, sha384}` object that the fact of a set must hold, made without the loader: the kind of the
/// segment, the seq the test signed it at and the SHA-384 of the reviewed file, as `sha384sum` prints it.
fn expected_documents(docs: &[(&str, &str, u64)]) -> serde_json::Value {
    use std::fmt::Write as _;
    docs.iter()
        .map(|(segment, text, seq)| {
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, text.as_bytes());
            let hex = digest.as_ref().iter().fold(String::new(), |mut s, b| {
                write!(s, "{b:02x}").unwrap();
                s
            });
            let kind = sluis_registry::kind_by_segment(segment).unwrap().name;
            (
                kind.to_owned(),
                serde_json::json!({ "seq": seq, "sha384": hex }),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// verifies: REQ-DATA-085
/// The fact of a reload that applies, as the emitter makes it into a record, names all ten documents with the kind, the
/// seq (a different one for each, so that a swap shows) and the SHA-384 of the reviewed file, when only one of them
/// changed, and the fact of the start (checked in `serve_config.rs` through the binary) is the same object before it.
#[tokio::test]
async fn the_reload_fact_names_every_document_by_kind_seq_and_sha384_when_one_changed() {
    let e = env().await;
    let mut signed: Vec<(&str, String, u64)> = LOCAL
        .iter()
        .enumerate()
        .map(|(i, (segment, text))| (*segment, (*text).to_owned(), 3 + i as u64))
        .collect();
    for (segment, text, seq) in &signed {
        e.sign(segment, text, *seq);
    }
    let emitter = sluis_audit::Emitter::new(sluis_audit::Config {
        actor: "store".into(),
        boundary: "dev".into(),
        release: "0.0.0".into(),
        transport_socket: "/nonexistent/emit.sock".into(),
        key_socket: None,
        now: None,
    })
    .unwrap();
    let record = |outcome: &Reloaded| {
        let event =
            store::config::reload_event("dev", outcome).expect("an applied reload is a fact");
        let emitter = &emitter;
        async move {
            let (bytes, _) = emitter
                .record(store::audit::EmitterSink::event(event))
                .await
                .expect("the emitter takes the fact");
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        }
    };
    let expected = |signed: &[(&str, String, u64)]| {
        let docs: Vec<(&str, &str, u64)> = signed
            .iter()
            .map(|(s, t, q)| (*s, t.as_str(), *q))
            .collect();
        expected_documents(&docs)
    };

    let loader = e.start().await.unwrap();
    // The set the start holds, as the same object.
    let at_start = {
        let summaries = loader.snapshot().summaries();
        let event = store::audit::EmitterSink::event(store::audit::AuditEvent {
            action: "store.start",
            failure: false,
            reason: String::new(),
            fields: vec![("boundary", "dev".into())],
            documents: summaries,
            correlation_id: None,
        });
        let (bytes, _) = emitter
            .record(event)
            .await
            .expect("the emitter takes the start");
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };
    assert_eq!(
        at_start["unmapped"]["sluis"]["documents"],
        expected(&signed)
    );

    // One document changes; the fact names the new seq and digest of that one and the old ones of the other nine.
    let changed = source("token-lifetime").replace("10m", "20m");
    let at = signed
        .iter()
        .position(|(s, _, _)| *s == "token-lifetime")
        .unwrap();
    signed[at] = ("token-lifetime", changed.clone(), 40);
    e.sign("token-lifetime", &changed, 40);
    let outcome = loader.reload().await;
    let rec = record(&outcome).await;
    assert_eq!(rec["metadata"]["event_code"], "store.reload");
    let documents = &rec["unmapped"]["sluis"]["documents"];
    assert_eq!(documents, &expected(&signed));
    assert_eq!(documents.as_object().unwrap().len(), 10);
    let before = &at_start["unmapped"]["sluis"]["documents"];
    let differing: Vec<&String> = documents
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| documents[k.as_str()] != before[k.as_str()])
        .collect();
    assert_eq!(differing, ["TokenLifetime"]);
}

/// verifies: REQ-DATA-083
#[tokio::test]
async fn a_cold_start_refuses_on_any_failure_and_says_why() {
    // Each case starts from a valid directory and breaks one thing.
    type Break = Box<dyn Fn(&Env)>;
    let cases: Vec<(&str, Break, &str)> = vec![
        (
            "a declared document is missing",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("audit-log.jws")).unwrap()),
            "AuditLog: the source has no document",
        ),
        (
            "the boundary document is missing",
            Box::new(|e| std::fs::remove_file(e.docs.path().join("boundary.jws")).unwrap()),
            "Boundary: the source has no document",
        ),
        (
            "a document is signed by a key that is not pinned",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "key-plan",
                    &Pipeline::new("publisher-1").sign(
                        "key-plan",
                        source("key-plan").as_bytes(),
                        1,
                    ),
                )
            }),
            "KeyPlan: step 4",
        ),
        (
            "a document names a kid that is not pinned",
            Box::new(|e| {
                put(
                    e.docs.path(),
                    "key-plan",
                    &Pipeline::new("rogue").sign("key-plan", source("key-plan").as_bytes(), 1),
                )
            }),
            "KeyPlan: step 3",
        ),
        (
            "a document is not signed at all",
            Box::new(|e| put(e.docs.path(), "key-plan", source("key-plan").as_bytes())),
            "KeyPlan: step 1",
        ),
        (
            "a document is signed but its payload is not valid for the kind",
            Box::new(|e| e.sign("token-lifetime", "default:\n  id_token: ten minutes\n", 1)),
            "TokenLifetime: step 6: default.id_token",
        ),
        (
            "the boundary is not the bootstrap file's",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("name: dev", "name: other"),
                    1,
                )
            }),
            "Boundary: name: is not the boundary of the bootstrap file",
        ),
        (
            "the boundary declares a kind this build cannot read",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary").replace("- KeyPlan", "- RegulatedPartyPolicy"),
                    1,
                )
            }),
            "Boundary: declared_kinds: RegulatedPartyPolicy has no reader",
        ),
        (
            "production with a plain http issuer",
            Box::new(|e| {
                e.sign(
                    "boundary",
                    &source("boundary")
                        .replace("environment: development", "environment: production"),
                    1,
                )
            }),
            "must be https outside development",
        ),
    ];
    for (name, break_it, want) in cases {
        let e = env().await;
        write_local(e.docs.path(), &e.pipeline, 1);
        break_it(&e);
        let err = e
            .start()
            .await
            .err()
            .unwrap_or_else(|| panic!("{name}: it started"));
        assert!(err.to_string().contains(want), "{name}: {err}");
        assert!(!err.unreachable, "{name}");
    }
}

/// verifies: REQ-DATA-041
#[tokio::test]
async fn a_signed_document_with_an_unknown_key_is_refused_at_start_and_at_reload_with_no_value_shown()
 {
    let key_and_value = "  zq-unknown-key: zq-secret-value\n";
    let bad = format!("{}{key_and_value}", source("upstream"));
    // The cold start: the signature is good, the payload has a key the schema does not know.
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    e.sign("upstream", &bad, 1);
    let err = e.start().await.err().expect("an unknown key started");
    assert_eq!(
        err.to_string(),
        "Upstream: step 6: workforce.<key>: unknown key"
    );
    // The reload: the snapshot in force stays, and the audit fact of the refusal names the place and not the text.
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    e.sign("upstream", &bad, 2);
    let outcome = loader.reload().await;
    let event = store::config::reload_event("dev", &outcome).expect("a refusal is a fact");
    assert_eq!(event.action, "store.reload.refused");
    let why = event.fields.iter().find(|(k, _)| *k == "why").unwrap();
    assert_eq!(why.1, "step 6: workforce.<key>: unknown key");
    let shown = format!("{event:?}");
    assert!(
        !shown.contains("zq-secret-value") && !shown.contains("zq-unknown-key"),
        "{shown}"
    );
    assert_eq!(loader.version("upstream"), Some(1));
}

#[tokio::test]
async fn a_cold_start_waits_for_a_source_and_then_gives_up_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let client = dial(&dir.path().join("none.sock"));
    let err = Loader::start(
        &client,
        &bootstrap(vec![Pipeline::new("publisher-1").publisher(&[])]),
        Duration::from_millis(400),
    )
    .await
    .err()
    .unwrap();
    assert!(err.unreachable, "{err}");
}

/// The files of a directory with their bytes, by name: what a run left there.
fn tree(dir: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|f| {
            let f = f.unwrap();
            // A socket has a name and no bytes.
            let bytes = if f.file_type().unwrap().is_file() {
                std::fs::read(f.path()).unwrap()
            } else {
                Vec::new()
            };
            (f.file_name().to_string_lossy().into_owned(), bytes)
        })
        .collect()
}

/// What the directories of a run hold: the config source's files with their bytes, and the names in the socket
/// directory. Neither is touched by the loader, which is handed a client and a bootstrap file and no path.
type Dirs = (std::collections::BTreeMap<String, Vec<u8>>, Vec<String>);

fn dirs(e: &Env) -> Dirs {
    (
        tree(e.docs.path()),
        tree(e._sock.path()).keys().cloned().collect(),
    )
}

/// verifies: REQ-DATA-081
#[tokio::test]
async fn a_cold_start_takes_the_latest_signed_document_whatever_its_seq() {
    let e = env().await;
    // A first run: the set at seq 9, then a newer token lifetime at seq 12, which the running store takes. The
    // directories are taken just before each start or reload and compared just after it, so that nothing the test
    // writes sits between the two.
    write_local(e.docs.path(), &e.pipeline, 9);
    let before = dirs(&e);
    assert_eq!(before.0.len(), 10, "the ten signed documents of the set");
    assert!(
        before.0.keys().all(|n| n.ends_with(".jws")),
        "only the signed documents: {:?}",
        before.0.keys().collect::<Vec<_>>()
    );
    assert!(!before.1.is_empty(), "the socket of the config source");
    let first = e.start().await.unwrap();
    assert_eq!(dirs(&e), before, "the first start wrote nothing");
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("10m", "20m"),
        12,
    );
    let before = dirs(&e);
    assert!(matches!(first.reload().await, Reloaded::Applied(_)));
    assert_eq!(dirs(&e), before, "an applied reload wrote nothing");
    assert_eq!(first.version("token-lifetime"), Some(12));
    // The run ends. The publisher goes back: the whole set, validly signed again, at lower seqs than that run held
    // (1 for most kinds, 3 for the one that was at 12).
    drop(first);
    write_local(e.docs.path(), &e.pipeline, 1);
    e.sign("token-lifetime", source("token-lifetime"), 3);

    // A cold start has nothing in force to compare with: it starts, and it runs the documents as the source holds them.
    let before = dirs(&e);
    let second = e
        .start()
        .await
        .expect("a lower seq than a previous run starts");
    assert_eq!(dirs(&e), before, "the second start wrote nothing");
    assert_eq!(second.version("token-lifetime"), Some(3));
    assert_eq!(second.version("boundary"), Some(1));
    let t = pb::TokenLifetime::decode_from_slice(&second.get("token-lifetime", "default").unwrap())
        .unwrap();
    assert_eq!(
        t.id_token.seconds, 600,
        "it runs the older payload, not the one of the previous run"
    );
    // The audit fact of the start names those seqs.
    let summaries = second.snapshot().summaries();
    assert_eq!(summaries.len(), 10);
    assert_eq!(
        summaries
            .iter()
            .find(|s| s.kind == "TokenLifetime")
            .unwrap()
            .seq,
        3
    );

    // From then on the running store takes a growing seq only: the seq in force is the one mark, and it is in memory.
    e.sign("token-lifetime", source("token-lifetime"), 2);
    let before = dirs(&e);
    let (err, _) = refused_reload(second.reload().await);
    assert!(err.to_string().contains("step 5: a lower seq"), "{err}");
    assert_eq!(dirs(&e), before, "a refused reload wrote nothing");
    assert_eq!(
        second.version("token-lifetime"),
        Some(3),
        "the refused reload kept the document in force"
    );
}

/// The local Boundary document without the kind ExchangeTrust in its declaration.
fn without_trust() -> String {
    let b = source("boundary");
    assert!(b.contains("    - ExchangeTrust\n"));
    b.replace("    - ExchangeTrust\n", "")
}

fn refused_reload(r: Reloaded) -> (store::config::LoadError, bool) {
    match r {
        Reloaded::Refused { error, report } => (error, report),
        other => panic!("not refused: {other:?}"),
    }
}

/// verifies: REQ-DATA-086
/// A good change and a bad one that arrive together apply none of them, and fixing the bad one applies the set.
#[tokio::test]
async fn a_bad_document_on_reload_keeps_the_snapshot_and_is_reported_once() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    let before = loader.snapshot().summaries();

    // Nothing changed.
    assert!(matches!(loader.reload().await, Reloaded::Unchanged));

    // A good new document and a bad one in the same set: none of it is applied.
    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("10m", "20m"),
        2,
    );
    e.sign("key-plan", "default:\n  cache_ttl: nonsense\n", 2);
    let (err, report) = refused_reload(loader.reload().await);
    assert!(err.to_string().starts_with("KeyPlan: step 6"), "{err}");
    assert!(report);
    assert_eq!(
        loader.snapshot().summaries(),
        before,
        "the snapshot in force stays"
    );
    assert_eq!(loader.version("token-lifetime"), Some(1));
    // The same refused document is reported once, not at every poll.
    let (_, report) = refused_reload(loader.reload().await);
    assert!(!report);
    // Another bad document is a new report.
    e.sign("key-plan", "default:\n  cache_ttl: still nonsense\n", 3);
    let (_, report) = refused_reload(loader.reload().await);
    assert!(report);

    // Fixing it applies the whole set: both documents.
    e.sign("key-plan", source("key-plan"), 4);
    let Reloaded::Applied(applied) = loader.reload().await else {
        panic!("not applied")
    };
    assert_eq!(applied.len(), 10);
    assert_eq!(loader.version("token-lifetime"), Some(2));
    assert_eq!(loader.version("key-plan"), Some(4));
    let t = pb::TokenLifetime::decode_from_slice(&loader.get("token-lifetime", "default").unwrap())
        .unwrap();
    assert_eq!(t.id_token.seconds, 1200);
}

/// verifies: REQ-DATA-080
#[tokio::test]
async fn the_sequence_number_only_grows_on_a_running_store() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 5);
    let loader = e.start().await.unwrap();
    let payload = source("token-lifetime");

    // A lower seq, with a new payload or the old one.
    e.sign("token-lifetime", &payload.replace("10m", "20m"), 4);
    let (err, _) = refused_reload(loader.reload().await);
    assert!(err.to_string().contains("step 5: a lower seq"), "{err}");
    // The same seq with another payload.
    e.sign("token-lifetime", &payload.replace("10m", "20m"), 5);
    let (err, _) = refused_reload(loader.reload().await);
    assert!(
        err.to_string()
            .contains("step 5: the same seq with another payload"),
        "{err}"
    );
    assert_eq!(loader.version("token-lifetime"), Some(5));
    // The same seq with the same payload, signed again: no change.
    e.sign("token-lifetime", payload, 5);
    assert!(matches!(loader.reload().await, Reloaded::Unchanged));
    // A higher seq replaces it.
    e.sign("token-lifetime", &payload.replace("10m", "20m"), 6);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.version("token-lifetime"), Some(6));
}

#[tokio::test]
async fn a_source_that_goes_away_keeps_the_snapshot_and_comes_back() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    std::fs::remove_file(e.docs.path().join("upstream.jws")).unwrap();
    let (err, report) = refused_reload(loader.reload().await);
    assert!(
        err.to_string()
            .contains("Upstream: the source has no document"),
        "{err}"
    );
    assert!(report);
    assert!(
        loader.get("upstream", "workforce").is_some(),
        "the old document still serves"
    );
    e.sign("upstream", source("upstream"), 1);
    assert!(matches!(loader.reload().await, Reloaded::Unchanged));
}

#[tokio::test]
async fn a_declared_kind_that_is_added_or_dropped_follows_the_boundary() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    // The local boundary declares ExchangeTrust; leaving it out drops the kind from the snapshot.
    e.sign("boundary", &without_trust(), 2);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.version("exchange-trust"), None);
    // Declaring a kind with no document is a failure, and the set stays.
    std::fs::remove_file(e.docs.path().join("exchange-trust.jws")).unwrap();
    e.sign("boundary", source("boundary"), 3);
    let (err, _) = refused_reload(loader.reload().await);
    assert!(
        err.to_string()
            .contains("ExchangeTrust: the source has no document"),
        "{err}"
    );
    assert_eq!(loader.version("exchange-trust"), None);
    // With the document, it joins.
    e.sign("exchange-trust", "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks }\n", 1);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.version("exchange-trust"), Some(1));
    // Dropping it from the declaration removes it from the snapshot.
    e.sign("boundary", &without_trust(), 4);
    assert!(matches!(loader.reload().await, Reloaded::Applied(_)));
    assert_eq!(loader.version("exchange-trust"), None);
}

#[tokio::test]
async fn a_regulated_party_co_signature_is_required_by_the_bootstrap_file() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let party = Pipeline::new("party-1");
    // The party co-signs KeyPlan: the publisher's signature alone no longer loads it.
    let b = bootstrap(vec![
        e.pipeline.publisher(&[]),
        party.publisher(&["KeyPlan"]),
    ]);
    let err = Loader::start(&e.client, &b, Duration::from_millis(300))
        .await
        .err()
        .unwrap();
    assert!(
        err.to_string()
            .contains("KeyPlan: step 4: a co-signer's signature is missing"),
        "{err}"
    );
    // With both signatures over one payload and one seq, it loads.
    let text = source("key-plan");
    let both = document(
        text.as_bytes(),
        &[
            e.pipeline.signature("key-plan", text.as_bytes(), 1),
            party.signature("key-plan", text.as_bytes(), 1),
        ],
    );
    put(e.docs.path(), "key-plan", &both);
    assert!(
        Loader::start(&e.client, &b, Duration::from_millis(300))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_watcher_reloads_when_a_document_changes_and_hands_over_each_outcome() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let task = tokio::spawn({
        let (loader, seen) = (Arc::clone(&loader), Arc::clone(&seen));
        async move {
            store::config::reload::run(loader, move |r| {
                let seen = Arc::clone(&seen);
                async move {
                    let line = match &r {
                        Reloaded::Unchanged => "unchanged".to_owned(),
                        Reloaded::Applied(d) => format!("applied {}", d.len()),
                        Reloaded::Refused { error, report } => format!("refused {report}: {error}"),
                    };
                    seen.lock().unwrap().push(line);
                }
            })
            .await;
        }
    });
    let wait_for = |want: &'static str| {
        let seen = Arc::clone(&seen);
        async move {
            for _ in 0..200 {
                if seen.lock().unwrap().iter().any(|l| l.contains(want)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("never saw {want:?} in {:?}", seen.lock().unwrap());
        }
    };

    e.sign(
        "token-lifetime",
        &source("token-lifetime").replace("10m", "20m"),
        2,
    );
    wait_for("applied 10").await;
    assert_eq!(loader.version("token-lifetime"), Some(2));

    e.sign("key-plan", "default: {}\n", 9);
    wait_for("refused true: KeyPlan: step 6").await;
    assert_eq!(
        loader.version("key-plan"),
        Some(1),
        "the snapshot in force stays"
    );
    task.abort();
}

/// verifies: REQ-DATA-086
/// One document of each of the ten kinds that this build reads changes in turn, under one running loader and one running
/// watcher: each change takes effect on the reload with no restart, the reload applies the whole set (ten documents) and
/// nothing else in the snapshot moves.
#[tokio::test]
async fn a_change_of_any_one_document_reloads_the_whole_snapshot_with_no_restart() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    let applied: Arc<Mutex<Vec<usize>>> = Arc::default();
    let task = tokio::spawn({
        let (loader, applied) = (Arc::clone(&loader), Arc::clone(&applied));
        async move {
            store::config::reload::run(loader, move |r| {
                let applied = Arc::clone(&applied);
                async move {
                    if let Reloaded::Applied(d) = r {
                        applied.lock().unwrap().push(d.len());
                    }
                }
            })
            .await;
        }
    });
    let trust = "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks }\n";
    let changes: [(&str, String); 10] = [
        (
            "boundary",
            source("boundary").replace("default_tenant: acme", "default_tenant: globex"),
        ),
        (
            "key-plan",
            source("key-plan").replace("cache_ttl: 15m", "cache_ttl: 10m"),
        ),
        (
            "token-lifetime",
            source("token-lifetime").replace("10m", "20m"),
        ),
        (
            "grant-vocabulary",
            format!("{}# changed\n", source("grant-vocabulary")),
        ),
        ("policy", format!("{}// changed\n", source("policy"))),
        (
            "audit-log",
            source("audit-log").replace("project: sluis", "project: other"),
        ),
        (
            "audit-catalogue",
            source("audit-catalogue").replace("release: \"0.0.0\"", "release: \"0.0.1\""),
        ),
        (
            "upstream",
            source("upstream").replace("client_id: sluis-local", "client_id: sluis-local-2"),
        ),
        (
            "installation-client",
            source("installation-client")
                .replace("http://127.0.0.1/callback", "http://127.0.0.1/cb"),
        ),
        ("exchange-trust", trust.to_owned()),
    ];
    type Held = (&'static str, Option<u64>, Vec<(String, Vec<u8>)>);
    let state = |loader: &Loader| -> Vec<Held> {
        LOCAL
            .iter()
            .map(|(segment, _)| (*segment, loader.version(segment), loader.list(segment)))
            .collect()
    };
    for (i, (segment, text)) in changes.iter().enumerate() {
        assert_ne!(
            text,
            source(segment),
            "{segment}: the change changed nothing"
        );
        let before = state(&loader);
        let seq = 10 + i as u64;
        e.sign(segment, text, seq);
        let mut seen = false;
        for _ in 0..200 {
            if loader.version(segment) == Some(seq) {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(seen, "{segment}: the reload did not take it");
        let after = state(&loader);
        for (b, a) in before.iter().zip(&after) {
            if b.0 == *segment {
                assert_eq!(a.1, Some(seq), "{segment}");
                assert_ne!(a.2, b.2, "{segment}: the items did not change");
            } else {
                assert_eq!(
                    a, b,
                    "{segment} was changed by a reload of another document"
                );
            }
        }
        // The outcome is handed over after the snapshot is swapped: wait for it.
        for _ in 0..200 {
            if applied.lock().unwrap().len() > i {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            applied.lock().unwrap().len(),
            i + 1,
            "{segment}: one reload applies one change"
        );
    }
    assert_eq!(
        *applied.lock().unwrap(),
        [10; 10],
        "each reload applied the whole set"
    );
    task.abort();
}

#[tokio::test]
async fn a_kind_declared_later_with_no_document_yet_is_retried_until_it_arrives() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    let loader = e.start().await.unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let task = tokio::spawn({
        let (loader, seen) = (Arc::clone(&loader), Arc::clone(&seen));
        async move {
            store::config::reload::run(loader, move |r| {
                let seen = Arc::clone(&seen);
                async move {
                    let line = match &r {
                        Reloaded::Unchanged => "unchanged".to_owned(),
                        Reloaded::Applied(d) => format!("applied {}", d.len()),
                        Reloaded::Refused { error, report } => format!("refused {report}: {error}"),
                    };
                    seen.lock().unwrap().push(line);
                }
            })
            .await;
        }
    });
    let wait_for = |want: &'static str| {
        let seen = Arc::clone(&seen);
        async move {
            for _ in 0..200 {
                if seen.lock().unwrap().iter().any(|l| l.contains(want)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("never saw {want:?} in {:?}", seen.lock().unwrap());
        }
    };

    // The boundary stops declaring ExchangeTrust, and declares it again while its document is not in the source: the
    // reload is refused and the snapshot stays. The kind is not in the snapshot, so nothing watches its name.
    e.sign("boundary", &without_trust(), 2);
    wait_for("applied 9").await;
    std::fs::remove_file(e.docs.path().join("exchange-trust.jws")).unwrap();
    e.sign("boundary", source("boundary"), 3);
    wait_for("refused true: ExchangeTrust: the source has no document").await;
    assert_eq!(loader.version("exchange-trust"), None);

    // The document arrives. No watched name changes, so only the retry can find it.
    e.sign("exchange-trust", "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks }\n", 1);
    wait_for("applied 10").await;
    assert_eq!(loader.version("exchange-trust"), Some(1));
    assert_eq!(loader.version("boundary"), Some(3));
    task.abort();
}

/// verifies: REQ-ISO-106
#[tokio::test]
async fn a_credential_name_belongs_to_one_secret_kind() {
    // The upstream names the credential of the confidential client example-app: InstallationClientSecret's readers
    // could otherwise be served the upstream's secret, or the adapter the client's.
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    e.sign(
        "upstream",
        &source("upstream").replace("secret: upstream-workforce", "secret: client-example-app"),
        1,
    );
    let err = e
        .start()
        .await
        .err()
        .unwrap_or_else(|| panic!("a credential shared by two secret kinds started"));
    assert!(
        err.to_string()
            .contains("Upstream: secret: names a credential an InstallationClient names"),
        "{err}"
    );
    assert!(
        !err.to_string().contains("client-example-app"),
        "an error never shows a value: {err}"
    );
    // The local set, where each names its own, starts.
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 1);
    assert!(e.start().await.is_ok());
}

/// verifies: REQ-SEC-037
#[tokio::test]
async fn plain_http_is_for_development_and_only_on_a_loopback_ip_literal() {
    // Each URL the set publishes or fetches, one at a time; every other URL is https. ADR 0011:
    // a development boundary takes http on 127.0.0.1 or [::1] only, never a name and never another
    // address; staging and production take no http URL at all.
    #[derive(Clone, Copy)]
    enum At {
        Boundary,
        Upstream,
        TrustIssuer,
        TrustJwks,
    }
    let set = |e: &Env, environment: &str, at: At, url: &str| {
        let pick = |here: At, default: &str| {
            if std::mem::discriminant(&here) == std::mem::discriminant(&at) {
                url.to_owned()
            } else {
                default.to_owned()
            }
        };
        e.sign(
            "boundary",
            &source("boundary")
                .replace(
                    "environment: development",
                    &format!("environment: {environment}"),
                )
                .replace(
                    "issuer: https://sluis.dev.local.test",
                    &format!(
                        "issuer: {}",
                        pick(At::Boundary, "https://sluis.dev.local.test")
                    ),
                )
                .replace("    - Upstream\n", "    - Upstream\n    - ExchangeTrust\n"),
            1,
        );
        e.sign(
            "upstream",
            &source("upstream").replace(
                "http://127.0.0.1:8180/realms/sluis-test",
                &pick(At::Upstream, "https://idp.example.com/realms/sluis-test"),
            ),
            1,
        );
        e.sign(
            "exchange-trust",
            &format!(
                "default:\n  issuers:\n    - {{ issuer: \"{}\", audiences: [sluis], proof_kind: jwks, jwks_uri: \"{}\" }}\n",
                pick(At::TrustIssuer, "https://token.example.com"),
                pick(At::TrustJwks, "https://token.example.com/keys"),
            ),
            1,
        );
    };
    let places = [
        (At::Boundary, "Boundary: issuer"),
        (At::Upstream, "Upstream: issuer"),
        (At::TrustIssuer, "ExchangeTrust: issuers: issuer"),
        (At::TrustJwks, "ExchangeTrust: issuers: jwks_uri"),
    ];
    let loopback = [
        "http://127.0.0.1:8180/realms/x",
        "http://[::1]:8180/realms/x",
    ];
    let off_loopback = [
        "http://idp.example.com/realms/x",
        // A name that may not resolve to loopback (RFC 8252 section 8.3).
        "http://localhost:8180/realms/x",
        "http://127.0.0.2:8180/realms/x",
        "http://192.0.2.7/realms/x",
        "http://127.0.0.1.example.com/realms/x",
    ];
    for (at, place) in places {
        for environment in ["development", "staging", "production"] {
            let development = environment == "development";
            let start = |url: &'static str| {
                let set = &set;
                async move {
                    let e = env().await;
                    write_local(e.docs.path(), &e.pipeline, 1);
                    set(&e, environment, at, url);
                    e.start().await.err().map(|err| err.to_string())
                }
            };
            assert_eq!(
                start("https://idp.example.com/realms/x").await,
                None,
                "{environment}: {place}: https was refused"
            );
            for url in loopback {
                match start(url).await {
                    None => assert!(development, "{environment}: {place}: {url} started"),
                    Some(err) => {
                        assert!(
                            !development,
                            "development: {place}: {url} was refused: {err}"
                        );
                        assert!(
                            err.contains(&format!("{place} must be https outside development"))
                                || err.contains(&format!(
                                    "{place}: must be https outside development"
                                )),
                            "{environment}: {place}: {err}"
                        );
                    }
                }
            }
            for url in off_loopback {
                let err = start(url)
                    .await
                    .unwrap_or_else(|| panic!("{environment}: {place}: {url} started"));
                let want = if development {
                    "must be https, or http on a loopback IP literal"
                } else {
                    "must be https outside development"
                };
                assert!(
                    err.contains(place) && err.contains(want),
                    "{environment}: {place}: {url}: {err}"
                );
                assert!(!err.contains(url), "an error never shows a value: {err}");
            }
        }
    }
}

/// verifies: REQ-SUBJ-044
#[test]
fn a_subject_claim_that_changes_for_a_person_is_refused_by_place() {
    let upstream = |claim: &str| {
        format!(
            "workforce:\n  kind: oidc\n  issuer: https://idp.example.com\n  client_id: sluis\n  subject_claim: {claim}\n"
        )
    };
    for claim in ["email", "preferred_username", "upn", "name"] {
        let msg = refused("Upstream", &upstream(claim));
        assert!(
            msg.starts_with("workforce.subject_claim: "),
            "{claim}: {msg}"
        );
        assert!(msg.contains("changes for a person"), "{claim}: {msg}");
    }
    // A stable claim is accepted: `sub`, and Entra's `oid`.
    for claim in ["sub", "oid"] {
        payload::decode(kind("Upstream"), upstream(claim).as_bytes())
            .unwrap_or_else(|e| panic!("{claim}: {}", e.0));
    }
}

#[test]
fn a_jwks_uri_that_is_not_a_url_is_refused_by_place() {
    let msg = refused(
        "ExchangeTrust",
        "default:\n  issuers:\n    - { issuer: \"https://idp.example.com\", audiences: [sluis], proof_kind: jwks, jwks_uri: \"ftp://idp.example.com/keys\" }\n",
    );
    assert!(msg.contains("jwks_uri"), "{msg}");
}

#[tokio::test]
async fn the_policy_kind_is_served_to_its_reader_as_the_one_cedar_file() {
    let e = env().await;
    write_local(e.docs.path(), &e.pipeline, 3);
    let loader = e.start().await.unwrap();
    assert_eq!(loader.version("policy"), Some(3));

    // One document is one Cedar file: the one item `default`, byte for byte the reviewed file.
    let items = loader.list("policy");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].0, "default");
    let p = pb::Policy::decode_from_slice(&loader.get("policy", "default").unwrap()).unwrap();
    let cedar = include_str!("../../../tests/installations/local/policy/local.cedar");
    assert_eq!(p.cedar, cedar);
    assert_eq!(p.id, "default");

    // The registry lets policy read it, through Get and List, and nobody else; it lets no one write.
    for verb in ["get", "list"] {
        assert!(
            sluis_registry::store_allows("policy", "policy", verb),
            "{verb}"
        );
        assert!(
            !sluis_registry::store_allows("session", "policy", verb),
            "{verb}"
        );
    }
    assert!(!sluis_registry::store_allows("policy", "policy", "create"));
}

#[test]
fn the_local_policy_documents_are_the_files_the_policy_actor_is_tested_with() {
    // config/ holds the sources the harness signs; policy/ holds the files the policy tests run
    // on. They are one text, so the document cannot drift from the vectors.
    assert_eq!(
        source("policy"),
        include_str!("../../../tests/installations/local/policy/local.cedar")
    );
    assert_eq!(
        source("grant-vocabulary"),
        include_str!("../../../tests/installations/local/policy/vocabulary.yaml")
    );
}

#[test]
fn a_policy_payload_is_cedar_text_and_not_empty() {
    assert!(payload::decode(kind("Policy"), b"permit (principal, action, resource);\n").is_ok());
    assert_eq!(refused("Policy", " \n"), "has no policy");
    let bad = payload::decode(kind("Policy"), &[0xff, 0xfe]).expect_err("must be refused");
    assert_eq!(bad.0, "not UTF-8");
}

#[test]
fn the_local_catalogue_names_the_actions_policy_the_signer_and_exchange_emit() {
    let a = pb::AuditCatalogue::decode_from_slice(
        &payload::decode(kind("AuditCatalogue"), source("audit-catalogue").as_bytes())
            .unwrap()
            .remove(0)
            .1,
    )
    .unwrap();
    for action in [
        "policy.decide",
        "policy.start",
        "policy.reload",
        "policy.reload.refused",
        "signer.refused",
        "signer.sign",
        "signer.ring.add",
        "signer.ring.change",
        "signer.ring.drop",
        "exchange.token",
        "exchange.refused",
    ] {
        assert!(a.actions.iter().any(|x| x == action), "{action}");
    }
}

/// verifies: REQ-POLICY-012
#[test]
fn a_wildcard_or_a_malformed_name_in_a_clients_requires_is_refused_with_its_path_and_never_its_value()
 {
    let client = |requires: &str| {
        format!(
            "app:\n  kind: confidential\n  redirects: [\"https://app.example.com/cb\"]\n  requires: {requires}\n  secret: client-app\n"
        )
    };
    let ok = |requires: &str| {
        payload::decode(kind("InstallationClient"), client(requires).as_bytes()).is_ok()
    };
    assert!(ok("[\"dev:app:user\", \"acme:billing:admin\"]"));
    assert!(ok("[]"));
    for (bad, want) in [
        (
            "[\"dev:app:user\", \"*:app:user\"]",
            "app.requires[1]: a wildcard is not allowed in requires",
        ),
        (
            "[\"dev:*:user\"]",
            "app.requires[0]: a wildcard is not allowed in requires",
        ),
        (
            "[\"dev:app:*\"]",
            "app.requires[0]: a wildcard is not allowed in requires",
        ),
        (
            "[\"dev:app:us*\"]",
            "app.requires[0]: a wildcard is not allowed in requires",
        ),
        ("[\"dev:app\"]", "app.requires[0]: is not a grant name"),
        (
            "[\"dev:app:user:extra\"]",
            "app.requires[0]: is not a grant name",
        ),
        ("[\"dev::user\"]", "app.requires[0]: is not a grant name"),
        (
            "[\"dev:app:user \"]",
            "app.requires[0]: is not a grant name",
        ),
    ] {
        let e = refused("InstallationClient", &client(bad));
        assert!(e.contains(want), "{bad}: {e}");
        // The error names the path and never the value.
        assert!(
            !e.contains("billing") && !e.contains("us*") && !e.contains("extra"),
            "{e}"
        );
    }
}
