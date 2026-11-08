#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The payload readers of the config kinds `FrontHost` and `SignInMethods` (ADR 0017 "Passkeys"): what they accept, each
//! value domain with real vectors, and what they refuse with the path of the fault and never the value.

use buffa::Message as _;
use sluis_proto::sluis::config::v2alpha1 as pb;
use store::config::payload;

fn kind(name: &str) -> &'static sluis_registry::Kind {
    sluis_registry::kinds()
        .iter()
        .find(|k| k.name == name)
        .unwrap()
}

fn front(doc: &str) -> Result<Vec<pb::FrontHost>, String> {
    payload::decode(kind("FrontHost"), doc.as_bytes())
        .map(|items| {
            items
                .iter()
                .map(|(_, b)| pb::FrontHost::decode_from_slice(b).unwrap())
                .collect()
        })
        .map_err(|e| e.to_string())
}

fn methods(doc: &str) -> Result<pb::SignInMethods, String> {
    payload::decode(kind("SignInMethods"), doc.as_bytes())
        .map(|items| pb::SignInMethods::decode_from_slice(&items[0].1).unwrap())
        .map_err(|e| e.to_string())
}

/// What the decoder alone says about a document: its own words and its own places. The service applies the generated schema
/// first (`schema/front-host/v1`, `schema/sign-in-methods/v1`), and the schema's refusal is the one a person sees, so the
/// rules of the decoder are dead behind it unless they are tested on their own. Each layer is pinned by itself: the schema
/// by the shared vectors (`schema-vectors.json`) and the decoder here. Both must refuse, at the same place or at the list
/// that holds it. Returns the decoder's words.
fn refused_by_both(kind_name: &str, doc: &str) -> String {
    let k = kind(kind_name);
    let decoder = payload::decode_unvalidated(k, doc.as_bytes())
        .expect_err("the decoder must refuse it")
        .0;
    let service = payload::decode(k, doc.as_bytes())
        .expect_err("the service, schema first, must refuse it too")
        .0;
    let place = |e: &str| {
        e.split_once(": ")
            .map(|(p, _)| p.to_owned())
            .unwrap_or_default()
    };
    let (d, s) = (place(&decoder), place(&service));
    assert!(
        d == s || d.strip_prefix(&s).is_some_and(|r| r.starts_with('[')),
        "the place: decoder {decoder:?}, service {service:?}"
    );
    decoder
}

/// As [`refused_by_both`], for a FrontHost document.
fn front_refused(doc: &str) -> String {
    refused_by_both("FrontHost", doc)
}

/// As [`refused_by_both`], for a SignInMethods document.
fn methods_refused(doc: &str) -> String {
    refused_by_both("SignInMethods", doc)
}

const GOOD_FRONT: &str = "default:\n  rp_id: local.test\n  rp_name: sluis local\n  origins:\n    - https://sluis.dev.local.test\n";

/// A FrontHost with the given line replacing the one that starts with `key`.
fn front_with(key: &str, line: &str) -> String {
    GOOD_FRONT
        .lines()
        .map(|l| {
            if l.trim_start().starts_with(key) {
                line
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn a_front_host_loads_and_is_read_back_whole() {
    let items = front(GOOD_FRONT).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].rp_id, "local.test");
    assert_eq!(items[0].rp_name, "sluis local");
    assert_eq!(items[0].origins, ["https://sluis.dev.local.test"]);
}

#[test]
fn a_front_host_is_a_keyed_kind() {
    // Two items, one of them for a client (ADR 0035 "Passkeys and the relying-party ID").
    let doc = format!(
        "{GOOD_FRONT}app:\n  rp_id: local.test\n  rp_name: app\n  origins:\n    - https://app.local.test:8443\n"
    );
    assert_eq!(front(&doc).unwrap().len(), 2);
}

/// Every origin that a browser can serialize and that sits at or below the rp_id loads: host names with digits, hyphens
/// inside labels, a port, and the one `http` origin that is a secure context.
#[test]
fn origins_that_a_browser_serializes_load() {
    for (rp, origin) in [
        ("local.test", "https://local.test"),
        ("local.test", "https://sluis.local.test"),
        ("local.test", "https://a-b.c1.local.test:8443"),
        ("local.test", "https://x.local.test:65535"),
        ("local.test", "https://x.local.test:444"),
        ("local.test", "https://x.local.test:80"),
        ("localhost", "http://localhost"),
        ("localhost", "http://localhost:8080"),
        ("localhost", "https://localhost:8443"),
        ("e9.test", "https://e9.test"),
    ] {
        let doc = front_with("rp_id", &format!("  rp_id: {rp}"))
            .replace("https://sluis.dev.local.test", origin);
        front(&doc).unwrap_or_else(|e| panic!("{rp} {origin}: {e}"));
    }
}

/// An origin spelled any way a browser would not serialize it is refused, because it would never match, and an origin
/// outside the rp_id is refused, because no page there can claim the rp_id.
#[test]
fn origins_that_no_browser_would_send_or_that_cannot_claim_the_rp_id_are_refused() {
    for origin in [
        "https://sluis.dev.local.test/",
        "https://sluis.dev.local.test/path",
        "https://sluis.dev.local.test:443",
        "https://sluis.dev.local.test:0",
        "https://sluis.dev.local.test:65536",
        "https://sluis.dev.local.test:08080",
        "https://sluis.dev.local.test:",
        "https://sluis.dev.local.test:80a",
        "https://SLUIS.dev.local.test",
        "https://sluis.dev.local.test.",
        "https://user@sluis.dev.local.test",
        "https://*.local.test",
        "https://sluis.dev.local.test?x=1",
        "https://sluis.dev.local.test#f",
        "http://sluis.dev.local.test",
        "http://localhost.local.test",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "https://[::1]",
        "ftp://sluis.dev.local.test",
        "sluis.dev.local.test",
        "https://other.test",
        "https://notlocal.test",
        "https://local.test.evil.test",
        "https://evil-local.test",
        "https://",
        "",
    ] {
        let doc = GOOD_FRONT.replace("https://sluis.dev.local.test", origin);
        let e = front_refused(&doc);
        assert!(e.contains("default.origins[0]"), "{origin:?}: {e}");
        // The value is never in the refusal.
        if origin.len() > 8 {
            assert!(!e.contains(origin), "{origin:?} is printed: {e}");
        }
    }
}

#[test]
fn an_origin_listed_twice_or_a_list_too_long_or_none_is_refused() {
    let twice = GOOD_FRONT.to_owned() + "    - https://sluis.dev.local.test\n";
    assert!(front_refused(&twice).contains("default.origins[1]"));
    let mut many = String::from("default:\n  rp_id: local.test\n  rp_name: n\n  origins:\n");
    for i in 0..17 {
        many.push_str(&format!("    - https://h{i}.local.test\n"));
    }
    assert!(front_refused(&many).contains("default.origins"));
    let sixteen: String = many.lines().take(4 + 16).collect::<Vec<_>>().join("\n") + "\n";
    assert_eq!(front(&sixteen).unwrap()[0].origins.len(), 16);
    let none = "default:\n  rp_id: local.test\n  rp_name: n\n";
    assert!(front_refused(none).contains("default.origins"));
    let empty = "default:\n  rp_id: local.test\n  rp_name: n\n  origins: []\n";
    assert!(front_refused(empty).contains("default.origins"));
}

#[test]
fn rp_id_is_a_lower_case_host_name_and_never_an_address() {
    for bad in [
        "Local.test",
        "local.test.",
        ".local.test",
        "local..test",
        "-local.test",
        "local-.test",
        "local_test.test",
        "127.0.0.1",
        "10",
        "local.test:443",
        "https://local.test",
        "local test",
        "é.test",
        &"a".repeat(64),
        &format!("{}.test", "a".repeat(250)),
    ] {
        let e = front_refused(&front_with("rp_id", &format!("  rp_id: \"{bad}\"")));
        assert!(e.contains("default.rp_id"), "{bad:?}: {e}");
    }
    // The label of 63 characters is the longest served.
    let long = format!("{}.test", "a".repeat(63));
    let doc = front_with("rp_id", &format!("  rp_id: {long}"))
        .replace("https://sluis.dev.local.test", &format!("https://{long}"));
    front(&doc).unwrap();
}

/// The plain YAML scalars a person writes without quotes: a number, a boolean and null are not strings, and are
/// refused with the path, not read as the text "123" or "true".
#[test]
fn a_plain_yaml_scalar_is_not_a_string() {
    for (key, line, path) in [
        ("rp_id", "  rp_id: 123", "default.rp_id"),
        ("rp_id", "  rp_id: true", "default.rp_id"),
        ("rp_id", "  rp_id: 1.5", "default.rp_id"),
        ("rp_name", "  rp_name: 42", "default.rp_name"),
        ("rp_name", "  rp_name: [a]", "default.rp_name"),
        ("rp_name", "  rp_name:", "default.rp_name"),
    ] {
        let e = front_refused(&front_with(key, line));
        assert!(e.contains(path), "{line:?}: {e}");
    }
    // The profile reads `yes` as the string it is (YAML 1.2), as the bootstrap file's vectors say.
    assert_eq!(
        front(&front_with("rp_name", "  rp_name: yes")).unwrap()[0].rp_name,
        "yes"
    );
    let e = front_refused(&GOOD_FRONT.replace("https://sluis.dev.local.test", "123"));
    assert!(e.contains("default.origins[0]"), "{e}");
    let e = front_refused(&GOOD_FRONT.replace("    - https://sluis.dev.local.test\n", "    - 5\n"));
    assert!(e.contains("default.origins[0]"), "{e}");
}

#[test]
fn rp_name_is_bounded_and_has_no_control_character() {
    front(&front_with(
        "rp_name",
        &format!("  rp_name: {}", "n".repeat(64)),
    ))
    .unwrap();
    for bad in ["n".repeat(65), "a\\nb".to_owned(), "a\\u0007b".to_owned()] {
        let e = front_refused(&front_with("rp_name", &format!("  rp_name: \"{bad}\"")));
        assert!(e.contains("default.rp_name"), "{bad:?}: {e}");
    }
    // 64 characters that are more than 64 bytes: the bound counts characters.
    front(&front_with(
        "rp_name",
        &format!("  rp_name: \"{}\"", "é".repeat(64)),
    ))
    .unwrap();
}

#[test]
fn a_front_host_with_an_unknown_key_is_refused_without_naming_it() {
    let e = front_refused(&(GOOD_FRONT.to_owned() + "  surprise: 1\n"));
    assert!(e.contains("<key>") && !e.contains("surprise"), "{e}");
}

const GOOD_METHODS: &str = "default:\n  registration_client: example-app\n  passkey_acr: urn:sluis:acr:passkey\n  upstream_recheck: 14d\n";

#[test]
fn sign_in_methods_load() {
    let m = methods(GOOD_METHODS).unwrap();
    assert_eq!(m.passkey_acr, "urn:sluis:acr:passkey");
    assert_eq!(m.registration_client, "example-app");
    assert_eq!(m.upstream_recheck.as_option().unwrap().seconds, 14 * 86400);
    // The recheck is optional: the built-in default is session's.
    let m = methods(
        "default:\n  registration_client: example-app\n  passkey_acr: urn:sluis:acr:passkey\n",
    )
    .unwrap();
    assert!(m.upstream_recheck.as_option().is_none());
}

/// An acr value as the real ones are written: a URN, a URL, a word, and values that start with `-` or `_`, which a plain
/// YAML scalar can start with.
#[test]
fn acr_values_of_every_real_shape_load() {
    for acr in [
        "urn:sluis:acr:passkey",
        "https://example.com/acr/passkey",
        "passkey",
        "-passkey",
        "_passkey",
        "a",
        "0",
        "phr",
        "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
        &"a".repeat(256),
    ] {
        let doc =
            format!("default:\n  registration_client: example-app\n  passkey_acr: \"{acr}\"\n");
        let m = methods(&doc).unwrap_or_else(|e| panic!("{acr:?}: {e}"));
        assert_eq!(m.passkey_acr, acr);
    }
    // And unquoted, where YAML reads them as a string.
    assert_eq!(
        methods("default:\n  registration_client: example-app\n  passkey_acr: -passkey\n")
            .unwrap()
            .passkey_acr,
        "-passkey"
    );
    assert_eq!(
        methods("default:\n  registration_client: example-app\n  passkey_acr: _passkey\n")
            .unwrap()
            .passkey_acr,
        "_passkey"
    );
}

#[test]
fn acr_values_that_a_request_could_not_carry_are_refused() {
    for bad in [
        "a b",
        "a\\tb",
        "a\\\"b",
        "a\\\\b",
        "é",
        &"a".repeat(257),
        "a\\u0000b",
    ] {
        let e = methods_refused(&format!(
            "default:\n  registration_client: example-app\n  passkey_acr: \"{bad}\"\n"
        ));
        assert!(e.contains("default.passkey_acr"), "{bad:?}: {e}");
    }
    // Plain scalars that are not strings.
    for line in [
        "  passkey_acr: 1",
        "  passkey_acr: true",
        "  passkey_acr: 0.5",
        "  passkey_acr:",
        "  passkey_acr: [a]",
    ] {
        let e = methods_refused(&format!(
            "default:\n  registration_client: example-app\n{line}\n"
        ));
        assert!(e.contains("default.passkey_acr"), "{line:?}: {e}");
    }
    let e =
        methods_refused("default:\n  registration_client: example-app\n  upstream_recheck: 14d\n");
    assert!(e.contains("default.passkey_acr"), "{e}");
}

#[test]
fn the_recheck_is_a_duration_between_an_hour_and_ninety_days() {
    for good in ["1h", "60m", "3600s", "1d", "14d", "90d", "2160h"] {
        methods(&format!(
            "default:\n  registration_client: example-app\n  passkey_acr: x\n  upstream_recheck: {good}\n"
        ))
        .unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "59m", "3599s", "91d", "2161h", "0s", "0d", "14", "1.5d", "14 d", "-1d", "d", "P14D", "14w",
    ] {
        let e = methods_refused(&format!(
            "default:\n  registration_client: example-app\n  passkey_acr: x\n  upstream_recheck: \"{bad}\"\n"
        ));
        assert!(e.contains("default.upstream_recheck"), "{bad:?}: {e}");
    }
    // The unquoted number a person writes for "14 days" is not a duration.
    for plain in ["14", "336", "1209600", "0", "true"] {
        let e = methods_refused(&format!(
            "default:\n  registration_client: example-app\n  passkey_acr: x\n  upstream_recheck: {plain}\n"
        ));
        assert!(e.contains("default.upstream_recheck"), "{plain:?}: {e}");
    }
}

#[test]
fn sign_in_methods_is_a_singleton_with_closed_keys() {
    // The two layers word this differently and both refuse: the decoder's singleton rule, the schema's keys.
    let doc = "other:\n  passkey_acr: x\n";
    let k = kind("SignInMethods");
    let e = payload::decode_unvalidated(k, doc.as_bytes())
        .expect_err("the decoder must refuse it")
        .0;
    assert!(e.contains("singleton"), "{e}");
    let e = payload::decode(k, doc.as_bytes())
        .expect_err("the service must refuse it too")
        .0;
    assert!(e.contains("<key>") && !e.contains("other"), "{e}");
    let e = methods_refused(&(GOOD_METHODS.to_owned() + "  surprise: 1\n"));
    assert!(e.contains("<key>") && !e.contains("surprise"), "{e}");
}

/// The client a registration is admitted for is required (passkeys are on when the document exists), is a client id, and is read
/// as written. Both layers refuse a missing one, one of the wrong type and one that is not a client id, at the same place.
///
/// verifies: REQ-REG-052
#[test]
fn the_registration_client_is_required_and_is_a_client_id() {
    let e = methods_refused("default:\n  passkey_acr: x\n");
    assert!(
        e.contains("default.registration_client") && e.contains("required"),
        "{e}"
    );
    for bad in [
        "registration_client:",
        "registration_client: 5",
        "registration_client: true",
        "registration_client: [a]",
        "registration_client: \"\"",
        "registration_client: Example",
        "registration_client: a/b",
        "registration_client: \"a b\"",
        "registration_client: \"é\"",
        "registration_client: \".\"",
        "registration_client: \"..\"",
    ] {
        let e = methods_refused(&format!("default:\n  passkey_acr: x\n  {bad}\n"));
        assert!(e.contains("default.registration_client"), "{bad:?}: {e}");
    }
    // Every id a client can have, the shapes the local installation and the suite use.
    for good in [
        "example-app",
        "sluis-cli",
        "oidf-suite-2",
        "a",
        "0",
        "-x",
        "_y",
        "a.b",
        &"a".repeat(128),
    ] {
        let m = methods(&format!(
            "default:\n  passkey_acr: x\n  registration_client: \"{good}\"\n"
        ))
        .unwrap_or_else(|e| panic!("{good}: {e}"));
        assert_eq!(m.registration_client, good);
    }
}
