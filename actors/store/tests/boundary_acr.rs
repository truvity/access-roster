#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! `acr_values_supported` of the Boundary document: what the payload reader accepts and refuses (REQ-AUTHN-009). The list
//! is the one source of what `entry` lists in discovery and `session` enforces in `acr_values`.

use buffa::Message as _;
use sluis_proto::sluis::config::v2alpha1 as pb;
use store::config::payload;

fn boundary(extra: &str) -> Result<pb::Boundary, String> {
    let kind = sluis_registry::kinds()
        .iter()
        .find(|k| k.name == "Boundary")
        .unwrap();
    let doc = format!(
        "default:\n  name: dev\n  kind: environment\n  level: L2\n  environment: development\n  issuer: https://sluis.dev.local.test\n  uid_block: 0\n  default_tenant: acme\n{extra}"
    );
    payload::decode(kind, doc.as_bytes())
        .map(|items| pb::Boundary::decode_from_slice(&items[0].1).unwrap())
        .map_err(|e| e.to_string())
}

/// What the decoder alone says about a document: its own words and its own places. The service applies the generated schema
/// first, and the schema's refusal is the one a person sees, so the rules of the decoder are dead behind it unless they are
/// tested on their own (the helper of `config.rs`): each layer is pinned by itself, the schema by the shared vectors
/// (`schema-vectors.json`, `boundary/v1`) and the decoder here. Both must refuse, at the same place or at the list that holds
/// it.
fn refused(extra: &str) -> String {
    let kind = sluis_registry::kinds()
        .iter()
        .find(|k| k.name == "Boundary")
        .unwrap();
    let doc = format!(
        "default:\n  name: dev\n  kind: environment\n  level: L2\n  environment: development\n  issuer: https://sluis.dev.local.test\n  uid_block: 0\n  default_tenant: acme\n{extra}"
    );
    let decoder = payload::decode_unvalidated(kind, doc.as_bytes())
        .expect_err("the decoder must refuse it")
        .0;
    let service = payload::decode(kind, doc.as_bytes())
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

fn accepted_by_the_decoder(extra: &str) -> pb::Boundary {
    let kind = sluis_registry::kinds()
        .iter()
        .find(|k| k.name == "Boundary")
        .unwrap();
    let doc = format!(
        "default:\n  name: dev\n  kind: environment\n  level: L2\n  environment: development\n  issuer: https://sluis.dev.local.test\n  uid_block: 0\n  default_tenant: acme\n{extra}"
    );
    let items = payload::decode_unvalidated(kind, doc.as_bytes()).unwrap();
    pb::Boundary::decode_from_slice(&items[0].1).unwrap()
}

fn list(values: &[&str]) -> String {
    let mut s = String::from("  acr_values_supported:\n");
    for v in values {
        s.push_str(&format!("    - \"{v}\"\n"));
    }
    s
}

#[test]
fn a_boundary_with_no_list_lists_none() {
    assert!(boundary("").unwrap().acr_values_supported.is_empty());
    assert!(
        boundary("  acr_values_supported: []\n")
            .unwrap()
            .acr_values_supported
            .is_empty()
    );
}

/// An acr value as it is written: a URN, a URL, a word, a number, and values that begin with `-` or `_`, in the order given.
#[test]
fn acr_values_of_every_real_shape_load_in_order() {
    let values = [
        "urn:example:acr:mfa",
        "https://example.com/acr/passkey",
        "phr",
        "0",
        "1",
        "-hyphen",
        "_underscore",
        "a:b/c+d=e~f",
    ];
    assert_eq!(
        boundary(&list(&values)).unwrap().acr_values_supported,
        values
    );
    // Unquoted, where YAML reads a string; a number is a string here only when quoted.
    assert_eq!(
        boundary("  acr_values_supported: [urn:example:acr:mfa, -x, _y]\n")
            .unwrap()
            .acr_values_supported,
        ["urn:example:acr:mfa", "-x", "_y"]
    );
    let at_most = "a".repeat(256);
    assert_eq!(
        boundary(&list(&[&at_most])).unwrap().acr_values_supported,
        [at_most]
    );
}

#[test]
fn acr_values_that_a_request_could_not_carry_are_refused_by_place() {
    let over = "a".repeat(257);
    for bad in [
        "a b",
        "a\\tb",
        "a\\\"b",
        "a\\\\b",
        "é",
        "a\\u0000b",
        over.as_str(),
        "",
    ] {
        // The place of the value, by the decoder and by the service; never the value.
        let e = refused(&list(&["ok", bad]));
        assert!(
            e.starts_with("default.acr_values_supported[1]: "),
            "{bad:?}: {e}"
        );
        if bad.len() > 3 {
            assert!(!e.contains(bad), "{bad:?} is printed: {e}");
        }
    }
    // Plain scalars that are not strings: the schema says so by place, and a bare 1 is a number (write "1").
    for plain in ["1", "true", "0.5"] {
        let e = boundary(&format!("  acr_values_supported: [{plain}]\n")).expect_err(plain);
        assert!(
            e.contains("acr_values_supported[0]: must be a string"),
            "{plain}: {e}"
        );
    }
    let e = boundary("  acr_values_supported: urn:example:acr:mfa\n").unwrap_err();
    assert!(e.contains("acr_values_supported"), "{e}");
    // What the schema accepts, the decoder accepts: the same values, in the same order.
    assert_eq!(
        accepted_by_the_decoder(&list(&["-a", "_b", "1", "urn:example:acr:mfa"]))
            .acr_values_supported,
        ["-a", "_b", "1", "urn:example:acr:mfa"]
    );
}

#[test]
fn the_list_is_bounded_and_has_no_repeat() {
    let sixteen: Vec<String> = (0..16).map(|i| format!("v{i}")).collect();
    let refs: Vec<&str> = sixteen.iter().map(String::as_str).collect();
    assert_eq!(
        boundary(&list(&refs)).unwrap().acr_values_supported.len(),
        16
    );
    assert_eq!(
        accepted_by_the_decoder(&list(&refs))
            .acr_values_supported
            .len(),
        16
    );
    let mut seventeen = refs.clone();
    seventeen.push("v16");
    // The decoder names the first value over the bound; the schema names the list.
    let e = refused(&list(&seventeen));
    assert!(e.starts_with("default.acr_values_supported[16]: "), "{e}");
    // A repeat: the decoder names the place of the second.
    let e = refused(&list(&["a", "b", "a"]));
    assert!(e.starts_with("default.acr_values_supported[2]: "), "{e}");
    let e = refused(&list(&["a", "a"]));
    assert!(e.starts_with("default.acr_values_supported[1]: "), "{e}");
}
