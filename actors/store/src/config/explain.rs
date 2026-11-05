//! `sluis config explain`: what each setting of a bootstrap file and a config set resolves to, and where it comes
//! from (REQ-OPS-023; cli.md "`sluis config check` and `explain`"; ADR 0005, "Configuration loading").
//!
//! It runs on the very set that [`super::offline::load_dir`] accepts, so only a set that store@ would load is
//! explained: an effective value exists only for a set that is in force. For each setting it names the storage class,
//! the layer that set it (`bootstrap`, `config` or `built-in`), the version of that layer (the `seq` of a document,
//! the release for a built-in) and the source (the document as the audit fact of a start names it,
//! `Kind:seq:sha384`). Settings that share all of these are one [`Group`], so the output grows with the settings and
//! not with the provenance repeated on each.
//!
//! # What it prints and never prints
//!
//! It fails closed. [`FIELDS`] is a closed table of the fields of each readable kind, each with a [`Treatment`]; a
//! field the table does not list is a digest (`Treatment::Digest`), so a new field or a new readable kind never prints
//! in clear until someone has decided that it may. The sweep test below fails when [`super::payload`] reads a key that
//! the table does not cover.
//!
//! - `Show`: the value, for a name, a number or an identifier that a reviewer reads in git. A document holds no
//!   credential by construction (bootstrap-file.md; ADR 0004, "Storage classes").
//! - `Url`: the value without its query and fragment, which carry tokens more often than anything else in a URL. The
//!   payload refuses user information in a URL, and a URL that holds some anyway is a digest.
//! - `Duration`: the value in the largest whole unit, as the bootstrap file's grammar writes it.
//! - `Reference`: the name of a credential in the secret source (`Upstream` and `InstallationClient`, `secret`), never
//!   the secret. It is marked, and this command opens no socket, so it cannot resolve one.
//! - `Pin`: a public key, as the SHA-384 of its bytes, the way a publisher key is its pin.
//! - `Digest`: the SHA-384 of the value's bytes.
//!
//! Whatever the treatment, a value longer than [`SHOWN_MAX`] bytes, or with a control character or an invisible
//! format character (bidirectional controls, zero-width characters, line and paragraph separators), is a digest: a
//! line stays a line, and a document cannot write an escape sequence or reorder the text on a terminal. A refusal names
//! a path and a rule, never a value, as `sluis config check` does.

use super::document::{self, hex};
use super::snapshot::Document;
use crate::bootstrap::Bootstrap;
use crate::yaml::{self, Value};
use base64::Engine as _;
use sluis_registry::Kind;

/// The longest value printed as it is; a longer one is printed as its digest.
pub const SHOWN_MAX: usize = 256;

/// The layer of the bootstrap file (bootstrap-file.md): a file of the host, not a kind.
pub const LAYER_BOOTSTRAP: &str = "bootstrap";
/// The layer of a signed config document (ADR 0004, "Layers and the direction rule").
pub const LAYER_CONFIG: &str = "config";
/// The layer of what the binary carries (ADR 0004, "Built-in").
pub const LAYER_BUILT_IN: &str = "built-in";

/// How a field of a document is printed. See the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Treatment {
    Show,
    Url,
    Duration,
    Reference,
    Pin,
    Digest,
}

use Treatment::{Digest, Duration, Pin, Reference, Show, Url};

/// The fields of the kinds this build reads, by kind and by path inside an item (a list element is `[]`). It is closed:
/// a field that is not here is printed as [`Treatment::Digest`].
pub const FIELDS: &[(&str, &str, Treatment)] = &[
    ("Boundary", "name", Show),
    ("Boundary", "kind", Show),
    ("Boundary", "level", Show),
    ("Boundary", "environment", Show),
    ("Boundary", "issuer", Url),
    ("Boundary", "uid_block", Show),
    ("Boundary", "declared_kinds[]", Show),
    ("Boundary", "default_tenant", Show),
    ("KeyPlan", "purposes[].purpose", Show),
    ("KeyPlan", "purposes[].algorithm", Show),
    ("KeyPlan", "purposes[].slot", Show),
    ("KeyPlan", "cache_ttl", Duration),
    ("KeyPlan", "recipients[]", Show),
    ("KeyPlan", "slot_map[].node", Show),
    ("KeyPlan", "slot_map[].slots[].slot", Show),
    ("KeyPlan", "slot_map[].slots[].purpose", Show),
    ("KeyPlan", "slot_map[].slots[].public_key", Pin),
    ("KeyPlan", "slot_map[].slots[].attestation", Digest),
    ("KeyPlan", "slot_map[].slots[].attestation_signer", Digest),
    ("TokenLifetime", "id_token", Duration),
    ("TokenLifetime", "access_token", Duration),
    ("TokenLifetime", "human_session_absolute", Duration),
    ("TokenLifetime", "refresh_idle", Duration),
    ("AuditLog", "project", Show),
    ("AuditLog", "logs[].kind", Show),
    ("AuditLog", "logs[].id", Show),
    ("AuditLog", "logs[].origin", Show),
    ("AuditLog", "lock_mode", Show),
    ("AuditCatalogue", "release", Show),
    ("AuditCatalogue", "actions[]", Show),
    ("ExchangeTrust", "issuers[].issuer", Url),
    ("ExchangeTrust", "issuers[].audiences[]", Show),
    ("ExchangeTrust", "issuers[].proof_kind", Show),
    ("ExchangeTrust", "issuers[].jwks_uri", Url),
    ("Upstream", "name", Show),
    ("Upstream", "kind", Show),
    ("Upstream", "issuer", Url),
    ("Upstream", "client_id", Show),
    ("Upstream", "subject_claim", Show),
    ("Upstream", "org_claim", Show),
    ("Upstream", "scopes[]", Show),
    ("Upstream", "secret", Reference),
    ("InstallationClient", "id", Show),
    ("InstallationClient", "kind", Show),
    ("InstallationClient", "redirects[]", Url),
    ("InstallationClient", "requires[]", Show),
    ("InstallationClient", "ttl_cap", Duration),
    ("InstallationClient", "profile", Show),
    ("InstallationClient", "secret", Reference),
    // The payload of these two is not a mapping of items. store@ does not interpret either (policy does), so each is
    // one setting, identified by the digest of the payload that `sha384sum` of the reviewed file gives.
    ("Policy", "cedar", Digest),
    ("GrantVocabulary", "document", Digest),
];

/// The treatment of the field `rel` of a kind (a path inside an item, `redirects[0]`); the digest when the table
/// does not list it.
#[must_use]
pub fn treatment(kind: &str, rel: &str) -> Treatment {
    let rel = generic(rel);
    FIELDS
        .iter()
        .find(|(k, p, _)| *k == kind && *p == rel)
        .map_or(Digest, |(_, _, t)| *t)
}

/// `purposes[2].slot` as `purposes[].slot`: the path as the table writes it.
fn generic(rel: &str) -> String {
    let mut out = String::with_capacity(rel.len());
    let mut chars = rel.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        if c == '[' {
            while chars.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
            }
        }
    }
    out
}

/// One setting: where it is, and its value as it is printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    /// The place of the setting: the path in the bootstrap file (`durable.driver`, the one `config check` names), or
    /// `Kind.item.path` in a document (`Upstream.workforce.issuer`; a singleton kind's item is `default`).
    pub path: String,
    /// The value, or `sha384:` and the digest of one that is not printed as it is.
    pub value: String,
    /// The value is the name of a credential in the secret source, never the secret.
    pub secret: bool,
    /// The value is a digest of what the file holds.
    pub digest: bool,
}

/// Settings with one provenance: cli.md "JSON output", the members `class`, `layer`, `version`, `source` and `checks`
/// of each field of `fields`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// The storage class of the kind, `config`; `-` for the bootstrap file and for a built-in, which are not a kind.
    pub class: &'static str,
    /// `bootstrap`, `config` or `built-in`.
    pub layer: &'static str,
    /// The `seq` of the document, or the release of a built-in; empty for the bootstrap file, which has none.
    pub version: String,
    /// `bootstrap`, `store@` for a built-in, or the document as the audit fact names it: `Kind:seq:sha384`.
    pub source: String,
    /// The checks of `sluis config check` that cover the settings, by name.
    pub checks: Vec<&'static str>,
    pub settings: Vec<Setting>,
}

impl Group {
    fn same_provenance(&self, o: &Self) -> bool {
        (
            self.class,
            self.layer,
            &self.version,
            &self.source,
            &self.checks,
        ) == (o.class, o.layer, &o.version, &o.source, &o.checks)
    }
}

/// Appends `g` to `out`, joining it to the last group when they have one provenance, so that the order is kept.
fn push(out: &mut Vec<Group>, g: Group) {
    match out.last_mut() {
        Some(last) if last.same_provenance(&g) => last.settings.extend(g.settings),
        _ => out.push(g),
    }
}

/// Keeps the settings under `scope`, and drops a group left with none.
pub fn retain_within(groups: &mut Vec<Group>, scope: &str) {
    for g in groups.iter_mut() {
        g.settings.retain(|s| within(&s.path, scope));
    }
    groups.retain(|g| !g.settings.is_empty());
}

/// Whether `path` is `scope` or inside it: `durable` holds `durable.driver`, `publishers` holds `publishers[0].kid`.
/// The match is on the text at a `.` or `[`, and an item id may hold a dot, so with the items `corp` and
/// `corp.example` the scope `Upstream.corp` holds the settings of both.
#[must_use]
pub fn within(path: &str, scope: &str) -> bool {
    path.strip_prefix(scope)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
}

/// The settings of the bootstrap file, in the order of the file. The bootstrap file is a typed struct with a closed
/// list of keys, so each is printed by its own rule; none of it is a credential, and a public key is its pin.
#[must_use]
pub fn bootstrap_groups(b: &Bootstrap, release: &str) -> Vec<Group> {
    let mut out = Vec::new();
    let mut file = |path: String, value: &str, checks: Vec<&'static str>| {
        let (value, digest) = printable(value);
        push(
            &mut out,
            Group {
                class: "-",
                layer: LAYER_BOOTSTRAP,
                version: String::new(),
                source: "bootstrap".to_owned(),
                checks,
                settings: vec![Setting {
                    path,
                    value,
                    secret: false,
                    digest,
                }],
            },
        );
    };
    file("boundary".to_owned(), &b.boundary, vec!["bootstrap"]);
    if b.start_timeout_set {
        file(
            "start_timeout".to_owned(),
            &duration(b.start_timeout),
            vec!["bootstrap"],
        );
    }
    for (port, d) in b.destinations() {
        file(
            format!("{port}.driver"),
            &d.driver,
            vec!["bootstrap", "installation"],
        );
        file(
            format!("{port}.socket"),
            &d.socket.display().to_string(),
            vec!["bootstrap"],
        );
    }
    for (i, p) in b.publishers.iter().enumerate() {
        file(format!("publishers[{i}].kid"), &p.kid, vec!["bootstrap"]);
        // The pin is a hash already: it identifies the key, and the key itself is not repeated.
        file(
            format!("publishers[{i}].spki_sha384"),
            &p.spki_sha384,
            vec!["bootstrap"],
        );
        for (j, c) in p.co_signs.iter().enumerate() {
            file(
                format!("publishers[{i}].co_signs[{j}]"),
                c,
                vec!["bootstrap"],
            );
        }
    }
    if !b.start_timeout_set {
        // The default of a key the file leaves out is the binary's.
        push(
            &mut out,
            Group {
                class: "-",
                layer: LAYER_BUILT_IN,
                version: release.to_owned(),
                source: "store@".to_owned(),
                checks: vec!["bootstrap"],
                settings: vec![Setting {
                    path: "start_timeout".to_owned(),
                    value: duration(b.start_timeout),
                    secret: false,
                    digest: false,
                }],
            },
        );
    }
    out
}

/// A leaf of a payload as the file holds it, before the treatment of its field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// The item, `default` for a singleton kind.
    pub id: String,
    /// The path inside the item (`redirects[0]`).
    pub rel: String,
    /// The value as text: a string as it is, a number as it was written, a boolean as `true` or `false`.
    pub value: String,
    /// The file wrote a string (a quoted or plain text scalar), not a number or a boolean.
    pub text: bool,
}

/// The leaves of a payload, depth first in document order, for the verified payload `text` of `kind`. A `null`, an
/// empty list and an empty mapping set nothing, as the readers of the payload take them, so they are not leaves.
///
/// # Errors
///
/// The reason, with no value, when the payload is not readable.
pub fn leaves(kind: &Kind, text: &str) -> Result<Vec<Leaf>, String> {
    let one = |rel: &str| {
        vec![Leaf {
            id: super::payload::SINGLETON_ID.to_owned(),
            rel: rel.to_owned(),
            value: text.to_owned(),
            text: true,
        }]
    };
    match kind.name {
        // Opaque to store@: one setting each.
        "Policy" => return Ok(one("cedar")),
        "GrantVocabulary" => return Ok(one("document")),
        _ => {}
    }
    let doc =
        yaml::parse(text).map_err(|_| format!("{}: the payload is not readable", kind.name))?;
    let Value::Map(items) = doc else {
        return Err(format!(
            "{}: the payload is not a mapping of items",
            kind.name
        ));
    };
    let mut out = Vec::new();
    for (id, item) in &items {
        walk(id, "", item, &mut out);
    }
    Ok(out)
}

fn walk(id: &str, rel: &str, v: &Value, out: &mut Vec<Leaf>) {
    let mut leaf = |value: String, text: bool| {
        out.push(Leaf {
            id: id.to_owned(),
            rel: rel.to_owned(),
            value,
            text,
        });
    };
    match v {
        Value::Null => {}
        Value::Bool(b) => leaf(b.to_string(), false),
        Value::Number(n) => leaf(n.clone(), false),
        Value::String(s) => leaf(s.clone(), true),
        Value::Seq(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(id, &format!("{rel}[{i}]"), item, out);
            }
        }
        Value::Map(entries) => {
            for (k, item) in entries {
                let at = if rel.is_empty() {
                    k.clone()
                } else {
                    format!("{rel}.{k}")
                };
                walk(id, &at, item, out);
            }
        }
    }
}

/// The settings of an accepted document, in the order of its payload: one group. The payload is read again from the
/// signed bytes the document was accepted from, so it is the one that was verified.
///
/// # Errors
///
/// The reason, with no value, when the bytes no longer verify or the payload is no longer readable. The document
/// passed both a moment ago, so this is a defect and not a finding about the config.
pub fn document_group(d: &Document, b: &Bootstrap) -> Result<Group, String> {
    let kind = d.kind;
    let v = document::verify(d.signed_bytes(), kind, &b.publishers)
        .map_err(|e| format!("{}: {e}", kind.name))?;
    let text = std::str::from_utf8(&v.payload)
        .map_err(|_| format!("{}: the payload is not UTF-8", kind.name))?;
    let settings = leaves(kind, text)?
        .into_iter()
        .map(|l| {
            let path = if l.rel.is_empty() {
                format!("{}.{}", kind.name, l.id)
            } else {
                format!("{}.{}.{}", kind.name, l.id, l.rel)
            };
            let t = treatment(kind.name, &l.rel);
            let (value, digest) = render(t, &l.value);
            Setting {
                path,
                value,
                secret: t == Reference,
                digest,
            }
        })
        .collect();
    Ok(Group {
        class: match kind.class {
            sluis_registry::Class::Config => "config",
            sluis_registry::Class::Secret => "secret",
            sluis_registry::Class::Durable => "durable",
            sluis_registry::Class::Temp => "temp",
        },
        layer: LAYER_CONFIG,
        version: d.seq.to_string(),
        source: format!("{}:{}:{}", kind.name, d.seq, hex(&d.digest)),
        checks: vec!["document", "set"],
        settings,
    })
}

/// The value as it is printed for a field of the treatment `t`, and whether it is a digest.
fn render(t: Treatment, raw: &str) -> (String, bool) {
    match t {
        Show | Reference => printable(raw),
        Url => url_shown(raw),
        Duration => match crate::bootstrap::duration(Value::String(raw.to_owned()), "") {
            Ok(d) => (duration(d), false),
            // The payload was accepted, so it is a duration; a value that is not is not shown.
            Err(_) => digest_of(raw.as_bytes()),
        },
        Pin => match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw) {
            Ok(bytes) => digest_of(&bytes),
            Err(_) => digest_of(raw.as_bytes()),
        },
        Digest => digest_of(raw.as_bytes()),
    }
}

/// A duration in the grammar of the bootstrap file, in the largest whole unit (`90s`, `15m`, `1h`).
fn duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    for (unit, per) in [('d', 86_400), ('h', 3_600), ('m', 60)] {
        if s >= per && s.is_multiple_of(per) {
            return format!("{}{unit}", s / per);
        }
    }
    format!("{s}s")
}

fn digest_of(bytes: &[u8]) -> (String, bool) {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, bytes);
    (format!("sha384:{}", hex(d.as_ref())), true)
}

/// Whether a character may not reach a terminal from a document: a control character (Cc), or an invisible format
/// character (Cf: bidirectional controls, zero-width and joiner characters, the BOM, tags) or a line or paragraph
/// separator (Zl, Zp). The list is Unicode's general categories Cf, Zl and Zp.
#[must_use]
pub fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}')
}

/// `s` with each unsafe character replaced by `?`, for text that is printed whatever it holds.
#[must_use]
pub fn lossy(s: &str) -> String {
    s.chars()
        .map(|c| if is_unsafe(c) { '?' } else { c })
        .collect()
}

/// The value as it is printed: itself, or its digest when it is long or holds an unsafe character.
fn printable(value: &str) -> (String, bool) {
    if value.len() <= SHOWN_MAX && !value.chars().any(is_unsafe) {
        return (value.to_owned(), false);
    }
    digest_of(value.as_bytes())
}

/// A URL without its query and fragment: `https://h/cb?<elided>`. A URL that holds user information, which the
/// payload refuses, or anything that is not an `http` or `https` URL, is a digest.
fn url_shown(raw: &str) -> (String, bool) {
    let Some(rest) = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
    else {
        return digest_of(raw.as_bytes());
    };
    if super::payload::has_userinfo(rest) {
        return digest_of(raw.as_bytes());
    }
    let Some(at) = raw.find(['?', '#']) else {
        return printable(raw);
    };
    let (base, tail) = raw.split_at(at);
    let (shown, digest) = printable(base);
    if digest {
        return (shown, digest);
    }
    let mark = if tail.starts_with('?') { '?' } else { '#' };
    (format!("{shown}{mark}<elided>"), false)
}

/// The groups as the list of the helper's JSON object: `groups`, each with its provenance and its `settings`. The CLI
/// writes one field of cli.md "JSON output" for each setting.
#[must_use]
pub fn to_json(groups: &[Group]) -> serde_json::Value {
    serde_json::Value::Array(
        groups
            .iter()
            .map(|g| {
                let settings: Vec<_> = g
                    .settings
                    .iter()
                    .map(|s| {
                        let mut o = serde_json::json!({"path": s.path, "value": s.value});
                        if s.secret {
                            o["secret"] = serde_json::Value::Bool(true);
                        }
                        if s.digest {
                            o["digest"] = serde_json::Value::Bool(true);
                        }
                        o
                    })
                    .collect();
                serde_json::json!({
                    "class": g.class,
                    "layer": g.layer,
                    "version": g.version,
                    "source": g.source,
                    "checks": g.checks,
                    "settings": settings,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn a_scope_holds_its_own_subtree_and_not_a_neighbour_by_prefix() {
        assert!(within("durable.driver", "durable"));
        assert!(within("durable", "durable"));
        assert!(within("publishers[0].kid", "publishers"));
        assert!(within("publishers[0].kid", "publishers[0]"));
        assert!(!within("durable_x.driver", "durable"));
        assert!(!within("publishers[10].kid", "publishers[1]"));
        assert!(!within("durable", "durable.driver"));
        // An item id with a dot reads as nested, so its scope holds what shares the text up to a dot.
        assert!(within("Upstream.corp.example.issuer", "Upstream.corp"));
        assert!(within(
            "Upstream.corp.example.issuer",
            "Upstream.corp.example"
        ));
    }

    #[test]
    fn durations_are_shown_in_the_largest_whole_unit() {
        let s = std::time::Duration::from_secs;
        assert_eq!(duration(s(30)), "30s");
        assert_eq!(duration(s(90)), "90s");
        assert_eq!(duration(s(900)), "15m");
        assert_eq!(duration(s(3600)), "1h");
        assert_eq!(duration(s(86_400)), "1d");
        assert_eq!(duration(s(86_460)), "1441m");
        // A document's duration is normalised the same way.
        assert_eq!(render(Duration, "3600s"), ("1h".to_owned(), false));
        assert_eq!(render(Duration, "60s"), ("1m".to_owned(), false));
        assert!(render(Duration, "soon").1);
    }

    #[test]
    fn a_long_value_or_one_with_an_unsafe_character_is_shown_as_its_digest() {
        assert_eq!(printable("dev"), ("dev".to_owned(), false));
        assert_eq!(
            printable(&"a".repeat(SHOWN_MAX)),
            ("a".repeat(SHOWN_MAX), false)
        );
        assert_eq!(
            printable("caf\u{e9} \u{4e2d}"),
            ("caf\u{e9} \u{4e2d}".to_owned(), false)
        );
        for v in [
            "a".repeat(SHOWN_MAX + 1),
            "one\ntwo".to_owned(),
            "esc\u{1b}[31m".to_owned(),
            "tab\there".to_owned(),
            // Cf: right-to-left override, zero-width space, BOM, word joiner, tag characters.
            "ab\u{202e}cd".to_owned(),
            "ab\u{200b}cd".to_owned(),
            "\u{feff}ab".to_owned(),
            "ab\u{2060}cd".to_owned(),
            "ab\u{e0041}cd".to_owned(),
            // Zl and Zp.
            "ab\u{2028}cd".to_owned(),
            "ab\u{2029}cd".to_owned(),
        ] {
            let (p, digest) = printable(&v);
            assert!(
                digest && p.starts_with("sha384:") && p.len() == 7 + 96,
                "{p}"
            );
        }
    }

    #[test]
    fn a_url_loses_its_query_and_fragment_and_never_shows_user_information() {
        let shown = |u: &str| url_shown(u);
        assert_eq!(
            shown("https://h.example.com/cb"),
            ("https://h.example.com/cb".to_owned(), false)
        );
        assert_eq!(
            shown("https://h.example.com/cb?token=zq"),
            ("https://h.example.com/cb?<elided>".to_owned(), false)
        );
        assert_eq!(
            shown("https://h.example.com/cb#zq"),
            ("https://h.example.com/cb#<elided>".to_owned(), false)
        );
        assert_eq!(
            shown("https://h.example.com/a?x=1#zq"),
            ("https://h.example.com/a?<elided>".to_owned(), false)
        );
        let (v, digest) = shown("https://u:zq@h.example.com/");
        assert!(digest && v.starts_with("sha384:"));
        assert!(shown("ftp://h").1);
        for (u, _) in [
            shown("https://h.example.com/cb?token=zq"),
            shown("https://h/#zq"),
        ] {
            assert!(!u.contains("zq"), "{u}");
        }
    }

    #[test]
    fn an_unlisted_field_is_a_digest_and_a_list_index_is_generic() {
        assert_eq!(treatment("Boundary", "issuer"), Url);
        assert_eq!(treatment("Boundary", "declared_kinds[3]"), Show);
        assert_eq!(
            treatment("KeyPlan", "slot_map[1].slots[22].public_key"),
            Pin
        );
        assert_eq!(treatment("Boundary", "a_field_nobody_listed"), Digest);
        assert_eq!(treatment("FirstAdmin", "email"), Digest);
        assert_eq!(treatment("Upstream", "secret"), Reference);
    }

    /// The keys that the decoders of `payload.rs` read, by kind, found in its text: the closed key lists of the
    /// payload. A key is a string literal that follows a reader method of `Obj` or a helper that takes one.
    fn payload_keys() -> BTreeMap<&'static str, BTreeSet<String>> {
        const SRC: &str = include_str!("payload.rs");
        const DECODERS: &[(&str, &str)] = &[
            ("boundary", "Boundary"),
            ("key_plan", "KeyPlan"),
            ("slot_map", "KeyPlan"),
            ("token_lifetime", "TokenLifetime"),
            ("audit_log", "AuditLog"),
            ("audit_catalogue", "AuditCatalogue"),
            ("exchange_trust", "ExchangeTrust"),
            ("upstream", "Upstream"),
            ("installation_client", "InstallationClient"),
        ];
        const READERS: &[&str] = &[
            ".required(\"",
            ".string(\"",
            ".strings(\"",
            ".objects(\"",
            ".duration(\"",
            ".required_duration(\"",
            ".uint32(\"",
            ".one_of(\"",
            ".base64url(\"",
            ".peek(\"",
            "url(&mut o, \"",
            "url(&mut t, \"",
            "named(&mut o, \"",
        ];
        let mut out: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
        let mut current: Option<&'static str> = None;
        for line in SRC.lines() {
            if let Some(rest) = line.strip_prefix("fn ") {
                let name = rest.split(['(', '<']).next().unwrap_or("");
                current = DECODERS.iter().find(|(f, _)| *f == name).map(|(_, k)| *k);
            }
            let Some(kind) = current else { continue };
            for r in READERS {
                let mut from = 0;
                while let Some(i) = line[from..].find(r) {
                    let start = from + i + r.len();
                    let end = start + line[start..].find('"').expect("a closed literal");
                    out.entry(kind)
                        .or_default()
                        .insert(line[start..end].to_owned());
                    from = end;
                }
            }
        }
        out
    }

    /// The keys on a path of the table: `slot_map[].slots[].slot` is `slot_map`, `slots` and `slot`.
    fn segments(path: &str) -> impl Iterator<Item = &str> {
        path.split('.').map(|s| s.strip_suffix("[]").unwrap_or(s))
    }

    /// Every kind this build reads, and every key the payload reads for it, has a row in [`FIELDS`], and every row
    /// names a key that exists: a new field cannot print in clear by default, and the table cannot drift from the
    /// decoders. A sweep over nothing would prove nothing, so it also asserts how much it swept.
    #[test]
    fn the_table_covers_every_readable_kind_and_every_key_the_payload_reads() {
        let keys = payload_keys();
        let swept: usize = keys.values().map(BTreeSet::len).sum();
        assert!(
            swept >= 40,
            "the sweep found {swept} keys: has payload.rs changed shape?"
        );
        assert_eq!(keys.len(), 8, "{:?}", keys.keys().collect::<Vec<_>>());

        let readable: Vec<_> = sluis_registry::kinds()
            .iter()
            .filter(|k| super::super::payload::readable(k))
            .collect();
        assert!(readable.len() >= 10, "{} readable kinds", readable.len());
        for k in readable {
            assert!(
                FIELDS.iter().any(|(kn, _, _)| *kn == k.name),
                "{} is readable and has no row in FIELDS: it would print as digests only",
                k.name
            );
        }
        for (kind, ks) in &keys {
            for key in ks {
                assert!(
                    FIELDS
                        .iter()
                        .any(|(k, p, _)| k == kind && segments(p).any(|s| s == key)),
                    "{kind}.{key} is read by payload.rs and is not in FIELDS"
                );
            }
        }
        for (kind, path, _) in FIELDS {
            if matches!(*kind, "Policy" | "GrantVocabulary") {
                continue;
            }
            for key in segments(path) {
                assert!(
                    keys.get(kind).is_some_and(|ks| ks.contains(key)),
                    "{kind}.{path} is in FIELDS and {key} is read by no decoder"
                );
            }
        }
    }
}
