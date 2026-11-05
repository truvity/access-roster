//! `sluis config explain`: what each setting of a bootstrap file and a config set resolves to, and where it comes
//! from (REQ-OPS-023; cli.md "`sluis config check` and `explain`"; ADR 0005, "Configuration loading").
//!
//! It runs on the very set that [`super::offline::load_dir`] accepts, so only a set that store@ would load is
//! explained: an effective value exists only for a set that is in force. For each leaf it names the storage class, the
//! layer that set it (`bootstrap`, `config` or `built-in`), the version of that layer (the `seq` of a document, the
//! release for a built-in) and the source (the document as the audit fact of a start names it, `Kind:seq:sha384`).
//!
//! What it prints and never prints:
//!
//! - It prints the values of the bootstrap file and of the config documents. Both are written by hand, reviewed in git
//!   and hold no credential by construction (bootstrap-file.md; ADR 0004, "Storage classes"), which is why the class
//!   `config` exists apart from `secret`.
//! - A credential is a reference: the field `secret` of an `Upstream` and of an `InstallationClient` holds the name of
//!   a credential, never the secret, and it is printed as that name and marked. This command opens no socket, so it
//!   cannot resolve one.
//! - A value that is long (more than [`SHOWN_MAX`] bytes) or has a line break or any control character is replaced by
//!   the SHA-384 of its bytes: a line stays a line, a terminal gets no escape sequence from a document, and a Cedar
//!   text or a vocabulary (which store@ does not interpret) is identified by a digest that `sha384sum` of the payload
//!   can be compared with.
//! - A refusal names a path and a rule, never a value, as `sluis config check` does.
//! - The public key of a publisher is not repeated: its pin, the SHA-384 of its key, identifies it.

use super::document::{self, hex};
use super::snapshot::Document;
use crate::bootstrap::Bootstrap;
use crate::yaml::{self, Value};
use sluis_registry::Class;

/// The longest value printed as it is; a longer one is printed as its digest.
pub const SHOWN_MAX: usize = 256;

/// The layer of the bootstrap file (bootstrap-file.md): a file of the host, not a kind.
pub const LAYER_BOOTSTRAP: &str = "bootstrap";
/// The layer of a signed config document (ADR 0004, "Layers and the direction rule").
pub const LAYER_CONFIG: &str = "config";
/// The layer of what the binary carries (ADR 0004, "Built-in").
pub const LAYER_BUILT_IN: &str = "built-in";

/// The fields of a kind that hold the name of a credential in the secret source, and not the credential.
const SECRET_REFERENCES: [(&str, &str); 2] =
    [("Upstream", "secret"), ("InstallationClient", "secret")];

/// One setting: cli.md "JSON output", the `fields` list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The place of the setting: the path in the bootstrap file (`durable.driver`, the one `config check` names), or
    /// `Kind.item.path` in a document (`Upstream.workforce.issuer`; a singleton kind's item is `default`).
    pub path: String,
    /// The effective value, or `sha384:` and the digest of one that is not printed as it is.
    pub value: String,
    /// The storage class of the kind, `config`; `-` for the bootstrap file and for a built-in, which are not a kind.
    pub class: &'static str,
    /// `bootstrap`, `config` or `built-in`.
    pub layer: &'static str,
    /// The `seq` of the document, or the release of a built-in; empty for the bootstrap file, which has none.
    pub version: String,
    /// `bootstrap`, `store@` for a built-in, or the document as the audit fact names it: `Kind:seq:sha384`.
    pub source: String,
    /// The value is the name of a credential in the secret source, never the secret.
    pub secret: bool,
    /// The checks of `sluis config check` that cover the field, by name.
    pub checks: Vec<&'static str>,
}

/// Whether `path` is `scope` or inside it: `durable` holds `durable.driver`, `publishers` holds `publishers[0].kid`.
#[must_use]
pub fn within(path: &str, scope: &str) -> bool {
    path.strip_prefix(scope)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
}

/// The settings of the bootstrap file, in the order of the file.
#[must_use]
pub fn bootstrap_fields(b: &Bootstrap, release: &str) -> Vec<Field> {
    let from_file = |path: String, value: String, checks: Vec<&'static str>| Field {
        path,
        value,
        class: "-",
        layer: LAYER_BOOTSTRAP,
        version: String::new(),
        source: "bootstrap".to_owned(),
        secret: false,
        checks,
    };
    let mut out = vec![from_file(
        "boundary".to_owned(),
        b.boundary.clone(),
        vec!["bootstrap"],
    )];
    let mut timeout = from_file(
        "start_timeout".to_owned(),
        duration(b.start_timeout),
        vec!["bootstrap"],
    );
    if !b.start_timeout_set {
        // The default of a key the file leaves out is the binary's.
        timeout.layer = LAYER_BUILT_IN;
        timeout.version = release.to_owned();
        timeout.source = "store@".to_owned();
    }
    out.push(timeout);
    for (port, d) in b.destinations() {
        out.push(from_file(
            format!("{port}.driver"),
            d.driver.clone(),
            vec!["bootstrap", "installation"],
        ));
        out.push(from_file(
            format!("{port}.socket"),
            d.socket.display().to_string(),
            vec!["bootstrap"],
        ));
    }
    for (i, p) in b.publishers.iter().enumerate() {
        let at = |key: &str| format!("publishers[{i}].{key}");
        out.push(from_file(at("kid"), p.kid.clone(), vec!["bootstrap"]));
        out.push(from_file(
            at("spki_sha384"),
            p.spki_sha384.clone(),
            vec!["bootstrap"],
        ));
        for (j, c) in p.co_signs.iter().enumerate() {
            out.push(from_file(
                format!("publishers[{i}].co_signs[{j}]"),
                c.clone(),
                vec!["bootstrap"],
            ));
        }
    }
    shown(out)
}

/// The settings of an accepted document: one for each leaf of its payload, in the order of the payload. The
/// payload is read again from the signed bytes the document was accepted from, so it is the one that was verified.
///
/// # Errors
///
/// The reason, with no value, when the bytes no longer verify or the payload is no longer readable. The document
/// passed both a moment ago, so this is a defect and not a finding about the config.
pub fn document_fields(d: &Document, b: &Bootstrap) -> Result<Vec<Field>, String> {
    let kind = d.kind;
    let v = document::verify(d.signed_bytes(), kind, &b.publishers)
        .map_err(|e| format!("{}: {e}", kind.name))?;
    let text = std::str::from_utf8(&v.payload)
        .map_err(|_| format!("{}: the payload is not UTF-8", kind.name))?;
    let class = match kind.class {
        Class::Config => "config",
        Class::Secret => "secret",
        Class::Durable => "durable",
        Class::Temp => "temp",
    };
    let source = format!("{}:{}:{}", kind.name, d.seq, hex(&d.digest));
    let mut leaves: Vec<(String, String)> = Vec::new();
    match kind.name {
        // The payload of these two is not a mapping of items. store@ does not interpret either (policy does), so each
        // is one setting, and it is printed as its digest unless it is one short line.
        "Policy" => leaves.push((
            format!("{}.{}.cedar", kind.name, super::payload::SINGLETON_ID),
            text.to_owned(),
        )),
        "GrantVocabulary" => leaves.push((
            format!("{}.{}.document", kind.name, super::payload::SINGLETON_ID),
            text.to_owned(),
        )),
        _ => {
            let doc = yaml::parse(text)
                .map_err(|_| format!("{}: the payload is not readable", kind.name))?;
            let Value::Map(items) = doc else {
                return Err(format!(
                    "{}: the payload is not a mapping of items",
                    kind.name
                ));
            };
            for (id, item) in &items {
                leaf(&format!("{}.{id}", kind.name), item, &mut leaves);
            }
        }
    }
    Ok(shown(
        leaves
            .into_iter()
            .map(|(path, value)| Field {
                secret: SECRET_REFERENCES
                    .iter()
                    .any(|(k, f)| *k == kind.name && path.rsplit('.').next() == Some(f)),
                path,
                value,
                class,
                layer: LAYER_CONFIG,
                version: d.seq.to_string(),
                source: source.clone(),
                checks: vec!["document", "set"],
            })
            .collect(),
    ))
}

/// The leaves of `v` under `path`, depth first, in document order. A `null`, an empty list and an empty mapping set
/// nothing, as the readers of the payload take them, so they are not settings.
fn leaf(path: &str, v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::Null => {}
        Value::Bool(b) => out.push((path.to_owned(), b.to_string())),
        Value::Number(n) | Value::String(n) => out.push((path.to_owned(), n.clone())),
        Value::Seq(items) => {
            for (i, item) in items.iter().enumerate() {
                leaf(&format!("{path}[{i}]"), item, out);
            }
        }
        Value::Map(entries) => {
            for (k, item) in entries {
                leaf(&format!("{path}.{k}"), item, out);
            }
        }
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

/// The value as it is printed: itself, or the digest of a value that is long or holds a control character.
fn printable(value: &str) -> String {
    if value.len() <= SHOWN_MAX && !value.chars().any(char::is_control) {
        return value.to_owned();
    }
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, value.as_bytes());
    format!("sha384:{}", hex(d.as_ref()))
}

fn shown(mut fields: Vec<Field>) -> Vec<Field> {
    for f in &mut fields {
        f.value = printable(&f.value);
    }
    fields
}

/// The fields as the JSON list of cli.md "JSON output". `version`, `source` and `class` are always strings; `secret` is
/// present only when true.
#[must_use]
pub fn to_json(fields: &[Field]) -> serde_json::Value {
    serde_json::Value::Array(
        fields
            .iter()
            .map(|f| {
                let mut o = serde_json::json!({
                    "path": f.path,
                    "value": f.value,
                    "class": f.class,
                    "layer": f.layer,
                    "version": f.version,
                    "source": f.source,
                    "checks": f.checks,
                });
                if f.secret {
                    o["secret"] = serde_json::Value::Bool(true);
                }
                o
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_holds_its_own_subtree_and_not_a_neighbour_by_prefix() {
        assert!(within("durable.driver", "durable"));
        assert!(within("durable", "durable"));
        assert!(within("publishers[0].kid", "publishers"));
        assert!(within("publishers[0].kid", "publishers[0]"));
        assert!(!within("durable_x.driver", "durable"));
        assert!(!within("publishers[10].kid", "publishers[1]"));
        assert!(!within("durable", "durable.driver"));
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
    }

    #[test]
    fn a_long_value_or_one_with_a_control_character_is_shown_as_its_digest() {
        assert_eq!(printable("dev"), "dev");
        assert_eq!(printable(&"a".repeat(SHOWN_MAX)), "a".repeat(SHOWN_MAX));
        for v in [
            "a".repeat(SHOWN_MAX + 1),
            "one\ntwo".to_owned(),
            "esc\u{1b}[31m".to_owned(),
            "tab\there".to_owned(),
        ] {
            let p = printable(&v);
            assert!(p.starts_with("sha384:") && p.len() == 7 + 96, "{p}");
            assert!(!p.contains(&v[..3]) || v.len() <= 3, "{p}");
        }
    }
}
