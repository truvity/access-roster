//! What `exporter` is told: the sockets it dials and the destinations it publishes to.
//!
//! The destinations are the kind `ExportDestination` (ADR 0009, "Destinations"), a config kind that IaC writes. store@
//! does not serve that kind yet (its reader of config payloads knows the kinds of the skeleton only), so `exporter`
//! reads the same message from a file it is given, `--destinations`, in the JSON form of the message with a closed list
//! of keys, and checks it as the configuration check will:
//!
//! ```json
//! { "destinations": { "local": { "type": "directory", "edge": "none", "documents": [
//!     { "name": "jwks", "kind": "SigningRing", "address": "jwks", "content_type": "application/json", "max_age": "300s" } ] } } }
//! ```
//!
//! Every board of a boundary must run `exporter` with the same file: the `ExportManifest` it writes is one item for the
//! whole boundary.
//!
//! A document the check refuses is not published and is reported once (an audit fact and an alarm), and the others go
//! on (ADR 0009, "Refusals"). A file that is not of this shape fails the start.

use std::path::{Path, PathBuf};
use std::time::Duration;

use buffa_types::google::protobuf::Duration as PbDuration;
use serde_json::{Map, Value};
use sluis_destination::check_address;
use sluis_proto::sluis::config::v2alpha1::{ExportDestination, ExportedDocument};

/// The only destination type this build has a driver for.
pub const DIRECTORY: &str = "directory";
/// The one kind this build can turn into a document.
pub const SIGNING_RING: &str = "SigningRing";
/// The longest `max-age` of a key set: the figure the lead time of a new key is derived from (REQ-KEYS-016).
pub const KEY_SET_MAX_AGE: Duration = Duration::from_secs(300);

/// Whether the driver of a destination type can read a public address back the way a verifier does. A document with a
/// public address that is written where nothing can read it back could never be `published`, and `signer` would count a
/// report it can never trust, so the configuration check refuses the pairing. The directory driver has no edge and no
/// public address of its own: a file server in front of it is the operator's, and `exporter` cannot see it.
#[must_use]
pub fn reads_back(dtype: &str) -> bool {
    dtype != DIRECTORY
}

/// The sockets `exporter` dials.
#[derive(Clone, Debug)]
pub struct Sockets {
    /// store@.
    pub store: PathBuf,
    /// The audit transport (emit.sock).
    pub audit: PathBuf,
    /// The directory of the destination drivers' sockets: `<type>.sock` each.
    pub drivers: PathBuf,
}

impl Sockets {
    /// The default layout below the run directory (PLAN.md "Socket layout").
    #[must_use]
    pub fn under(run: &Path, boundary: &str) -> Self {
        Self {
            store: run.join("store").join(format!("{boundary}.sock")),
            audit: run.join("audit").join(boundary).join("emit.sock"),
            drivers: run.join("exporter").join(boundary),
        }
    }

    /// The socket of the driver of a destination type.
    #[must_use]
    pub fn driver(&self, dtype: &str) -> PathBuf {
        self.drivers.join(format!("{dtype}.sock"))
    }
}

/// A document that passed the check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Doc {
    /// Names it in the destination; the id of its report.
    pub name: String,
    /// Where it goes at the destination.
    pub address: String,
    /// Its `Content-Type`.
    pub content_type: String,
    /// Its `Cache-Control`, from the `max-age` the destination declares.
    pub cache_control: String,
    /// The URL a verifier fetches, when there is one.
    pub public_address: Option<String>,
}

/// A destination that passed the check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dest {
    /// Its name; the id of its cursor.
    pub name: String,
    /// Its driver.
    pub dtype: String,
    /// The documents that passed.
    pub documents: Vec<Doc>,
}

/// A document the check refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    /// The destination.
    pub destination: String,
    /// The document.
    pub document: String,
    /// A closed reason.
    pub reason: &'static str,
}

/// What the file says, checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Loaded {
    /// The destinations, with the documents that passed.
    pub destinations: Vec<Dest>,
    /// The documents that did not.
    pub refused: Vec<Refused>,
}

/// A file that is not of the shape, with the path of the fault. Never a value.
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed(pub String);

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Malformed {}

fn bad<T>(path: &str, rule: &str) -> Result<T, Malformed> {
    Err(Malformed(format!("{path}: {rule}")))
}

/// An id part: 1 to 128 of lower-case letters, digits, `-`, `_` and `.`, never `.` or `..` (store-api.md).
fn id_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

fn closed<'a>(
    path: &str,
    v: &'a Value,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, Malformed> {
    let Some(o) = v.as_object() else {
        return bad(path, "must be an object");
    };
    if let Some(k) = o.keys().find(|k| !keys.contains(&k.as_str())) {
        // The key names the fault; it is the operator's own text, not a secret.
        return bad(&format!("{path}.{k}"), "unknown key");
    }
    Ok(o)
}

fn text(path: &str, o: &Map<String, Value>, key: &str) -> Result<String, Malformed> {
    match o.get(key) {
        None => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => bad(&format!("{path}.{key}"), "must be a string"),
    }
}

/// `"300s"`: whole seconds, the protobuf JSON form of a duration.
fn seconds(path: &str, s: &str) -> Result<PbDuration, Malformed> {
    let n = s
        .strip_suffix('s')
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|n| n.parse::<i64>().ok());
    match n {
        Some(seconds) => Ok(PbDuration {
            seconds,
            nanos: 0,
            ..PbDuration::default()
        }),
        None => bad(path, "must be whole seconds, such as \"300s\""),
    }
}

/// Reads the file into the messages of the kind, by name.
///
/// # Errors
///
/// [`Malformed`] with the path of the first fault.
pub fn decode(bytes: &[u8]) -> Result<Vec<(String, ExportDestination)>, Malformed> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return bad("", "not JSON");
    };
    let top = closed("", &root, &["destinations"])?;
    let Some(dests) = top.get("destinations") else {
        return bad("destinations", "is missing");
    };
    let Some(dests) = dests.as_object() else {
        return bad("destinations", "must be an object of destinations by name");
    };
    let mut out = Vec::new();
    for (name, v) in dests {
        let path = format!("destinations.{name}");
        if !id_part(name) {
            return bad(&path, "not a valid name");
        }
        let o = closed(&path, v, &["type", "edge", "documents"])?;
        let mut d = ExportDestination {
            r#type: text(&path, o, "type")?,
            edge: text(&path, o, "edge")?,
            ..ExportDestination::default()
        };
        let docs = match o.get("documents") {
            None => &Vec::new(),
            Some(Value::Array(a)) => a,
            Some(_) => return bad(&format!("{path}.documents"), "must be a list"),
        };
        for (i, dv) in docs.iter().enumerate() {
            let p = format!("{path}.documents[{i}]");
            let o = closed(
                &p,
                dv,
                &[
                    "name",
                    "kind",
                    "address",
                    "content_type",
                    "max_age",
                    "public_address",
                ],
            )?;
            let max_age = match o.get("max_age") {
                None => None,
                Some(Value::String(s)) => Some(seconds(&format!("{p}.max_age"), s)?),
                Some(_) => return bad(&format!("{p}.max_age"), "must be a string"),
            };
            d.documents.push(ExportedDocument {
                name: text(&p, o, "name")?,
                kind: text(&p, o, "kind")?,
                address: text(&p, o, "address")?,
                content_type: text(&p, o, "content_type")?,
                max_age: max_age.into(),
                public_address: text(&p, o, "public_address")?,
                ..ExportedDocument::default()
            });
        }
        out.push((name.clone(), d));
    }
    Ok(out)
}

/// A public address a verifier can fetch: an `https` URL with a host and no query, fragment or white space.
fn public_ok(u: &str) -> bool {
    u.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && !rest.starts_with('/')
            && !rest.contains(['?', '#'])
            && !u.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

/// Checks one document the way the configuration check will (ADR 0009, "What is exportable" and "Destinations").
fn check_doc(dtype: &str, d: &ExportedDocument) -> Result<Doc, &'static str> {
    if !id_part(&d.name) {
        return Err("name");
    }
    // The mark is a property of the kind, set in review (REQ-EXPORT-007, REQ-EXPORT-008).
    let Some(kind) = sluis_registry::kind_by_name(&d.kind) else {
        return Err("unknown_kind");
    };
    if !kind.exportable {
        return Err("not_exportable");
    }
    // A directory and a bucket receive public material only; a sealed kind never goes there (REQ-EXPORT-011).
    if dtype == DIRECTORY && kind.name == "ClientSecretExport" {
        return Err("sealed_to_public_destination");
    }
    if kind.name != SIGNING_RING {
        return Err("not_built");
    }
    if check_address(&d.address).is_err() {
        return Err("address");
    }
    if d.content_type.is_empty()
        || d.content_type.len() > 128
        || !d.content_type.bytes().all(|b| (0x20..0x7f).contains(&b))
    {
        return Err("content_type");
    }
    let max_age = d.max_age.as_option().map_or(0, |m| m.seconds);
    // The lead time of a new key counts the key set's max-age (REQ-KEYS-016, REQ-KEYS-085): a longer one breaks it.
    if max_age <= 0 || u64::try_from(max_age).is_ok_and(|s| s > KEY_SET_MAX_AGE.as_secs()) {
        return Err("max_age");
    }
    if !d.public_address.is_empty() && !public_ok(&d.public_address) {
        return Err("public_address");
    }
    if !d.public_address.is_empty() && !reads_back(dtype) {
        return Err("public_address_unreadable");
    }
    Ok(Doc {
        name: d.name.clone(),
        address: d.address.clone(),
        content_type: d.content_type.clone(),
        cache_control: format!("public, max-age={max_age}"),
        public_address: (!d.public_address.is_empty()).then(|| d.public_address.clone()),
    })
}

/// Checks the destinations.
///
/// # Errors
///
/// [`Malformed`] for a destination of a type this build has no driver for, an edge it cannot honour, or two documents
/// of one name.
pub fn check(dests: Vec<(String, ExportDestination)>) -> Result<Loaded, Malformed> {
    let mut out = Loaded::default();
    for (name, d) in dests {
        let path = format!("destinations.{name}");
        if d.r#type != DIRECTORY {
            return bad(
                &format!("{path}.type"),
                "no driver for this type in this build",
            );
        }
        if !(d.edge.is_empty() || d.edge == "none") {
            return bad(&format!("{path}.edge"), "a directory has no edge");
        }
        let mut docs = Vec::new();
        for ed in &d.documents {
            if docs.iter().any(|x: &Doc| x.name == ed.name) {
                return bad(&format!("{path}.documents"), "two documents of one name");
            }
            match check_doc(&d.r#type, ed) {
                Ok(doc) => docs.push(doc),
                Err(reason) => out.refused.push(Refused {
                    destination: name.clone(),
                    document: ed.name.clone(),
                    reason,
                }),
            }
        }
        out.destinations.push(Dest {
            name,
            dtype: d.r#type,
            documents: docs,
        });
    }
    Ok(out)
}

/// Reads and checks the file.
///
/// # Errors
///
/// [`Malformed`] with the path of the fault, or an unreadable file.
pub fn load(path: &Path) -> Result<Loaded, Malformed> {
    let bytes = std::fs::read(path)
        .map_err(|e| Malformed(format!("the destinations file: {:?}", e.kind())))?;
    check(decode(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A file with one directory destination and one document, with `patch` merged over the document.
    fn file(patch: &Value) -> Vec<u8> {
        let mut doc = json!({
            "name": "jwks", "kind": "SigningRing", "address": "jwks",
            "content_type": "application/json", "max_age": "300s"
        });
        for (k, v) in patch.as_object().into_iter().flatten() {
            doc[k] = v.clone();
        }
        json!({"destinations": {"local": {"type": "directory", "documents": [doc]}}})
            .to_string()
            .into_bytes()
    }

    fn refused(patch: &Value) -> Option<&'static str> {
        check(decode(&file(patch)).unwrap())
            .unwrap()
            .refused
            .first()
            .map(|r| r.reason)
    }

    #[test]
    fn a_key_set_document_passes_and_gets_its_cache_control() {
        let l = check(decode(&file(&json!({}))).unwrap()).unwrap();
        assert!(l.refused.is_empty());
        let d = &l.destinations[0].documents[0];
        assert_eq!(d.cache_control, "public, max-age=300");
        assert_eq!(d.public_address, None);
    }

    /// A public address on a driver that cannot read it back is refused, at the check and so at the load: the document
    /// could only ever be `written`, and `signer` would not wait for it. The directory driver is such a driver.
    ///
    /// verifies: REQ-KEYS-116
    #[test]
    fn a_public_address_where_nothing_can_read_it_back_is_refused() {
        assert!(!reads_back(DIRECTORY));
        assert_eq!(
            refused(&json!({"public_address": "https://sluis.example.com/jwks"})),
            Some("public_address_unreadable")
        );
        // The same file loaded from disk: the document is not in the destination at all.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.json");
        std::fs::write(
            &path,
            file(&json!({"public_address": "https://sluis.example.com/jwks"})),
        )
        .unwrap();
        let l = load(&path).unwrap();
        assert!(l.destinations[0].documents.is_empty());
        assert_eq!(l.refused[0].reason, "public_address_unreadable");
        // A driver that can read back passes the same document.
        let doc = ExportedDocument {
            name: "jwks".into(),
            kind: "SigningRing".into(),
            address: "jwks".into(),
            content_type: "application/json".into(),
            max_age: seconds("", "300s").unwrap().into(),
            public_address: "https://sluis.example.com/jwks".into(),
            ..ExportedDocument::default()
        };
        assert_eq!(
            check_doc("bucket", &doc).unwrap().public_address.as_deref(),
            Some("https://sluis.example.com/jwks")
        );
    }

    /// Every kind of the registry is tried: the ones not marked are refused as such, whatever else is true of them.
    ///
    /// verifies: REQ-EXPORT-007
    #[test]
    fn only_a_kind_the_registry_marks_exportable_is_published() {
        let kinds = sluis_registry::kinds();
        assert!(kinds.len() > 50, "a sweep over nothing proves nothing");
        let mut exportable = 0;
        for k in kinds {
            let r = refused(&json!({"kind": k.name}));
            if k.exportable {
                exportable += 1;
                assert_ne!(r, Some("not_exportable"), "{}", k.name);
            } else {
                assert_eq!(r, Some("not_exportable"), "{}", k.name);
            }
        }
        assert_eq!(
            exportable, 7,
            "ADR 0009: exactly seven kinds are exportable"
        );
        // The marked kinds that this build cannot turn into a document are refused as not built, never published as
        // something else; a sealed kind never goes to a directory.
        assert_eq!(refused(&json!({"kind": "TrustBundle"})), Some("not_built"));
        assert_eq!(
            refused(&json!({"kind": "ClientSecretExport"})),
            Some("sealed_to_public_destination")
        );
        assert_eq!(refused(&json!({"kind": "SigningRing"})), None);
        assert_eq!(
            refused(&json!({"kind": "NoSuchKind"})),
            Some("unknown_kind")
        );
    }

    #[test]
    fn the_rest_of_the_check() {
        assert_eq!(refused(&json!({"address": "../jwks"})), Some("address"));
        assert_eq!(refused(&json!({"name": "Jwks"})), Some("name"));
        assert_eq!(refused(&json!({"content_type": ""})), Some("content_type"));
        for pa in [
            "http://x.example.com/j",
            "https://x.example.com/j?a=1",
            "https:///j",
            "https://x y",
        ] {
            assert_eq!(
                refused(&json!({"public_address": pa})),
                Some("public_address"),
                "{pa}"
            );
        }
        // The key set may not be cached longer than the figure the lead time of a new key counts.
        assert_eq!(refused(&json!({"max_age": "3600s"})), Some("max_age"));
        assert_eq!(refused(&json!({"max_age": "0s"})), Some("max_age"));
        assert_eq!(refused(&json!({"max_age": "60s"})), None);
    }

    #[test]
    fn a_file_of_another_shape_fails_the_start_with_a_path() {
        let e = |b: &str| decode(b.as_bytes()).unwrap_err().0;
        assert_eq!(e("nope"), ": not JSON");
        assert_eq!(e(r#"{"destinations":{},"x":1}"#), ".x: unknown key");
        assert_eq!(
            e(r#"{"destinations":{"d":{"tpye":"directory"}}}"#),
            "destinations.d.tpye: unknown key"
        );
        assert_eq!(
            e(r#"{"destinations":{"D":{}}}"#),
            "destinations.D: not a valid name"
        );
        assert_eq!(
            e(r#"{"destinations":{"d":{"documents":[{"max_age":300}]}}}"#),
            "destinations.d.documents[0].max_age: must be a string"
        );
        let bucket = decode(br#"{"destinations":{"d":{"type":"bucket"}}}"#).unwrap();
        assert_eq!(
            check(bucket).unwrap_err().0,
            "destinations.d.type: no driver for this type in this build"
        );
        let edge =
            decode(br#"{"destinations":{"d":{"type":"directory","edge":"cloudflare"}}}"#).unwrap();
        assert!(check(edge).is_err());
    }
}
