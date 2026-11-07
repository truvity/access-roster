//! The generated JSON Schemas of the configuration files (ADR 0004, "Schemas are Protobuf"), embedded in the binary, and the
//! check that a document satisfies its schema before anything decodes it (REQ-DATA-038, REQ-OPS-002).
//!
//! The schemas are the golden files of `schema/`, made by `tools/gen/configschema` from the Protobuf messages. The
//! `jsonschema` crate applies them: sluis writes no code of its own for a published standard when a vetted library exists
//! (REQ-SEC-018, `docs/reference/approved-libraries.md`). The Go package `kits/go/configschema` applies the same documents
//! with `santhosh-tekuri/jsonschema`, and the vectors of `kits/conformance/config` hold the two to the same verdicts and
//! the same words.
//!
//! An error names a path and a rule, never a value. The path is made of the names the schema declares and the positions
//! of list items, and a key the schema does not declare is shown as `<key>`, because it is the file's own text.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use jsonschema::error::ValidationErrorKind;
use jsonschema::paths::LocationSegment;
use jsonschema::{JsonType, Validator};
use serde_json::Value;

/// The identifier of the schema of the bootstrap file: the path below `https://sluis.id/schema/`.
pub const BOOTSTRAP: &str = "bootstrap/v1/bootstrap.schema.json";

/// Every schema, by identifier. The files are the ones the Go package embeds.
const SCHEMAS: &[(&str, &str)] = &[
    (
        BOOTSTRAP,
        include_str!("../../../../schema/bootstrap/v1/bootstrap.schema.json"),
    ),
    (
        "boundary/v1/boundary.schema.json",
        include_str!("../../../../schema/boundary/v1/boundary.schema.json"),
    ),
    (
        "key-plan/v1/key-plan.schema.json",
        include_str!("../../../../schema/key-plan/v1/key-plan.schema.json"),
    ),
    (
        "token-lifetime/v1/token-lifetime.schema.json",
        include_str!("../../../../schema/token-lifetime/v1/token-lifetime.schema.json"),
    ),
    (
        "audit-log/v1/audit-log.schema.json",
        include_str!("../../../../schema/audit-log/v1/audit-log.schema.json"),
    ),
    (
        "audit-catalogue/v1/audit-catalogue.schema.json",
        include_str!("../../../../schema/audit-catalogue/v1/audit-catalogue.schema.json"),
    ),
    (
        "exchange-trust/v1/exchange-trust.schema.json",
        include_str!("../../../../schema/exchange-trust/v1/exchange-trust.schema.json"),
    ),
    (
        "upstream/v1/upstream.schema.json",
        include_str!("../../../../schema/upstream/v1/upstream.schema.json"),
    ),
    (
        "installation-client/v1/installation-client.schema.json",
        include_str!("../../../../schema/installation-client/v1/installation-client.schema.json"),
    ),
];

/// The identifier of the schema of the payload of a signed config document of the kind, if the kind has one: the kind name
/// in lower-case words joined by hyphens, below its version (`KeyPlan` is `key-plan/v1/key-plan.schema.json`). `Policy`
/// and `GrantVocabulary`, whose payload is not a mapping of items, have none.
#[must_use]
pub fn payload_id(kind: &str) -> Option<&'static str> {
    let mut name = String::new();
    for (i, c) in kind.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                name.push('-');
            }
            name.push(c.to_ascii_lowercase());
        } else {
            name.push(c);
        }
    }
    let id = format!("{name}/v1/{name}.schema.json");
    SCHEMAS.iter().find(|(i, _)| *i == id).map(|(i, _)| *i)
}

/// The identifiers of every schema, for a test that holds them to the files of `schema/`.
#[must_use]
pub fn ids() -> Vec<&'static str> {
    SCHEMAS.iter().map(|(i, _)| *i).collect()
}

/// Where a document failed its schema and by which rule. It never holds a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaError {
    /// For example `publishers[0].kid`; empty for the document itself.
    pub path: String,
    /// For example `required`; the same words in the Go package.
    pub rule: String,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            f.write_str(&self.rule)
        } else {
            write!(f, "{}: {}", self.path, self.rule)
        }
    }
}

impl std::error::Error for SchemaError {}

fn failure(path: impl Into<String>, rule: impl Into<String>) -> SchemaError {
    SchemaError {
        path: path.into(),
        rule: rule.into(),
    }
}

fn validators() -> &'static Result<HashMap<&'static str, Validator>, String> {
    static ALL: OnceLock<Result<HashMap<&'static str, Validator>, String>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mut all = HashMap::new();
        for (id, text) in SCHEMAS {
            let doc: Value =
                serde_json::from_str(text).map_err(|_| format!("schema {id}: not JSON"))?;
            let v = jsonschema::validator_for(&doc)
                .map_err(|_| format!("schema {id}: cannot be compiled"))?;
            all.insert(*id, v);
        }
        Ok(all)
    })
}

/// Checks a document, read as plain data, against the schema of the given identifier. It returns the first failure in the
/// order of path and rule, so that Go and Rust name the same one.
///
/// # Errors
///
/// [`SchemaError`] when the document does not satisfy the schema, or the identifier is unknown.
pub fn validate(id: &str, doc: &Value) -> Result<(), SchemaError> {
    let all = validators().as_ref().map_err(|e| failure("", e.clone()))?;
    let v = all.get(id).ok_or_else(|| failure("", "unknown schema"))?;
    check(v, doc)
}

/// Applies one compiled schema and names the first failure.
fn check(v: &Validator, doc: &Value) -> Result<(), SchemaError> {
    let mut found: Vec<Found> = Vec::new();
    // The ids of items that the schema refuses: the location of the object and the name.
    let mut bad: Vec<Vec<Seg>> = Vec::new();
    for e in v.iter_errors(doc) {
        let loc = segments(e.instance_path().into_iter());
        match e.kind() {
            // An item id that the schema refuses is the document's own text: name its place.
            ValidationErrorKind::PropertyNames { error } => {
                let mut id = loc.clone();
                id.push(Seg::Name(
                    error.instance().as_str().unwrap_or_default().to_owned(),
                ));
                bad.push(id);
                found.push(Found::new(loc, Some("<id>"), "not a valid id"));
            }
            ValidationErrorKind::Required { property } => {
                // The name is the schema's own: it is the key the document lacks.
                let name = property.as_str().unwrap_or_default();
                found.push(Found::new(loc, Some(name), "required"));
            }
            ValidationErrorKind::UnevaluatedProperties { .. }
            | ValidationErrorKind::AdditionalProperties { .. } => {
                found.push(Found::new(loc, Some("<key>"), "unknown key"));
            }
            ValidationErrorKind::FalseSchema => found.push(Found::new(loc, None, "retired key")),
            other => found.push(Found::new(loc, None, &rule(other))),
        }
    }
    // An item id that the schema refuses is the document's own text, and so is everything below it that is named by it: a
    // second fault under a bad id is reported under <id>, never under the id.
    let mut errs: Vec<SchemaError> = found
        .into_iter()
        .map(|mut f| {
            if let Some(b) = bad.iter().find(|b| f.loc.starts_with(b)) {
                let mut loc = f.loc[..b.len() - 1].to_vec();
                loc.push(Seg::Name("<id>".to_owned()));
                loc.extend_from_slice(&f.loc[b.len()..]);
                f.loc = loc;
            }
            let path = path_of(&f.loc);
            failure(f.tail.map_or(path.clone(), |t| join(&path, &t)), f.rule)
        })
        .collect();
    errs.sort_by(|a, b| (&a.path, &a.rule).cmp(&(&b.path, &b.rule)));
    errs.into_iter().next().map_or(Ok(()), Err)
}

/// A failure before its path is written: the location of the value, a name to add to it, and the rule.
struct Found {
    loc: Vec<Seg>,
    tail: Option<String>,
    rule: String,
}

impl Found {
    fn new(loc: Vec<Seg>, tail: Option<&str>, rule: &str) -> Self {
        Self {
            loc,
            tail: tail.map(str::to_owned),
            rule: rule.to_owned(),
        }
    }
}

/// A part of a location: a name, or the position in a list.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seg {
    Name(String),
    Index(usize),
}

fn segments<'a>(it: impl Iterator<Item = LocationSegment<'a>>) -> Vec<Seg> {
    it.map(|s| match s {
        LocationSegment::Index(i) => Seg::Index(i),
        LocationSegment::Property(p) => Seg::Name(p.into_owned()),
    })
    .collect()
}

/// A location the way the loaders write it: names joined by dots, list positions in brackets.
fn path_of(segments: &[Seg]) -> String {
    let mut out = String::new();
    for s in segments {
        match s {
            Seg::Index(i) => {
                out.push('[');
                out.push_str(&i.to_string());
                out.push(']');
            }
            Seg::Name(p) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(p);
            }
        }
    }
    out
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path}.{name}")
    }
}

/// The words for a failed keyword. They are the ones the Go package uses.
fn rule(kind: &ValidationErrorKind) -> String {
    match kind {
        ValidationErrorKind::Type { kind } => format!("must be {}", type_words(kind)),
        ValidationErrorKind::Pattern { .. } => "not in the form the schema requires".to_owned(),
        ValidationErrorKind::MinLength { .. } => "too short".to_owned(),
        ValidationErrorKind::MaxLength { .. } => "too long".to_owned(),
        ValidationErrorKind::MinItems { .. } => "too few items".to_owned(),
        ValidationErrorKind::MinProperties { .. } => "too few keys".to_owned(),
        ValidationErrorKind::Minimum { .. } => "too low".to_owned(),
        ValidationErrorKind::Maximum { .. } => "too high".to_owned(),
        ValidationErrorKind::MaxItems { .. } => "too many items".to_owned(),
        ValidationErrorKind::UniqueItems => "items are not unique".to_owned(),
        ValidationErrorKind::Constant { .. } => "not the value the schema requires".to_owned(),
        ValidationErrorKind::Enum { .. } => "not one of the values the schema allows".to_owned(),
        other => format!("violates {}", other.keyword()),
    }
}

/// The one type a schema wants, as the loaders said it: "a string", "a mapping", "a list". A type or null (a field that
/// may be null in the file) is worded as the type.
fn type_words(kind: &jsonschema::error::TypeKind) -> &'static str {
    use jsonschema::error::TypeKind;
    fn one(t: JsonType) -> &'static str {
        match t {
            JsonType::Object => "a mapping",
            JsonType::Array => "a list",
            JsonType::String => "a string",
            JsonType::Boolean => "a boolean",
            JsonType::Integer => "an integer",
            JsonType::Number => "a number",
            JsonType::Null => "null",
        }
    }
    match kind {
        TypeKind::Single(t) => one(*t),
        TypeKind::Multiple(set) => {
            let rest: Vec<JsonType> = set.iter().filter(|t| *t != JsonType::Null).collect();
            if let [t] = rest.as_slice() {
                one(*t)
            } else {
                "of another type"
            }
        }
    }
}

#[cfg(test)]
mod tests;
