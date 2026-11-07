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
const SCHEMAS: &[(&str, &str)] = &[(
    BOOTSTRAP,
    include_str!("../../../../schema/bootstrap/v1/bootstrap.schema.json"),
)];

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
    let mut found: Vec<SchemaError> = Vec::new();
    for e in v.iter_errors(doc) {
        let loc = path_of(e.instance_path().into_iter());
        match e.kind() {
            ValidationErrorKind::Required { property } => {
                // The name is the schema's own: it is the key the document lacks.
                let name = property.as_str().unwrap_or_default();
                found.push(failure(join(&loc, name), "required"));
            }
            ValidationErrorKind::UnevaluatedProperties { .. }
            | ValidationErrorKind::AdditionalProperties { .. } => {
                found.push(failure(join(&loc, "<key>"), "unknown key"));
            }
            ValidationErrorKind::FalseSchema => found.push(failure(loc, "retired key")),
            other => found.push(failure(loc, rule(other))),
        }
    }
    found.sort_by(|a, b| (&a.path, &a.rule).cmp(&(&b.path, &b.rule)));
    found.into_iter().next().map_or(Ok(()), Err)
}

/// A location the way the loaders write it: names joined by dots, list positions in brackets.
fn path_of<'a>(segments: impl Iterator<Item = LocationSegment<'a>>) -> String {
    let mut out = String::new();
    for s in segments {
        match s {
            LocationSegment::Index(i) => {
                out.push('[');
                out.push_str(&i.to_string());
                out.push(']');
            }
            LocationSegment::Property(p) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&p);
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
        ValidationErrorKind::MaxItems { .. } => "too many items".to_owned(),
        ValidationErrorKind::UniqueItems => "items are not unique".to_owned(),
        ValidationErrorKind::Constant { .. } => "not the value the schema requires".to_owned(),
        ValidationErrorKind::Enum { .. } => "not one of the values the schema allows".to_owned(),
        other => format!("violates {}", other.keyword()),
    }
}

/// The one type a schema wants, as the loaders said it: "a string", "a mapping", "a list".
fn type_words(kind: &jsonschema::error::TypeKind) -> &'static str {
    match kind {
        jsonschema::error::TypeKind::Single(JsonType::Object) => "a mapping",
        jsonschema::error::TypeKind::Single(JsonType::Array) => "a list",
        jsonschema::error::TypeKind::Single(JsonType::String) => "a string",
        jsonschema::error::TypeKind::Single(JsonType::Boolean) => "a boolean",
        jsonschema::error::TypeKind::Single(JsonType::Integer) => "an integer",
        jsonschema::error::TypeKind::Single(JsonType::Number) => "a number",
        jsonschema::error::TypeKind::Single(JsonType::Null) => "null",
        jsonschema::error::TypeKind::Multiple(_) => "of another type",
    }
}

#[cfg(test)]
mod tests;
