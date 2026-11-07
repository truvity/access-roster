//! The action table and the schemas generated from it (ADR 0030, "The action table is code").
//!
//! The table is `docs/architecture/audit-actions.yaml`; `tools/gen/audit` makes `generated.rs` from it. The schemas
//! are JSON Schema 2020-12 documents, applied by the `jsonschema` crate: sluis writes no code of its own for a
//! published standard when a vetted library exists (REQ-SEC-018, `docs/reference/approved-libraries.md`). The Go
//! package applies the same documents with `santhosh-tekuri/jsonschema`, and the vectors of
//! `kits/conformance/audit` keep the two in step (REQ-AUDIT-101).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use connectrpc::error::ErrorCode;
use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;
use sluis_kit::refusal;

use crate::{Action, Result};

/// One OCSF activity an action may have; `name` is `activity_name`, empty when the record carries none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activity {
    /// `activity_id`.
    pub id: u32,
    /// `activity_name`, or empty.
    pub name: &'static str,
}

/// One action of a table: the class and the activities it may have, and the outcomes it may report.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    /// `metadata.event_code`.
    pub name: &'static str,
    /// The actor that writes it.
    pub actor: &'static str,
    /// The OCSF class.
    pub class: u32,
    /// The activities the action may have.
    pub activities: &'static [Activity],
    /// The `status_id` values the action may report: 1 success, 2 failure.
    pub outcomes: &'static [i64],
}

/// The name of the document of shared definitions.
pub const DEFS_NAME: &str = "defs.schema.json";

/// Nothing is fetched from this base: the documents are served by name, and a `$ref` between them
/// (`defs.schema.json#/$defs/word`) resolves against it.
const BASE: &str = "https://sluis.id/schema/audit/";

/// The action table of one project's release with the schemas generated from it. The emitter refuses an action that
/// is not a row (REQ-AUDIT-022) and a record that does not validate against the schema of its row (REQ-AUDIT-099).
/// A table is immutable.
pub struct Table {
    rows: HashMap<&'static str, Row>,
    validators: HashMap<&'static str, Validator>,
}

fn schema_file(action: &str) -> String {
    format!("{action}.schema.json")
}

/// Serves the documents of a table to the library, by address.
struct Docs(Arc<HashMap<String, Value>>);

impl Retrieve for Docs {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.0
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("no schema document at {uri}").into())
    }
}

/// Compiles one document of a set, which resolves its references among the set by name.
fn compile(
    uri: &str,
    doc: &Value,
    docs: &Arc<HashMap<String, Value>>,
) -> std::result::Result<Validator, String> {
    jsonschema::options()
        .with_base_uri(uri.to_owned())
        .with_retriever(Docs(Arc::clone(docs)))
        .build(doc)
        .map_err(|e| e.to_string())
}

/// Checks that a set of schema documents (file name to JSON text), as an `AuditCatalogue` holds them, is a set the
/// writer can use: each is JSON, [`DEFS_NAME`] is among them, and each of the others compiles with the references
/// among the set resolved. store@ refuses a catalogue that fails this, so the writer never starts on one.
///
/// # Errors
///
/// A message that names the document and the reason, never a value of a record.
pub fn check_documents(documents: &[(String, String)]) -> std::result::Result<(), String> {
    let mut docs = HashMap::new();
    for (name, text) in documents {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("schema {name}: {e}"))?;
        if !v.is_object() {
            return Err(format!("schema {name}: not a JSON Schema object"));
        }
        docs.insert(format!("{BASE}{name}"), v);
    }
    if !docs.contains_key(&format!("{BASE}{DEFS_NAME}")) {
        return Err(format!("schema: no {DEFS_NAME}"));
    }
    let docs = Arc::new(docs);
    for (name, _) in documents {
        if name == DEFS_NAME {
            continue;
        }
        let uri = format!("{BASE}{name}");
        compile(&uri, &docs[&uri], &docs).map_err(|e| format!("schema {name}: {e}"))?;
    }
    Ok(())
}

impl Table {
    /// Returns a table from rows and schema documents (file name to JSON text), which must hold [`DEFS_NAME`] and the
    /// schema of every row.
    ///
    /// # Errors
    ///
    /// A message when a document is not JSON or does not compile, or a row has no schema or is twice in the table.
    pub fn new(
        rows: &'static [Row],
        schemas: &'static [(&'static str, &'static str)],
    ) -> std::result::Result<Self, String> {
        let mut docs = HashMap::new();
        for (name, text) in schemas {
            let v: Value = serde_json::from_str(text).map_err(|e| format!("schema {name}: {e}"))?;
            docs.insert(format!("{BASE}{name}"), v);
        }
        if !docs.contains_key(&format!("{BASE}{DEFS_NAME}")) {
            return Err(format!("schema: no {DEFS_NAME}"));
        }
        let docs = Arc::new(docs);
        let mut by_name = HashMap::new();
        let mut validators = HashMap::new();
        for r in rows {
            if by_name.insert(r.name, *r).is_some() {
                return Err(format!(
                    "audit table: the action {:?} is twice in the table",
                    r.name
                ));
            }
            let uri = format!("{BASE}{}", schema_file(r.name));
            let doc = docs
                .get(&uri)
                .ok_or_else(|| format!("audit table: the action {:?} has no schema", r.name))?;
            let v = compile(&uri, doc, &docs).map_err(|e| format!("schema {}: {e}", r.name))?;
            validators.insert(r.name, v);
        }
        Ok(Self {
            rows: by_name,
            validators,
        })
    }

    /// The action table of sluis itself, generated from `docs/architecture/audit-actions.yaml`. An emitter with no
    /// other table uses it.
    ///
    /// # Panics
    ///
    /// When the generated table is broken, which a test of this crate catches.
    #[must_use]
    pub fn sluis() -> Arc<Table> {
        static SLUIS: OnceLock<Arc<Table>> = OnceLock::new();
        Arc::clone(SLUIS.get_or_init(|| {
            #[allow(clippy::expect_used)]
            // a broken generated table is a build error, caught by the tests
            Arc::new(
                Table::new(crate::generated::ROWS, crate::generated::SCHEMAS)
                    .expect("the generated action table is broken"),
            )
        }))
    }

    /// The row of an action.
    #[must_use]
    pub fn row(&self, name: &str) -> Option<&Row> {
        self.rows.get(name)
    }

    /// The action of the row with its first activity, the one an action that has only one uses.
    #[must_use]
    pub fn action(&self, name: &str) -> Option<Action> {
        let r = self.rows.get(name)?;
        let a = r.activities.first()?;
        Some(Action {
            name: r.name.to_owned(),
            class_uid: r.class,
            activity_id: a.id,
            activity_name: a.name.to_owned(),
        })
    }

    /// The actions of the table, in order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.rows.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Refuses an action that is not a row, or whose class, activity or activity name is not one the row has.
    ///
    /// # Errors
    ///
    /// `invalid_argument` with reason `schema`.
    pub fn check_action(&self, a: &Action) -> Result<()> {
        let Some(r) = self.rows.get(a.name.as_str()) else {
            return Err(refusal(ErrorCode::InvalidArgument, "schema", "action"));
        };
        if r.class != a.class_uid {
            return Err(refusal(ErrorCode::InvalidArgument, "schema", "action"));
        }
        if r.activities
            .iter()
            .any(|x| x.id == a.activity_id && x.name == a.activity_name)
        {
            return Ok(());
        }
        Err(refusal(
            ErrorCode::InvalidArgument,
            "schema",
            "action.activity",
        ))
    }

    /// Checks a record (RFC 8785 bytes) against the schema of the action it names in `metadata.event_code`.
    ///
    /// # Errors
    ///
    /// `invalid_argument` with reason `schema` and the path of the member, never a value.
    pub fn validate(&self, record: &[u8]) -> Result<()> {
        let bad = |path: &str| refusal(ErrorCode::InvalidArgument, "schema", path);
        let v: Value = serde_json::from_slice(record).map_err(|_| bad("record"))?;
        // The profile of a record first: integers of 64 bits and no float, as the canonical form has it.
        if !profile_ok(&v, 0) {
            return Err(bad("record"));
        }
        let name = v["metadata"]["event_code"].as_str().unwrap_or("");
        let Some(validator) = self.validators.get(name) else {
            return Err(bad("metadata.event_code"));
        };
        validator
            .validate(&v)
            .map_err(|e| bad(&format!("record{}", e.instance_path())))
    }
}

/// The profile of a record: integers of 64 bits and no float, nested no deeper than the parser of the Go package follows.
fn profile_ok(v: &Value, depth: usize) -> bool {
    if depth > crate::canonical::MAX_DEPTH + 2 {
        return false;
    }
    match v {
        Value::Number(n) => n.is_i64() || n.as_u64().is_some_and(|u| i64::try_from(u).is_ok()),
        Value::Array(a) => a.iter().all(|e| profile_ok(e, depth + 1)),
        Value::Object(o) => o.values().all(|e| profile_ok(e, depth + 1)),
        _ => true,
    }
}
