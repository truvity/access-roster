//! The offline check of a config set: what `sluis config check` runs through `store check --validate DIR`
//! (ADR 0005, "Configuration loading"; signed-config.md "The snapshot"; REQ-DATA-090).
//!
//! It reads the signed documents from a directory, `<segment>.jws` as the `file` driver names them, and runs each
//! through [`super::snapshot::accept`] and the set through [`super::snapshot::assemble`]: the very functions the
//! loader runs at a start and at a reload, so that the check and store@ cannot disagree. Nothing is in force offline,
//! so step 5 takes any `seq`, as at a cold start.
//!
//! Unlike the loader, which stops at the first failure, the check reports every document: one line per check, with
//! the kind and the rule, never a value.

use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use sluis_registry::Kind;

use super::document::DOCUMENT_MAX;
use super::snapshot::{self, Document, LoadError};
use crate::bootstrap::Bootstrap;

/// The result of one check: cli.md "JSON output", the `checks` list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// What was checked: `bootstrap`, `document` or `set`.
    pub name: &'static str,
    /// `ok`, `fail` or `not-run`.
    pub result: &'static str,
    /// The kind a document check is about; empty for the bootstrap file and the set.
    pub path: String,
    /// The step and rule that failed, with the field path; empty when it passed. Never a value.
    pub rule: String,
}

/// The JSON object of `store check --validate`: `{"checks": [...]}`, each check as cli.md "JSON output" lists it,
/// with `rule` beside a failed one.
#[must_use]
pub fn to_json(checks: &[Check]) -> serde_json::Value {
    let list: Vec<_> = checks
        .iter()
        .map(|c| {
            let mut o = serde_json::json!({"name": c.name, "result": c.result, "path": c.path});
            if !c.rule.is_empty() {
                o["rule"] = serde_json::Value::String(c.rule.clone());
            }
            o
        })
        .collect();
    serde_json::json!({ "checks": list })
}

impl Check {
    fn ok(name: &'static str, path: &str) -> Self {
        Self {
            name,
            result: "ok",
            path: path.to_owned(),
            rule: String::new(),
        }
    }

    fn fail(name: &'static str, path: &str, rule: impl Into<String>) -> Self {
        Self {
            name,
            result: "fail",
            path: path.to_owned(),
            rule: rule.into(),
        }
    }

    fn not_run(name: &'static str, path: &str) -> Self {
        Self {
            name,
            result: "not-run",
            path: path.to_owned(),
            rule: String::new(),
        }
    }
}

/// The checks of the bootstrap file `b` and of the documents in `dir`, in order: the Boundary document, the
/// documents of the kinds it declares, then the set.
#[must_use]
pub fn check_dir(dir: &Path, b: &Bootstrap) -> Vec<Check> {
    let mut out = Vec::new();
    let boundary_kind = snapshot::kind("Boundary");
    let boundary = match read_and_accept(dir, boundary_kind, b) {
        Ok(d) => {
            out.push(Check::ok("document", boundary_kind.name));
            d
        }
        Err(e) => {
            out.push(Check::fail("document", boundary_kind.name, e.reason));
            out.push(Check::not_run("set", ""));
            return out;
        }
    };
    let declared = match snapshot::declared_kinds(&boundary) {
        Ok(k) => k,
        Err(e) => {
            // The Boundary document read, but declares a kind this build cannot read: the set cannot be built.
            out.pop();
            out.push(Check::fail("document", boundary_kind.name, e.reason));
            out.push(Check::not_run("set", ""));
            return out;
        }
    };
    let mut docs = Vec::with_capacity(declared.len());
    let mut all_read = true;
    for k in declared {
        match read_and_accept(dir, k, b) {
            Ok(d) => {
                out.push(Check::ok("document", k.name));
                docs.push(d);
            }
            Err(e) => {
                all_read = false;
                out.push(Check::fail("document", k.name, e.reason));
            }
        }
    }
    if !all_read {
        out.push(Check::not_run("set", ""));
        return out;
    }
    match snapshot::assemble(&b.boundary, boundary, docs) {
        Ok(_) => out.push(Check::ok("set", "")),
        Err(e) => out.push(Check::fail(
            "set",
            "",
            match e.kind {
                Some(k) => format!("{k}: {}", e.reason),
                None => e.reason,
            },
        )),
    }
    out
}

/// Whether every check passed.
#[must_use]
pub fn passed(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.result == "ok")
}

fn read_and_accept(dir: &Path, kind: &'static Kind, b: &Bootstrap) -> Result<Document, LoadError> {
    let data = read(dir, kind)?;
    // The label is the source's; offline it names nothing, as nothing is in force.
    snapshot::accept(kind, &data, String::new(), &b.publishers, None)
}

/// The bytes of `<dir>/<segment>.jws`, bounded as the loader bounds a document.
fn read(dir: &Path, kind: &Kind) -> Result<Vec<u8>, LoadError> {
    let path = dir.join(format!("{}.jws", kind.segment));
    // NONBLOCK: a FIFO in the directory cannot hang the open; it is refused below as not a regular file.
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed())
        .open(&path);
    let file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(snapshot::failed(
                Some(kind.name),
                "the source has no document of the kind",
            ));
        }
        Err(e) => {
            return Err(snapshot::failed(
                Some(kind.name),
                format!("cannot open the document ({:?})", e.kind()),
            ));
        }
    };
    let regular = file.metadata().is_ok_and(|m| m.is_file());
    if !regular {
        return Err(snapshot::failed(Some(kind.name), "not a regular file"));
    }
    let mut data = Vec::new();
    // One byte over the bound, so that `verify` refuses a document that is too large, as it does for the loader.
    let limit = u64::try_from(DOCUMENT_MAX)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(limit).read_to_end(&mut data).map_err(|e| {
        snapshot::failed(
            Some(kind.name),
            format!("cannot read the document ({:?})", e.kind()),
        )
    })?;
    Ok(data)
}
