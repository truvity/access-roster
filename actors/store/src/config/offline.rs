//! The offline check of a config set: what `sluis config check` runs through `store check --validate DIR`
//! (ADR 0005, "Configuration loading"; signed-config.md "The snapshot"; REQ-DATA-090).
//!
//! It reads the signed documents from a directory with the `file` driver's own reader, and runs each
//! through [`super::snapshot::accept`] and the set through [`super::snapshot::assemble`]: the very functions the
//! loader runs at a start and at a reload, so that the check and store@ cannot disagree. Nothing is in force offline,
//! so step 5 takes any `seq`, as at a cold start.
//!
//! Unlike the loader, which stops at the first failure, the check reports every document: one line per check, with
//! the kind and the rule, never a value.

use std::path::Path;

use sluis_registry::Kind;

use super::ConfigSnapshot as _;
use super::snapshot::{self, Document, LoadError};
use crate::bootstrap::Bootstrap;

/// The name of the check that reports the lock mode of the audit log's blob.
pub const LOCK_MODE: &str = "lock-mode";
/// The name of the check that warns about a key purpose that is slow on a card.
pub const SLOW_KEY: &str = "slow-key";

/// The result of one check: cli.md "JSON output", the `checks` list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// What was checked: `bootstrap`, `document` or `set`.
    pub name: &'static str,
    /// `ok`, `warn`, `fail` or `not-run`.
    pub result: &'static str,
    /// The kind a document check is about; empty for the bootstrap file and the set.
    pub path: String,
    /// The step and rule that failed, with the field path; empty when it passed, except for a check that reports a
    /// fact (`lock-mode`), which holds the fact. For a check that did not run, what to do to run it. Never a value of
    /// a secret.
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
    pub(crate) fn ok(name: &'static str, path: &str) -> Self {
        Self {
            name,
            result: "ok",
            path: path.to_owned(),
            rule: String::new(),
        }
    }

    /// A finding that does not fail the check: it exits 0 and is read in the output.
    pub(crate) fn warn(name: &'static str, path: &str, rule: impl Into<String>) -> Self {
        Self {
            name,
            result: "warn",
            path: path.to_owned(),
            rule: rule.into(),
        }
    }

    pub(crate) fn fail(name: &'static str, path: &str, rule: impl Into<String>) -> Self {
        Self {
            name,
            result: "fail",
            path: path.to_owned(),
            rule: rule.into(),
        }
    }

    fn not_run(name: &'static str, path: &str) -> Self {
        Self::not_run_because(name, path, "")
    }

    /// A check that did not run, with the reason a person needs to run it.
    pub(crate) fn not_run_because(name: &'static str, path: &str, why: impl Into<String>) -> Self {
        Self {
            name,
            result: "not-run",
            path: path.to_owned(),
            rule: why.into(),
        }
    }
}

/// The checks of the bootstrap file `b` and of the documents in `dir`, in order: the Boundary document, the
/// documents of the kinds it declares, then the set.
#[must_use]
pub fn check_dir(dir: &Path, b: &Bootstrap) -> Vec<Check> {
    load_dir(dir, b, false).0
}

/// [`check_dir`], and with `keep` the documents of a set that passed every check, in order: the Boundary document, then
/// the kinds it declares. That set is what store@ would load, which `sluis config explain` describes; a caller that
/// only checks passes `false` and no document is copied.
#[must_use]
pub fn load_dir(dir: &Path, b: &Bootstrap, keep: bool) -> (Vec<Check>, Vec<Document>) {
    let mut out = Vec::new();
    let Ok(dir) = sluis_file::Dir::open(dir) else {
        out.push(Check::fail(
            "document",
            "",
            "the directory of the documents cannot be opened as a directory",
        ));
        out.push(Check::not_run("set", ""));
        return (out, Vec::new());
    };
    let dir = &dir;
    let boundary_kind = snapshot::kind("Boundary");
    let boundary = match read_and_accept(dir, boundary_kind, b) {
        Ok(d) => {
            out.push(Check::ok("document", boundary_kind.name));
            d
        }
        Err(e) => {
            out.push(Check::fail("document", boundary_kind.name, e.reason));
            out.push(Check::not_run("set", ""));
            return (out, Vec::new());
        }
    };
    let declared = match snapshot::declared_kinds(&boundary) {
        Ok(k) => k,
        Err(e) => {
            // The Boundary document read, but declares a kind this build cannot read: the set cannot be built.
            out.pop();
            out.push(Check::fail("document", boundary_kind.name, e.reason));
            out.push(Check::not_run("set", ""));
            return (out, Vec::new());
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
        return (out, Vec::new());
    }
    let mut accepted = Vec::new();
    if keep {
        accepted.reserve(docs.len() + 1);
        accepted.push(boundary.clone());
        accepted.extend(docs.iter().cloned());
    }
    match snapshot::assemble(&b.boundary, boundary, docs) {
        Ok(set) => {
            // Before the set, which stays the last line.
            out.extend(lock_mode(&set));
            out.extend(slow_keys(&set));
            out.push(Check::ok("set", ""));
            (out, accepted)
        }
        Err(e) => {
            out.push(Check::fail(
                "set",
                "",
                match e.kind {
                    Some(k) => format!("{k}: {}", e.reason),
                    None => e.reason,
                },
            ));
            (out, Vec::new())
        }
    }
}

/// The lock mode of the logs' blob, as the `AuditLog` document declares it, for a set that declares one: the report of
/// REQ-AUDIT-028. The payload reader has refused a value that is not a lock mode, so this reports what store@ would run
/// with. A set without an `AuditLog` has no audit log to report.
fn lock_mode(set: &snapshot::Snapshot) -> Option<Check> {
    use buffa::Message as _;
    let bytes = set.get(
        snapshot::kind("AuditLog").segment,
        super::payload::SINGLETON_ID,
    )?;
    let log = sluis_proto::sluis::config::v2alpha1::AuditLog::decode_from_slice(&bytes).ok()?;
    let mut c = Check::ok(LOCK_MODE, "AuditLog.default.lock_mode");
    c.rule = log.lock_mode;
    Some(c)
}

/// A KeyPlan that lists the RS256 purpose is carried by software or by a card, and no file names which: the check cannot tell
/// (REQ-KEYS-015), so it warns, as REQ-KEYS-023 asks for a pinned algorithm that is slow on the hardware, and the warning says
/// when it applies. An RSA-2048 private-key operation takes seconds on a YubiKey (ADR 0006 gives 2.3 s for PS256, the same card
/// operation), the card does one thing at a time, and the ES384 signatures, the ECDH unwraps and the audit checkpoints of the
/// board wait for it; the card driver admits only a few RSA signatures and refuses the rest as busy.
fn slow_keys(set: &snapshot::Snapshot) -> Option<Check> {
    use buffa::Message as _;
    let kind = snapshot::kind("KeyPlan");
    let listed = set.list(kind.segment).into_iter().any(|(_, bytes)| {
        sluis_proto::sluis::config::v2alpha1::KeyPlan::decode_from_slice(&bytes).is_ok_and(|p| {
            p.purposes
                .iter()
                .any(|p| p.purpose == "token-signing-rs256")
        })
    });
    listed.then(|| {
        Check::warn(
            SLOW_KEY,
            "KeyPlan.default.purposes",
            "token-signing-rs256: on a card an RSA signature takes seconds and holds the card, so ES384 signing, key unwraps and \
             audit checkpoints wait for it; the card driver admits few at once and refuses the rest as busy, and key@ limits the \
             purpose to about one signature in four seconds. Software keys are not affected",
        )
    })
}

fn read_and_accept(
    dir: &sluis_file::Dir,
    kind: &'static Kind,
    b: &Bootstrap,
) -> Result<Document, LoadError> {
    let data = read(dir, kind)?;
    // The label is the source's; offline it names nothing, as nothing is in force.
    snapshot::accept(kind, &data, String::new(), &b.publishers, None)
}

/// The bytes of the document of `kind`, read by the `file` driver's own code ([`sluis_file::Dir::read`]): the same
/// name, the same `openat2(RESOLVE_BENEATH)` resolution, the same refusal of a link out of the directory and of
/// anything that is not a regular file, and the same bound. A document the driver would not serve, the check does not
/// read either.
fn read(dir: &sluis_file::Dir, kind: &Kind) -> Result<Vec<u8>, LoadError> {
    match dir.read(kind.segment) {
        Ok(d) => Ok(d.data),
        // The loader's words for a `not_found` from the source.
        Err(sluis_file::Error::Absent) => Err(snapshot::failed(
            Some(kind.name),
            "the source has no document of the kind",
        )),
        // The source refuses to serve it, which the loader takes as a source that does not answer: store@ does not
        // start. The check says which refusal of the driver it was.
        Err(e) => Err(snapshot::failed(
            Some(kind.name),
            format!("the config source did not answer: the file driver refuses the document ({e})"),
        )),
    }
}
