//! The conformance kit of the item port (store-api.md "The command line and the suite"):
//!
//! - [`item_suite`] runs the cases against any engine behind `sluis.port.item.v2alpha1.ItemService`,
//!   over a client of the kit. "A driver passes the suite or it is not a driver."
//! - [`rules`] holds what every engine decides in the same way (keys, page sizes, timestamps,
//!   the checks of a `Transact`), so the engines and the suite cannot drift.
//! - [`memory::MemoryEngine`] (feature `memory`, tests only) is the in-memory engine; it passes the
//!   same suite as the rqlite driver.

//! # What the suite fixes beyond the comments of the proto
//!
//! These are the choices the contract left open; both engines make them and store@ may rely on them.
//!
//! - **A key** is printable ASCII without a space, at most 512 bytes ([`rules::check_key`]).
//! - **A condition** expects `absent: true` or a version; `absent: false` and none are `invalid_argument/batch`.
//!   A failed condition is `aborted/version` with the field path `conditions[i]`, `i` the first that failed.
//! - **An item past its expiry** is absent to a read, a listing and a condition; a put over it
//!   (not yet freed by a sweep) continues from its version, so a version never goes back.
//! - **`Transact`** applies conditions, then deletes, then puts. A key may be written or deleted once per request.
//! - **A delete's log row** holds the version the item had when it was removed; a delete of an absent key logs nothing.
//! - **`TailLog` from 0** starts after the newest row at the time of the call. A sequence beyond the newest, or below
//!   the oldest kept, is `failed_precondition/sequence_expired`: a watcher must not resume where a change could be lost.
//! - **`Query`**: `page_size` 0 is 100 and above 500 is 500; the page token is the last key of the page, as bytes, and
//!   must be a key under the prefix; the token is empty on the last page.

pub mod rules;
mod suite;

#[cfg(feature = "memory")]
pub mod memory;

use std::future::Future;
use std::io::Write;

pub use suite::item_suite;

/// The result of one case.
#[derive(Clone, Debug)]
pub struct Case {
    /// The name of the case.
    pub name: &'static str,
    /// Whether it passed.
    pub passed: bool,
    /// Why it failed; empty when it passed.
    pub detail: String,
}

async fn run_case(name: &'static str, fut: impl Future<Output = anyhow::Result<()>>) -> Case {
    match suite::bounded(fut).await {
        Ok(()) => Case {
            name,
            passed: true,
            detail: String::new(),
        },
        Err(e) => Case {
            name,
            passed: false,
            detail: format!("{e:#}"),
        },
    }
}

/// Prints each case (name and result) and fails when a case failed, and when no case ran: a
/// suite that ran nothing proved nothing.
///
/// # Errors
///
/// A failed case, or no case at all.
pub fn report(cases: &[Case], out: &mut impl Write) -> anyhow::Result<()> {
    anyhow::ensure!(!cases.is_empty(), "no case ran");
    let mut failed = 0usize;
    for c in cases {
        if c.passed {
            writeln!(out, "PASS {}", c.name)?;
        } else {
            failed += 1;
            writeln!(out, "FAIL {}: {}", c.name, c.detail)?;
        }
    }
    writeln!(
        out,
        "{} cases, {} passed, {failed} failed",
        cases.len(),
        cases.len() - failed
    )?;
    anyhow::ensure!(failed == 0, "{failed} of {} cases failed", cases.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_suite_that_ran_nothing_fails() {
        assert!(report(&[], &mut Vec::new()).is_err());
    }

    #[test]
    fn a_failed_case_fails_the_report_and_is_named() {
        let cases = [
            Case {
                name: "a",
                passed: true,
                detail: String::new(),
            },
            Case {
                name: "b",
                passed: false,
                detail: "because".into(),
            },
        ];
        let mut out = Vec::new();
        assert!(report(&cases, &mut out).is_err());
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("PASS a") && out.contains("FAIL b: because"),
            "{out}"
        );
    }
}
