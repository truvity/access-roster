//! `sluis config check --against OLD`: what a change of the bootstrap file does (bootstrap-file.md "A change needs a
//! restart"; cli.md "`sluis config check` and `explain`").
//!
//! The bootstrap file is the one setting whose change needs a restart of store@, so a pipeline that must not publish
//! such a change wants to see it. This compares the effective settings of the new file with those of the previous one,
//! the ones `explain` prints, and names each path that differs. It names the path and the kind of change, never a
//! value: a changed value of the bootstrap file is not a secret, but the line is read in a pipeline log and a rule of
//! `check` is one place where nothing is printed. A signed config document needs no such line: every config change
//! reloads as a whole snapshot.

use std::collections::BTreeMap;

use crate::bootstrap::Bootstrap;
use crate::config::explain::bootstrap_groups;
use crate::config::offline::Check;

/// The name of the check, in the `checks` list.
pub const NAME: &str = "against";

/// The effective settings of a bootstrap file, by path. A key the file leaves out has the binary's default, so a
/// default that turns into a written value (or the reverse) is a change only when the value differs.
fn settings(b: &Bootstrap) -> BTreeMap<String, String> {
    bootstrap_groups(b, "")
        .into_iter()
        .flat_map(|g| g.settings)
        .map(|s| (s.path, s.value))
        .collect()
}

/// The previous file could not be used as the old side of the comparison: the rule of the bootstrap reader, which names
/// a path and never a value. The comparison did not run, and `against` is a request to run it, so it fails.
#[must_use]
pub fn unreadable(rule: &str) -> Check {
    Check::fail(NAME, "", format!("the previous bootstrap file: {rule}"))
}

/// One `warn` line for each setting that differs between `old` and `new`, in the order of the paths, or one `ok` line
/// when none does. A warning exits 0: the caller who must not publish a change reads the lines.
#[must_use]
pub fn compare(old: &Bootstrap, new: &Bootstrap) -> Vec<Check> {
    let (before, after) = (settings(old), settings(new));
    let mut out = Vec::new();
    for (path, value) in &after {
        match before.get(path) {
            None => out.push(Check::warn(NAME, path, "added")),
            Some(was) if was != value => out.push(Check::warn(NAME, path, "changed")),
            Some(_) => {}
        }
    }
    for path in before.keys().filter(|p| !after.contains_key(*p)) {
        out.push(Check::warn(NAME, path, "removed"));
    }
    if out.is_empty() {
        out.push(Check::ok(NAME, ""));
    }
    out
}
