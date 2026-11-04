//! The enforcement tables that every process of sluis compiles in: the store's rules
//! (actor x kind x verb), key's rules (actor x purpose x op), the call graph and the pinned uids.
//!
//! `generated.rs` is made by `tools/gen/registry` from `docs/architecture/actors.yaml`,
//! `kinds.yaml` and `keys.yaml`, so that nothing that enforces least privilege is written by hand
//! (ADR 0002, "Registries generate the enforcement"). Run `just registry-gen` after a registry
//! changes; `just registry-check` fails while the generated files are stale. This file is the
//! hand-written API over them. The Go package `kits/go/registry` has the same API and the same
//! data.
//!
//! Every lookup is by exact name and allocates nothing: an unknown actor, kind, purpose or verb is
//! denied, never an error.

use core::time::Duration;

#[rustfmt::skip]
mod generated;

use generated::{
    ACTOR_INDEX, ACTORS, CALLEES, CALLERS, DRIVER_OWNERS, KEY_RULES, KIND_BY_NAME, KIND_BY_SEGMENT,
    KINDS, STORE_RULES, UID_BASE, UID_BLOCK_STRIDE, UID_NAMES,
};

/// The class of a kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Config,
    Secret,
    Durable,
    Temp,
}

/// The scope of a kind: `boundary` or `boundary+tenant`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Boundary,
    BoundaryTenant,
}

/// A row of the kind registry (`docs/architecture/kinds.yaml`).
#[derive(Debug)]
pub struct Kind {
    pub name: &'static str,
    pub segment: &'static str,
    pub class: Class,
    pub scope: Scope,
    /// `hashed`, `sealed` or `plain`.
    pub treatment: &'static str,
    /// The actor that writes the kind, `self`, `adapter-<vendor>`, `IaC` or `pipeline`.
    pub writer: &'static str,
    pub self_scoped: bool,
    pub personal: bool,
    pub exportable: bool,
    pub backed_up: bool,
    /// Some actor may watch the kind.
    pub watched: bool,
    /// The default lifetime. `Duration::ZERO` means the writer must give a TTL.
    pub ttl_default: Duration,
    pub ttl_max: Duration,
    pub indexes: &'static [&'static str],
}

/// A row of the actor registry (`docs/architecture/actors.yaml`), or a platform piece (family
/// `platform`).
#[derive(Debug)]
pub struct Actor {
    pub name: &'static str,
    pub family: &'static str,
    pub language: &'static str,
    pub holder: bool,
    pub ports: &'static [&'static str],
    pub calls: &'static [&'static str],
    pub egress: &'static [&'static str],
}

/// The bit of each verb in a store rule is its index here; bit `SELF_SHIFT + i` marks the verb as
/// self-scoped.
const VERBS: [&str; 7] = [
    "get", "list", "create", "update", "delete", "apply", "watch",
];
const SELF_SHIFT: usize = 7;
const CREATE: usize = 2;

/// The bit of each op in a key rule is its index here.
const OPS: [&str; 7] = [
    "seal",
    "open",
    "sign",
    "mac",
    "public-key",
    "wrap",
    "unwrap",
];

/// The kind with a PascalCase name such as `DataKeyWrap`.
#[must_use]
pub fn kind_by_name(name: &str) -> Option<&'static Kind> {
    let i = KIND_BY_NAME
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()?;
    KINDS.get(KIND_BY_NAME.get(i)?.1)
}

/// The kind with an address segment such as `data-key-wrap`.
#[must_use]
pub fn kind_by_segment(segment: &str) -> Option<&'static Kind> {
    let i = KIND_BY_SEGMENT
        .binary_search_by(|(n, _)| (*n).cmp(segment))
        .ok()?;
    KINDS.get(KIND_BY_SEGMENT.get(i)?.1)
}

/// Every kind, in the order of the registry.
#[must_use]
pub fn kinds() -> &'static [Kind] {
    KINDS
}

fn store_rule(actor: &str, segment: &str) -> Option<u16> {
    let i = STORE_RULES
        .binary_search_by(|(a, s, _)| (*a, *s).cmp(&(actor, segment)))
        .ok()?;
    STORE_RULES.get(i).map(|r| r.2)
}

/// Whether the actor may use the verb (`get`, `list`, `create`, `update`, `delete`, `apply` or
/// `watch`) on the kind with the address segment. Everything the registries do not allow is denied.
#[must_use]
pub fn store_allows(actor: &str, segment: &str, verb: &str) -> bool {
    let (Some(bits), Some(i)) = (
        store_rule(actor, segment),
        VERBS.iter().position(|v| *v == verb),
    ) else {
        return false;
    };
    bits & (1 << i) != 0
}

/// Whether any rule of the actor on the kind holds only for ids that start with `<actor>/`. It is
/// the strict answer: use [`store_self_scoped_for`] when the verb is known, because an actor may be
/// bound to its own ids when it writes and free to read the ids of others (an adapter and its
/// facts).
#[must_use]
pub fn store_self_scoped(actor: &str, segment: &str) -> bool {
    store_rule(actor, segment).is_some_and(|bits| bits >> SELF_SHIFT != 0)
}

/// Whether the actor's rule for this verb on the kind holds only for ids that start with
/// `<actor>/`. It is false when the actor may not use the verb at all.
#[must_use]
pub fn store_self_scoped_for(actor: &str, segment: &str, verb: &str) -> bool {
    let (Some(bits), Some(i)) = (
        store_rule(actor, segment),
        VERBS.iter().position(|v| *v == verb),
    ) else {
        return false;
    };
    bits & (1 << i) != 0 && bits & (1 << (SELF_SHIFT + i)) != 0
}

/// Whether the actor may write the kind (create, update, delete or apply). A self-scoped kind has
/// every actor as a writer, each under its own ids.
#[must_use]
pub fn is_writer(actor: &str, segment: &str) -> bool {
    store_rule(actor, segment).is_some_and(|bits| bits & (1 << CREATE) != 0)
}

/// Whether the actor may ask key for the op (`seal`, `open`, `sign`, `mac`, `public-key`, `wrap`
/// or `unwrap`) under the key purpose.
#[must_use]
pub fn key_allows(actor: &str, purpose: &str, op: &str) -> bool {
    let Ok(i) = KEY_RULES.binary_search_by(|(a, p, _)| (*a, *p).cmp(&(actor, purpose))) else {
        return false;
    };
    let (Some(rule), Some(bit)) = (KEY_RULES.get(i), OPS.iter().position(|o| *o == op)) else {
        return false;
    };
    rule.2 & (1 << bit) != 0
}

fn lookup(
    table: &'static [(&'static str, &'static [&'static str])],
    key: &str,
) -> &'static [&'static str] {
    match table.binary_search_by(|(k, _)| (*k).cmp(key)) {
        Ok(i) => table.get(i).map_or(&[], |e| e.1),
        Err(_) => &[],
    }
}

/// Whether the caller may call the callee over its transport. The audit transport (the spool) is
/// the callee `transport`. A holder reaches its own drivers outside this graph: a driver checks
/// [`driver_owner`].
#[must_use]
pub fn may_call(caller: &str, callee: &str) -> bool {
    lookup(CALLEES, caller).binary_search(&callee).is_ok()
}

/// The sorted callers of a callee, for socket groups and units.
#[must_use]
pub fn callers_of(callee: &str) -> &'static [&'static str] {
    lookup(CALLERS, callee)
}

/// The uid of the named actor, platform piece, driver user or harness user in the boundary with the
/// uid block: 61000 + ordinal + 1000 x `uid_block` (REQ-ISO-072). The ordinal is the name's place
/// in `tools/gen/registry/uids.yaml`. `None` for an unknown name or a block that gives no valid
/// uid.
#[must_use]
pub fn uid(name: &str, uid_block: u32) -> Option<u32> {
    let ordinal = UID_NAMES.iter().position(|n| *n == name)?;
    let uid = u64::from(UID_BASE)
        + u64::try_from(ordinal).ok()?
        + u64::from(UID_BLOCK_STRIDE) * u64::from(uid_block);
    // 2^32-1 is "no uid" and 2^32-2 is the overflow uid
    if uid > u64::from(u32::MAX) - 2 {
        return None;
    }
    u32::try_from(uid).ok()
}

/// The reverse of [`uid`]: the name and the uid block.
#[must_use]
pub fn name_for_uid(uid: u32) -> Option<(&'static str, u32)> {
    let rel = uid.checked_sub(UID_BASE)?;
    let ordinal = usize::try_from(rel % UID_BLOCK_STRIDE).ok()?;
    let name = UID_NAMES.get(ordinal)?;
    Some((name, rel / UID_BLOCK_STRIDE))
}

/// The actor that owns a driver, from the driver's user name: `driver-store-rqlite` is owned by
/// `store`.
#[must_use]
pub fn driver_owner(driver: &str) -> Option<&'static str> {
    let i = DRIVER_OWNERS
        .binary_search_by(|(d, _)| (*d).cmp(driver))
        .ok()?;
    DRIVER_OWNERS.get(i).map(|e| e.1)
}

/// An actor of the registry or a platform piece such as `sluis-node`.
#[must_use]
pub fn actor_by_name(name: &str) -> Option<&'static Actor> {
    let i = ACTOR_INDEX.binary_search_by(|(n, _)| (*n).cmp(name)).ok()?;
    ACTORS.get(ACTOR_INDEX.get(i)?.1)
}

/// The actors in the order of the registry, then the platform pieces (family `platform`).
#[must_use]
pub fn actors() -> &'static [Actor] {
    ACTORS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tables are sorted, which the binary searches rely on, and agree on their sizes.
    #[test]
    fn tables_are_sorted_and_sized_as_in_go() {
        assert!(
            STORE_RULES
                .windows(2)
                .all(|w| (w[0].0, w[0].1) < (w[1].0, w[1].1))
        );
        assert!(
            KEY_RULES
                .windows(2)
                .all(|w| (w[0].0, w[0].1) < (w[1].0, w[1].1))
        );
        assert!(KIND_BY_NAME.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(KIND_BY_SEGMENT.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(ACTOR_INDEX.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(DRIVER_OWNERS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(CALLEES.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(CALLERS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(
            CALLEES
                .iter()
                .all(|(_, v)| v.windows(2).all(|w| w[0] < w[1]))
        );
        assert!(
            CALLERS
                .iter()
                .all(|(_, v)| v.windows(2).all(|w| w[0] < w[1]))
        );
        // the numbers the Go test asserts of the same tables (kits/go/registry/registry_test.go)
        assert_eq!(KINDS.len(), 112);
        assert_eq!(ACTORS.len(), 20);
        assert_eq!(STORE_RULES.len(), 480);
        assert_eq!(KEY_RULES.len(), 61);
        let verbs: u32 = STORE_RULES.iter().map(|r| (r.2 & 0x7f).count_ones()).sum();
        let self_marks: u32 = STORE_RULES
            .iter()
            .map(|r| (r.2 >> SELF_SHIFT).count_ones())
            .sum();
        let ops: u32 = KEY_RULES.iter().map(|r| r.2.count_ones()).sum();
        assert_eq!((verbs, self_marks, ops), (1742, 704, 86));
    }
}
