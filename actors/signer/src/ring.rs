//! The key set: the kind `SigningRing`, one item `default` per boundary (PLAN.md D-17), that
//! `signer` writes and `entry` and exporter@ read (kinds.yaml).
//!
//! # Nodes and keys
//!
//! Every board has a token-signing key of its own in its card, and the boards share one ring, so the
//! ring holds one `active` key per node (ADR 0006 "The token-signing key": the key set carries every
//! active token key). Each key names its node, and a `signer` changes the keys of its own node
//! only: it never promotes, retires or reactivates another node's key. A node that rotates its key
//! therefore cannot make the other boards' keys stop, and two boards never undo each other.
//!
//! # The states of a key
//!
//! A key moves one way, `pre-published`, then `active`, then `retiring`, then it is dropped
//! (ADR 0006 "Rotation": the new key first, the old one after; ADR 0017 "Issuers"). A retiring
//! key never signs again:
//!
//! - **`pre-published`**: in the key set, not signing. Every cache between sluis and a verifier learns
//!   the key before the first token is signed with it. The lead time, [`Timing::prepublish`], is
//!   derived from the cache budget that sluis publishes (ADR 0006 "Rotation"): the key set's
//!   `max-age` of 300 s, the edge cache's time to live of at most as much, 10 minutes for a
//!   verifier's throttled refetch on an unknown `kid` (OpenID Connect Core section 10.1.1) and
//!   5 minutes of clock skew, 25 minutes, rounded up to 30. A verifier that keeps the set longer than
//!   `max-age` and does not refetch on an unknown `kid` is broken; v1 published a key for 12 hours
//!   because of one, and v2 detects such a verifier instead. A key becomes `active` after the lead time.
//! - **`active`**: the key that signs. `signer` signs only when the key key@ signs with is `active`.
//! - **`retiring`**: stopped signing, still in the key set until every token it signed has expired:
//!   the longest token lifetime plus the clock skew (REQ-KEYS-007). Any instance then drops it.
//! - **`dropped`**: left the key set. What stays in the ring is a tombstone, the `kid` and the times with no key, so that
//!   a key which key@ presents again after the drop is not taken for a new key and published again (REQ-KEYS-079): it
//!   is not added, not published and not promoted. At most [`MAX_DROPPED`] tombstones are kept, the ones dropped last.
//!   The guard begins with the tombstones: a key dropped before them, in a ring written by an earlier `signer`, or
//!   more than [`MAX_DROPPED`] drops ago, is a new key again. A key that is blocked this way stays blocked, a key
//!   restored from a backup of key@ included; the way out is a new key at key@. An earlier `signer` reads `dropped` as
//!   a state it does not know and counts it as signing for ever, so after a rollback a replacement for a revoked key
//!   waits for the lead time (REQ-KEYS-089) for as long as the ring holds a tombstone.
//!
//! Where a destination with a public address publishes the static key set, the lead time does not count from the write
//! to the ring but from the moment `exporter@` read the key back from the public address, and a key is not active
//! before it did (see "The static key set").
//!
//! A node's first key is `active` at once while the ring is young: when no key of the ring is older
//! than [`Timing::bootstrap`]. The boards of a first deploy start within minutes of each other, no
//! verifier has seen a token yet, and holding every board's first token back for the window would
//! stop the installation from starting. A node that joins later, or a key that replaces another,
//! is published for the full window first.
//!
//! A key also signs at once when the issuer has no other key that signs: no `active` key of the ring
//! that `KeyRevocation` does not list (see "A replacement for a revoked key"). Waiting would stop
//! every sign-in for the whole lead time, and there is no cached key for a verifier to rely on.
//!
//! # The static key set
//!
//! `exporter@` publishes the key set to a destination and reports what a verifier would see in the temp kind
//! `ExportReport` (ADR 0009, "The order and the time"). `signer` reads the reports of the key sets ([`Publication`]):
//! when a destination with a public address reports one, a key becomes active only after the report of every such
//! destination has the state `published`, lists the kid and has a read back at most 26 hours old (REQ-KEYS-116), the
//! lead time counts from that read back (REQ-KEYS-085), and a replacement for the last key that signs waits for the
//! read back and for nothing more (REQ-KEYS-089). A report that is `unverified`, `purge-pending`, without the kid or
//! too old keeps the key pre-published. A destination with no public address reports `written` and is not counted; with
//! none counted the lead time counts from the write, as it did before `exporter@` existed. A report that expires (seven
//! days without a publication) is also not counted: closing that gap needs `signer` to know which destinations should
//! report, which it cannot read yet (`ExportDestination` has no reader but `exporter@`).
//!
//! # A revoked key
//!
//! `revoked` is a fourth state, and a key is in it when `KeyRevocation` lists its kid (ADR 0041, "The
//! tighten-only record"): the item is the state, so `signer` writes nothing for it. A revoked key is never
//! added, promoted or signed with here (REQ-KEYS-106), and it is not in the key set that `signer`
//! answers with (REQ-KEYS-107). `signer` reads `KeyRevocation` at every call that needs it, and a
//! `KeyRevocation` that cannot be read refuses the call.
//!
//! # A replacement for a revoked key
//!
//! A replacement signs soon, not after the lead time, when the issuer has no live key that signs (ADR
//! 0041, "The replacement", REQ-KEYS-089). The issuer is the boundary, so the keys of every node
//! count: while any node still has a key that signs and that `KeyRevocation` does not list, verifiers
//! know it and see no unfamiliar `kid`, and a replacement is published for the full window like any
//! other new key. A key signs when it is `active`; one in a state this code does not know counts as
//! possibly signing (a rolling upgrade or downgrade must not skip the window), and only `retiring`
//! and `pre-published` keys, and revoked ones, count as not signing. So a normal rotation (the old key
//! is `active`) and a revoked spare never skip the window; in practice the shortcut is the case where
//! every `active` key is revoked. A revoked key itself never gets the shortcut (REQ-KEYS-106). The
//! change is an audit fact with the reason [`NO_ACTIVE_KEY`].
//!
//! What holds when the shortcut is taken: the new key is written to the ring, which `signer` and
//! `entry` build `/jwks` from, before `signer` answers for it, but `entry` keeps its built key set for
//! [`KEY_SET_CACHE`] (`entry` is separate and cannot be told to rebuild). So when the ring holds a
//! revoked entry, `signer` signs with an `active` key only from [`KEY_SET_HOLD`] (that time and a
//! second of margin) after the key joined the ring, and refuses the call as "not yet" until then. The
//! hold is read from the ring (`added_at`), so a restart does not lose it. After the hold, a key set
//! that `entry` serves lists the new key. A relying party may still hold a copy of `/jwks` from before
//! for the key set's `max-age` (300 s) plus the edge copy, which `exporter@` is to purge (REQ-KEYS-088;
//! not built): it must fetch the key set again on an unfamiliar `kid` (OpenID Connect Core 1.0,
//! section 10.1.1), and one that does not is broken, not accommodated (ADR 0041).
//!
//! A revoked key stays in the ring in the state it had, and every reader filters it by
//! `KeyRevocation` (`without_revoked`); nothing removes it yet (a garbage-collection follow-up).
//!
//! # How it is written
//!
//! The ring is created once (`create`: it fails if another instance did it first) and every later
//! change is an `update` at the version that was read, so two instances of `signer` never overwrite
//! each other: the one that loses re-reads and plans again. Each change is an audit fact.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buffa_types::google::protobuf::Timestamp;
use sluis_kit::Client;
use sluis_proto::sluis::config::v2alpha1::KeyPlan;
use sluis_proto::sluis::exporter::v2alpha1::{ExportManifest, ExportReport};
use sluis_proto::sluis::signer::v2alpha1::{SigningKey, SigningRing};
use sluis_store::KEY_SET_CACHE;
use sluis_store::revocation::{KeyRevocations, without_revoked};
use sluis_store::{Error as StoreError, Kind, Store, WriteOpts};
use tokio::sync::Mutex;

use crate::audit::Auditor;
use crate::claims::HARD_CAP_SECS;
use crate::keys::{Alg, Current, KeyAt, KeyError};
use crate::service::Clock;

/// The state of a key that is in the key set and does not sign yet.
pub const PRE_PUBLISHED: &str = "pre-published";
/// The state of the key that signs.
pub const ACTIVE: &str = "active";
/// The state of a key that stopped signing and stays in the key set.
pub const RETIRING: &str = "retiring";
/// The state of a key that left the key set after its retention: the entry that remains is a tombstone with the `kid`
/// and no key, so that a key which key@ presents again is not taken for a new key (REQ-KEYS-079). It is in no key
/// set: every reader publishes only the three states above, and `signer` counts it as a key that does not sign.
pub const DROPPED: &str = "dropped";
/// How many tombstones the ring keeps; when there are more, the oldest go. A key that was dropped longer ago than that
/// many rotations is a new key again.
pub const MAX_DROPPED: usize = 1024;

/// The reason of a change that skips the lead time because no key of the issuer signs (REQ-KEYS-089),
/// in the audit fact.
pub const NO_ACTIVE_KEY: &str = "no_active_key";
/// How long after a key joined the ring `signer` waits to sign with it when the ring holds a revoked
/// key: `entry` keeps its built key set for [`KEY_SET_CACHE`], and a second more for the clocks of
/// two hosts and a read in flight.
pub const KEY_SET_HOLD: Duration = KEY_SET_CACHE.saturating_add(Duration::from_secs(1));

/// How old the read back of a report may be for `signer` to rely on it (REQ-KEYS-116): a day of the reconcile and a
/// margin (ADR 0009, "The order and the time").
pub const REPORT_MAX_AGE: Duration = Duration::from_secs(26 * 60 * 60);
/// The kind a report has when it describes a key set.
const KEY_SET: &str = "SigningRing";

/// What the `ExportReport`s say about the static key sets (ADR 0006, "Rotation"; ADR 0009).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Publication {
    /// No destination with a public address reports a key set: the live key set of `entry` is the only one, and the
    /// lead time counts from the write to the ring (REQ-KEYS-085).
    #[default]
    Unreported,
    /// At least one destination with a public address reports a key set. A key is published only when it is in the
    /// map: every such report has the state `published`, lists the kid and has a read back at most
    /// [`REPORT_MAX_AGE`] old. The value is when the last of them read the key back; the lead time counts from it
    /// (REQ-KEYS-116, REQ-KEYS-085).
    Required(HashMap<String, SystemTime>),
}

impl Publication {
    /// What the manifest and the reports say at `now`. `exporter@` writes the manifest, the documents it is configured
    /// to publish, and a report for each. Only an entry of the manifest that is a key set with a public address counts:
    ///
    /// - an entry with **no report** counts as not published, so a new public destination holds activation from the
    ///   moment the manifest names it;
    /// - a report that **no entry names** (a destination that was removed) is not read at all;
    /// - with **no manifest**, or none of its entries counted, nothing is reported and the lead time counts from the
    ///   write to the ring.
    ///
    /// A kid is in the answer only when the report of every counted entry is `published`, lists the kid and has a read
    /// back at most [`REPORT_MAX_AGE`] old.
    #[must_use]
    pub fn of(
        manifest: Option<&ExportManifest>,
        reports: &[(String, ExportReport)],
        now: SystemTime,
    ) -> Self {
        let Some(manifest) = manifest else {
            return Self::Unreported;
        };
        let entries: Vec<_> = manifest
            .entries
            .iter()
            .filter(|e| e.kind == KEY_SET && e.public)
            .collect();
        if entries.is_empty() {
            return Self::Unreported;
        }
        let by_id: HashMap<&str, &ExportReport> =
            reports.iter().map(|(id, r)| (id.as_str(), r)).collect();
        let mut counted: Vec<&ExportReport> = Vec::new();
        for e in &entries {
            match by_id.get(format!("{}/{}", e.destination, e.document).as_str()) {
                Some(r) if r.kind == KEY_SET => counted.push(r),
                // Declared and not reported: nothing is published there as far as signer can tell.
                _ => return Self::held(),
            }
        }
        let mut seen: HashMap<String, SystemTime> = HashMap::new();
        let mut kids: HashSet<&str> = HashSet::new();
        for r in &counted {
            kids.extend(r.kids.iter().map(String::as_str));
        }
        for kid in kids {
            let mut latest: Option<SystemTime> = None;
            let all = counted.iter().all(|r| {
                let read = instant(r.read_back_at.as_option());
                // A read back from the future is a clock a little ahead, not a stale one.
                let fresh = read.is_some_and(|t| {
                    now.duration_since(t)
                        .map_or(true, |age| age <= REPORT_MAX_AGE)
                });
                if r.state == "published" && fresh && r.kids.iter().any(|k| k == kid) {
                    latest = latest.max(read);
                    true
                } else {
                    false
                }
            });
            if all && let Some(t) = latest {
                seen.insert(kid.to_owned(), t);
            }
        }
        Self::Required(seen)
    }

    /// No key is published as far as `signer` can tell: what it answers when it cannot read the manifest or the reports.
    /// Activation is held, never released, on a doubt (REQ-KEYS-116).
    #[must_use]
    pub fn held() -> Self {
        Self::Required(HashMap::new())
    }

    /// Whether a pre-published key may sign now: the lead time has passed since the key was read back (or, with
    /// `immediately`, when it has been read back at all: nothing else signs, REQ-KEYS-089).
    fn ready(
        &self,
        kid: &str,
        since: SystemTime,
        now: SystemTime,
        lead: Duration,
        immediately: bool,
    ) -> bool {
        match self {
            Self::Unreported => immediately || now >= since + lead,
            Self::Required(seen) => seen
                .get(kid)
                .is_some_and(|t| immediately || now >= *t + lead),
        }
    }
}

/// The singleton id of the ring (PLAN.md D-17).
const ID: &str = "default";
/// The kind `ExportManifest`, which `signer` reads (kinds.yaml).
struct ManifestKind;
impl Kind for ManifestKind {
    type Id = String;
    type Value = ExportManifest;
    const NAME: &'static str = "ExportManifest";
}

/// The kind `ExportReport`, which `signer` reads (kinds.yaml).
struct ReportKind;
impl Kind for ReportKind {
    type Id = String;
    type Value = ExportReport;
    const NAME: &'static str = "ExportReport";
}

/// How long a snapshot of the ring is used before `signer` looks again.
const REFRESH: Duration = Duration::from_secs(10);
/// How long one call to store@ may take.
const CALL: Duration = Duration::from_secs(5);
/// How many times a lost race is retried before the attempt is given up.
const ATTEMPTS: usize = 3;

/// The ring keeps a revoked key in the state it had: `signer` writes nothing for a revoked key (the item
/// of `KeyRevocation` is its state), so every reader of the kind filters by `KeyRevocation`
/// (`without_revoked`). Nothing removes a revoked entry yet (a garbage-collection follow-up).
struct RingKind;
impl Kind for RingKind {
    type Id = &'static str;
    type Value = SigningRing;
    const NAME: &'static str = "SigningRing";
}

/// The kind `KeyPlan`, which `signer` reads (kinds.yaml) for one fact: whether the RS256 purpose is listed.
struct KeyPlanKind;
impl Kind for KeyPlanKind {
    type Id = &'static str;
    type Value = KeyPlan;
    const NAME: &'static str = "KeyPlan";
}

/// How long a key is published before it signs, and after it stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// A new key is published this long before it signs: the key set's `max-age` (300 s), the edge
    /// time to live (at most 300 s), a verifier's throttled refetch (10 minutes) and clock skew
    /// (5 minutes), rounded up to 30 minutes (ADR 0006 "Rotation", REQ-KEYS-076).
    pub prepublish: Duration,
    /// A key that stopped signing stays published this long: the longest token lifetime of one hour
    /// (ADR 0020 "Lifetimes") plus five minutes of clock skew (REQ-KEYS-007).
    pub retain: Duration,
    /// A node's first key signs at once while no key of the ring is older than this: the boards of
    /// a first deploy.
    pub bootstrap: Duration,
}

impl Timing {
    /// The values of ADR 0006 "Rotation": 30 minutes before a key signs, 65 minutes after.
    pub const DEFAULT: Self = Self {
        prepublish: Duration::from_secs(30 * 60),
        retain: Duration::from_secs(HARD_CAP_SECS.unsigned_abs() + 5 * 60),
        bootstrap: Duration::from_secs(15 * 60),
    };
}

/// One change to the ring, for the audit log and for the tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The key.
    pub key_id: String,
    /// Its algorithm, which the audit fact names.
    pub alg: Alg,
    /// What happened.
    pub kind: ChangeKind,
    /// Why the lead time was skipped ([`NO_ACTIVE_KEY`]); `None` for every other change.
    pub reason: Option<&'static str>,
}

/// What happened to a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// The key joined the ring in the given state.
    Added(&'static str),
    /// The key became `active`.
    Activated,
    /// The key stopped signing.
    Retired,
    /// key@ withdrew the chain (`x5c`) of the key: the certificate ended, the intermediate is revoked or it did not sign it. The
    /// ring has none then. The state is the key's, unchanged.
    Uncertified(&'static str),
    /// The key's chain (`x5c`) changed: key@ gave another certificate chain for it (the token certificate was made, or made
    /// again). The state is the key's, unchanged.
    Certified(&'static str),
    /// The key left the ring.
    Dropped,
}

/// The state words, as `&'static str`, for a change that names the state a key is in.
fn state_word(state: &str) -> &'static str {
    match state {
        ACTIVE => ACTIVE,
        PRE_PUBLISHED => PRE_PUBLISHED,
        RETIRING => RETIRING,
        _ => "unknown",
    }
}

fn stamp(t: SystemTime) -> Timestamp {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        ..Timestamp::default()
    }
}

fn instant(t: Option<&Timestamp>) -> Option<SystemTime> {
    let t = t?;
    let secs = u64::try_from(t.seconds).ok()?;
    Some(UNIX_EPOCH + Duration::new(secs, u32::try_from(t.nanos).unwrap_or(0)))
}

/// When the key entered its state. A key without the stamp counts from when it joined, and one with
/// neither counts from now, so that a missing stamp never drops a key early.
fn since(k: &SigningKey, now: SystemTime) -> SystemTime {
    instant(k.state_since.as_option())
        .or_else(|| instant(k.added_at.as_option()))
        .unwrap_or(now)
}

fn enter(k: &mut SigningKey, state: &str, now: SystemTime) {
    k.state = state.to_owned();
    k.state_since = stamp(now).into();
}

/// Plans the next ring from the ring as it is, the key key@ signs with, the node it belongs to, the
/// kids that `KeyRevocation` lists, and the clock. Nothing is written here. The ring is unchanged when
/// the list of changes is empty.
///
/// Only the keys of `node` are changed, apart from the drop of any key that has been retiring for
/// the retention. A revoked key is not added to the ring and is not promoted or made to retire others
/// (REQ-KEYS-106): the item of `KeyRevocation` is its state, and the ring does not write it. A key
/// that replaces a revoked one is `active` at once when no non-revoked key of the ring is `active`
/// (REQ-KEYS-089), and published for the lead time otherwise.
#[must_use]
pub fn plan(
    ring: &SigningRing,
    cur: &Current,
    node: &str,
    now: SystemTime,
    t: &Timing,
    revoked: &HashSet<String>,
) -> (SigningRing, Vec<Change>) {
    plan_with(ring, cur, node, now, t, revoked, &Publication::Unreported)
}

/// As [`plan`], with what the reports of `exporter@` say about the static key sets. When a destination with a public
/// address reports one ([`Publication::Required`]), a key becomes active only once it has been read back from there
/// (REQ-KEYS-116), the lead time counts from that read back and not from the write to the ring (REQ-KEYS-085), and a
/// key that replaces the last one that signs waits for the read back, and for nothing else (REQ-KEYS-089). A key is
/// then never active at once when it joins the ring: no report can list it yet.
///
/// The plan is made **for one algorithm** (`cur.alg`): the keys of the other algorithm are not read for any decision and are
/// never changed (ADR 0006, "Named exceptions": an RS256 key has its own life). So the lead time, the shortcut of
/// REQ-KEYS-089, the first-deploy window, the retirement of the node's earlier keys and the retention count the keys of
/// that algorithm only: an ES384 key that signs does not make an RS256 replacement wait, and a revoked RS256 key does not
/// make an ES384 replacement skip the window (REQ-KEYS-270).
#[must_use]
pub fn plan_with(
    ring: &SigningRing,
    cur: &Current,
    node: &str,
    now: SystemTime,
    t: &Timing,
    revoked: &HashSet<String>,
    publication: &Publication,
) -> (SigningRing, Vec<Change>) {
    plan_alg(ring, cur.alg, Some(cur), node, now, t, revoked, publication)
}

/// The plan for an algorithm that the installation does not enable (the KeyPlan does not list its purpose): no key joins
/// or is promoted, the node's keys of the algorithm stop signing and are retired, and the retention drops them as usual.
/// Without it a removed purpose would leave an `active` key in the ring, and the key set and discovery would keep
/// promising an algorithm that signs nothing.
#[must_use]
pub fn plan_disabled(
    ring: &SigningRing,
    alg: Alg,
    node: &str,
    now: SystemTime,
    t: &Timing,
    revoked: &HashSet<String>,
) -> (SigningRing, Vec<Change>) {
    plan_alg(
        ring,
        alg,
        None,
        node,
        now,
        t,
        revoked,
        &Publication::Unreported,
    )
}

/// Whether a ring key is of the algorithm. A key with no algorithm is ES384, the only one a ring had before the RS256
/// exception: the keys of such a ring keep their life.
fn is_alg(k: &SigningKey, alg: Alg) -> bool {
    k.algorithm == alg.name() || (k.algorithm.is_empty() && alg == Alg::Es384)
}

/// Puts the planned keys of one algorithm back into the ring: the keys of the other algorithms stay where they are, a key
/// of the algorithm stays in its place (or is gone), and a key that joined goes last.
fn merged(all: &[SigningKey], alg: Alg, own: Vec<SigningKey>) -> Vec<SigningKey> {
    let mut out = Vec::with_capacity(all.len() + 1);
    let mut planned = own.into_iter().peekable();
    for k in all {
        if !is_alg(k, alg) {
            out.push(k.clone());
        } else if planned.peek().is_some_and(|p| p.key_id == k.key_id) {
            out.extend(planned.next());
        }
    }
    out.extend(planned);
    out
}

#[allow(clippy::too_many_arguments)]
fn plan_alg(
    ring: &SigningRing,
    alg: Alg,
    cur: Option<&Current>,
    node: &str,
    now: SystemTime,
    t: &Timing,
    revoked: &HashSet<String>,
    publication: &Publication,
) -> (SigningRing, Vec<Change>) {
    let reported = matches!(publication, Publication::Required(_));
    let cur_revoked = cur.is_some_and(|c| revoked.contains(&c.key_id));
    let mut keys: Vec<SigningKey> = ring
        .keys
        .iter()
        .filter(|k| is_alg(k, alg))
        .cloned()
        .collect();
    // Whether the issuer signs now: a key of any node that `KeyRevocation` does not list and that is not
    // known not to sign.
    // When nothing signs, a key waits for the lead time for nobody (REQ-KEYS-089).
    // A state this code does not know counts as signing: only the known states that do not sign, and
    // revoked keys, are left out, so another version's state never skips the lead time.
    let issuer_signs = keys.iter().any(|k| {
        !revoked.contains(&k.key_id)
            && k.state != RETIRING
            && k.state != PRE_PUBLISHED
            && k.state != DROPPED
    });
    // The first key of an algorithm on a ring that already serves (a key of another algorithm has signed) has no key to replace:
    // it waits for the window like any new key, because a relying party may hold a key set from a moment ago without it, and the
    // shortcut of REQ-KEYS-089 is not taken for it. That holds for every node's first key of the algorithm while none of the
    // algorithm's keys has signed (every key of it is still pre-published). A ring where nothing has served, the first
    // deploy of an installation, is not that ring: its first key of any algorithm is the first key of the issuer.
    let other_serves = ring
        .keys
        .iter()
        .any(|k| !is_alg(k, alg) && k.state != PRE_PUBLISHED && !revoked.contains(&k.key_id));
    let never_served = other_serves
        && keys
            .iter()
            .all(|k| k.state == PRE_PUBLISHED && !revoked.contains(&k.key_id));
    // (An algorithm with no key at all is `never_served` too: `all` over nothing holds.)
    let shortcut = !issuer_signs && !never_served;
    let mut changes = Vec::new();
    let change = |k: &str, kind| Change {
        key_id: k.to_owned(),
        alg,
        kind,
        reason: None,
    };

    if let Some(cur) = cur {
        match keys.iter().position(|k| k.key_id == cur.key_id) {
            // A revoked key does not join the ring, in any state.
            None if cur_revoked => {}
            None => {
                // A node's first key signs at once while the ring is young (the first deploy); every other
                // key is published for the full window first.
                let first_of_node = !keys.iter().any(|k| k.node == node);
                // A key of unknown age counts as old: it never makes the ring young. The whole ring counts, whatever the
                // algorithm of its keys: a ring that has served for a while is not young because it holds no key of this one.
                let young = ring.keys.iter().all(|k| {
                    instant(k.added_at.as_option()).is_some_and(|at| now < at + t.bootstrap)
                });
                let first_deploy = first_of_node && young;
                // The shortcut of REQ-KEYS-089 is for the replacement of a key that was revoked: the first key of an algorithm on a
                // ring that already serves, of this node or of another, has none to replace (`shortcut`, above).
                let state = if (first_deploy || shortcut) && !reported {
                    ACTIVE
                } else {
                    PRE_PUBLISHED
                };
                let skipped = (state == ACTIVE && !first_deploy).then_some(NO_ACTIVE_KEY);
                keys.push(SigningKey {
                    key_id: cur.key_id.clone(),
                    algorithm: alg.name().to_owned(),
                    spki_der: cur.spki_der.clone(),
                    x5c: cur.x5c.clone(),
                    added_at: stamp(now).into(),
                    state: state.to_owned(),
                    state_since: stamp(now).into(),
                    node: node.to_owned(),
                    ..SigningKey::default()
                });
                changes.push(Change {
                    reason: skipped,
                    ..change(&cur.key_id, ChangeKind::Added(state))
                });
            }
            Some(i) => {
                let k = &mut keys[i];
                // The chain key@ gives for the node's own key is the key set's `x5c`. It arrives after the key does (ca makes the
                // certificate once an intermediate is installed) and changes when the certificate is made again, so the ring takes
                // it whenever it differs. An empty answer leaves what the ring has: the old chain still verifies the same key,
                // and a revoked key is not in the key set at all. Another node's key is that node's to update.
                // key@ says when it withdraws a chain on purpose (the certificate ended, the intermediate is revoked): then the ring
                // has none, and the key set does not claim a custody that key@ no longer vouches for. An empty answer that is not
                // a withdrawal means none yet, or that key@ could not tell, and leaves the chain.
                if !cur_revoked
                    && k.node == node
                    && cur.x5c.is_empty()
                    && cur.x5c_withdrawn
                    && !k.x5c.is_empty()
                {
                    k.x5c.clear();
                    changes.push(change(
                        &cur.key_id,
                        ChangeKind::Uncertified(state_word(&k.state)),
                    ));
                }
                if !cur_revoked && k.node == node && !cur.x5c.is_empty() && k.x5c != cur.x5c {
                    k.x5c = cur.x5c.clone();
                    changes.push(change(
                        &cur.key_id,
                        ChangeKind::Certified(state_word(&k.state)),
                    ));
                }
                // Only the node's own key, and only a key that was published for the whole window, or any
                // time once the issuer has no key that signs. A retiring key does not come back, and
                // another node's key is not ours to promote.
                if !cur_revoked
                    && k.node == node
                    && k.state == PRE_PUBLISHED
                    && publication.ready(&k.key_id, since(k, now), now, t.prepublish, shortcut)
                {
                    let skipped = match publication {
                        Publication::Unreported => now < since(k, now) + t.prepublish,
                        Publication::Required(seen) => {
                            seen.get(&k.key_id).is_some_and(|s| now < *s + t.prepublish)
                        }
                    };
                    enter(k, ACTIVE, now);
                    changes.push(Change {
                        reason: skipped.then_some(NO_ACTIVE_KEY),
                        ..change(&cur.key_id, ChangeKind::Activated)
                    });
                }
            }
        }
    }

    // Once the key key@ signs with is active, the node's earlier keys stop. The keys of other nodes
    // are theirs: their signers retire them. A revoked key is left as it is: the item of
    // `KeyRevocation` is its state, and it is not in the key set. With no key at all (the algorithm is not enabled) every
    // key of the node that signs or is about to stops.
    let current_signs = match cur {
        Some(cur) => {
            !cur_revoked
                && keys
                    .iter()
                    .any(|k| k.key_id == cur.key_id && k.node == node && k.state == ACTIVE)
        }
        None => true,
    };
    if current_signs {
        for k in keys.iter_mut().filter(|k| {
            k.node == node
                && cur.is_none_or(|c| k.key_id != c.key_id)
                && !revoked.contains(&k.key_id)
                && (k.state == ACTIVE || k.state == PRE_PUBLISHED)
        }) {
            enter(k, RETIRING, now);
            changes.push(change(&k.key_id.clone(), ChangeKind::Retired));
        }
    }

    // A retiring key leaves the key set after its retention, and what stays is a tombstone (REQ-KEYS-079).
    for k in keys
        .iter_mut()
        .filter(|k| k.state == RETIRING && now >= since(k, now) + t.retain)
    {
        changes.push(change(&k.key_id.clone(), ChangeKind::Dropped));
        enter(k, DROPPED, now);
        k.spki_der.clear();
        k.x5c.clear();
    }
    let tombstones = keys.iter().filter(|k| k.state == DROPPED).count();
    if tombstones > MAX_DROPPED {
        // The oldest drop goes first, the one with the smallest `state_since` (ties by place in the ring). The ring lists a
        // key where it joined, not where it was dropped, so the first tombstones in the list are not the oldest drops.
        let mut by_age: Vec<(SystemTime, usize)> = keys
            .iter()
            .enumerate()
            .filter(|(_, k)| k.state == DROPPED)
            .map(|(i, k)| (since(k, now), i))
            .collect();
        by_age.sort();
        let forget: HashSet<usize> = by_age
            .iter()
            .take(tombstones - MAX_DROPPED)
            .map(|(_, i)| *i)
            .collect();
        for i in &forget {
            // A key forgotten here is a new key if key@ presents it again: it is never silent.
            tracing::warn!(
                alert = "signer-tombstone-forgotten",
                key_id = %keys[*i].key_id,
                bound = MAX_DROPPED,
                "the ring is full of dropped keys: the oldest is forgotten, and key@ presenting it would add it as a new key"
            );
        }
        let mut place = 0;
        keys.retain(|_| {
            place += 1;
            !forget.contains(&(place - 1))
        });
    } else if tombstones >= MAX_DROPPED / 10 * 9
        && changes.iter().any(|c| c.kind == ChangeKind::Dropped)
    {
        tracing::warn!(
            tombstones,
            bound = MAX_DROPPED,
            "the ring holds nearly the most dropped keys it keeps: the next drops will forget the oldest"
        );
    }

    (
        SigningRing {
            keys: merged(&ring.keys, alg, keys),
            ..ring.clone()
        },
        changes,
    )
}

/// Why `signer` has no key to sign with.
#[derive(Debug)]
pub enum RingError {
    /// store@ cannot be reached, or the ring could not be written after the attempts.
    Store,
    /// key@ gave no usable key.
    Key(KeyError),
    /// The key that key@ signs with is not an active key of the ring: it is still being published
    /// (or it is not one of the states that sign).
    NotActive,
    /// `KeyRevocation` lists the key that key@ signs with: it signs nothing more (REQ-KEYS-106).
    Revoked,
}

/// What `signer` knows of one key of the ring a moment ago.
#[derive(Clone)]
struct Slot {
    current: Current,
    /// The key is an active key of the ring.
    active: bool,
    /// `KeyRevocation` listed the key when the snapshot was made.
    revoked: bool,
    /// Until when `entry`'s key set may lack the key, when the ring holds a revoked key and this one is
    /// new: the key does not sign before then. `None` when it is not held, or the time has passed.
    hold_until: Option<SystemTime>,
}

/// What `signer` knows of the ring a moment ago: the key key@ signs with for each algorithm. The RS256 key is there only
/// while the KeyPlan lists its purpose and key@ gave the key; an algorithm with no slot signs nothing.
#[derive(Clone)]
struct Snapshot {
    at: SystemTime,
    es384: Slot,
    rs256: Option<Slot>,
}

impl Snapshot {
    fn slot(&self, alg: Alg) -> Option<&Slot> {
        match alg {
            Alg::Es384 => Some(&self.es384),
            Alg::Rs256 => self.rs256.as_ref(),
        }
    }

    fn hold_until(&self) -> Option<SystemTime> {
        self.es384
            .hold_until
            .into_iter()
            .chain(self.rs256.as_ref().and_then(|r| r.hold_until))
            .max()
    }
}

/// How long the KeyPlan may omit the RS256 purpose before the node's RS256 keys stop. A key that stopped does not come back
/// (a retiring key never signs again), so one write of the KeyPlan that forgot the purpose must not end the key: for this
/// long the algorithm is not offered (nothing signs with RS256) and the key stays as it is, and a KeyPlan that lists the
/// purpose again within it finds the key active.
///
/// The time since the omission is kept in memory: a restart of `signer` begins the grace again, and the key stays `active` in
/// the ring, published, for as long as that takes. Nothing signs with it meanwhile (the algorithm is not offered).
pub const RS256_OFF_GRACE: Duration = Duration::from_secs(60 * 60);
/// How long `signer` leaves key@ alone after key@ refused the RS256 purpose as one its KeyPlan does not list: a minute at first,
/// when the KeyPlan was published a moment before key@ restarts onto it (the normal order), then twice as long after each refusal,
/// up to an hour. key@ audits each refusal, and an idle installation writes at most 60 records an hour (REQ-AUDIT-180): the
/// schedule makes 7 in the first two hours and 1 an hour after.
pub const RS256_RETRY_FIRST: Duration = Duration::from_secs(60);
/// The longest of those waits.
pub const RS256_RETRY: Duration = Duration::from_secs(60 * 60);

/// What the KeyPlan and key@ say of the RS256 key at a reconcile.
enum Rs256 {
    /// The KeyPlan has not listed the purpose for [`RS256_OFF_GRACE`]: the node's RS256 keys stop and the algorithm is not
    /// offered.
    Off,
    /// The KeyPlan or key@ could not be read, or key@ gave a key that is not an RS256 key: nothing is planned for the
    /// algorithm this time and nothing signs with it. The other algorithm is not touched.
    Unknown,
    /// The purpose is listed, and this is the key key@ signs with.
    On(Current),
}

/// The manager of the ring: reads it, plans, writes with the version guard, and says which key may
/// sign.
pub struct RingKeeper {
    store: Store<RingKind>,
    reports: Store<ReportKind>,
    manifests: Store<ManifestKind>,
    revocations: KeyRevocations,
    key_plan: Store<KeyPlanKind>,
    /// Since when the KeyPlan has not listed the RS256 purpose, as `signer` has seen it; `None` while it lists it.
    rs256_off_since: Mutex<Option<SystemTime>>,
    /// Until when `signer` does not ask key@ for the RS256 key, after key@ refused the purpose, and the wait it used.
    rs256_retry: Mutex<(Option<SystemTime>, Duration)>,
    key: Arc<KeyAt>,
    audit: Arc<Auditor>,
    clock: Clock,
    timing: Timing,
    node: String,
    snapshot: Mutex<Option<Snapshot>>,
}

impl RingKeeper {
    /// A keeper over store@'s socket.
    ///
    /// # Errors
    ///
    /// When the kind is not in the registry.
    pub fn new(
        store: &Client,
        key: Arc<KeyAt>,
        audit: Arc<Auditor>,
        clock: Clock,
        timing: Timing,
        node: String,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            store: Store::new(store.clone())?,
            reports: Store::new(store.clone())?,
            manifests: Store::new(store.clone())?,
            revocations: KeyRevocations::new(store)?,
            key_plan: Store::new(store.clone())?,
            rs256_off_since: Mutex::new(None),
            rs256_retry: Mutex::new((None, Duration::ZERO)),
            key,
            audit,
            clock,
            timing,
            node,
            snapshot: Mutex::new(None),
        })
    }

    /// The key key@ signs with for an algorithm, once it is an active key of the ring. The ring is looked at again
    /// when the last look is older than ten seconds, so a key that was retired or promoted is
    /// noticed within that time. There is no key of an algorithm that is not enabled or has none active, and then the
    /// answer is [`RingError::NotActive`]: the other algorithm is never offered in its place.
    ///
    /// # Errors
    ///
    /// [`RingError`]; `signer` signs nothing then.
    pub async fn signing_key(&self, alg: Alg) -> Result<Current, RingError> {
        // The guard is held only to read or to refresh the snapshot, never across the store call below: a slow
        // `KeyRevocation` must not queue every other caller behind it.
        let snap = {
            let mut guard = self.snapshot.lock().await;
            let now = (self.clock)();
            let fresh = guard
                .as_ref()
                .filter(|s| now.duration_since(s.at).is_ok_and(|age| age < REFRESH))
                // A held snapshot is looked at again once the hold is over.
                .filter(|s| s.hold_until().is_none_or(|h| now < h));
            match fresh {
                Some(s) => s.clone(),
                None => {
                    let s = self.reconcile_locked().await?;
                    *guard = Some(s.clone());
                    s
                }
            }
        };
        let Some(slot) = snap.slot(alg) else {
            return Err(RingError::NotActive);
        };
        // A key that `KeyRevocation` lists is revoked, whatever else is true of it.
        if slot.revoked {
            return Err(RingError::Revoked);
        }
        if !slot.active {
            return Err(RingError::NotActive);
        }
        // The key joined the ring a moment ago, after a revocation: the key set that `entry` serves may
        // not list it yet, and no token is signed before it does.
        if slot.hold_until.is_some_and(|h| (self.clock)() < h) {
            return Err(RingError::NotActive);
        }
        // The snapshot is up to ten seconds old, and a revocation must stop a signature at once: ask for the key's own
        // revocation at every call, and refuse when it cannot be read in time (fail closed). It is the index `by_target`,
        // one linearizable listing of at most one item, and not a `Get` of the key's item or a walk over the kind: store@
        // audits every refusal, so a `Get` of an item that is absent, the normal case, would write one record for every
        // token (ADR 0005, REQ-AUDIT-180), and a walk over a kind that only grows would one day outlast the call's time
        // and stop every token. An item with no entry in the index (one that an older `key@` wrote) is seen by the
        // snapshot's full listing within ten seconds, as it is for `key@` (revocation.go, unindexedSet).
        match tokio::time::timeout(
            CALL,
            self.revocations.is_revoked_by_index(&slot.current.key_id),
        )
        .await
        {
            Ok(Ok(true)) => Err(RingError::Revoked),
            Ok(Ok(false)) => Ok(slot.current.clone()),
            _ => Err(RingError::Store),
        }
    }

    /// Brings the ring in line with key@'s key and the clock, now. The loop of the service calls it,
    /// so a boundary with no traffic still promotes and drops keys on time.
    ///
    /// # Errors
    ///
    /// [`RingError`].
    pub async fn reconcile(&self) -> Result<(), RingError> {
        let mut guard = self.snapshot.lock().await;
        *guard = Some(self.reconcile_locked().await?);
        Ok(())
    }

    /// The ring as store@ holds it (empty when none was written), without the keys that
    /// `KeyRevocation` lists: the ring that the key set is built from (REQ-KEYS-107).
    ///
    /// # Errors
    ///
    /// [`RingError::Store`], also when `KeyRevocation` cannot be read: a key set that might list a
    /// revoked key is not served.
    pub async fn read(&self) -> Result<SigningRing, RingError> {
        let ring = match tokio::time::timeout(CALL, self.store.get("", ID)).await {
            Ok(Ok(item)) => item.value,
            Ok(Err(StoreError::NotFound)) => SigningRing::default(),
            _ => return Err(RingError::Store),
        };
        let revoked = self.revoked().await?;
        Ok(without_revoked(ring, &revoked))
    }

    /// The kids that `KeyRevocation` lists.
    async fn revoked(&self) -> Result<HashSet<String>, RingError> {
        match tokio::time::timeout(CALL, self.revocations.revoked_kids()).await {
            Ok(Ok(kids)) => Ok(kids),
            _ => Err(RingError::Store),
        }
    }

    /// What the manifest and the reports of `exporter@` say about the static key sets now. It lists, linearizable, and
    /// does not `Get`: no manifest is the normal state of an installation without a public destination, and a `Get` of
    /// an absent item is a refusal that store@ audits (REQ-AUDIT-180). The reports are read only when the manifest
    /// counts an entry. A listing that fails is a doubt, and a doubt holds activation ([`Publication::held`]); it never
    /// fails the reconcile, which must go on to keep the ring and the signing key (REQ-KEYS-116).
    async fn publication(&self, now: SystemTime) -> Publication {
        match self.read_publication(now).await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!(
                    alert = "signer-publication-unreadable",
                    "the manifest or the reports of the static key set cannot be read: no key becomes active"
                );
                Publication::held()
            }
        }
    }

    async fn read_publication(&self, now: SystemTime) -> Result<Publication, RingError> {
        let mut manifest = None;
        let mut page = None;
        for _ in 0..100 {
            let (items, next) = match tokio::time::timeout(
                CALL,
                self.manifests.list_linearizable("", page),
            )
            .await
            {
                Ok(Ok(r)) => r,
                _ => return Err(RingError::Store),
            };
            if let Some(i) = items.into_iter().find(|i| i.id == ID) {
                manifest = Some(i.value);
            }
            match next {
                Some(n) => page = Some(n),
                None => break,
            }
        }
        let Some(manifest) = manifest else {
            return Ok(Publication::of(None, &[], now));
        };
        if !manifest
            .entries
            .iter()
            .any(|e| e.kind == KEY_SET && e.public)
        {
            return Ok(Publication::of(Some(&manifest), &[], now));
        }
        let mut all = Vec::new();
        let mut page = None;
        for _ in 0..100 {
            let (items, next) =
                match tokio::time::timeout(CALL, self.reports.list_linearizable("", page)).await {
                    Ok(Ok(r)) => r,
                    _ => return Err(RingError::Store),
                };
            all.extend(items.into_iter().map(|i| (i.id, i.value)));
            match next {
                Some(n) => page = Some(n),
                None => return Ok(Publication::of(Some(&manifest), &all, now)),
            }
        }
        Err(RingError::Store)
    }

    /// The plan for this moment. What the manifest and the reports say matters only to a key that is about to become
    /// active, so they are read only then: the plan is made as if nothing were reported. A report can only hold a key
    /// back: the read back it names comes after the key joined the ring, so the real plan activates a key no sooner than
    /// this one does, up to the difference between the clocks of the two hosts (which can only delay it). When this plan
    /// activates none, the real plan activates none, and nothing is read. An
    /// installation with no exporter, or one whose store@ cannot answer for the reports, signs as before until a key
    /// needs the answer; then a doubt holds the key ([`Publication::held`]) and the reconcile goes on.
    async fn plan(
        &self,
        ring: &SigningRing,
        cur: &Current,
        now: SystemTime,
        revoked: &HashSet<String>,
    ) -> (SigningRing, Vec<Change>) {
        let first = plan_with(
            ring,
            cur,
            &self.node,
            now,
            &self.timing,
            revoked,
            &Publication::Unreported,
        );
        let activates = first
            .1
            .iter()
            .any(|c| matches!(c.kind, ChangeKind::Activated | ChangeKind::Added(ACTIVE)));
        if !activates {
            return first;
        }
        let publication = self.publication(now).await;
        if publication == Publication::Unreported {
            return first;
        }
        plan_with(
            ring,
            cur,
            &self.node,
            now,
            &self.timing,
            revoked,
            &publication,
        )
    }

    /// Whether the KeyPlan lists the RS256 purpose, and the key key@ signs with when it does. The KeyPlan is read, and
    /// key@ is asked for the RS256 key only when the purpose is listed: an installation without the purpose never sends
    /// key@ a request that it would refuse and audit (REQ-AUDIT-180). Whatever goes wrong here concerns the RS256 key
    /// alone; the reconcile of the ES384 key goes on (REQ-KEYS-270).
    async fn rs256(&self) -> Rs256 {
        let now = (self.clock)();
        let listed = match tokio::time::timeout(CALL, self.key_plan.get("", ID)).await {
            Ok(Ok(item)) => item
                .value
                .purposes
                .iter()
                .any(|p| p.purpose == Alg::Rs256.purpose() && p.algorithm == Alg::Rs256.name()),
            // No KeyPlan, or none that can be read, is a doubt and not "unlisted": the RS256 keys are not retired on it.
            _ => {
                tracing::warn!(
                    alert = "signer-keyplan-unreadable",
                    "the KeyPlan cannot be read: the RS256 key is left as it is"
                );
                return Rs256::Unknown;
            }
        };
        let mut off_since = self.rs256_off_since.lock().await;
        if !listed {
            // Not offered meanwhile, and the key is left alone until the purpose has been out for the grace.
            let since = *off_since.get_or_insert(now);
            return if now
                .duration_since(since)
                .is_ok_and(|d| d >= RS256_OFF_GRACE)
            {
                Rs256::Off
            } else {
                Rs256::Unknown
            };
        }
        *off_since = None;
        drop(off_since);
        let mut retry = self.rs256_retry.lock().await;
        if retry.0.is_some_and(|at| now < at) {
            return Rs256::Unknown;
        }
        match self.key.current(Alg::Rs256).await {
            Ok(cur) => {
                *retry = (None, Duration::ZERO);
                Rs256::On(cur)
            }
            Err(KeyError::NotPlanned) => {
                let gap = if retry.1.is_zero() {
                    RS256_RETRY_FIRST
                } else {
                    (retry.1 * 2).min(RS256_RETRY)
                };
                *retry = (Some(now + gap), gap);
                Rs256::Unknown
            }
            Err(e) => {
                tracing::warn!(alert = "signer-rs256-key-unavailable", error = ?e, "key@ gave no RS256 key: nothing signs with RS256");
                Rs256::Unknown
            }
        }
    }

    async fn reconcile_locked(&self) -> Result<Snapshot, RingError> {
        for _ in 0..ATTEMPTS {
            let cur = self.key.current(Alg::Es384).await.map_err(RingError::Key)?;
            let rs = self.rs256().await;
            let (ring, version) = match tokio::time::timeout(CALL, self.store.get("", ID)).await {
                Ok(Ok(item)) => (item.value, item.version),
                Ok(Err(StoreError::NotFound)) => (SigningRing::default(), 0),
                _ => return Err(RingError::Store),
            };
            let revoked = self.revoked().await?;
            let now = (self.clock)();
            let (mut next, mut changes) = self.plan(&ring, &cur, now, &revoked).await;
            match &rs {
                Rs256::On(r) => {
                    let (n, c) = self.plan(&next, r, now, &revoked).await;
                    (next, changes) = (n, [changes, c].concat());
                }
                Rs256::Off => {
                    let (n, c) =
                        plan_disabled(&next, Alg::Rs256, &self.node, now, &self.timing, &revoked);
                    (next, changes) = (n, [changes, c].concat());
                }
                Rs256::Unknown => {}
            }
            let rs_cur = match rs {
                Rs256::On(r) => Some(r),
                Rs256::Off | Rs256::Unknown => None,
            };
            if changes.is_empty() {
                return Ok(snapshot(&ring, cur, rs_cur, now, &revoked));
            }
            let written = if version == 0 {
                self.store.create("", ID, &next, WriteOpts::default()).await
            } else {
                self.store
                    .update("", ID, &next, version, WriteOpts::default())
                    .await
            };
            match written {
                Ok(_) => {
                    for c in &changes {
                        // The ring is public material and key@ audits every signature, so a fact
                        // the log could not take is logged and counted, and the change stays.
                        if self.audit.ring(c).await.is_err() {
                            tracing::error!(key_id = %c.key_id, "the audit of a change of the ring failed");
                        }
                    }
                    return Ok(snapshot(&next, cur, rs_cur, now, &revoked));
                }
                // Another instance wrote first: read again and plan again.
                Err(StoreError::Exists | StoreError::Version) => {}
                Err(_) => return Err(RingError::Store),
            }
        }
        Err(RingError::Store)
    }
}

fn slot(ring: &SigningRing, current: Current, at: SystemTime, revoked: &HashSet<String>) -> Slot {
    let active = ring
        .keys
        .iter()
        .any(|k| k.key_id == current.key_id && k.state == ACTIVE);
    // The hold is only for a ring that holds a revoked key: the first keys of a first deploy sign at
    // once, as nothing has seen a token yet. A key that waited for the lead time is long past it.
    // Only the keys of the key's own algorithm count: a revoked ES384 key does not hold an RS256 key, nor the reverse.
    let hold_until = ring
        .keys
        .iter()
        .filter(|k| is_alg(k, current.alg))
        .any(|k| revoked.contains(&k.key_id))
        .then(|| {
            ring.keys
                .iter()
                .find(|k| k.key_id == current.key_id && k.state == ACTIVE)
                .and_then(|k| instant(k.added_at.as_option()))
                .map(|added| added + KEY_SET_HOLD)
        })
        .flatten()
        .filter(|h| *h > at);
    if ring
        .keys
        .iter()
        .any(|k| k.key_id == current.key_id && k.state == DROPPED)
    {
        // key@ signs with a key that left the key set; nothing signs until key@ has another (REQ-KEYS-079). There is no
        // way back for that key, a key restored from a backup included: make a new key at key@.
        tracing::error!(
            alert = "signer-key-dropped",
            key_id = %current.key_id,
            "the key that key@ signs with was dropped from the key set and will not come back: nothing signs until key@ has a new key (a restored key is blocked too: make a new one)"
        );
    }
    let revoked = revoked.contains(&current.key_id);
    Slot {
        current,
        active,
        revoked,
        hold_until,
    }
}

fn snapshot(
    ring: &SigningRing,
    es384: Current,
    rs256: Option<Current>,
    at: SystemTime,
    revoked: &HashSet<String>,
) -> Snapshot {
    Snapshot {
        at,
        es384: slot(ring, es384, at, revoked),
        rs256: rs256.map(|c| slot(ring, c, at, revoked)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60;
    const HOUR: u64 = 3600;
    const WINDOW: u64 = 30 * MIN;
    const A: &str = "node-a";
    const B: &str = "node-b";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }
    fn cur(id: &str) -> Current {
        Current {
            alg: Alg::Es384,
            key_id: id.into(),
            spki_der: vec![1, 2, 3],
            x5c: vec![],
            x5c_withdrawn: false,
        }
    }
    /// The keys that are in the key set or about to be: the tombstones of dropped keys are not.
    fn states(r: &SigningRing) -> Vec<(&str, &str)> {
        r.keys
            .iter()
            .filter(|k| k.state != DROPPED)
            .map(|k| (k.key_id.as_str(), k.state.as_str()))
            .collect()
    }
    fn added(id: &str, kind: ChangeKind) -> Change {
        Change {
            key_id: id.into(),
            alg: Alg::Es384,
            kind,
            reason: None,
        }
    }
    /// [`added`] for an RS256 key.
    fn rs(c: Change) -> Change {
        Change {
            alg: Alg::Rs256,
            ..c
        }
    }
    /// A change that skipped the lead time because no key of the issuer signed.
    fn skipped(id: &str, kind: ChangeKind) -> Change {
        Change {
            reason: Some(NO_ACTIVE_KEY),
            ..added(id, kind)
        }
    }
    const T: Timing = Timing::DEFAULT;

    /// Runs `signer` of `node`, whose key@ signs with `id`, at `secs`, and returns the ring.
    fn step(ring: &SigningRing, node: &str, id: &str, secs: u64) -> (SigningRing, Vec<Change>) {
        plan(ring, &cur(id), node, at(secs), &T, &HashSet::new())
    }

    fn revoked(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|i| (*i).to_owned()).collect()
    }

    fn chain(n: u8) -> Vec<Vec<u8>> {
        vec![vec![n, 1], vec![n, 2]]
    }

    /// The chain of a node's own key joins the ring when key@ has one, and follows a certificate made again; an empty answer
    /// leaves the chain; another node's chain and a revoked key's are not touched.
    /// verifies: REQ-PKI-034
    #[test]
    fn the_chain_of_the_nodes_own_key_follows_what_key_gives() {
        let (r0, _) = step(&SigningRing::default(), A, "a", 0);
        assert!(r0.keys[0].x5c.is_empty());
        let with = |c: Vec<Vec<u8>>| Current { x5c: c, ..cur("a") };
        let (r1, ch) = plan(&r0, &with(chain(1)), A, at(10), &T, &HashSet::new());
        assert_eq!(r1.keys[0].x5c, chain(1));
        assert_eq!(ch, [added("a", ChangeKind::Certified(ACTIVE))]);
        // The same chain again changes nothing; an empty one leaves the chain.
        let (r2, ch) = plan(&r1, &with(chain(1)), A, at(20), &T, &HashSet::new());
        assert!(ch.is_empty());
        let (r3, ch) = plan(&r2, &with(vec![]), A, at(30), &T, &HashSet::new());
        assert!(ch.is_empty());
        assert_eq!(r3.keys[0].x5c, chain(1));
        // A certificate made again replaces it.
        let (r4, ch) = plan(&r3, &with(chain(2)), A, at(40), &T, &HashSet::new());
        assert_eq!(r4.keys[0].x5c, chain(2));
        assert_eq!(ch, [added("a", ChangeKind::Certified(ACTIVE))]);
        // Another node's signer does not write the chain of a key that is not its own.
        let (r5, ch) = plan(&r4, &with(chain(3)), B, at(50), &T, &HashSet::new());
        assert_eq!(r5.keys[0].x5c, chain(2));
        assert!(
            ch.iter()
                .all(|c| !matches!(c.kind, ChangeKind::Certified(_)))
        );
        // A revoked key's chain is not taken.
        let (r6, ch) = plan(&r4, &with(chain(4)), A, at(60), &T, &revoked(&["a"]));
        assert_eq!(r6.keys[0].x5c, chain(2));
        assert!(
            ch.iter()
                .all(|c| !matches!(c.kind, ChangeKind::Certified(_)))
        );
    }

    /// A chain that key@ withdraws on purpose (the certificate ended, the intermediate is revoked) leaves the ring; an empty
    /// answer that is not a withdrawal (none yet, or key@ could not tell) leaves what the ring has; another node's chain and a
    /// revoked key's are not touched.
    /// verifies: REQ-PKI-034
    #[test]
    fn a_chain_key_withdraws_leaves_the_ring_and_an_empty_answer_does_not() {
        let with = |c: Vec<Vec<u8>>, withdrawn: bool| Current {
            x5c: c,
            x5c_withdrawn: withdrawn,
            ..cur("a")
        };
        let (r0, _) = step(&SigningRing::default(), A, "a", 0);
        let (r1, _) = plan(&r0, &with(chain(1), false), A, at(10), &T, &HashSet::new());
        assert_eq!(r1.keys[0].x5c, chain(1));
        // None yet / could not tell: kept.
        let (r2, ch) = plan(&r1, &with(vec![], false), A, at(20), &T, &HashSet::new());
        assert_eq!(r2.keys[0].x5c, chain(1));
        assert!(ch.is_empty());
        // Another node's key: not ours to change.
        let (r3, ch) = plan(&r1, &with(vec![], true), B, at(30), &T, &HashSet::new());
        assert_eq!(r3.keys[0].x5c, chain(1));
        assert!(
            ch.iter()
                .all(|c| !matches!(c.kind, ChangeKind::Uncertified(_)))
        );
        // Withdrawn: dropped, once.
        let (r4, ch) = plan(&r1, &with(vec![], true), A, at(40), &T, &HashSet::new());
        assert!(r4.keys[0].x5c.is_empty());
        assert_eq!(ch, [added("a", ChangeKind::Uncertified(ACTIVE))]);
        let (_, ch) = plan(&r4, &with(vec![], true), A, at(50), &T, &HashSet::new());
        assert!(ch.is_empty(), "a chain that is gone is not dropped again");
        // And it comes back when key@ gives one again.
        let (r5, _) = plan(&r4, &with(chain(2), false), A, at(60), &T, &HashSet::new());
        assert_eq!(r5.keys[0].x5c, chain(2));
    }

    /// verifies: REQ-KEYS-079, REQ-KEYS-106
    #[test]
    fn a_revoked_key_is_never_added_to_the_ring() {
        let (r, ch) = plan(
            &SigningRing::default(),
            &cur("a"),
            A,
            at(1000),
            &T,
            &revoked(&["a"]),
        );
        assert!(r.keys.is_empty());
        assert!(ch.is_empty());
    }

    /// verifies: REQ-KEYS-079, REQ-KEYS-106
    #[test]
    fn a_revoked_key_is_never_promoted_even_when_its_window_is_over() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let due = 2000 + WINDOW;
        let (r2, ch) = plan(&r, &cur("a2"), A, at(due), &T, &revoked(&["a2"]));
        assert!(
            ch.is_empty(),
            "the owner node promoted a revoked key: {ch:?}"
        );
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        // Nor does the revoked key stop the key that is signing.
        let (r3, ch) = plan(&r, &cur("a2"), A, at(due), &T, &revoked(&[]));
        assert_eq!(states(&r3), [("a", RETIRING), ("a2", ACTIVE)]);
        assert_eq!(ch.len(), 2);
    }

    /// verifies: REQ-KEYS-106
    #[test]
    fn a_revoked_active_key_does_not_retire_the_nodes_other_keys() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        // key@ is back on `a`, which is active and revoked: the plan leaves the ring alone.
        let (r2, ch) = plan(&r, &cur("a"), A, at(2000 + WINDOW), &T, &revoked(&["a"]));
        assert!(ch.is_empty());
        assert_eq!(r2, r);
    }

    /// A ring that is long past its first deploy, with `a` the only key of A, active.
    fn old_ring_of_one() -> SigningRing {
        step(&SigningRing::default(), A, "a", 1000).0
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn the_replacement_of_the_only_key_signs_at_once_when_that_key_is_revoked() {
        let r = old_ring_of_one();
        let now = 1000 + 30 * HOUR;
        let (r2, ch) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["a"]));
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", ACTIVE)]);
        assert_eq!(ch, [skipped("a2", ChangeKind::Added(ACTIVE))]);
        // The revoked entry is left as it is: its state is the item of `KeyRevocation`.
        assert_eq!(r2.keys[0], r.keys[0]);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn the_replacement_signs_at_once_even_in_the_first_minutes_of_the_ring() {
        // The ring is a minute old, so it is young, but the node already has a key, the revoked one:
        // `first_of_node` is false for a2, so the first-deploy rule does not apply. The rule that
        // holds here is that no live key signs.
        let r = old_ring_of_one();
        let (r2, _) = plan(&r, &cur("a2"), A, at(1000 + MIN), &T, &revoked(&["a"]));
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", ACTIVE)]);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn a_pre_published_key_activates_at_once_when_the_active_key_is_revoked() {
        // a2 was published a minute ago for a rotation, then a was revoked: a2 signs now.
        let (r, _) = step(&old_ring_of_one(), A, "a2", 5000);
        assert_eq!(states(&r), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        let (r2, ch) = plan(&r, &cur("a2"), A, at(5000 + MIN), &T, &revoked(&["a"]));
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", ACTIVE)]);
        assert_eq!(ch, [skipped("a2", ChangeKind::Activated)]);
        // Without the revocation it waits for the window.
        let (r3, ch) = step(&r, A, "a2", 5000 + MIN);
        assert!(ch.is_empty());
        assert_eq!(r3, r);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn the_replacement_retires_the_nodes_other_live_keys_but_leaves_the_revoked_one() {
        let (r, _) = step(&old_ring_of_one(), A, "a2", 5000);
        let (r, _) = step(&r, A, "a3", 5001);
        // a is revoked and a2 is a live spare; a3 signs at once and a2 stops, a stays as it is.
        let (r2, ch) = plan(&r, &cur("a3"), A, at(6000), &T, &revoked(&["a"]));
        assert_eq!(
            states(&r2),
            [("a", ACTIVE), ("a2", RETIRING), ("a3", ACTIVE)]
        );
        assert_eq!(
            ch,
            [
                skipped("a3", ChangeKind::Activated),
                added("a2", ChangeKind::Retired)
            ]
        );
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-106
    #[test]
    fn a_revoked_replacement_never_signs_at_once() {
        let r = old_ring_of_one();
        let (r2, ch) = plan(
            &r,
            &cur("a2"),
            A,
            at(1000 + 30 * HOUR),
            &T,
            &revoked(&["a", "a2"]),
        );
        assert!(ch.is_empty());
        assert_eq!(r2, r);
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-076
    #[test]
    fn a_node_with_a_revoked_key_waits_for_the_window_while_another_node_signs() {
        // Both boards have a key, long after the first deploy. A's key is revoked: the issuer still
        // signs with B's key, which every verifier has, so A's replacement is published first.
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000);
        let now = 2 * HOUR;
        let (r2, ch) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["a"]));
        assert_eq!(
            states(&r2),
            [("a", ACTIVE), ("b", ACTIVE), ("a2", PRE_PUBLISHED)]
        );
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        let (r3, ch) = plan(
            &r2,
            &cur("a2"),
            A,
            at(now + WINDOW - 1),
            &T,
            &revoked(&["a"]),
        );
        assert!(ch.is_empty());
        assert_eq!(r3, r2);
        let (r4, _) = plan(&r2, &cur("a2"), A, at(now + WINDOW), &T, &revoked(&["a"]));
        assert_eq!(states(&r4), [("a", ACTIVE), ("b", ACTIVE), ("a2", ACTIVE)]);
        // When B's key is revoked too, nothing signs, and A's replacement signs at once.
        let (r5, _) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["a", "b"]));
        assert_eq!(r5.keys[2].state, ACTIVE);
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-076
    #[test]
    fn a_normal_rotation_and_a_revoked_spare_still_wait_for_the_window() {
        let r = old_ring_of_one();
        let now = 1000 + 30 * HOUR;
        // No revocation at all.
        let (r2, _) = step(&r, A, "a2", now);
        assert_eq!(states(&r2), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        // A revoked entry of another state, or of another node, that is not the live active key.
        let mut ring = r.clone();
        ring.keys.push(SigningKey {
            key_id: "old".into(),
            state: RETIRING.into(),
            node: A.into(),
            ..SigningKey::default()
        });
        ring.keys.push(SigningKey {
            key_id: "spare".into(),
            state: PRE_PUBLISHED.into(),
            node: B.into(),
            ..SigningKey::default()
        });
        let (r3, ch) = plan(
            &ring,
            &cur("a2"),
            A,
            at(now),
            &T,
            &revoked(&["old", "spare"]),
        );
        assert_eq!(r3.keys[3].state, PRE_PUBLISHED);
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        // The live active key is revoked for an unrelated kid only: the window stands.
        let (r4, _) = plan(&r, &cur("a2"), A, at(now), &T, &revoked(&["unrelated"]));
        assert_eq!(states(&r4), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        let (r5, ch) = plan(
            &r4,
            &cur("a2"),
            A,
            at(now + WINDOW - 1),
            &T,
            &revoked(&["unrelated"]),
        );
        assert!(ch.is_empty());
        assert_eq!(r5, r4);
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn a_key_in_a_state_this_code_does_not_know_counts_as_signing() {
        // A rolling upgrade or downgrade: a state of another version must not skip the lead time.
        let mut r = old_ring_of_one();
        r.keys[0].state = "signing-v2".into();
        let (r2, ch) = step(&r, A, "a2", 1000 + 30 * HOUR);
        assert_eq!(r2.keys[1].state, PRE_PUBLISHED);
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        // Revoked, it counts for nothing, as an active key would.
        let (r3, _) = plan(
            &r,
            &cur("a2"),
            A,
            at(1000 + 30 * HOUR),
            &T,
            &revoked(&["a"]),
        );
        assert_eq!(r3.keys[1].state, ACTIVE);
        // Known non-signing states alone leave nothing that signs.
        r.keys[0].state = RETIRING.into();
        let (r4, ch) = step(&r, A, "a2", 1000 + 10 * MIN);
        assert_eq!(states(&r4), [("a", RETIRING), ("a2", ACTIVE)]);
        assert_eq!(ch, [skipped("a2", ChangeKind::Added(ACTIVE))]);
    }

    /// verifies: REQ-KEYS-089, REQ-KEYS-080
    #[test]
    fn only_a_change_that_skips_the_lead_time_names_the_reason() {
        // The first keys of a first deploy are not a skipped lead time.
        let (r, ch) = step(&SigningRing::default(), A, "a", 1000);
        assert_eq!(ch, [added("a", ChangeKind::Added(ACTIVE))]);
        // A normal rotation neither.
        let (r, ch) = step(&r, A, "a2", 1000 + 30 * HOUR);
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        let (_, ch) = step(&r, A, "a2", 1000 + 31 * HOUR);
        assert_eq!(
            ch,
            [
                added("a2", ChangeKind::Activated),
                added("a", ChangeKind::Retired)
            ]
        );
    }

    /// verifies: REQ-KEYS-089
    #[test]
    fn two_nodes_with_every_key_revoked_converge_on_one_active_replacement() {
        // The signers look one after the other, each with the ring the other wrote. A's replacement
        // is active, so B's sees a key that signs and waits for the window: a ring with two nodes,
        // each of which would go on alone, does not end with both skipping it.
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000);
        let all = revoked(&["a", "b"]);
        let now = 2 * HOUR;
        let (r, ch) = plan(&r, &cur("a2"), A, at(now), &T, &all);
        assert_eq!(ch, [skipped("a2", ChangeKind::Added(ACTIVE))]);
        let (r, ch) = plan(&r, &cur("b2"), B, at(now), &T, &all);
        assert_eq!(
            states(&r),
            [
                ("a", ACTIVE),
                ("b", ACTIVE),
                ("a2", ACTIVE),
                ("b2", PRE_PUBLISHED)
            ]
        );
        assert_eq!(ch, [added("b2", ChangeKind::Added(PRE_PUBLISHED))]);
        // B's replacement is promoted after its window, like any other.
        let (r, _) = plan(&r, &cur("b2"), B, at(now + WINDOW), &T, &all);
        assert_eq!(r.keys[3].state, ACTIVE);
    }

    #[test]
    fn the_window_is_the_cache_budget_of_the_key_set() {
        // 300 s of max-age + 300 s of edge time to live + 10 minutes of refetch + 5 minutes of
        // skew is 25 minutes, rounded up to 30 (ADR 0006 "Rotation").
        let derived = Duration::from_secs(300 + 300 + 10 * 60 + 5 * 60);
        assert!(T.prepublish >= derived);
        assert_eq!(T.prepublish, Duration::from_secs(30 * MIN));
        assert_eq!(T.retain, Duration::from_secs(65 * MIN));
    }

    #[test]
    fn the_first_key_of_a_boundary_is_active_at_once_and_names_its_node() {
        let (r, ch) = step(&SigningRing::default(), A, "a", 1000);
        assert_eq!(states(&r), [("a", ACTIVE)]);
        assert_eq!(ch, [added("a", ChangeKind::Added(ACTIVE))]);
        assert_eq!(r.keys[0].algorithm, "ES384");
        assert_eq!(r.keys[0].spki_der, [1, 2, 3]);
        assert_eq!(r.keys[0].node, A);
    }

    /// verifies: REQ-KEYS-080
    #[test]
    fn the_boards_of_a_first_deploy_each_activate_their_first_key_at_once() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000 + 5 * MIN);
        let (r, _) = step(&r, "node-c", "c", 1000 + 14 * MIN);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", ACTIVE), ("c", ACTIVE)]);
    }

    /// verifies: REQ-KEYS-080
    #[test]
    fn a_board_that_joins_after_the_first_deploy_is_published_for_the_full_window() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, ch) = step(&r, B, "b", 1000 + 15 * MIN);
        assert_eq!(states(&r), [("a", ACTIVE), ("b", PRE_PUBLISHED)]);
        assert_eq!(ch, [added("b", ChangeKind::Added(PRE_PUBLISHED))]);
        let joined = 1000 + 15 * MIN;
        let (r2, ch) = step(&r, B, "b", joined + WINDOW - 1);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
        let (r3, ch) = step(&r, B, "b", joined + WINDOW);
        assert_eq!(states(&r3), [("a", ACTIVE), ("b", ACTIVE)]);
        assert_eq!(ch, [added("b", ChangeKind::Activated)]);
    }

    #[test]
    fn nothing_changes_when_nothing_is_due() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r2, ch) = step(&r, A, "a", 1000 + 30 * HOUR);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
    }

    /// verifies: REQ-KEYS-076, REQ-KEYS-085
    #[test]
    fn a_new_key_of_a_node_is_published_for_the_window_before_it_signs() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        // Even in the first minutes: a replacement key is never a first key.
        let (r, ch) = step(&r, A, "a2", 2000);
        assert_eq!(states(&r), [("a", ACTIVE), ("a2", PRE_PUBLISHED)]);
        assert_eq!(ch.len(), 1);
        let (r2, ch) = step(&r, A, "a2", 2000 + WINDOW - 1);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
        // At the window: it signs, and the node's old key stops.
        let (r3, ch) = step(&r, A, "a2", 2000 + WINDOW);
        assert_eq!(states(&r3), [("a", RETIRING), ("a2", ACTIVE)]);
        assert_eq!(
            ch,
            [
                added("a2", ChangeKind::Activated),
                added("a", ChangeKind::Retired)
            ]
        );
    }

    /// verifies: REQ-KEYS-007, REQ-KEYS-078
    #[test]
    fn a_retired_key_stays_for_a_token_lifetime_plus_the_skew_and_then_leaves() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let retired_at = 2000 + WINDOW;
        let (r, _) = step(&r, A, "a2", retired_at);
        let keep = 65 * MIN;
        let (r2, ch) = step(&r, A, "a2", retired_at + keep - 1);
        assert!(ch.is_empty(), "a token it signed may still be valid");
        assert_eq!(states(&r2), [("a", RETIRING), ("a2", ACTIVE)]);
        let (r3, ch) = step(&r, A, "a2", retired_at + keep);
        assert_eq!(states(&r3), [("a2", ACTIVE)]);
        assert_eq!(ch, [added("a", ChangeKind::Dropped)]);
    }

    #[test]
    fn a_retiring_key_never_signs_again() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let (r, _) = step(&r, A, "a2", 2000 + WINDOW);
        // key@ goes back to a, which is retiring: it stays retiring, and nothing else changes.
        let (r2, ch) = step(&r, A, "a", 2000 + WINDOW + MIN);
        assert!(ch.is_empty());
        assert_eq!(states(&r2), [("a", RETIRING), ("a2", ACTIVE)]);
    }

    /// A retiring key stays retiring, in the ring and so in the key set, until the retention drops it, however often
    /// and from whichever node key@ is asked to sign with it again or with another key. The retention is 65 minutes,
    /// and the run is 4 hours at 5 minutes, from both nodes, with key@ asking for the retiring key and for its
    /// successor in turn. (A key that was dropped and is then presented again is the next test.)
    ///
    /// verifies: REQ-KEYS-079
    #[test]
    fn a_retiring_key_stays_retiring_until_it_is_dropped_whichever_key_signs_after() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let (mut r, _) = step(&r, A, "a2", 2000 + WINDOW);
        assert_eq!(states(&r), [("a", RETIRING), ("a2", ACTIVE)]);
        let retired_at = 2000 + WINDOW;
        let mut t = retired_at;
        let mut dropped = false;
        while t < retired_at + 4 * HOUR {
            t += 5 * MIN;
            for node in [A, B] {
                for key in ["a", "a2"] {
                    if dropped && key == "a" {
                        continue;
                    }
                    let (next, _) = step(&r, node, key, t);
                    r = next;
                    match r
                        .keys
                        .iter()
                        .find(|k| k.key_id == "a" && k.state != DROPPED)
                    {
                        Some(k) => {
                            assert_eq!(k.state, RETIRING, "at {t}, {node} asked for {key}");
                            assert!(t < retired_at + 65 * MIN + 5 * MIN);
                        }
                        None => {
                            assert!(t >= retired_at + 65 * MIN, "dropped early at {t}");
                            dropped = true;
                        }
                    }
                    let a2 = r.keys.iter().find(|k| k.key_id == "a2").unwrap();
                    assert_eq!(a2.state, ACTIVE, "at {t}");
                }
            }
        }
        assert!(dropped, "the retiring key was kept for ever");
    }

    /// A key that was dropped is not a new key when key@ presents it again: it is not added, not published and not
    /// promoted, however long after and from whichever node.
    ///
    /// verifies: REQ-KEYS-079
    #[test]
    fn a_dropped_key_that_key_presents_again_does_not_come_back() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let retired_at = 2000 + WINDOW;
        let (r, _) = step(&r, A, "a2", retired_at);
        let dropped_at = retired_at + 65 * MIN;
        let (r, ch) = step(&r, A, "a2", dropped_at);
        assert_eq!(ch, [added("a", ChangeKind::Dropped)]);
        assert!(
            r.keys
                .iter()
                .all(|k| k.key_id != "a" || k.spki_der.is_empty())
        );
        let mut r = r;
        for (t, node) in [
            (0, A),
            (MIN, A),
            (HOUR, B),
            (30 * 24 * HOUR, A),
            (30 * 24 * HOUR + WINDOW, B),
        ] {
            let (next, ch) = step(&r, node, "a", dropped_at + t);
            assert!(ch.is_empty(), "at +{t} {node}: {ch:?}");
            assert_eq!(next, r, "the ring changed when a dropped key was presented");
            assert!(
                !next.keys.iter().any(|k| k.key_id == "a"
                    && [PRE_PUBLISHED, ACTIVE, RETIRING].contains(&k.state.as_str())),
                "the dropped key is in the key set again"
            );
            r = next;
        }
        // The successor goes on signing, and a key that was never in the ring is still new.
        assert_eq!(
            r.keys
                .iter()
                .find(|k| k.key_id == "a2")
                .map(|k| k.state.as_str()),
            Some(ACTIVE)
        );
        let (_, ch) = step(&r, A, "a3", dropped_at + HOUR);
        assert_eq!(ch, [added("a3", ChangeKind::Added(PRE_PUBLISHED))]);
    }

    /// A tombstone is a key that does not sign: it neither keeps the shortcut of REQ-KEYS-089 from a replacement nor
    /// lets one through, and it is kept only up to [`MAX_DROPPED`].
    ///
    /// verifies: REQ-KEYS-079, REQ-KEYS-089
    #[test]
    fn a_tombstone_counts_as_a_key_that_does_not_sign_and_the_oldest_are_forgotten() {
        let tomb = |id: &str, secs: u64| SigningKey {
            key_id: id.into(),
            state: DROPPED.into(),
            node: A.into(),
            added_at: stamp(at(1)).into(),
            state_since: stamp(at(secs)).into(),
            ..SigningKey::default()
        };
        // Every key of the ring is revoked or a tombstone: a replacement signs at once.
        let ring = SigningRing {
            keys: vec![
                tomb("t", 5),
                SigningKey {
                    key_id: "r".into(),
                    state: ACTIVE.into(),
                    node: A.into(),
                    added_at: stamp(at(1)).into(),
                    state_since: stamp(at(1)).into(),
                    spki_der: vec![1],
                    ..SigningKey::default()
                },
            ],
            ..SigningRing::default()
        };
        let (r, ch) = plan(&ring, &cur("n"), A, at(10 * HOUR), &T, &revoked(&["r"]));
        assert_eq!(ch, [skipped("n", ChangeKind::Added(ACTIVE))]);
        assert_eq!(r.keys.iter().filter(|k| k.state == DROPPED).count(), 1);
        // A live key next to the tombstone does not let the replacement skip the window.
        let (_, ch) = plan(&ring, &cur("n"), A, at(10 * HOUR), &T, &revoked(&[]));
        assert_eq!(ch, [added("n", ChangeKind::Added(PRE_PUBLISHED))]);
        // The bound: one more than the ring may keep, and the oldest goes.
        let mut full = SigningRing {
            keys: (0..=MAX_DROPPED)
                .map(|i| tomb(&format!("t{i}"), 10 + i as u64))
                .collect(),
            ..SigningRing::default()
        };
        full.keys.push(SigningKey {
            key_id: "live".into(),
            state: ACTIVE.into(),
            node: A.into(),
            added_at: stamp(at(1)).into(),
            state_since: stamp(at(1)).into(),
            spki_der: vec![1],
            ..SigningKey::default()
        });
        let (r, ch) = step(&full, A, "live", 100_000);
        assert!(ch.is_empty(), "the bound is a bookkeeping, not an event");
        let ids: Vec<&str> = r.keys.iter().map(|k| k.key_id.as_str()).collect();
        assert_eq!(r.keys.len(), MAX_DROPPED + 1);
        assert!(!ids.contains(&"t0") && ids.contains(&"t1") && ids.contains(&"live"));
    }

    /// The tombstones that go are the ones dropped longest ago, not the ones that joined the ring first: the ring lists a
    /// key where it joined, and a key of another node that joined early may be dropped last.
    ///
    /// verifies: REQ-KEYS-079
    #[test]
    fn the_tombstone_that_goes_is_the_oldest_drop_and_not_the_first_in_the_list() {
        let tomb = |id: &str, secs: u64| SigningKey {
            key_id: id.into(),
            state: DROPPED.into(),
            node: A.into(),
            added_at: stamp(at(1)).into(),
            state_since: stamp(at(secs)).into(),
            ..SigningKey::default()
        };
        // The first in the list was dropped last; the oldest drop is in the middle; two have the same time.
        let mut keys = vec![tomb("first-in-list-dropped-last", 900_000)];
        keys.extend((0..MAX_DROPPED - 3).map(|i| tomb(&format!("t{i}"), 10_000 + i as u64)));
        keys.push(tomb("oldest-in-the-middle", 5_000));
        keys.push(tomb("twin-a", 20_000_000));
        keys.push(tomb("twin-b", 20_000_000));
        keys.push(SigningKey {
            key_id: "live".into(),
            state: ACTIVE.into(),
            node: A.into(),
            added_at: stamp(at(1)).into(),
            state_since: stamp(at(1)).into(),
            spki_der: vec![1],
            ..SigningKey::default()
        });
        let ring = SigningRing {
            keys,
            ..SigningRing::default()
        };
        // MAX_DROPPED + 1 tombstones: exactly one goes, the oldest drop.
        let (r, _) = step(&ring, A, "live", 30_000_000);
        let ids: Vec<&str> = r.keys.iter().map(|k| k.key_id.as_str()).collect();
        assert_eq!(r.keys.len(), ring.keys.len() - 1);
        assert!(!ids.contains(&"oldest-in-the-middle"), "{ids:?}");
        assert!(ids.contains(&"first-in-list-dropped-last") && ids.contains(&"live"));
        // A tie in the time of the drop: the one earlier in the list goes, once, and the other stays.
        let mut tied = ring.clone();
        tied.keys.retain(|k| k.key_id != "t0");
        tied.keys.insert(0, tomb("tie-earlier-in-the-list", 5_000));
        let (r, _) = step(&tied, A, "live", 30_000_000);
        let ids: Vec<&str> = r.keys.iter().map(|k| k.key_id.as_str()).collect();
        assert!(!ids.contains(&"tie-earlier-in-the-list"), "{ids:?}");
        assert!(ids.contains(&"oldest-in-the-middle"), "{ids:?}");
    }

    /// The guard begins with the tombstones. A ring that an earlier `signer` wrote has none, so a key it dropped is not
    /// remembered: key@ presenting it joins as a new key (the behaviour before the tombstones, stated and not hidden).
    ///
    /// verifies: REQ-KEYS-079
    #[test]
    fn a_key_dropped_before_the_tombstones_existed_is_a_new_key_again() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        let (r, _) = step(&r, A, "a2", 2000 + WINDOW);
        // The old signer drops the key and leaves nothing behind.
        let mut r = r;
        r.keys.retain(|k| k.key_id != "a");
        let (r2, ch) = step(&r, A, "a", 2000 + WINDOW + 66 * MIN);
        assert_eq!(ch, [added("a", ChangeKind::Added(PRE_PUBLISHED))]);
        assert_eq!(r2.keys.len(), 2);
        // From the drop that this version makes, the guard holds.
        let (r3, _) = step(&r, A, "a2", 2000 + WINDOW + 66 * MIN);
        assert_eq!(r3, r);
    }

    /// verifies: REQ-KEYS-077
    #[test]
    fn a_node_never_changes_the_key_of_another_node() {
        // Both boards have a key; B rotates. A's signer, running at every moment, changes nothing.
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, B, "b", 1000);
        let (r, _) = step(&r, B, "b2", 2 * HOUR);
        assert_eq!(
            states(&r),
            [("a", ACTIVE), ("b", ACTIVE), ("b2", PRE_PUBLISHED)]
        );
        for t in [2 * HOUR + 1, 2 * HOUR + WINDOW / 2, 2 * HOUR + WINDOW - 1] {
            let (r2, ch) = step(&r, A, "a", t);
            assert!(ch.is_empty(), "A changed something at {t}: {ch:?}");
            assert_eq!(r2, r);
        }
        // A's signer does not promote B's key even when it is due, and B's does not retire A's.
        let due = 2 * HOUR + WINDOW;
        let (r2, ch) = step(&r, A, "a", due);
        assert!(ch.is_empty());
        assert_eq!(r2, r);
        let (r3, _) = step(&r, B, "b2", due);
        assert_eq!(
            states(&r3),
            [("a", ACTIVE), ("b", RETIRING), ("b2", ACTIVE)]
        );
    }

    #[test]
    fn two_boards_with_one_ring_do_not_flap() {
        // 90 hours of both signers looking every 30 seconds, as the loop does, with B rotating once
        // in the middle: every change is one that its own node makes, and no key goes back.
        let (mut r, _) = step(&SigningRing::default(), A, "a", 0);
        (r, _) = step(&r, B, "b", 0);
        let mut b_key = "b";
        let mut seen: Vec<(String, String)> = Vec::new();
        let mut t = 0;
        while t < 90 * HOUR {
            if t == 30 * HOUR {
                b_key = "b2";
            }
            for (node, key) in [(A, "a"), (B, b_key)] {
                let (next, ch) = step(&r, node, key, t);
                for c in &ch {
                    seen.push((c.key_id.clone(), format!("{:?}", c.kind)));
                    let owner = next
                        .keys
                        .iter()
                        .find(|k| k.key_id == c.key_id)
                        .map(|k| k.node.clone());
                    // A change is made by the node that owns the key, except the drop of a retiring key.
                    if c.kind != ChangeKind::Dropped {
                        assert_eq!(owner.as_deref(), Some(node), "{node} changed {}", c.key_id);
                    }
                }
                r = next;
            }
            t += 30 * 60; // a coarser step than the loop's 30 seconds; the plan has no state of its own
        }
        let log: Vec<_> = seen.iter().map(|(k, c)| format!("{k}:{c}")).collect();
        assert_eq!(
            log,
            [
                "b2:Added(\"pre-published\")",
                "b2:Activated",
                "b:Retired",
                "b:Dropped"
            ]
        );
        assert_eq!(states(&r), [("a", ACTIVE), ("b2", ACTIVE)]);
    }

    #[test]
    fn a_pre_published_key_that_key_never_signs_with_retires_and_leaves() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step(&r, A, "a2", 2000);
        // a2 was replaced by a3 before its window: a3 is published, a2 never signs.
        let (r, _) = step(&r, A, "a3", 3000);
        assert_eq!(
            states(&r),
            [("a", ACTIVE), ("a2", PRE_PUBLISHED), ("a3", PRE_PUBLISHED)]
        );
        let (r, ch) = step(&r, A, "a3", 3000 + WINDOW);
        assert_eq!(
            states(&r),
            [("a", RETIRING), ("a2", RETIRING), ("a3", ACTIVE)]
        );
        assert_eq!(ch.len(), 3);
        let (r, ch) = step(&r, A, "a3", 3000 + WINDOW + 65 * MIN);
        assert_eq!(states(&r), [("a3", ACTIVE)]);
        assert_eq!(ch.len(), 2);
    }

    #[test]
    fn a_key_with_no_stamp_is_never_dropped_early_and_a_foreign_state_is_left_alone() {
        let ring = SigningRing {
            keys: vec![
                SigningKey {
                    key_id: "old".into(),
                    state: RETIRING.into(),
                    ..SigningKey::default()
                },
                SigningKey {
                    key_id: "odd".into(),
                    state: "revoked".into(),
                    ..SigningKey::default()
                },
            ],
            ..SigningRing::default()
        };
        let (r, ch) = step(&ring, A, "a", 10_000_000);
        // a joins pre-published (the ring was not young: no key has a stamp, so none counts as old,
        // and the node has no key yet), because "odd" is in a state this code does not know and counts
        // as possibly signing; "old" counts from now and stays; "odd" is untouched.
        assert_eq!(r.keys.len(), 3);
        assert_eq!(r.keys[2].state, PRE_PUBLISHED);
        assert_eq!(r.keys[0].state, RETIRING);
        assert_eq!(r.keys[1].state, "revoked");
        assert_eq!(ch.len(), 1);
    }

    // ---- one life for each algorithm (REQ-KEYS-270)

    fn cur_rs(id: &str) -> Current {
        Current {
            alg: Alg::Rs256,
            ..cur(id)
        }
    }

    /// Runs `signer` of `node`, whose key@ signs RS256 with `id`, at `secs`.
    fn step_rs(ring: &SigningRing, node: &str, id: &str, secs: u64) -> (SigningRing, Vec<Change>) {
        plan(ring, &cur_rs(id), node, at(secs), &T, &HashSet::new())
    }

    fn state_of<'a>(r: &'a SigningRing, id: &str) -> Option<&'a str> {
        r.keys
            .iter()
            .find(|k| k.key_id == id)
            .map(|k| k.state.as_str())
    }

    fn alg_of<'a>(r: &'a SigningRing, id: &str) -> Option<&'a str> {
        r.keys
            .iter()
            .find(|k| k.key_id == id)
            .map(|k| k.algorithm.as_str())
    }

    /// A ring with an ES384 key `a` and an RS256 key `r` of node A, both active.
    fn both() -> SigningRing {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step_rs(&r, A, "r", 1000);
        assert_eq!(
            (state_of(&r, "a"), state_of(&r, "r")),
            (Some(ACTIVE), Some(ACTIVE))
        );
        r
    }

    /// An RS256 key joins the ring with its algorithm and leaves the ES384 key alone. On a ring that has served for a while it is
    /// the first key of its algorithm and is published for the window before it signs, like any new key: a relying party may hold
    /// a key set from a moment ago that lacks it. On a ring that is young (the first deploy) it signs at once, as the first key
    /// of a node does.
    ///
    /// verifies: REQ-KEYS-270
    #[test]
    fn an_rs256_key_joins_with_its_algorithm_changes_no_es384_key_and_is_published_first_on_a_ring_that_serves()
     {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (next, ch) = step_rs(&r, A, "r", 1000 + 3 * HOUR);
        assert_eq!(ch, [rs(added("r", ChangeKind::Added(PRE_PUBLISHED)))]);
        assert_eq!(alg_of(&next, "r"), Some("RS256"));
        assert_eq!(alg_of(&next, "a"), Some("ES384"));
        assert_eq!(next.keys[0], r.keys[0], "the ES384 key is untouched");
        assert_eq!(next.keys.len(), 2);
        // Before the window is over it does not sign; when it is, it does, and the ES384 key is not touched.
        let (still, ch) = step_rs(&next, A, "r", 1000 + 3 * HOUR + WINDOW - 1);
        assert!(ch.is_empty(), "{ch:?}");
        assert_eq!(state_of(&still, "r"), Some(PRE_PUBLISHED));
        let (active, ch) = step_rs(&next, A, "r", 1000 + 3 * HOUR + WINDOW);
        assert_eq!(ch, [rs(added("r", ChangeKind::Activated))]);
        assert_eq!(state_of(&active, "a"), Some(ACTIVE));
        // A young ring: both algorithms of a first deploy sign at once.
        let (young, ch) = step_rs(&r, A, "r", 1000 + MIN);
        assert_eq!(ch, [rs(added("r", ChangeKind::Added(ACTIVE)))]);
        assert_eq!(state_of(&young, "r"), Some(ACTIVE));
        // The shortcut of a replacement is for a revoked key: a ring that serves, with its RS256 key revoked, still replaces it at once.
        let (both_r, _) = step_rs(&r, A, "r", 1000 + MIN);
        let (_, ch) = plan(
            &both_r,
            &cur_rs("r2"),
            A,
            at(1000 + 3 * HOUR),
            &T,
            &revoked(&["r"]),
        );
        assert_eq!(ch, [rs(skipped("r2", ChangeKind::Added(ACTIVE)))]);
    }

    /// The first RS256 key of a second node is published for the window too, while the first node's key is itself still
    /// pre-published: no RS256 key has signed, so there is no replacement to hurry, and every board holds a key of its own.
    ///
    /// verifies: REQ-KEYS-270
    #[test]
    fn a_second_nodes_first_rs256_key_waits_for_the_window_as_well() {
        let (r, _) = step(&SigningRing::default(), A, "a", 1000);
        let (r, _) = step_rs(&r, A, "ra", 1000 + 3 * HOUR);
        assert_eq!(state_of(&r, "ra"), Some(PRE_PUBLISHED));
        let (r, ch) = step_rs(&r, B, "rb", 1000 + 3 * HOUR + MIN);
        assert_eq!(ch, [rs(added("rb", ChangeKind::Added(PRE_PUBLISHED)))]);
        assert_eq!(state_of(&r, "rb"), Some(PRE_PUBLISHED));
        // ... and it is active when its window has run out, with node A's.
        let (r, _) = step_rs(&r, B, "rb", 1000 + 3 * HOUR + MIN + WINDOW);
        assert_eq!(state_of(&r, "rb"), Some(ACTIVE));
    }

    /// A rotation of one algorithm does not retire, activate, drop or hold the key of the other, even of the same node.
    ///
    /// verifies: REQ-KEYS-270
    #[test]
    fn a_rotation_of_one_algorithm_never_changes_a_key_of_the_other() {
        let start = 1000 + 3 * HOUR;
        let (r, _) = step(&both(), A, "a2", start);
        assert_eq!(state_of(&r, "a2"), Some(PRE_PUBLISHED));
        let (r, ch) = step(&r, A, "a2", start + WINDOW);
        assert_eq!(
            ch,
            [
                added("a2", ChangeKind::Activated),
                added("a", ChangeKind::Retired)
            ]
        );
        assert_eq!(
            state_of(&r, "r"),
            Some(ACTIVE),
            "the ES384 rotation retired the RS256 key"
        );
        // The reverse: an RS256 rotation, and ES384 key `a2` stays active.
        let (r, _) = step_rs(&r, A, "r2", start + 2 * HOUR);
        assert_eq!(
            state_of(&r, "r2"),
            Some(PRE_PUBLISHED),
            "a live RS256 key makes a replacement wait"
        );
        let (r, ch) = step_rs(&r, A, "r2", start + 2 * HOUR + WINDOW);
        assert_eq!(
            ch,
            [
                rs(added("r2", ChangeKind::Activated)),
                rs(added("r", ChangeKind::Retired))
            ]
        );
        assert_eq!(
            state_of(&r, "a2"),
            Some(ACTIVE),
            "the RS256 rotation retired the ES384 key"
        );
        // The retention of one is not the retention of the other: the RS256 key `r` is dropped by an RS256 step, and the ES384
        // key `a`, due long before, is dropped by an ES384 step only.
        let due = start + 2 * HOUR + WINDOW + 65 * MIN;
        let (r2, ch) = step_rs(&r, A, "r2", due);
        assert_eq!(ch, [rs(added("r", ChangeKind::Dropped))]);
        assert_eq!(
            state_of(&r2, "a"),
            Some(RETIRING),
            "an RS256 step dropped an ES384 key"
        );
        let (r3, ch) = step(&r2, A, "a2", due);
        assert_eq!(ch, [added("a", ChangeKind::Dropped)]);
        assert_eq!(state_of(&r3, "r"), Some(DROPPED));
        assert_eq!(state_of(&r3, "a"), Some(DROPPED));
    }

    /// The shortcut of REQ-KEYS-089 is taken for an algorithm whose keys are all revoked, whatever the other algorithm
    /// holds, and is not taken for an algorithm that has a key that signs.
    ///
    /// verifies: REQ-KEYS-270, REQ-KEYS-089
    #[test]
    fn the_replacement_of_a_revoked_key_skips_the_window_by_its_own_algorithm_only() {
        let now = 1000 + 3 * HOUR;
        // RS256 revoked, ES384 live: the RS256 replacement signs at once, no RS256 key signs.
        let (r, ch) = plan(&both(), &cur_rs("r2"), A, at(now), &T, &revoked(&["r"]));
        assert_eq!(ch, [rs(skipped("r2", ChangeKind::Added(ACTIVE)))]);
        assert_eq!(state_of(&r, "a"), Some(ACTIVE));
        // ES384 revoked, RS256 live: the ES384 replacement signs at once.
        let (r, ch) = plan(&both(), &cur("a2"), A, at(now), &T, &revoked(&["a"]));
        assert_eq!(ch, [skipped("a2", ChangeKind::Added(ACTIVE))]);
        assert_eq!(state_of(&r, "r"), Some(ACTIVE));
        // ES384 revoked, RS256 live and not revoked: an RS256 rotation still waits for the window.
        let (_, ch) = plan(&both(), &cur_rs("r2"), A, at(now), &T, &revoked(&["a"]));
        assert_eq!(ch, [rs(added("r2", ChangeKind::Added(PRE_PUBLISHED)))]);
        // RS256 revoked, ES384 live and not revoked: an ES384 rotation still waits.
        let (_, ch) = plan(&both(), &cur("a2"), A, at(now), &T, &revoked(&["r"]));
        assert_eq!(ch, [added("a2", ChangeKind::Added(PRE_PUBLISHED))]);
        // A revoked key of the algorithm that is not the only one: the other key of the algorithm signs, so the window holds.
        let (two, _) = step_rs(&both(), B, "rb", 1000);
        let (_, ch) = plan(&two, &cur_rs("r2"), A, at(now), &T, &revoked(&["r"]));
        assert_eq!(ch, [rs(added("r2", ChangeKind::Added(PRE_PUBLISHED)))]);
    }

    /// A ring with an ES384 key `a` and an RS256 key `r` of node A, both added at `secs` and active.
    fn both_at(secs: u64) -> SigningRing {
        let (r, _) = step(&SigningRing::default(), A, "a", secs);
        let (r, _) = step_rs(&r, A, "r", secs);
        r
    }

    /// A revoked key of one algorithm does not hold the new key of the other (the hold is for the key set `entry` cached).
    ///
    /// verifies: REQ-KEYS-270
    #[test]
    fn a_revoked_key_holds_only_the_new_key_of_its_own_algorithm() {
        let now = 1000 + 3 * HOUR;
        let held = |ring: &SigningRing, c: &Current, rev: &[&str]| {
            slot(ring, c.clone(), at(now + 1), &revoked(rev)).hold_until
        };
        // Both keys joined a moment ago, which is the case the hold is for. A revocation of the RSA key holds a new RSA key
        // and not the ES384 key, and the reverse.
        let ring = both_at(now);
        assert!(
            held(&ring, &cur_rs("r"), &["r"]).is_some(),
            "the RSA key after its own revocation"
        );
        assert!(
            held(&ring, &cur("a"), &["r"]).is_none(),
            "an RS256 revocation held the ES384 key"
        );
        assert!(
            held(&ring, &cur("a"), &["a"]).is_some(),
            "the ES384 key after its own revocation"
        );
        assert!(
            held(&ring, &cur_rs("r"), &["a"]).is_none(),
            "an ES384 revocation held the RS256 key"
        );
        assert!(held(&ring, &cur("a"), &[]).is_none() && held(&ring, &cur_rs("r"), &[]).is_none());
    }

    /// An algorithm that is not enabled: the node's keys of it stop and are dropped by the retention, and the keys of other
    /// nodes and of the other algorithm are not touched; with nothing to retire the ring is unchanged.
    ///
    /// verifies: REQ-KEYS-270
    #[test]
    fn an_algorithm_that_is_not_enabled_retires_the_nodes_own_keys_of_it_and_nothing_else() {
        let (ring, _) = step_rs(&both(), B, "rb", 1000);
        let now = 1000 + 3 * HOUR;
        let (off, ch) = plan_disabled(&ring, Alg::Rs256, A, at(now), &T, &HashSet::new());
        assert_eq!(ch, [rs(added("r", ChangeKind::Retired))]);
        assert_eq!(state_of(&off, "r"), Some(RETIRING));
        assert_eq!(state_of(&off, "rb"), Some(ACTIVE), "another node's key");
        assert_eq!(
            state_of(&off, "a"),
            Some(ACTIVE),
            "the other algorithm's key"
        );
        // Nothing more to do: the ring is the same, and the same again.
        let (same, ch) = plan_disabled(&off, Alg::Rs256, A, at(now + MIN), &T, &HashSet::new());
        assert!(ch.is_empty());
        assert_eq!(same, off);
        // The retention drops it, as for any key.
        let (gone, ch) =
            plan_disabled(&off, Alg::Rs256, A, at(now + 65 * MIN), &T, &HashSet::new());
        assert_eq!(ch, [rs(added("r", ChangeKind::Dropped))]);
        assert_eq!(state_of(&gone, "r"), Some(DROPPED));
        // A revoked key is left as it is.
        let (off, ch) = plan_disabled(&ring, Alg::Rs256, A, at(now), &T, &revoked(&["r"]));
        assert!(ch.is_empty());
        assert_eq!(off, ring);
        // Enabling it again publishes a key for the window when the ring has a live RS256 key of the other node, and adds it.
        let (back, _) = plan_disabled(&ring, Alg::Es384, B, at(now), &T, &HashSet::new());
        assert_eq!(back, ring, "node B has no ES384 key: nothing to retire");
    }

    /// A ring key with no algorithm is an ES384 key, the only one a ring had before the RS256 exception, and an RS256 plan
    /// does not touch it. The place of every key is kept: a plan writes back the ring in the order it had, new keys last.
    ///
    /// verifies: REQ-KEYS-270
    #[test]
    fn a_key_with_no_algorithm_is_es384_and_the_order_of_the_ring_is_kept() {
        let mut r = both();
        r.keys[0].algorithm.clear();
        let (_, ch) = step_rs(&r, A, "r", 1000 + 3 * HOUR);
        assert!(ch.is_empty());
        let (r2, ch) = step(&r, A, "a", 1000 + 3 * HOUR);
        assert!(
            ch.is_empty(),
            "a key with no algorithm was not read as ES384"
        );
        assert_eq!(r2, r);
        // Both algorithms and two nodes: new keys go last, and the others keep their places.
        let (r3, _) = step(&r, B, "b", 1000);
        let (r4, _) = step_rs(&r3, B, "rb", 1000);
        let ids: Vec<&str> = r4.keys.iter().map(|k| k.key_id.as_str()).collect();
        assert_eq!(ids, ["a", "r", "b", "rb"]);
        let (r5, _) = step(&r4, B, "b2", 1000 + 3 * HOUR);
        let ids: Vec<&str> = r5.keys.iter().map(|k| k.key_id.as_str()).collect();
        assert_eq!(ids, ["a", "r", "b", "rb", "b2"]);
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    const WINDOW: u64 = 30 * 60;
    const HOUR: u64 = 3600;
    const A: &str = "node-a";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn cur(id: &str) -> Current {
        Current {
            alg: Alg::Es384,
            key_id: id.into(),
            spki_der: vec![1, 2, 3],
            x5c: vec![],
            x5c_withdrawn: false,
        }
    }

    fn report(state: &str, kids: &[&str], read_back: Option<u64>) -> ExportReport {
        ExportReport {
            state: state.into(),
            kind: "SigningRing".into(),
            public: true,
            kids: kids.iter().map(|k| (*k).to_owned()).collect(),
            read_back_at: read_back.map(|s| stamp(at(s))).into(),
            ..ExportReport::default()
        }
    }

    /// A ring whose node holds `a` (active) and `a2` (pre-published since second 0).
    fn ring() -> SigningRing {
        let key = |id: &str, state: &str| SigningKey {
            key_id: id.into(),
            state: state.into(),
            node: A.into(),
            added_at: stamp(at(0)).into(),
            state_since: stamp(at(0)).into(),
            ..SigningKey::default()
        };
        SigningRing {
            keys: vec![key("a", ACTIVE), key("a2", PRE_PUBLISHED)],
            ..SigningRing::default()
        }
    }

    fn state_of(r: &SigningRing, id: &str) -> String {
        r.keys
            .iter()
            .find(|k| k.key_id == id)
            .unwrap()
            .state
            .clone()
    }

    /// A manifest that names a public key set `d<i>/jwks` for each report, and the reports under those ids; none at all
    /// for no report (an installation with no exporter).
    fn publication(reports: &[ExportReport], now: SystemTime) -> Publication {
        if reports.is_empty() {
            return Publication::of(None, &[], now);
        }
        let m = ExportManifest {
            entries: (0..reports.len())
                .map(|i| entry(&format!("d{i}"), "jwks", true))
                .collect(),
            ..ExportManifest::default()
        };
        let rs: Vec<_> = reports
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("d{i}/jwks"), r.clone()))
            .collect();
        Publication::of(Some(&m), &rs, now)
    }

    fn entry(
        destination: &str,
        document: &str,
        public: bool,
    ) -> sluis_proto::sluis::exporter::v2alpha1::export_manifest::Entry {
        sluis_proto::sluis::exporter::v2alpha1::export_manifest::Entry {
            destination: destination.into(),
            document: document.into(),
            kind: "SigningRing".into(),
            public,
            ..Default::default()
        }
    }

    fn after(reports: &[ExportReport], secs: u64) -> String {
        let now = at(secs);
        let p = publication(reports, now);
        let (next, _) = plan_with(
            &ring(),
            &cur("a2"),
            A,
            now,
            &Timing::DEFAULT,
            &HashSet::new(),
            &p,
        );
        state_of(&next, "a2")
    }

    /// A report that is unverified, absent for the kid, or older than 26 hours keeps a pre-published key
    /// pre-published; a published report that lists the kid lets it become active after the lead time, counted from the
    /// read back.
    ///
    /// verifies: REQ-KEYS-116
    #[test]
    fn a_key_waits_for_a_published_report_that_lists_it_and_is_fresh() {
        let published = report("published", &["a", "a2"], Some(100));
        // Long after the lead time counted from the write (second 0), the key still waits for the read back.
        assert_eq!(
            after(&[report("unverified", &["a", "a2"], Some(100))], 10 * HOUR),
            PRE_PUBLISHED
        );
        assert_eq!(
            after(&[report("purge-pending", &["a", "a2"], None)], 10 * HOUR),
            PRE_PUBLISHED
        );
        assert_eq!(
            after(&[report("published", &["a"], Some(100))], 10 * HOUR),
            PRE_PUBLISHED,
            "without the kid"
        );
        assert_eq!(
            after(&[report("published", &["a", "a2"], None)], 10 * HOUR),
            PRE_PUBLISHED,
            "no read back"
        );
        // 26 hours and a second after the read back: too old, whatever else is true.
        assert_eq!(
            after(std::slice::from_ref(&published), 100 + 26 * HOUR + 1),
            PRE_PUBLISHED,
            "older than 26 hours"
        );
        assert_eq!(
            after(std::slice::from_ref(&published), 100 + 26 * HOUR),
            ACTIVE,
            "exactly 26 hours is still fresh"
        );
        // Published, listed and fresh: active once the lead time has passed since the read back, and not a second sooner.
        assert_eq!(
            after(std::slice::from_ref(&published), 100 + WINDOW - 1),
            PRE_PUBLISHED
        );
        assert_eq!(
            after(std::slice::from_ref(&published), 100 + WINDOW),
            ACTIVE
        );
    }

    /// The lead time counts from the read back, not from the write to the ring: a key written to the ring at second 0 and
    /// read back at second 3000 is not active at 1801, when the write alone would have allowed it (REQ-KEYS-085).
    ///
    /// verifies: REQ-KEYS-085
    #[test]
    fn the_lead_time_counts_from_the_read_back() {
        let r = [report("published", &["a2"], Some(3000))];
        assert_eq!(after(&r, WINDOW + 1), PRE_PUBLISHED);
        assert_eq!(after(&r, 3000 + WINDOW - 1), PRE_PUBLISHED);
        assert_eq!(after(&r, 3000 + WINDOW), ACTIVE);
        // Without a destination that reports, it is the write, as before.
        assert_eq!(after(&[], WINDOW), ACTIVE);
        assert_eq!(after(&[], WINDOW - 1), PRE_PUBLISHED);
    }

    /// Every destination with a public address must have read the key back; the lead time counts from the last.
    #[test]
    fn every_destination_must_have_the_key_and_the_last_read_back_counts() {
        let two = [
            report("published", &["a2"], Some(100)),
            report("published", &["a2"], Some(900)),
        ];
        assert_eq!(after(&two, 100 + WINDOW), PRE_PUBLISHED);
        assert_eq!(after(&two, 900 + WINDOW), ACTIVE);
        let one_late = [
            report("published", &["a2"], Some(100)),
            report("purge-pending", &["a2"], None),
        ];
        assert_eq!(after(&one_late, 10 * HOUR), PRE_PUBLISHED);
    }

    /// A destination with no public address, a report of another kind, and no manifest are not counted.
    #[test]
    fn a_destination_without_a_public_address_is_not_counted() {
        let m = ExportManifest {
            entries: vec![entry("local", "jwks", false)],
            ..ExportManifest::default()
        };
        let written = ExportReport {
            public: false,
            ..report("written", &["a2"], None)
        };
        let rs = [("local/jwks".to_owned(), written)];
        assert_eq!(
            Publication::of(Some(&m), &rs, at(10)),
            Publication::Unreported
        );
        let mut other = entry("edge", "bundle", true);
        other.kind = "TrustBundle".into();
        let m = ExportManifest {
            entries: vec![other],
            ..ExportManifest::default()
        };
        assert_eq!(
            Publication::of(Some(&m), &[], at(10)),
            Publication::Unreported
        );
        assert_eq!(Publication::of(None, &[], at(10)), Publication::Unreported);
    }

    /// A public entry of the manifest with no report is not published: the key waits, however long, and a new public
    /// destination holds activation from the moment the manifest names it.
    ///
    /// verifies: REQ-KEYS-116
    #[test]
    fn a_manifest_entry_with_no_report_holds_activation() {
        let m = ExportManifest {
            entries: vec![entry("edge", "jwks", true)],
            ..ExportManifest::default()
        };
        let p = Publication::of(Some(&m), &[], at(10 * HOUR));
        assert_eq!(p, Publication::held());
        let (next, _) = plan_with(
            &ring(),
            &cur("a2"),
            A,
            at(100 * HOUR),
            &Timing::DEFAULT,
            &HashSet::new(),
            &p,
        );
        assert_eq!(state_of(&next, "a2"), PRE_PUBLISHED);
        // One of two entries reported is not enough.
        let m = ExportManifest {
            entries: vec![entry("edge", "jwks", true), entry("cdn", "jwks", true)],
            ..ExportManifest::default()
        };
        let rs = [(
            "edge/jwks".to_owned(),
            report("published", &["a2"], Some(100)),
        )];
        assert_eq!(Publication::of(Some(&m), &rs, at(200)), Publication::held());
    }

    /// The report of a destination that was removed is in no entry of the manifest and is not read: it can neither hold
    /// a key (a stale `unverified`, or a read back older than 26 hours) nor release one (an old `published`).
    ///
    /// verifies: REQ-KEYS-116
    #[test]
    fn the_report_of_a_removed_destination_is_ignored() {
        let m = ExportManifest {
            entries: vec![entry("edge", "jwks", true)],
            ..ExportManifest::default()
        };
        let live = report("published", &["a2"], Some(5 * HOUR));
        let stale = report("unverified", &[], None);
        let rs = [
            ("edge/jwks".to_owned(), live.clone()),
            ("old/jwks".to_owned(), stale),
        ];
        let want = Publication::of(Some(&m), &[("edge/jwks".to_owned(), live)], at(6 * HOUR));
        assert_eq!(Publication::of(Some(&m), &rs, at(6 * HOUR)), want);
        match want {
            Publication::Required(seen) => assert_eq!(seen.get("a2"), Some(&at(5 * HOUR))),
            Publication::Unreported => panic!("a public entry is counted"),
        }
        // And a removed destination's old `published` does not release a key the live one does not list.
        let m = ExportManifest {
            entries: vec![entry("edge", "jwks", true)],
            ..ExportManifest::default()
        };
        let rs = [
            (
                "edge/jwks".to_owned(),
                report("published", &["a"], Some(100)),
            ),
            (
                "old/jwks".to_owned(),
                report("published", &["a2"], Some(100)),
            ),
        ];
        let Publication::Required(seen) = Publication::of(Some(&m), &rs, at(200)) else {
            panic!("counted")
        };
        assert!(!seen.contains_key("a2"));
    }

    /// A replacement for the last key that signs waits for the key set to show it and for nothing else: it joins the
    /// ring pre-published, since no report can list it yet, and is active as soon as a report does, with no lead time.
    ///
    /// verifies: REQ-KEYS-089
    #[test]
    fn a_replacement_waits_for_the_read_back_and_for_nothing_else() {
        let revoked = HashSet::from(["a".to_owned()]);
        let ring = SigningRing {
            keys: ring().keys[..1].to_vec(),
            ..SigningRing::default()
        };
        let t = Timing::DEFAULT;
        let none = Publication::Required(HashMap::new());
        // It joins the ring: not active, since the reported key set cannot list it yet.
        let (r1, ch) = plan_with(&ring, &cur("b"), A, at(10 * HOUR), &t, &revoked, &none);
        assert_eq!(state_of(&r1, "b"), PRE_PUBLISHED);
        assert_eq!(ch[0].reason, None);
        // No report lists it: it waits, however long.
        let (r2, _) = plan_with(&r1, &cur("b"), A, at(20 * HOUR), &t, &revoked, &none);
        assert_eq!(state_of(&r2, "b"), PRE_PUBLISHED);
        // A report lists it a second after it joined: active at once, and the change says it skipped the lead time.
        let seen = Publication::Required(HashMap::from([("b".to_owned(), at(10 * HOUR + 1))]));
        let (r3, ch) = plan_with(&r1, &cur("b"), A, at(10 * HOUR + 2), &t, &revoked, &seen);
        assert_eq!(state_of(&r3, "b"), ACTIVE);
        assert_eq!(ch[0].reason, Some(NO_ACTIVE_KEY));
        // Without a reporting destination the replacement signs at once, as before.
        let (r4, _) = plan_with(
            &ring,
            &cur("b"),
            A,
            at(10 * HOUR),
            &t,
            &revoked,
            &Publication::Unreported,
        );
        assert_eq!(state_of(&r4, "b"), ACTIVE);
    }
    /// The first key of a new installation, which has a public destination for the key set, waits for the read back and for
    /// nothing more: no key of the issuer signs, so there is no lead time to wait for (REQ-KEYS-089, REQ-KEYS-116). A ring
    /// of one algorithm is the first deploy; the rule that the first key of another algorithm on a ring that serves is published
    /// first must not reach it.
    ///
    /// verifies: REQ-KEYS-089, REQ-KEYS-116
    #[test]
    fn the_first_key_of_a_new_installation_with_a_public_destination_waits_for_the_read_back_and_nothing_more()
     {
        let t = Timing::DEFAULT;
        let held = publication(&[report("unverified", &[], None)], at(60));
        // It joins pre-published (nothing is read back), and the ring holds nothing else.
        let (r, ch) = plan_with(
            &SigningRing::default(),
            &cur("a"),
            A,
            at(60),
            &t,
            &HashSet::new(),
            &held,
        );
        assert_eq!(state_of(&r, "a"), PRE_PUBLISHED);
        assert!(
            matches!(ch[0].kind, ChangeKind::Added(PRE_PUBLISHED)),
            "{ch:?}"
        );
        // Read back at second 120: it is active at once, not 30 minutes later.
        let read = publication(&[report("published", &["a"], Some(120))], at(130));
        let (r, ch) = plan_with(&r, &cur("a"), A, at(130), &t, &HashSet::new(), &read);
        assert_eq!(state_of(&r, "a"), ACTIVE, "{ch:?}");
        // The same on a ring that holds a key of another algorithm that has signed: the first RS256 key waits for the window.
        let mut serving = SigningRing::default();
        serving.keys.push(SigningKey {
            key_id: "e".into(),
            algorithm: "ES384".into(),
            state: ACTIVE.into(),
            node: A.into(),
            added_at: stamp(at(0)).into(),
            state_since: stamp(at(0)).into(),
            ..SigningKey::default()
        });
        let rs = Current {
            alg: Alg::Rs256,
            ..cur("r")
        };
        let (r, _) = plan_with(
            &serving,
            &rs,
            A,
            at(10 * HOUR),
            &t,
            &HashSet::new(),
            &Publication::Unreported,
        );
        assert_eq!(state_of(&r, "r"), PRE_PUBLISHED);
        let read = publication(
            &[report("published", &["r"], Some(10 * HOUR + 60))],
            at(10 * HOUR + 120),
        );
        let (r2, _) = plan_with(&r, &rs, A, at(10 * HOUR + 120), &t, &HashSet::new(), &read);
        assert_eq!(
            state_of(&r2, "r"),
            PRE_PUBLISHED,
            "the first RS256 key took the shortcut of a replacement"
        );
        let (r3, _) = plan_with(
            &r,
            &rs,
            A,
            at(10 * HOUR + 60 + WINDOW),
            &t,
            &HashSet::new(),
            &publication(
                &[report("published", &["r"], Some(10 * HOUR + 60))],
                at(10 * HOUR + 60 + WINDOW),
            ),
        );
        assert_eq!(state_of(&r3, "r"), ACTIVE);
    }
}
