//! The grant of an allow (ADR 0007 "Sealed grants"; build plan D-5): who carries it, for which
//! tenant, what it allows, and for how long. `key@` seals it with purpose `grant`.
//!
//! `policy` narrows and never widens: the grant allows what the asker asked for, cut down to what
//! the registry lets the asker do at all. `key@` and `store@` check the grant again against their
//! own tables, so a mistake here is caught there; this is the first check, not the only one.

use std::time::{Duration, SystemTime};

use buffa_types::google::protobuf::Timestamp;
use sluis_proto::sluis::r#type::v2alpha1::Grant;

/// How long a grant lives: ADR 0007 says about 60 seconds, and `key@` refuses a grant that lives
/// longer than 60 seconds or ends later than 65 seconds from its own clock.
pub const GRANT_LIFE: Duration = Duration::from_secs(60);

/// The verbs of a grant (store-api.md "Verbs"; `watch` is a read of the change log and needs none).
pub const STORE_VERBS: [&str; 6] = ["get", "list", "create", "update", "delete", "apply"];
/// The operations of a grant (D-5: the tenant purposes `data` and `evidence` need one; `mac` and
/// `sign` are named for the grant's later users).
pub const KEY_OPS: [&str; 4] = ["seal", "open", "mac", "sign"];

/// The tenant purposes of the key registry, by the operation a grant can name.
fn purposes(op: &str) -> &'static [&'static str] {
    match op {
        "seal" | "open" => &["data", "evidence"],
        "mac" => &["pseudonym", "pairwise"],
        "sign" => &["release-signing"],
        _ => &[],
    }
}

/// The most a holder can do under any grant: the store verbs it has on some tenant-scoped kind, and
/// the key operations it has on some tenant purpose (the generated tables of the registry).
#[must_use]
pub fn ceiling(holder: &str) -> (Vec<&'static str>, Vec<&'static str>) {
    let verbs = STORE_VERBS
        .iter()
        .copied()
        .filter(|v| {
            sluis_registry::kinds().iter().any(|k| {
                k.scope == sluis_registry::Scope::BoundaryTenant
                    && sluis_registry::store_allows(holder, k.segment, v)
            })
        })
        .collect();
    let ops = KEY_OPS
        .iter()
        .copied()
        .filter(|op| {
            purposes(op)
                .iter()
                .any(|p| sluis_registry::key_allows(holder, p, op))
        })
        .collect();
    (verbs, ops)
}

/// Why the asker's wishes cannot be a grant: a name that is not a verb or an operation.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownName;

/// What was asked, cut down to the ceiling, sorted and without repeats.
///
/// # Errors
///
/// [`UnknownName`] when a name is not in `names`: a request for something that does not exist is
/// refused, not narrowed to nothing.
pub fn narrow(
    asked: &[String],
    names: &[&str],
    ceiling: &[&'static str],
) -> Result<Vec<String>, UnknownName> {
    let mut out: Vec<String> = Vec::new();
    for a in asked {
        if !names.contains(&a.as_str()) {
            return Err(UnknownName);
        }
        if ceiling.contains(&a.as_str()) && !out.contains(a) {
            out.push(a.clone());
        }
    }
    out.sort();
    Ok(out)
}

pub use crate::decide::caps;

/// A `SystemTime` as a protobuf timestamp.
#[must_use]
pub fn timestamp(t: SystemTime) -> Timestamp {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        ..Timestamp::default()
    }
}

/// What a decision puts in its grant.
pub struct Parts<'a> {
    pub boundary: &'a str,
    /// The actor that asked and will carry the grant (from the transport).
    pub holder: &'a str,
    /// The tenant of the question, or `*`.
    pub tenant: &'a str,
    pub store_verbs: Vec<String>,
    pub key_ops: Vec<String>,
    pub decision_id: &'a str,
    pub action: &'a str,
    pub now: SystemTime,
}

/// The grant of a decision. It starts now and ends [`GRANT_LIFE`] later.
#[must_use]
pub fn build(p: Parts<'_>) -> Grant {
    Grant {
        boundary: p.boundary.to_owned(),
        tenants: vec![p.tenant.to_owned()],
        holder: p.holder.to_owned(),
        store_verbs: p.store_verbs,
        key_ops: p.key_ops,
        issued_at: timestamp(p.now).into(),
        expires_at: timestamp(p.now + GRANT_LIFE).into(),
        decision_id: p.decision_id.to_owned(),
        action: p.action.to_owned(),
        ..Grant::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_lives_exactly_as_long_as_key_allows() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let g = build(Parts {
            boundary: "dev",
            holder: "session",
            tenant: "acme",
            store_verbs: vec!["get".into()],
            key_ops: vec![],
            decision_id: "d",
            action: "token.issue",
            now,
        });
        let (i, e) = (
            g.issued_at.as_option().unwrap(),
            g.expires_at.as_option().unwrap(),
        );
        assert_eq!(e.seconds - i.seconds, 60);
        assert_eq!(e.nanos, i.nanos);
        assert_eq!(g.tenants, ["acme"]);
    }

    #[test]
    fn the_ceiling_of_an_actor_is_what_the_registry_gives_it() {
        // session writes tenant kinds and seals and opens under the tenant's data key.
        let (verbs, ops) = ceiling("session");
        assert!(verbs.contains(&"create") && verbs.contains(&"get"));
        assert!(ops.contains(&"seal") && ops.contains(&"open"));
        // an actor of no rule gets nothing, and so does a name that is no actor.
        assert_eq!(ceiling("nobody"), (vec![], vec![]));
        // policy opens under the tenant's data key and never seals under it (keys.yaml).
        let (_, ops) = ceiling("policy");
        assert!(ops.contains(&"open") && !ops.contains(&"seal"));
    }

    #[test]
    fn narrowing_cuts_to_the_ceiling_and_refuses_a_name_that_does_not_exist() {
        let ask = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            narrow(
                &ask(&["update", "get", "get", "delete"]),
                &STORE_VERBS,
                &["get", "update"]
            ),
            Ok(ask(&["get", "update"]))
        );
        assert_eq!(narrow(&ask(&["get"]), &STORE_VERBS, &[]), Ok(vec![]));
        assert_eq!(
            narrow(&ask(&["root"]), &STORE_VERBS, &["get"]),
            Err(UnknownName)
        );
    }
}
