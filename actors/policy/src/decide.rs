//! One decision: the request of an asker becomes a Cedar request and its entities, the person's
//! grant names are found, and Cedar decides (policy.md "What a decision holds", "How a person's
//! grants are found").
//!
//! Fail closed everywhere: a request that cannot be turned into a request of the schema, or whose
//! asker may not ask it, is a denial with a closed word saying which, never a guess.

use std::collections::BTreeSet;

use cedar_policy::Entities;
use connectrpc::error::ErrorCode;
use serde_json::{Map, Value, json};
use sluis_proto::sluis::policy::v2alpha1::{Authentication, DecideRequest};

use crate::engine::{Engine, Reason, uid_of};
use crate::vocab::GrantName;

/// What an action asks about and who may ask it.
struct Spec {
    name: &'static str,
    /// The Cedar types the principal may have.
    principals: &'static [&'static str],
    /// The registry names of the actors that may ask this action. The call graph says who may call
    /// `policy` at all; this says who may ask what.
    askers: &'static [&'static str],
    /// Whether `*` (every tenant of the boundary) is a tenant of the question.
    every_tenant: bool,
    /// Whether the question is about a person's token (their grant names are found first).
    token: bool,
    /// The most a grant of this action may allow, whatever the asker asks and the registry gives
    /// the asker: an action cannot widen its own grant (ADR 0007 "Sealed grants"). The store verbs
    /// and key operations are those the action's work needs and no more.
    verbs: &'static [&'static str],
    ops: &'static [&'static str],
}

/// The actions this build decides: the ones whose facts the contract carries (policy.proto). The
/// others of the schema (`artifact.sign`, `policy.link`) get their facts with their first asker.
const ACTIONS: [Spec; 5] = [
    Spec {
        name: "token.issue",
        principals: &["Person"],
        askers: &["session"],
        every_tenant: false,
        token: true,
        verbs: &["get", "list", "create", "update", "delete", "apply"],
        ops: &["seal", "open"],
    },
    Spec {
        name: "token.exchange",
        principals: &["Person"],
        askers: &["exchange"],
        every_tenant: false,
        token: true,
        verbs: &["get", "list", "create", "update"],
        ops: &["seal", "open"],
    },
    Spec {
        name: "audit.seal",
        principals: &["Actor"],
        askers: &["writer"],
        every_tenant: false,
        token: false,
        verbs: &[],
        ops: &["seal"],
    },
    Spec {
        name: "audit.index",
        principals: &["Actor"],
        askers: &["indexer"],
        every_tenant: true,
        token: false,
        verbs: &[],
        ops: &["open"],
    },
    Spec {
        name: "audit.read",
        principals: &["Actor", "Person"],
        askers: &["reader", "console"],
        every_tenant: true,
        token: false,
        verbs: &[],
        ops: &["open"],
    },
];

/// The most a request may carry of each repeated or long field.
const ACCOUNTS_MAX: usize = 32;
const REQUIRES_MAX: usize = 64;
const AMR_MAX: usize = 16;
const TEXT_MAX: usize = 256;

/// The caps of an action's grant: the store verbs and key operations it may ever allow.
#[must_use]
pub fn caps(action: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    ACTIONS
        .iter()
        .find(|s| s.name == action)
        .map(|s| (s.verbs, s.ops))
}

/// A question that was not decided because it is not one: the Connect code, the closed reason of
/// the `Refusal` detail and the path of the field at fault (contracts.md "Errors"). The asker can
/// tell it from a denial, which is an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    pub code: ErrorCode,
    pub reason: &'static str,
    pub path: &'static str,
}

/// The request does not fit the contract: a missing or malformed field.
pub(crate) const fn invalid(path: &'static str) -> Refused {
    Refused {
        code: ErrorCode::InvalidArgument,
        reason: "schema",
        path,
    }
}

/// The caller is known and may not ask this.
const fn forbidden(path: &'static str) -> Refused {
    Refused {
        code: ErrorCode::PermissionDenied,
        reason: "rule",
        path,
    }
}

/// What Cedar decided about a question that was one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub allow: bool,
    /// The Cedar action.
    pub action: &'static str,
    pub reasons: Vec<Reason>,
    /// For a token action, the full set of held grant names after the ladder (sorted).
    pub grant_names: Vec<String>,
    /// The tenant a grant would name: the tenant of the question.
    pub tenant: String,
    /// Empty for Cedar's own answer. `evaluation` when Cedar allowed past a policy that errored:
    /// the answer is a denial, and the audit record says why.
    pub why: &'static str,
    /// Policies that errored while deciding.
    pub errors: usize,
}

/// A tenant id, or `*` where the action takes every tenant: the part rule of store-api.md "Address
/// encoding", and not the `-` that stands for no tenant.
fn tenant_ok(t: &str, every: bool) -> bool {
    if t == "*" {
        return every;
    }
    (1..=128).contains(&t.len())
        && t != "-"
        && t != "."
        && t != ".."
        && t.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

fn text_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= TEXT_MAX && !s.chars().any(char::is_control)
}

fn entity_ref(ty: &str, id: &str) -> Value {
    json!({"__entity": {"type": ty, "id": id}})
}

/// The context of the request as Cedar JSON; `None` for a value that is out of range.
fn context_of(c: Option<&Authentication>) -> Option<Value> {
    let mut m = Map::new();
    if let Some(c) = c {
        if let Some(acr) = &c.acr {
            if !text_ok(acr) {
                return None;
            }
            m.insert("acr".into(), json!(acr));
        }
        // An absent name is unknown (policy.md "Context"): `amr` is sent when the upstream said
        // anything about it, even an empty list.
        if c.amr_present || !c.amr.is_empty() {
            if c.amr.len() > AMR_MAX || !c.amr.iter().all(|a| text_ok(a)) {
                return None;
            }
            m.insert("amr".into(), json!(c.amr));
        }
        if let Some(age) = c.auth_age {
            if age < 0 {
                return None;
            }
            m.insert("auth_age".into(), json!(age));
        }
    }
    Some(Value::Object(m))
}

/// The facts of a person, checked.
struct Person {
    subject: String,
    accounts: Vec<(String, String)>, // (the account id, its upstream)
    state: String,
    /// The tenant the person belongs to. The contract carries it; it is never taken from the
    /// tenant of the question.
    org: String,
}

fn person_of(req: &DecideRequest) -> Result<Person, Refused> {
    let p = req.person.as_option().ok_or(invalid("person"))?;
    if !text_ok(&p.subject) {
        return Err(invalid("person.subject"));
    }
    if !text_ok(&p.state) {
        return Err(invalid("person.state"));
    }
    if !tenant_ok(&p.org, false) {
        return Err(invalid("person.org"));
    }
    if p.accounts.len() > ACCOUNTS_MAX {
        return Err(invalid("person.accounts"));
    }
    let mut accounts = Vec::new();
    for a in &p.accounts {
        // `<upstream>/<claim value>` (policy.md "Entity types").
        let (up, claim) = a.split_once('/').ok_or(invalid("person.accounts"))?;
        if !text_ok(a) || up.is_empty() || claim.is_empty() {
            return Err(invalid("person.accounts"));
        }
        if !accounts.iter().any(|(id, _): &(String, String)| id == a) {
            accounts.push((a.clone(), up.to_owned()));
        }
    }
    Ok(Person {
        subject: p.subject.clone(),
        accounts,
        state: p.state.clone(),
        org: p.org.clone(),
    })
}

/// The kinds of client of the schema (policy.md "Entity types").
const CLIENT_KINDS: [&str; 3] = ["public", "confidential", "exchange"];

impl Engine {
    /// Decides one request of `caller`, a registry name that the transport gave.
    ///
    /// # Errors
    ///
    /// [`Refused`] when the question is not one: an unknown action, a request that does not fit
    /// the contract, an asker that may not ask it. A denial, including an allow that Cedar reached
    /// past an erroring policy, is an answer and not an error.
    pub fn decide(&self, caller: &str, req: &DecideRequest) -> Result<Verdict, Refused> {
        let tenant = req.tenant.as_str();
        let spec = ACTIONS
            .iter()
            .find(|s| s.name == req.action)
            .ok_or(invalid("action"))?;
        if !spec.askers.contains(&caller) {
            return Err(forbidden("action"));
        }
        if !tenant_ok(tenant, spec.every_tenant) {
            return Err(invalid("tenant"));
        }
        let (Some(p), Some(r)) = (req.principal.as_option(), req.resource.as_option()) else {
            return Err(invalid("principal"));
        };
        if !spec.principals.contains(&p.r#type.as_str()) {
            return Err(invalid("principal.type"));
        }
        let mut entities = vec![json!({
            "uid": {"type": "Boundary", "id": self.boundary}, "attrs": {}, "parents": []})];
        let mut person = None;
        let principal = if p.r#type == "Actor" {
            // An actor asks for itself, as the transport named it.
            if p.id != caller || req.actor.as_option().is_some_and(|a| a.name != caller) {
                return Err(forbidden("principal.id"));
            }
            entities
                .push(json!({"uid": {"type": "Actor", "id": caller}, "attrs": {}, "parents": []}));
            uid_of("Actor", caller)
        } else {
            let pf = person_of(req)?;
            if pf.subject != p.id {
                return Err(invalid("person.subject"));
            }
            let u = uid_of("Person", &pf.subject);
            person = Some(pf);
            u
        };
        let (resource_type, resource_id) = match r.r#type.as_str() {
            "Boundary" if r.id == self.boundary => ("Boundary", self.boundary.clone()),
            "Boundary" => return Err(invalid("resource.id")),
            "Client" if spec.token => {
                let c = req.client.as_option().ok_or(invalid("client"))?;
                if c.id != r.id || !text_ok(&c.id) || c.id.contains('/') {
                    return Err(invalid("client.id"));
                }
                // An empty or unknown kind is refused, not defaulted: a policy that forbids a
                // kind of client would otherwise miss it.
                if !CLIENT_KINDS.contains(&c.kind.as_str()) {
                    return Err(invalid("client.kind"));
                }
                if c.requires.len() > REQUIRES_MAX {
                    return Err(invalid("client.requires"));
                }
                // A client id carries its boundary (policy.md "Entity types"): `dev/example-app`.
                let id = format!("{}/{}", self.boundary, c.id);
                // A required name the vocabulary does not declare can be held by nobody, so it
                // cannot admit: it is left out and the client stays as strict as it was written.
                let requires: Vec<Value> = c
                    .requires
                    .iter()
                    .filter_map(|n| self.vocab.parse_name(n))
                    .map(|g| entity_ref("Grant", &g.id()))
                    .collect();
                entities.push(json!({
                    "uid": {"type": "Client", "id": id},
                    "attrs": {"kind": c.kind, "requires": requires},
                    "parents": [{"type": "Boundary", "id": self.boundary}],
                }));
                ("Client", id)
            }
            _ => return Err(invalid("resource.type")),
        };
        let (Some(principal), Some(resource), Some(action)) = (
            principal,
            uid_of(resource_type, &resource_id),
            uid_of("Action", spec.name),
        ) else {
            return Err(invalid("request"));
        };

        let context = if spec.name == "audit.seal" || spec.name == "audit.index" {
            json!({})
        } else {
            context_of(req.context.as_option()).ok_or(invalid("context"))?
        };

        entities.extend(self.grant_entities.iter().cloned());
        let mut grant_names = Vec::new();
        if let Some(pf) = &person {
            for (id, up) in &pf.accounts {
                // The account's own tenant is the sign-in's; the first version links an account
                // in the tenant of the person (policy.md "Entity types").
                entities.push(json!({
                    "uid": {"type": "Account", "id": id},
                    "attrs": {"upstream": up, "org": pf.org},
                    "parents": [],
                }));
            }
            let held = if spec.token {
                Some(
                    self.held_grants(pf, &entities)
                        .map_err(|()| invalid("request"))?,
                )
            } else {
                None
            };
            if let Some(h) = &held {
                grant_names = h.iter().map(GrantName::id).collect();
            }
            entities.push(person_entity(pf, held.as_ref()));
        }
        let entities = self.entities(entities).map_err(|_| invalid("request"))?;
        let e = self
            .evaluate_uids(principal, action, resource, context, &entities)
            .map_err(|_| invalid("request"))?;
        // A policy that errored may have been a forbid, and Cedar skips it: an allow that was
        // reached past an error is not one (ADR 0007: an evaluation that cannot be completed is a
        // denial). That is Cedar's answer, so it is a denial and not an error.
        let past_error = e.allow && e.errors > 0;
        Ok(Verdict {
            allow: e.allow && !past_error,
            action: spec.name,
            reasons: if past_error { Vec::new() } else { e.reasons },
            grant_names: if past_error { Vec::new() } else { grant_names },
            tenant: tenant.to_owned(),
            why: if past_error { "evaluation" } else { "" },
            errors: e.errors,
        })
    }

    /// The grant names the person holds (policy.md "How a person's grants are found"): `grant.hold`
    /// asked for every grant name of the vocabulary, a sensitive one counted only when a
    /// determining policy names it in full (REQ-POLICY-011), then the ladder.
    fn held_grants(&self, pf: &Person, base: &[Value]) -> Result<BTreeSet<GrantName>, ()> {
        let mut ents = base.to_vec();
        ents.push(person_entity(pf, None));
        let entities: Entities = self.entities(ents).map_err(|_| ())?;
        let principal = uid_of("Person", &pf.subject).ok_or(())?;
        let action = uid_of("Action", "grant.hold").ok_or(())?;
        let mut held = BTreeSet::new();
        for (g, sensitive) in self.vocab.grants() {
            let resource = uid_of("Grant", &g.id()).ok_or(())?;
            let e = self
                .evaluate_uids(
                    principal.clone(),
                    action.clone(),
                    resource,
                    json!({}),
                    &entities,
                )
                .map_err(|_| ())?;
            // A grant name counts as held only on a clean allow: a revocation that errored must not
            // be skipped into a hold.
            if !e.allow || e.errors > 0 {
                continue;
            }
            if sensitive
                && !e
                    .reasons
                    .iter()
                    .any(|r| self.names_in_full(&r.policy_id, &g))
            {
                continue;
            }
            held.insert(g);
        }
        Ok(self.vocab.expand(&held))
    }
}

fn person_entity(pf: &Person, grants: Option<&BTreeSet<GrantName>>) -> Value {
    let mut attrs = Map::new();
    attrs.insert("org".into(), json!(pf.org));
    attrs.insert("state".into(), json!(pf.state));
    if let Some(g) = grants {
        attrs.insert(
            "grants".into(),
            Value::Array(g.iter().map(|g| entity_ref("Grant", &g.id())).collect()),
        );
    }
    json!({
        "uid": {"type": "Person", "id": pf.subject},
        "attrs": Value::Object(attrs),
        "parents": pf.accounts.iter().map(|(id, _)| json!({"type": "Account", "id": id})).collect::<Vec<_>>(),
    })
}

impl Refused {
    /// A field that does not fit the contract, named by path.
    #[must_use]
    pub const fn schema(path: &'static str) -> Self {
        invalid(path)
    }
}
