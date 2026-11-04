//! One decision: the request of an asker becomes a Cedar request and its entities, the person's
//! grant names are found, and Cedar decides (policy.md "What a decision holds", "How a person's
//! grants are found").
//!
//! Fail closed everywhere: a request that cannot be turned into a request of the schema, or whose
//! asker may not ask it, is a denial with a closed word saying which, never a guess.

use std::collections::BTreeSet;

use cedar_policy::Entities;
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
    },
    Spec {
        name: "token.exchange",
        principals: &["Person"],
        askers: &["exchange"],
        every_tenant: false,
        token: true,
    },
    Spec {
        name: "audit.seal",
        principals: &["Actor"],
        askers: &["writer"],
        every_tenant: false,
        token: false,
    },
    Spec {
        name: "audit.index",
        principals: &["Actor"],
        askers: &["indexer"],
        every_tenant: true,
        token: false,
    },
    Spec {
        name: "audit.read",
        principals: &["Actor", "Person"],
        askers: &["reader", "console"],
        every_tenant: true,
        token: false,
    },
];

/// The most a request may carry of each repeated or long field.
const ACCOUNTS_MAX: usize = 32;
const REQUIRES_MAX: usize = 64;
const AMR_MAX: usize = 16;
const TEXT_MAX: usize = 256;

/// The outcome of a decision before anything is sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub allow: bool,
    /// The Cedar action, when the request named one of this build's.
    pub action: &'static str,
    pub reasons: Vec<Reason>,
    /// For a token action, the full set of held grant names after the ladder (sorted).
    pub grant_names: Vec<String>,
    /// The tenants a grant would name: the tenant of the question.
    pub tenant: String,
    /// Empty for a decision of Cedar. Otherwise the closed word for why the question was not
    /// decided: `action`, `asker`, `principal`, `resource`, `tenant`, `facts`, `schema` or
    /// `evaluation` (a policy errored on the way to an allow).
    pub why: &'static str,
    /// Policies that errored while deciding.
    pub errors: usize,
}

impl Verdict {
    fn denied(action: &'static str, tenant: &str, why: &'static str) -> Self {
        Self {
            allow: false,
            action,
            reasons: Vec::new(),
            grant_names: Vec::new(),
            tenant: tenant.to_owned(),
            why,
            errors: 0,
        }
    }
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
}

fn person_of(req: &DecideRequest) -> Option<Person> {
    let p = req.person.as_option()?;
    if !text_ok(&p.subject) || !text_ok(&p.state) || p.accounts.len() > ACCOUNTS_MAX {
        return None;
    }
    let mut accounts = Vec::new();
    for a in &p.accounts {
        // `<upstream>/<claim value>` (policy.md "Entity types").
        let (up, claim) = a.split_once('/')?;
        if !text_ok(a) || up.is_empty() || claim.is_empty() {
            return None;
        }
        if !accounts.iter().any(|(id, _): &(String, String)| id == a) {
            accounts.push((a.clone(), up.to_owned()));
        }
    }
    Some(Person {
        subject: p.subject.clone(),
        accounts,
        state: p.state.clone(),
    })
}

impl Engine {
    /// Decides one request of `caller`, a registry name that the transport gave.
    #[must_use]
    pub fn decide(&self, caller: &str, req: &DecideRequest) -> Verdict {
        let tenant = req.tenant.as_str();
        let Some(spec) = ACTIONS.iter().find(|s| s.name == req.action) else {
            return Verdict::denied("", tenant, "action");
        };
        let deny = |why| Verdict::denied(spec.name, tenant, why);
        if !spec.askers.contains(&caller) {
            return deny("asker");
        }
        if !tenant_ok(tenant, spec.every_tenant) {
            return deny("tenant");
        }
        let (Some(p), Some(r)) = (req.principal.as_option(), req.resource.as_option()) else {
            return deny("schema");
        };
        if !spec.principals.contains(&p.r#type.as_str()) {
            return deny("principal");
        }
        let mut entities = vec![json!({
            "uid": {"type": "Boundary", "id": self.boundary}, "attrs": {}, "parents": []})];
        let (principal, resource_id, resource_type);
        let mut person = None;
        match p.r#type.as_str() {
            "Actor" => {
                // An actor asks for itself, as the transport named it.
                if p.id != caller || req.actor.as_option().is_some_and(|a| a.name != caller) {
                    return deny("principal");
                }
                entities.push(
                    json!({"uid": {"type": "Actor", "id": caller}, "attrs": {}, "parents": []}),
                );
                principal = uid_of("Actor", caller);
            }
            _ => {
                let Some(pf) = person_of(req) else {
                    return deny("facts");
                };
                if pf.subject != p.id {
                    return deny("facts");
                }
                principal = uid_of("Person", &pf.subject);
                person = Some(pf);
            }
        }
        match r.r#type.as_str() {
            "Boundary" if r.id == self.boundary => {
                resource_id = self.boundary.clone();
                resource_type = "Boundary";
            }
            "Boundary" => return deny("resource"),
            "Client" if spec.token => {
                let Some(c) = req.client.as_option() else {
                    return deny("facts");
                };
                if c.id != r.id
                    || !text_ok(&c.id)
                    || c.id.contains('/')
                    || c.requires.len() > REQUIRES_MAX
                {
                    return deny("facts");
                }
                // A client id carries its boundary (policy.md "Entity types"): `dev/example-app`.
                resource_id = format!("{}/{}", self.boundary, c.id);
                resource_type = "Client";
                // A required name the vocabulary does not declare can be held by nobody, so it
                // cannot admit: it is left out and the client stays as strict as it was written.
                let requires: Vec<Value> = c
                    .requires
                    .iter()
                    .filter_map(|n| self.vocab.parse_name(n))
                    .map(|g| entity_ref("Grant", &g.id()))
                    .collect();
                // `kind` is not in the contract's facts (policy.proto ClientFacts); no policy of
                // the schema reads it yet.
                entities.push(json!({
                    "uid": {"type": "Client", "id": resource_id},
                    "attrs": {"kind": "", "requires": requires},
                    "parents": [{"type": "Boundary", "id": self.boundary}],
                }));
            }
            _ => return deny("resource"),
        }
        let (Some(principal), Some(resource)) = (principal, uid_of(resource_type, &resource_id))
        else {
            return deny("schema");
        };

        let Some(context) = (if spec.name == "audit.seal" || spec.name == "audit.index" {
            Some(json!({}))
        } else {
            context_of(req.context.as_option())
        }) else {
            return deny("schema");
        };

        entities.extend(self.grant_entities.iter().cloned());
        let mut grant_names = Vec::new();
        if let Some(pf) = &person {
            for (id, up) in &pf.accounts {
                entities.push(json!({
                    "uid": {"type": "Account", "id": id},
                    "attrs": {"upstream": up, "org": tenant},
                    "parents": [],
                }));
            }
            let held = if spec.token {
                match self.held_grants(pf, tenant, &entities) {
                    Ok(h) => Some(h),
                    Err(()) => return deny("schema"),
                }
            } else {
                None
            };
            if let Some(h) = &held {
                grant_names = h.iter().map(GrantName::id).collect();
            }
            entities.push(person_entity(pf, tenant, held.as_ref()));
        }
        let Ok(entities) = self.entities(entities) else {
            return deny("schema");
        };
        let Some(action) = uid_of("Action", spec.name) else {
            return deny("schema");
        };
        match self.evaluate_uids(principal, action, resource, context, &entities) {
            // A policy that errored may have been a forbid, and Cedar skips it: an allow that was
            // reached past an error is not one (ADR 0007: an evaluation that cannot be completed is
            // a denial).
            Ok(e) if e.allow && e.errors > 0 => Verdict {
                allow: false,
                action: spec.name,
                reasons: Vec::new(),
                grant_names: Vec::new(),
                tenant: tenant.to_owned(),
                why: "evaluation",
                errors: e.errors,
            },
            Ok(e) => Verdict {
                allow: e.allow,
                action: spec.name,
                reasons: e.reasons,
                grant_names,
                tenant: tenant.to_owned(),
                why: "",
                errors: e.errors,
            },
            Err(_) => deny("schema"),
        }
    }

    /// The grant names the person holds (policy.md "How a person's grants are found"): `grant.hold`
    /// asked for every grant name of the vocabulary, a sensitive one counted only when a
    /// determining policy names it in full (REQ-POLICY-011), then the ladder.
    fn held_grants(
        &self,
        pf: &Person,
        tenant: &str,
        base: &[Value],
    ) -> Result<BTreeSet<GrantName>, ()> {
        let mut ents = base.to_vec();
        ents.push(person_entity(pf, tenant, None));
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

fn person_entity(pf: &Person, tenant: &str, grants: Option<&BTreeSet<GrantName>>) -> Value {
    let mut attrs = Map::new();
    attrs.insert("org".into(), json!(tenant));
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
