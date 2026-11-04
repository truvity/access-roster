//! The compiled policy: the four layers of ADR 0007 as one Cedar set, checked against the schema,
//! and the evaluation of one request against it.
//!
//! An [`Engine`] is immutable. A reload builds a new one and swaps it in only when it is whole, so
//! the engine in force is always one that passed every check below (ADR 0007 "Cedar in a Rust
//! actor": a set that fails is refused as a whole and the set in force stays).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr as _;

use aws_lc_rs::digest;
use cedar_policy::{
    ActionConstraint, Authorizer, Context, Decision, Effect, Entities, EntityId, EntityTypeName,
    EntityUid, PolicyId, PolicySet, Request, ResourceConstraint, Schema, SlotId, Template,
    ValidationMode, Validator,
};
use serde_json::{Value, json};

use crate::schema;
use crate::vocab::{GrantName, Vocabulary};

/// One Cedar file of the config layer: the id of the `Policy` item and its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDoc {
    pub file: String,
    pub cedar: String,
}

/// A template link (policy.md "Template links"): the id of the link becomes the id of the linked
/// policy, which the reasons and the audit record name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub template_id: String,
    pub link_id: String,
    /// Slot (`?principal`, `?resource`) to entity (`Account::"acme/s-01"`).
    pub args: BTreeMap<String, String>,
    /// The layer the link is in: `operator` or `tenant`.
    pub layer: String,
}

/// Everything a set is built from.
#[derive(Clone, Debug)]
pub struct Inputs {
    pub boundary: String,
    pub policies: Vec<PolicyDoc>,
    /// The YAML of the `GrantVocabulary` document.
    pub vocabulary: Vec<u8>,
    pub links: Vec<Link>,
}

impl Inputs {
    /// A digest of the inputs, to tell a reload that changed nothing from one that did. It is not
    /// the digest of the set: that one also names the schema and the built-in layer.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut fields: Vec<Vec<u8>> =
            vec![self.boundary.clone().into_bytes(), self.vocabulary.clone()];
        let mut docs: Vec<&PolicyDoc> = self.policies.iter().collect();
        docs.sort_by(|a, b| a.file.cmp(&b.file));
        for d in docs {
            fields.push(d.file.clone().into_bytes());
            fields.push(d.cedar.clone().into_bytes());
        }
        let mut links: Vec<&Link> = self.links.iter().collect();
        links.sort_by(|a, b| a.link_id.cmp(&b.link_id));
        for l in links {
            fields.push(l.link_id.clone().into_bytes());
            fields.push(l.template_id.clone().into_bytes());
            for (k, v) in &l.args {
                fields.push(k.clone().into_bytes());
                fields.push(v.clone().into_bytes());
            }
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        digest_of(&refs)
    }
}

/// Why a set was not built: one line for each fault, each naming a policy id, a file or a path,
/// and never a value.
#[derive(Debug, PartialEq, Eq)]
pub struct LoadError(pub Vec<String>);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join("; "))
    }
}

impl std::error::Error for LoadError {}

/// A policy that determined a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    pub policy_id: String,
    pub layer: String,
    pub annotations: BTreeMap<String, String>,
}

/// What Cedar decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub allow: bool,
    pub reasons: Vec<Reason>,
    /// Policies that errored. An erroring policy counts as no permit and no forbid.
    pub errors: usize,
}

/// A request that does not fit the schema.
#[derive(Debug, PartialEq, Eq)]
pub struct Misfit(pub String);

/// The built-in layer's name, and the config layer's.
pub const LAYER_BUILTIN: &str = "built-in";
pub const LAYER_CONFIG: &str = "config";

/// The compiled policy of one boundary.
pub struct Engine {
    pub(crate) boundary: String,
    pub(crate) schema: Schema,
    set: PolicySet,
    pub(crate) vocab: Vocabulary,
    layers: HashMap<String, String>,
    /// Policy id to the grant name its resource is, when it is `resource == Grant::"..."`.
    names_grant: HashMap<String, String>,
    /// The `Grant` entities of the vocabulary, as Cedar JSON.
    pub(crate) grant_entities: Vec<Value>,
    digest: String,
    authorizer: Authorizer,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("boundary", &self.boundary)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// The entity of a type and an id, the id taken verbatim (no quoting, no escapes).
#[must_use]
pub fn uid_of(ty: &str, id: &str) -> Option<EntityUid> {
    let ty = EntityTypeName::from_str(ty).ok()?;
    Some(EntityUid::from_type_name_and_id(ty, EntityId::new(id)))
}

fn uid(text: &str) -> Result<EntityUid, String> {
    EntityUid::from_str(text).map_err(|_| "not an entity".to_owned())
}

/// Every `{"type": T, "id": ...}` in a JSON policy (EST), for the entity type `ty`.
fn entity_refs(v: &Value, ty: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            if let (Some(Value::String(t)), Some(Value::String(id))) = (m.get("type"), m.get("id"))
                && t == ty
            {
                out.push(id.clone());
            }
            for x in m.values() {
                entity_refs(x, ty, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| entity_refs(x, ty, out)),
        _ => {}
    }
}

/// `@step_up("acr_values=<values> max_age=<seconds>")` (policy.md "Step-up"): the values RFC 9470
/// puts in `insufficient_user_authentication`, at least one of them, each once.
fn step_up_well_formed(v: &str) -> bool {
    let (mut acr, mut age) = (false, false);
    for part in v.split(' ') {
        match part.split_once('=') {
            Some(("acr_values", x))
                if !acr && !x.is_empty() && x.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                acr = true;
            }
            Some(("max_age", x))
                if !age
                    && !x.is_empty()
                    && x.len() <= 9
                    && x.bytes().all(|b| b.is_ascii_digit()) =>
            {
                age = true;
            }
            _ => return false,
        }
    }
    acr || age
}

fn plain_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
}

/// Takes the `@id` of a policy or template: present, valid and not used before. The `@step_up`
/// annotation is checked here too.
fn claim(
    (layers, problems): (&mut HashMap<String, String>, &mut Vec<String>),
    (layer, file): (&str, &str),
    id: Option<&str>,
    (step_up, forbid): (Option<&str>, bool),
) -> Option<PolicyId> {
    let Some(id) = id else {
        problems.push(format!("{file}: a policy has no @id"));
        return None;
    };
    if !plain_id(id) {
        problems.push(format!("{file}: an @id is not a valid id"));
        return None;
    }
    if layers.contains_key(id) {
        problems.push(format!("{file}: the @id {id} is used twice"));
        return None;
    }
    if let Some(s) = step_up {
        if !forbid {
            problems.push(format!("{id}: @step_up is only for a forbid"));
        } else if !step_up_well_formed(s) {
            problems.push(format!(
                "{id}: @step_up is not acr_values=<values> max_age=<seconds>"
            ));
        }
    }
    layers.insert(id.to_owned(), layer.to_owned());
    PolicyId::from_str(id).ok()
}

/// Adds the policies and templates of one text under the ids of their `@id` annotations.
fn add_text(
    set: &mut PolicySet,
    layers: &mut HashMap<String, String>,
    layer: &str,
    file: &str,
    text: &str,
    problems: &mut Vec<String>,
) {
    let parsed = match PolicySet::from_str(text) {
        Ok(p) => p,
        Err(_) => {
            problems.push(format!("{file}: does not parse"));
            return;
        }
    };
    for p in parsed.policies() {
        let Some(id) = claim(
            (layers, problems),
            (layer, file),
            p.annotation("id"),
            (p.annotation("step_up"), p.effect() == Effect::Forbid),
        ) else {
            continue;
        };
        if set.add(p.new_id(id)).is_err() {
            problems.push(format!("{file}: a policy could not be added"));
        }
    }
    for t in parsed.templates() {
        let Some(id) = claim(
            (layers, problems),
            (layer, file),
            t.annotation("id"),
            (t.annotation("step_up"), t.effect() == Effect::Forbid),
        ) else {
            continue;
        };
        if set.add_template(t.new_id(id)).is_err() {
            problems.push(format!("{file}: a template could not be added"));
        }
    }
}

/// The SHA-384 of a length-prefixed sequence of fields, in lower-case hex.
fn digest_of(fields: &[&[u8]]) -> String {
    let mut ctx = digest::Context::new(&digest::SHA384);
    ctx.update(b"sluis-policy-digest-v1");
    for f in fields {
        ctx.update(&u64::try_from(f.len()).unwrap_or(u64::MAX).to_be_bytes());
        ctx.update(f);
    }
    let mut out = String::with_capacity(96);
    for b in ctx.finish().as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl Engine {
    /// Builds the set, and refuses it as a whole when any of these fails: every file parses; every
    /// policy and template has one `@id`, unique across the set; every `@step_up` is on a forbid and
    /// well formed; the whole set validates against the schema; every `Grant::"..."` is a grant
    /// name of the vocabulary; every link names a template and fits its slots; every binding passes
    /// the probe (policy.md "What `sluis config check` checks"; REQ-POLICY-010, -012).
    ///
    /// # Errors
    ///
    /// [`LoadError`] with one line for every fault found.
    pub fn build(inputs: &Inputs) -> Result<Self, LoadError> {
        let schema = schema::schema().map_err(|e| LoadError(vec![e]))?;
        let vocab = Vocabulary::parse(&inputs.vocabulary)
            .map_err(|e| LoadError(vec![format!("GrantVocabulary: {e}")]))?;

        let mut problems = Vec::new();
        let mut set = PolicySet::new();
        let mut layers = HashMap::new();
        add_text(
            &mut set,
            &mut layers,
            LAYER_BUILTIN,
            "built-in",
            schema::BUILTIN,
            &mut problems,
        );
        let mut seen_files = HashSet::new();
        for d in &inputs.policies {
            if !seen_files.insert(d.file.as_str()) {
                problems.push(format!("{}: the file is given twice", d.file));
                continue;
            }
            add_text(
                &mut set,
                &mut layers,
                LAYER_CONFIG,
                &d.file,
                &d.cedar,
                &mut problems,
            );
        }
        for l in &inputs.links {
            let mut vals = HashMap::new();
            for (slot, ent) in &l.args {
                let id = match slot.as_str() {
                    "?principal" => SlotId::principal(),
                    "?resource" => SlotId::resource(),
                    _ => {
                        problems.push(format!("link {}: an unknown slot", l.link_id));
                        continue;
                    }
                };
                match uid(ent) {
                    // The first version's templates bind an account to a grant name (policy.md
                    // "Template links"): a slot of another type means the layers have drifted.
                    Ok(u)
                        if u.type_name().to_string()
                            == if slot == "?principal" {
                                "Account"
                            } else {
                                "Grant"
                            } =>
                    {
                        vals.insert(id, u);
                    }
                    Ok(_) => {
                        problems.push(format!("link {}: a slot is of the wrong type", l.link_id))
                    }
                    Err(_) => problems.push(format!("link {}: a slot is not an entity", l.link_id)),
                }
            }
            if layers.contains_key(&l.link_id) || !plain_id(&l.link_id) {
                problems.push(format!("link {}: the id is used or not valid", l.link_id));
                continue;
            }
            // A link that cannot be applied is a refusal of the set: ignoring it could drop a forbid
            // (policy.md "How links reach policy").
            let (Ok(t), Ok(n)) = (
                PolicyId::from_str(&l.template_id),
                PolicyId::from_str(&l.link_id),
            );
            if set.link(t, n, vals).is_err() {
                problems.push(format!(
                    "link {}: does not apply to its template",
                    l.link_id
                ));
                continue;
            }
            layers.insert(l.link_id.clone(), l.layer.clone());
        }
        if !problems.is_empty() {
            return Err(LoadError(problems));
        }

        // The schema (REQ-POLICY: a policy that does not fit is refused, naming the policy).
        let validation = Validator::new(schema.clone()).validate(&set, ValidationMode::Strict);
        // A warning is a policy that can never apply (it contradicts the schema), or text that
        // looks other than it is (mixed scripts, bidirectional controls): refused like an error.
        if !validation.validation_passed_without_warnings() {
            let lines = validation
                .validation_errors()
                .map(|e| format!("{}: does not fit the schema ({e})", e.policy_id()))
                .chain(
                    validation
                        .validation_warnings()
                        .map(|w| format!("{}: is suspect against the schema ({w})", w.policy_id())),
                )
                .collect();
            return Err(LoadError(lines));
        }

        // Every grant name a policy writes is a grant name of the vocabulary (REQ-POLICY-010).
        let mut names_grant = HashMap::new();
        for p in set.policies() {
            if let Ok(j) = p.to_json() {
                let mut refs = Vec::new();
                entity_refs(&j, "Grant", &mut refs);
                for r in refs {
                    if vocab.parse_name(&r).is_none() {
                        problems.push(format!(
                            "{}: names a grant name the vocabulary does not declare",
                            p.id()
                        ));
                    }
                }
            }
            if let ResourceConstraint::Eq(e) = p.resource_constraint()
                && e.type_name().to_string() == "Grant"
            {
                names_grant.insert(p.id().to_string(), e.id().escaped().to_string());
            }
        }
        for t in set.templates() {
            if let Ok(j) = t.to_json() {
                let mut refs = Vec::new();
                entity_refs(&j, "Grant", &mut refs);
                for r in refs {
                    if vocab.parse_name(&r).is_none() {
                        problems.push(format!(
                            "{}: names a grant name the vocabulary does not declare",
                            t.id()
                        ));
                    }
                }
            }
        }
        for l in &inputs.links {
            for ent in l.args.values() {
                if let Ok(u) = uid(ent)
                    && u.type_name().to_string() == "Grant"
                    && vocab.parse_name(u.id().unescaped()).is_none()
                {
                    problems.push(format!(
                        "link {}: names a grant name the vocabulary does not declare",
                        l.link_id
                    ));
                }
            }
        }
        if !problems.is_empty() {
            return Err(LoadError(problems));
        }

        let grant_entities = vocab
            .grants()
            .into_iter()
            .map(|(g, sensitive)| grant_entity(&g, sensitive))
            .collect();

        let digest = {
            let mut docs: Vec<&PolicyDoc> = inputs.policies.iter().collect();
            docs.sort_by(|a, b| a.file.cmp(&b.file));
            let mut links: Vec<&Link> = inputs.links.iter().collect();
            links.sort_by(|a, b| a.link_id.cmp(&b.link_id));
            let schema_text = schema::text();
            let mut fields: Vec<Vec<u8>> = vec![
                schema::VERSION.as_bytes().to_vec(),
                schema_text.into_bytes(),
                schema::BUILTIN.as_bytes().to_vec(),
                inputs.boundary.as_bytes().to_vec(),
                inputs.vocabulary.clone(),
            ];
            for d in docs {
                fields.push(d.file.clone().into_bytes());
                fields.push(d.cedar.clone().into_bytes());
            }
            for l in links {
                fields.push(l.link_id.clone().into_bytes());
                fields.push(l.template_id.clone().into_bytes());
                fields.push(l.layer.clone().into_bytes());
                for (k, v) in &l.args {
                    fields.push(k.clone().into_bytes());
                    fields.push(v.clone().into_bytes());
                }
            }
            let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
            digest_of(&refs)
        };

        let engine = Self {
            boundary: inputs.boundary.clone(),
            schema,
            set,
            vocab,
            layers,
            names_grant,
            grant_entities,
            digest,
            authorizer: Authorizer::new(),
        };
        engine.probe()?;
        Ok(engine)
    }

    /// The digest of the set, the vocabulary and the schema version, for the audit record.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The vocabulary of the boundary.
    #[must_use]
    pub fn vocabulary(&self) -> &Vocabulary {
        &self.vocab
    }

    /// The loader tries each binding (policy.md "How a person's grants are found"): a permit on
    /// `grant.hold` that names an account is run for a probe person of that account against every
    /// grant name. One that no grant name satisfies expands to nothing (REQ-POLICY-012); one that
    /// satisfies several roles of one scope and thing at once has a wildcard in the role position.
    fn probe(&self) -> Result<(), LoadError> {
        let hold = uid("Action::\"grant.hold\"").map_err(|e| LoadError(vec![e]))?;
        let mut problems = Vec::new();
        for p in self.set.policies() {
            if p.effect() != Effect::Permit
                || p.action_constraint() != ActionConstraint::Eq(hold.clone())
            {
                continue;
            }
            let Ok(j) = p.to_json() else { continue };
            let mut accounts = Vec::new();
            entity_refs(&j, "Account", &mut accounts);
            if accounts.is_empty() {
                continue;
            }
            let mut only = PolicySet::new();
            if only.add(p.clone()).is_err() {
                continue;
            }
            for account in accounts {
                let satisfied = self.probe_one(&only, &account);
                if satisfied.is_empty() {
                    problems.push(format!(
                        "{}: expands to no grant name of the vocabulary",
                        p.id()
                    ));
                    break;
                }
                let mut roles: HashMap<(&str, &str), usize> = HashMap::new();
                for g in &satisfied {
                    *roles.entry((&g.scope, &g.thing)).or_default() += 1;
                }
                if roles.values().any(|n| *n > 1) {
                    problems.push(format!(
                        "{}: gives several roles of one scope and thing at once",
                        p.id()
                    ));
                    break;
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(LoadError(problems))
        }
    }

    fn probe_one(&self, only: &PolicySet, account: &str) -> Vec<GrantName> {
        let (upstream, _) = account.split_once('/').unwrap_or((account, ""));
        let mut ents = self.grant_entities.clone();
        ents.push(
            json!({"uid": {"type": "Boundary", "id": self.boundary}, "attrs": {}, "parents": []}),
        );
        ents.push(json!({"uid": {"type": "Account", "id": account},
            "attrs": {"upstream": upstream, "org": ""}, "parents": []}));
        ents.push(json!({"uid": {"type": "Person", "id": "probe"},
            "attrs": {"org": "", "state": "live"},
            "parents": [{"type": "Account", "id": account}]}));
        let Ok(entities) = Entities::from_json_value(Value::Array(ents), Some(&self.schema)) else {
            return Vec::new();
        };
        let Ok(person) = uid("Person::\"probe\"") else {
            return Vec::new();
        };
        let Ok(action) = uid("Action::\"grant.hold\"") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (g, _) in self.vocab.grants() {
            let Ok(resource) = uid(&format!("Grant::\"{}\"", g.id())) else {
                continue;
            };
            let Ok(ctx) = Context::from_json_value(json!({}), Some((&self.schema, &action))) else {
                continue;
            };
            let Ok(req) = Request::new(
                person.clone(),
                action.clone(),
                resource,
                ctx,
                Some(&self.schema),
            ) else {
                continue;
            };
            if self
                .authorizer
                .is_authorized(&req, only, &entities)
                .decision()
                == Decision::Allow
            {
                out.push(g);
            }
        }
        out
    }

    /// Evaluates one request against the set, the entities given as text (`Person::"p-1"`). The
    /// vectors of the reference page use this form.
    ///
    /// # Errors
    ///
    /// [`Misfit`] as for [`Engine::evaluate_uids`], and when a name is not an entity.
    pub fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: Value,
        entities: &Entities,
    ) -> Result<Evaluation, Misfit> {
        let bad = |what: &str| Misfit(what.to_owned());
        self.evaluate_uids(
            uid(principal).map_err(|_| bad("principal"))?,
            uid(action).map_err(|_| bad("action"))?,
            uid(resource).map_err(|_| bad("resource"))?,
            context,
            entities,
        )
    }

    /// Evaluates one request against the set.
    ///
    /// # Errors
    ///
    /// [`Misfit`] when the request does not fit the schema: an unknown action, a principal or
    /// resource of a type the action does not apply to, or a context of the wrong shape. Such a
    /// request is not decided.
    pub fn evaluate_uids(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Value,
        entities: &Entities,
    ) -> Result<Evaluation, Misfit> {
        let bad = |what: &str| Misfit(what.to_owned());
        let ctx = Context::from_json_value(context, Some((&self.schema, &action)))
            .map_err(|_| bad("context"))?;
        let req = Request::new(principal, action, resource, ctx, Some(&self.schema))
            .map_err(|_| bad("request"))?;
        let resp = self.authorizer.is_authorized(&req, &self.set, entities);
        let mut reasons = Vec::new();
        for id in resp.diagnostics().reason() {
            let key = id.to_string();
            let annotations = self
                .set
                .policy(id)
                .map(|p| {
                    p.annotations()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect()
                })
                .or_else(|| {
                    self.set.template(id).map(|t: &Template| {
                        t.annotations()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect()
                    })
                })
                .unwrap_or_default();
            reasons.push(Reason {
                layer: self.layers.get(&key).cloned().unwrap_or_default(),
                policy_id: key,
                annotations,
            });
        }
        reasons.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        Ok(Evaluation {
            allow: resp.decision() == Decision::Allow,
            reasons,
            errors: resp.diagnostics().errors().count(),
        })
    }

    /// Whether the policy names the grant in full: `resource == Grant::"..."`. A sensitive grant
    /// name counts as held only when a determining policy does (REQ-POLICY-011).
    pub(crate) fn names_in_full(&self, policy_id: &str, grant: &GrantName) -> bool {
        self.names_grant
            .get(policy_id)
            .is_some_and(|g| *g == grant.id())
    }

    /// Entities from Cedar JSON, checked against the schema.
    ///
    /// # Errors
    ///
    /// [`Misfit`] when an entity does not fit the schema.
    pub fn entities(&self, list: Vec<Value>) -> Result<Entities, Misfit> {
        Entities::from_json_value(Value::Array(list), Some(&self.schema))
            .map_err(|_| Misfit("entities".into()))
    }
}

/// The `Grant` entity of a grant name.
pub(crate) fn grant_entity(g: &GrantName, sensitive: bool) -> Value {
    json!({
        "uid": {"type": "Grant", "id": g.id()},
        "attrs": {"scope": g.scope, "thing": g.thing, "role": g.role, "sensitive": sensitive},
        "parents": [],
    })
}
