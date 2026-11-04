//! The payload of a config document (signed-config.md "The payload", step 6): the strict profile
//! of the bootstrap file, read into the Protobuf message of the kind.
//!
//! The shape of a document is one rule for every kind (decision D-17, and the one the records
//! leave open): the payload is a mapping from item id to item, and a singleton kind has one item
//! with the id `default`. `GrantVocabulary` is the exception, because its payload is the
//! vocabulary file itself, which policy parses (like a Cedar kind, whose payload is Cedar text).
//!
//! The message is the schema. No JSON Schema or protovalidate is generated for Rust yet, so this
//! module checks the same things by hand: the closed key list (an unknown key is refused, by place),
//! the types, the durations by the grammar of the bootstrap file, and the rules of the message.
//! An error names a path, never a value.

use buffa::Message as _;
use buffa_types::google::protobuf::Duration as PbDuration;
use sluis_proto::sluis::config::v2alpha1 as pb;
use sluis_registry::{Class, Kind};

use crate::address::valid_part;
use crate::yaml::{self, Value};

/// The id of the one item of a singleton kind (decision D-17).
pub const SINGLETON_ID: &str = "default";
/// The built-in cap of an access token (kinds.yaml, group TokenLifetime): config sits inside it.
pub const ACCESS_TOKEN_CAP: std::time::Duration = std::time::Duration::from_secs(3600);

/// A payload that is not valid for its kind: the path and the rule.
#[derive(Debug, PartialEq, Eq)]
pub struct PayloadError(pub String);

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type R<T> = Result<T, PayloadError>;

fn err<T>(path: &str, rule: &str) -> R<T> {
    Err(PayloadError(if path.is_empty() {
        rule.to_owned()
    } else {
        format!("{path}: {rule}")
    }))
}

fn child(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

/// The items of one document: (id, the kind's Protobuf bytes), sorted by id.
pub type Items = Vec<(String, Vec<u8>)>;

/// Whether this build reads the payload of the kind. The skeleton's kinds only.
#[must_use]
pub fn readable(kind: &Kind) -> bool {
    kind.class == Class::Config && SKELETON.contains(&kind.name)
}

const SKELETON: [&str; 9] = [
    "Boundary",
    "KeyPlan",
    "TokenLifetime",
    "GrantVocabulary",
    "AuditLog",
    "AuditCatalogue",
    "ExchangeTrust",
    "Upstream",
    "InstallationClient",
];

/// Whether a kind has one item, `default`; the keyed kinds use their name.
fn singleton(kind: &Kind) -> bool {
    !matches!(kind.name, "Upstream" | "InstallationClient")
}

/// Reads the payload of a document of `kind` into its items.
///
/// # Errors
///
/// [`PayloadError`] naming the path at fault.
pub fn decode(kind: &Kind, payload: &[u8]) -> R<Items> {
    if !readable(kind) {
        return err("", "this build has no reader for the kind");
    }
    let Ok(text) = std::str::from_utf8(payload) else {
        return err("", "not UTF-8");
    };
    let doc = yaml::parse(text).map_err(|e| PayloadError(e.to_string()))?;
    if kind.name == "GrantVocabulary" {
        // The vocabulary is policy's to read; here it is checked only for the profile.
        let item = pb::GrantVocabulary {
            document: payload.to_vec(),
            ..pb::GrantVocabulary::default()
        };
        return Ok(vec![(SINGLETON_ID.into(), item.encode_to_vec())]);
    }
    let Value::Map(entries) = doc else {
        return err("", "must be a mapping from item id to item");
    };
    if singleton(kind) && !(entries.len() == 1 && entries[0].0 == SINGLETON_ID) {
        return err("", "a singleton kind has one item, with the id default");
    }
    if entries.is_empty() {
        return err("", "has no item");
    }
    let mut items: Items = Vec::with_capacity(entries.len());
    for (id, value) in entries {
        if !valid_part(&id) {
            return err("<id>", "not a valid id");
        }
        let bytes = item(kind.name, &id, value)?;
        items.push((id, bytes));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

fn item(kind: &str, id: &str, v: Value) -> R<Vec<u8>> {
    let o = Obj::new(v, id)?;
    Ok(match kind {
        "Boundary" => boundary(o)?.encode_to_vec(),
        "KeyPlan" => key_plan(o)?.encode_to_vec(),
        "TokenLifetime" => token_lifetime(o)?.encode_to_vec(),
        "AuditLog" => audit_log(o)?.encode_to_vec(),
        "AuditCatalogue" => audit_catalogue(o)?.encode_to_vec(),
        "ExchangeTrust" => exchange_trust(o)?.encode_to_vec(),
        "Upstream" => upstream(o, id)?.encode_to_vec(),
        "InstallationClient" => installation_client(o, id)?.encode_to_vec(),
        _ => return err(id, "this build has no reader for the kind"),
    })
}

/// A mapping with a closed key list; each key is taken once, and `done` refuses what is left.
struct Obj {
    path: String,
    entries: Vec<(String, Value)>,
}

impl Obj {
    fn new(v: Value, path: &str) -> R<Self> {
        match v {
            Value::Map(entries) => Ok(Self {
                path: path.to_owned(),
                entries,
            }),
            _ => err(path, "must be a mapping"),
        }
    }

    fn take(&mut self, key: &str) -> Option<Value> {
        let i = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(i).1)
    }

    fn at(&self, key: &str) -> String {
        child(&self.path, key)
    }

    /// A string; absent is empty.
    fn string(&mut self, key: &str) -> R<String> {
        match self.take(key) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s),
            Some(_) => err(&self.at(key), "must be a string"),
        }
    }

    /// A non-empty string.
    fn required(&mut self, key: &str) -> R<String> {
        let s = self.string(key)?;
        if s.is_empty() {
            return err(&self.at(key), "required");
        }
        Ok(s)
    }

    /// A string from a closed list.
    fn one_of(&mut self, key: &str, allowed: &[&str]) -> R<String> {
        let s = self.required(key)?;
        if allowed.contains(&s.as_str()) {
            Ok(s)
        } else {
            err(&self.at(key), "not one of the values of the schema")
        }
    }

    fn strings(&mut self, key: &str) -> R<Vec<String>> {
        match self.take(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Seq(items)) => items
                .into_iter()
                .enumerate()
                .map(|(i, v)| match v {
                    Value::String(s) if !s.is_empty() => Ok(s),
                    _ => err(
                        &format!("{}[{i}]", self.at(key)),
                        "must be a non-empty string",
                    ),
                })
                .collect(),
            Some(_) => err(&self.at(key), "must be a list"),
        }
    }

    fn objects(&mut self, key: &str) -> R<Vec<Obj>> {
        match self.take(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Seq(items)) => items
                .into_iter()
                .enumerate()
                .map(|(i, v)| Obj::new(v, &format!("{}[{i}]", self.at(key))))
                .collect(),
            Some(_) => err(&self.at(key), "must be a list"),
        }
    }

    fn duration(&mut self, key: &str) -> R<Option<std::time::Duration>> {
        match self.take(key) {
            None => Ok(None),
            Some(v) => crate::bootstrap::duration(v, &self.at(key))
                .map(Some)
                .map_err(|e| PayloadError(e.0)),
        }
    }

    fn required_duration(&mut self, key: &str) -> R<std::time::Duration> {
        self.duration(key)?
            .map_or_else(|| err(&self.at(key), "required"), Ok)
    }

    fn uint32(&mut self, key: &str) -> R<u32> {
        match self.take(key) {
            None => Ok(0),
            Some(Value::Number(n)) => n
                .parse()
                .or_else(|_| err(&self.at(key), "must be a non-negative integer")),
            Some(_) => err(&self.at(key), "must be a non-negative integer"),
        }
    }

    fn done(self) -> R<()> {
        if self.entries.is_empty() {
            Ok(())
        } else {
            // An unknown key is the file's own text: name its place, not the key.
            err(&child(&self.path, "<key>"), "unknown key")
        }
    }
}

fn pb_duration(
    d: std::time::Duration,
) -> buffa::MessageField<PbDuration, buffa::Inline<PbDuration>> {
    buffa::MessageField::some(PbDuration {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: 0,
        ..PbDuration::default()
    })
}

/// A URL a client or the boundary is reached at: `https`, or `http` (the floor of an environment
/// is the set's to check, see `snapshot`).
fn url(o: &mut Obj, key: &str) -> R<String> {
    let s = o.required(key)?;
    check_url(&s, &o.at(key))?;
    Ok(s)
}

fn check_url(s: &str, path: &str) -> R<()> {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"));
    match rest {
        Some(r) if !r.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control()) => {
            Ok(())
        }
        _ => err(path, "must be an http or https URL"),
    }
}

fn boundary(mut o: Obj) -> R<pb::Boundary> {
    let name = o.required("name")?;
    let kind = o.required("kind")?;
    let level = o.required("level")?;
    let environment = o.one_of("environment", &["development", "staging", "production"])?;
    let issuer = url(&mut o, "issuer")?;
    let uid_block = o.uint32("uid_block")?;
    let declared_kinds = o.strings("declared_kinds")?;
    for (i, k) in declared_kinds.iter().enumerate() {
        if sluis_registry::kind_by_name(k).is_none_or(|k| k.class != Class::Config) {
            return err(
                &format!("declared_kinds[{i}]"),
                "not a config kind of the registry",
            );
        }
    }
    let default_tenant = o.string("default_tenant")?;
    if !default_tenant.is_empty() && !valid_part(&default_tenant) {
        return err(&o.at("default_tenant"), "not a valid tenant id");
    }
    o.done()?;
    Ok(pb::Boundary {
        name,
        kind,
        level,
        environment,
        issuer,
        uid_block,
        declared_kinds,
        default_tenant,
        ..pb::Boundary::default()
    })
}

fn key_plan(mut o: Obj) -> R<pb::KeyPlan> {
    let mut purposes = Vec::new();
    for mut p in o.objects("purposes")? {
        purposes.push(pb::KeyPurposePlan {
            purpose: p.required("purpose")?,
            algorithm: p.required("algorithm")?,
            slot: p.string("slot")?,
            ..pb::KeyPurposePlan::default()
        });
        p.done()?;
    }
    let cache_ttl = o.required_duration("cache_ttl")?;
    o.done()?;
    Ok(pb::KeyPlan {
        purposes,
        cache_ttl: pb_duration(cache_ttl),
        ..pb::KeyPlan::default()
    })
}

fn token_lifetime(mut o: Obj) -> R<pb::TokenLifetime> {
    let id_token = o.required_duration("id_token")?;
    let access_token = o.required_duration("access_token")?;
    if access_token > ACCESS_TOKEN_CAP {
        return err(&o.at("access_token"), "above the built-in cap of one hour");
    }
    let human_session_absolute = o.required_duration("human_session_absolute")?;
    let refresh_idle = o.required_duration("refresh_idle")?;
    o.done()?;
    Ok(pb::TokenLifetime {
        id_token: pb_duration(id_token),
        access_token: pb_duration(access_token),
        human_session_absolute: pb_duration(human_session_absolute),
        refresh_idle: pb_duration(refresh_idle),
        ..pb::TokenLifetime::default()
    })
}

fn audit_log(mut o: Obj) -> R<pb::AuditLog> {
    let project = o.required("project")?;
    let mut logs = Vec::new();
    for mut l in o.objects("logs")? {
        logs.push(pb::LogDecl {
            kind: l.one_of("kind", &["audit", "usage"])?,
            id: l.required("id")?,
            origin: l.required("origin")?,
            ..pb::LogDecl::default()
        });
        l.done()?;
    }
    if logs.is_empty() {
        return err(&o.at("logs"), "required");
    }
    let lock_mode = o.string("lock_mode")?;
    o.done()?;
    Ok(pb::AuditLog {
        project,
        logs,
        lock_mode,
        ..pb::AuditLog::default()
    })
}

fn audit_catalogue(mut o: Obj) -> R<pb::AuditCatalogue> {
    let release = o.required("release")?;
    let actions = o.strings("actions")?;
    if actions.is_empty() {
        return err(&o.at("actions"), "required");
    }
    for (i, a) in actions.iter().enumerate() {
        let ok = a.split('.').count() >= 2
            && a.split('.').all(|p| {
                p.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
                    && p.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            });
        if !ok {
            return err(&format!("{}[{i}]", o.at("actions")), "not an action name");
        }
    }
    o.done()?;
    Ok(pb::AuditCatalogue {
        release,
        actions,
        ..pb::AuditCatalogue::default()
    })
}

fn exchange_trust(mut o: Obj) -> R<pb::ExchangeTrust> {
    let mut issuers = Vec::new();
    for mut t in o.objects("issuers")? {
        let issuer = url(&mut t, "issuer")?;
        let audiences = t.strings("audiences")?;
        let proof_kind = t.required("proof_kind")?;
        let jwks_uri = t.string("jwks_uri")?;
        if !jwks_uri.is_empty() {
            check_url(&jwks_uri, &t.at("jwks_uri"))?;
        }
        issuers.push(pb::TrustedIssuer {
            issuer,
            audiences,
            proof_kind,
            jwks_uri,
            ..pb::TrustedIssuer::default()
        });
        t.done()?;
    }
    o.done()?;
    Ok(pb::ExchangeTrust {
        issuers,
        ..pb::ExchangeTrust::default()
    })
}

/// The name a message carries must be its item's id, or absent.
fn named(o: &mut Obj, key: &str, id: &str) -> R<String> {
    let given = o.string(key)?;
    if given.is_empty() || given == id {
        Ok(id.to_owned())
    } else {
        err(&o.at(key), "is not the id of the item")
    }
}

fn upstream(mut o: Obj, id: &str) -> R<pb::Upstream> {
    let name = named(&mut o, "name", id)?;
    let kind = o.one_of("kind", &["oidc"])?;
    let issuer = url(&mut o, "issuer")?;
    let client_id = o.required("client_id")?;
    let subject_claim = o.required("subject_claim")?;
    let org_claim = o.string("org_claim")?;
    let scopes = o.strings("scopes")?;
    o.done()?;
    Ok(pb::Upstream {
        name,
        kind,
        issuer,
        client_id,
        subject_claim,
        org_claim,
        scopes,
        ..pb::Upstream::default()
    })
}

fn installation_client(mut o: Obj, id: &str) -> R<pb::InstallationClient> {
    let client_id = named(&mut o, "id", id)?;
    let kind = o.one_of("kind", &["public", "confidential", "exchange"])?;
    let redirects = o.strings("redirects")?;
    for (i, r) in redirects.iter().enumerate() {
        check_url(r, &format!("{}[{i}]", o.at("redirects")))?;
    }
    let requires = o.strings("requires")?;
    let ttl_cap = o.duration("ttl_cap")?;
    let profile = o.string("profile")?;
    o.done()?;
    Ok(pb::InstallationClient {
        id: client_id,
        kind,
        redirects,
        requires,
        ttl_cap: ttl_cap.map(pb_duration).unwrap_or_default(),
        profile,
        ..pb::InstallationClient::default()
    })
}
