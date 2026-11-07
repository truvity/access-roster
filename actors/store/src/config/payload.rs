//! The payload of a config document (signed-config.md "The payload", step 6): the strict profile
//! of the bootstrap file, read into the Protobuf message of the kind.
//!
//! The shape of a document is one rule for every kind (decision D-17, and the one the records
//! leave open): the payload is a mapping from item id to item, and a singleton kind has one item
//! with the id `default`. `GrantVocabulary` is the exception, because its payload is the
//! vocabulary file itself, which policy parses. `Policy` is the other: its payload is Cedar text,
//! one file, which is the one item `default` (the grammar and the schema are policy's to check).
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
/// The built-in maximum of key@'s cache of opened data keys (ADR 0006, "The cache" and "Floors in code"): a KeyPlan
/// may shorten it and never lengthen it. key@'s reader of the payload holds the same maximum (`maxCacheTTL` in
/// actors/key), and the shared KeyPlan vectors (`cache_ttl_max_seconds`) tie the two, so a longer value is refused
/// when the configuration loads, by key@ and by `sluis config check` (REQ-KEYS-039).
pub const KEY_CACHE_TTL_MAX: std::time::Duration = std::time::Duration::from_secs(3600);

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

const SKELETON: [&str; 10] = [
    "Boundary",
    "KeyPlan",
    "TokenLifetime",
    "GrantVocabulary",
    "Policy",
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
    if kind.name == "Policy" {
        // Cedar text, not YAML (signed-config.md "The payload"). One document is one file, so the
        // kind has one item; policy parses the text and refuses what is not Cedar.
        if text.trim().is_empty() {
            return err("", "has no policy");
        }
        let item = pb::Policy {
            id: SINGLETON_ID.into(),
            cedar: text.to_owned(),
            ..pb::Policy::default()
        };
        return Ok(vec![(SINGLETON_ID.into(), item.encode_to_vec())]);
    }
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

    /// The value of a key, without taking it.
    fn peek(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Bytes written as base64url without padding (RFC 4648, section 5), strictly: the alphabet only, no padding, no
    /// stray bits in the last character. Absent or null is empty; `required` refuses that.
    fn base64url(&mut self, key: &str, required: bool) -> R<Vec<u8>> {
        use base64::Engine as _;
        let s = self.string(key)?;
        if s.is_empty() {
            if required {
                return err(&self.at(key), "required");
            }
            return Ok(Vec::new());
        }
        if !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return err(&self.at(key), "not base64url without padding");
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .or_else(|_| err(&self.at(key), "not base64url without padding"))
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
            // User information in the authority (`user:password@host`) is a credential in a document that is
            // printed, logged and reviewed as text; no issuer, key set or redirect needs it.
            if has_userinfo(r) {
                return err(path, "must not hold user information before the host");
            }
            Ok(())
        }
        _ => err(path, "must be an http or https URL"),
    }
}

/// Whether the authority of a URL (what follows `scheme://` up to the first `/`, `?` or `#`) holds an `@`.
pub(crate) fn has_userinfo(after_scheme: &str) -> bool {
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    after_scheme[..end].contains('@')
}

/// A client's redirect URI (REQ-AUTHN-004): `https`, or `http` on a loopback IP literal, `127.0.0.1` or `[::1]`, with
/// any port or none (RFC 8252 section 7.3). `localhost` is a name that may not resolve to loopback (RFC 8252 section
/// 8.3), so it is refused like any other host. This holds for every client kind and every environment; the
/// environment's floor (`snapshot`) adds nothing for a redirect.
fn check_redirect(s: &str, path: &str) -> R<()> {
    check_url(s, path)?;
    if s.starts_with("https://") || loopback_http(s) {
        Ok(())
    } else {
        err(path, "must be https, or http on a loopback IP literal")
    }
}

/// Whether `s` is an `http` URL whose host is the loopback IP literal `127.0.0.1` or `[::1]`, with an optional port
/// of 1 to 65535, followed by nothing, a path, a query or a fragment. A userinfo part or any other host is not.
pub(crate) fn loopback_http(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("http://") else {
        return false;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let port = authority
        .strip_prefix("127.0.0.1")
        .or_else(|| authority.strip_prefix("[::1]"));
    match port {
        Some("") => true,
        Some(p) => p.strip_prefix(':').is_some_and(|n| {
            !n.is_empty()
                && n.bytes().all(|c| c.is_ascii_digit())
                && n.parse::<u16>().is_ok_and(|n| n != 0)
        }),
        None => false,
    }
}

fn boundary(mut o: Obj) -> R<pb::Boundary> {
    let name = o.required("name")?;
    let kind = o.required("kind")?;
    let level = o.required("level")?;
    let environment = o.one_of("environment", &["development", "staging", "production"])?;
    let issuer = url(&mut o, "issuer")?;
    let uid_block = o.uint32("uid_block")?;
    // The pinned uids of the block must exist (REQ-ISO-073): a block past the end of the uid space gives no actor a uid.
    if !sluis_registry::uid_block_in_range(uid_block) {
        return err(&o.at("uid_block"), "the block gives a pinned name no uid");
    }
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

/// A wrap recipient is named by the RFC 7638 thumbprint of its wrapping key (ADR 0006, "Who may receive a wrap"):
/// SHA-256, so 43 characters of unpadded base64url. The last character carries 4 bits, so only 16 of its 64 values
/// are the canonical encoding of 32 bytes.
fn is_thumbprint(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        && matches!(
            s.as_bytes()[42],
            b'A' | b'E'
                | b'I'
                | b'M'
                | b'Q'
                | b'U'
                | b'Y'
                | b'c'
                | b'g'
                | b'k'
                | b'o'
                | b's'
                | b'w'
                | b'0'
                | b'4'
                | b'8'
        )
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
    if cache_ttl > KEY_CACHE_TTL_MAX {
        return err(&o.at("cache_ttl"), "above the built-in maximum of one hour");
    }
    let recipients = o.strings("recipients")?;
    for (i, r) in recipients.iter().enumerate() {
        if !is_thumbprint(r) {
            return err(
                &format!("{}[{i}]", o.at("recipients")),
                "not an RFC 7638 thumbprint",
            );
        }
        if recipients[..i].contains(r) {
            return err(&format!("{}[{i}]", o.at("recipients")), "listed twice");
        }
    }
    let slot_map = slot_map(&mut o)?;
    o.done()?;
    Ok(pb::KeyPlan {
        purposes,
        cache_ttl: pb_duration(cache_ttl),
        recipients,
        slot_map,
        ..pb::KeyPlan::default()
    })
}

/// The longest node name, as key@ and the card driver bound it (`pinrelease.MaxNodeChars`).
const NODE_MAX: usize = 64;

/// The slot map of the KeyPlan (D20b), read for its shape as key@ reads it (plan.go `decodeSlotMap`): a node is an
/// address part listed once, a slot is two lower-case hex digits listed once per node, a purpose is named and listed
/// once per node, the byte
/// fields are base64url without padding, and an attestation comes with its signer. What a key or an attestation says
/// is key@'s check where it uses the entry.
fn slot_map(o: &mut Obj) -> R<Vec<pb::NodeSlotMap>> {
    let mut out: Vec<pb::NodeSlotMap> = Vec::new();
    for mut n in o.objects("slot_map")? {
        let node = n.required("node")?;
        if !valid_part(&node) || node.len() > NODE_MAX {
            return err(&n.at("node"), "not a node name");
        }
        if out.iter().any(|x| x.node == node) {
            return err(&n.at("node"), "listed twice");
        }
        if !matches!(n.peek("slots"), Some(Value::Seq(_))) {
            return err(&n.at("slots"), "must be a list");
        }
        let mut slots: Vec<pb::SlotKey> = Vec::new();
        for mut k in n.objects("slots")? {
            let slot = k.required("slot")?;
            if slot.len() != 2 || !slot.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return err(&k.at("slot"), "not a slot of two lower-case hex digits");
            }
            if slots.iter().any(|x| x.slot == slot) {
                return err(&k.at("slot"), "listed twice");
            }
            let purpose = k.required("purpose")?;
            if slots.iter().any(|x| x.purpose == purpose) {
                return err(&k.at("purpose"), "listed twice in the node");
            }
            let public_key = k.base64url("public_key", true)?;
            let attestation = k.base64url("attestation", false)?;
            let attestation_signer = k.base64url("attestation_signer", false)?;
            if attestation.is_empty() != attestation_signer.is_empty() {
                return err(
                    &k.at("attestation_signer"),
                    "an attestation comes with its signer",
                );
            }
            k.done()?;
            slots.push(pb::SlotKey {
                slot,
                purpose,
                public_key,
                attestation,
                attestation_signer,
                ..pb::SlotKey::default()
            });
        }
        n.done()?;
        out.push(pb::NodeSlotMap {
            node,
            slots,
            ..pb::NodeSlotMap::default()
        });
    }
    Ok(out)
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

/// The ID-token claims an upstream's `subject_claim` may not name: the e-mail address (OpenID Connect Core 1.0
/// section 5.1 `email`), the user name (`preferred_username`, which section 5.1 says "MAY be any valid JSON string" and
/// "MUST NOT rely upon ... being unique"), Microsoft's `upn` and the display `name`.
const MUTABLE_CLAIMS: [&str; 4] = ["email", "preferred_username", "upn", "name"];

fn upstream(mut o: Obj, id: &str) -> R<pb::Upstream> {
    let name = named(&mut o, "name", id)?;
    let kind = o.one_of("kind", &["oidc"])?;
    let issuer = url(&mut o, "issuer")?;
    let client_id = o.required("client_id")?;
    let subject_claim = o.required("subject_claim")?;
    // A person is the pair of the issuer and this claim's value, with no fallback (ADR 0019, "Linking an upstream
    // account"). A claim that changes for a person would make a renamed account a new person, so the claims that do
    // are refused here, in every environment, and `sluis config check` refuses them the same way (REQ-SUBJ-044).
    if MUTABLE_CLAIMS.contains(&subject_claim.as_str()) {
        return err(
            &o.at("subject_claim"),
            "is a claim that changes for a person; name a stable one such as sub or oid",
        );
    }
    let org_claim = o.string("org_claim")?;
    let scopes = o.strings("scopes")?;
    // Where sluis's client secret at the upstream is in the secret source (ADR 0005, "Secret sources"; ADR 0025:
    // the operator's `UpstreamSecret`). The value is never in the document, only the name of a credential; store@
    // serves it to adapter-upstream-oidc alone. An upstream without one cannot sign anybody in: the adapter refuses.
    let secret = o.string("secret")?;
    if !secret.is_empty() && !credential_name(&secret) {
        return err(&o.at("secret"), "is not a credential name");
    }
    o.done()?;
    Ok(pb::Upstream {
        name,
        kind,
        issuer,
        client_id,
        subject_claim,
        org_claim,
        scopes,
        secret,
        ..pb::Upstream::default()
    })
}

/// A credential name as the credential driver accepts it (`sluis_credential::valid_name`, systemd's `LoadCredential=`
/// rule): letters, digits, `-`, `_` and `.`, not starting with anything but a letter or a digit, at most 128 characters.
/// The same rule here makes a bad name fail at `config check` and not when the first client asks.
fn credential_name(name: &str) -> bool {
    let mut b = name.bytes();
    name.len() <= 128
        && b.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

/// A grant name, `<scope>:<thing>:<role>`: three parts, each 1 to 64 ASCII letters, digits, `-` and `_`
/// (docs/reference/policy.md "Format").
fn grant_name(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            (1..=64).contains(&p.len())
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn installation_client(mut o: Obj, id: &str) -> R<pb::InstallationClient> {
    let client_id = named(&mut o, "id", id)?;
    let kind = o.one_of("kind", &["public", "confidential", "exchange"])?;
    let redirects = o.strings("redirects")?;
    for (i, r) in redirects.iter().enumerate() {
        check_redirect(r, &format!("{}[{i}]", o.at("redirects")))?;
    }
    let requires = o.strings("requires")?;
    for (i, r) in requires.iter().enumerate() {
        // A wildcard in `requires` would admit by pattern, where the rule should name the thing (ADR 0020, "Grant
        // names and the vocabulary"; REQ-POLICY-012). Whether the name is declared is checked with the vocabulary.
        let at = format!("{}[{i}]", o.at("requires"));
        if r.contains('*') {
            return err(&at, "a wildcard is not allowed in requires");
        }
        if !grant_name(r) {
            return err(&at, "is not a grant name, <scope>:<thing>:<role>");
        }
    }
    let ttl_cap = o.duration("ttl_cap")?;
    // A client lowers its tokens with `ttl_cap` and never raises them past the built-in cap (ADR 0020;
    // REQ-TOKEN-038).
    if ttl_cap.is_some_and(|d| d > ACCESS_TOKEN_CAP) {
        return err(&o.at("ttl_cap"), "above the built-in cap of one hour");
    }
    let profile = o.string("profile")?;
    // Where the client's secret is in the secret source (ADR 0005, "Secret sources": config names it). The value is
    // never in the document, only the name of a credential.
    let secret = o.string("secret")?;
    if !secret.is_empty() && !credential_name(&secret) {
        return err(&o.at("secret"), "is not a credential name");
    }
    if !secret.is_empty() && kind == "public" {
        return err(&o.at("secret"), "a public client has no secret");
    }
    o.done()?;
    Ok(pb::InstallationClient {
        id: client_id,
        secret,
        kind,
        redirects,
        requires,
        ttl_cap: ttl_cap.map(pb_duration).unwrap_or_default(),
        profile,
        ..pb::InstallationClient::default()
    })
}
