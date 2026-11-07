//! The snapshot of the config kinds and the loader that builds it (ADR 0005, "The snapshot";
//! signed-config.md "The snapshot", "The sequence number").
//!
//! A snapshot is immutable. The loader reads the Boundary document first, because the boundary
//! declares the other kinds, then reads and verifies one document per declared kind, checks the
//! set as a whole, and swaps. A set is all or nothing: a bad document keeps the snapshot in force.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use buffa::Message as _;
use connectrpc::error::ErrorCode;
use sluis_kit::{Client, Transport};
use sluis_proto::sluis::config::v2alpha1 as pb;
use sluis_proto::sluis::port::source::v2alpha1::{
    CapabilitiesRequest, ReadRequest, SourceServiceClient, Watch,
};
use sluis_registry::{Class, Kind};

use super::ConfigSnapshot;

/// Client ids that the actors use for no client: `unregistered` stands for the client of a request that names none that is
/// registered (session), `unknown-audience` for an audience that is no client (exchange). A document declares no client of
/// either name.
const RESERVED_CLIENT_IDS: [&str; 2] = ["unregistered", "unknown-audience"];
use super::document::{self, Sequence, hex};
use super::payload::{self, Items, SINGLETON_ID};
use crate::bootstrap::Bootstrap;

/// The key purpose of the ID tokens of an audience that needs RS256 (docs/architecture/keys.yaml).
const RS256_PURPOSE: &str = "token-signing-rs256";

/// How long one call to the config source may take.
const CALL: Duration = Duration::from_secs(10);
/// The pause between attempts while a cold start waits for the source.
const RETRY: Duration = Duration::from_millis(250);

/// One verified, validated document.
#[derive(Clone, Debug)]
pub struct Document {
    pub kind: &'static Kind,
    pub seq: u64,
    /// The SHA-384 of the payload.
    pub digest: [u8; 48],
    /// The source's version label of the bytes it gave.
    label: String,
    /// The document as the source gave it, for a caller that verifies it itself (`GetSignedConfig`).
    signed: Vec<u8>,
    items: Items,
}

impl Document {
    /// The document as the source gave it, for the offline `explain`, which reads the verified payload of the bytes
    /// again (signed-config.md "Verifying a document").
    pub(super) fn signed_bytes(&self) -> &[u8] {
        &self.signed
    }
}

/// What the audit fact of a start or a reload names for a document (0005 "The snapshot").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub kind: &'static str,
    pub seq: u64,
    /// The SHA-384 of the payload, in lower-case hex: `sha384sum` of the reviewed file.
    pub sha384: String,
}

/// The documents in force, by kind segment.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    docs: BTreeMap<&'static str, Document>,
}

impl Snapshot {
    /// The documents, by kind name.
    #[must_use]
    pub fn summaries(&self) -> Vec<Summary> {
        let mut v: Vec<_> = self
            .docs
            .values()
            .map(|d| Summary {
                kind: d.kind.name,
                seq: d.seq,
                sha384: hex(&d.digest),
            })
            .collect();
        v.sort_by_key(|s| s.kind);
        v
    }

    /// The segments of the kinds that have a document.
    #[must_use]
    pub fn segments(&self) -> Vec<&'static str> {
        self.docs.keys().copied().collect()
    }
}

impl ConfigSnapshot for Snapshot {
    fn get(&self, segment: &str, id: &str) -> Option<Vec<u8>> {
        self.docs
            .get(segment)?
            .items
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, b)| b.clone())
    }

    fn list(&self, segment: &str) -> Vec<(String, Vec<u8>)> {
        self.docs
            .get(segment)
            .map(|d| d.items.clone())
            .unwrap_or_default()
    }

    fn version(&self, segment: &str) -> Option<u64> {
        self.docs.get(segment).map(|d| d.seq)
    }

    fn signed(&self, segment: &str) -> Option<Vec<u8>> {
        self.docs.get(segment).map(|d| d.signed.clone())
    }
}

/// Why a load failed. It names the document by its kind, never a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadError {
    /// The kind of the document at fault; None for the source or the set.
    pub kind: Option<&'static str>,
    /// The source's label of the bytes at fault, which is the SHA-384 of the file for `file`.
    pub label: Option<String>,
    /// The rule that was broken.
    pub reason: String,
    /// The source did not answer: a cold start waits for it, a reload retries.
    pub unreachable: bool,
    /// The source has no document of a kind that the set needs. Nothing watches a kind that the
    /// snapshot in force does not hold, so a reload retries this one with a back-off until the
    /// document appears.
    pub absent: bool,
    /// The labels of everything read in the attempt: a refusal is reported once per refusal.
    pub(super) fingerprint: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            Some(k) => write!(f, "{k}: {}", self.reason),
            None => f.write_str(&self.reason),
        }
    }
}

impl std::error::Error for LoadError {}

pub(super) fn failed(kind: Option<&'static str>, reason: impl Into<String>) -> LoadError {
    LoadError {
        kind,
        label: None,
        reason: reason.into(),
        unreachable: false,
        absent: false,
        fingerprint: String::new(),
    }
}

/// The result of a reload.
#[derive(Debug)]
pub enum Reloaded {
    /// Every document is as it was.
    Unchanged,
    /// A new snapshot is in force.
    Applied(Vec<Summary>),
    /// The snapshot in force stays. `report` is false for a refusal already reported.
    Refused { error: LoadError, report: bool },
}

/// Loads the documents of one boundary from a config source and holds the snapshot in force.
pub struct Loader {
    source: SourceServiceClient<Transport>,
    boundary: String,
    publishers: Vec<crate::bootstrap::Publisher>,
    watch: Watch,
    current: RwLock<Arc<Snapshot>>,
    reported: Mutex<Option<String>>,
}

impl Loader {
    /// The cold start: loads the first snapshot or fails. A source that does not answer is waited
    /// for until `within` has passed; anything else that is wrong stops at once.
    ///
    /// # Errors
    ///
    /// [`LoadError`] for the first failure (a cold start refuses on any failure).
    pub async fn start(
        client: &Client,
        b: &Bootstrap,
        within: Duration,
    ) -> Result<Arc<Self>, LoadError> {
        let source = SourceServiceClient::new(client.transport(), client.config());
        let deadline = Instant::now() + within;
        let watch = loop {
            match tokio::time::timeout(CALL, source.capabilities(CapabilitiesRequest::default()))
                .await
            {
                Ok(Ok(r)) => break r.into_owned().watch.as_known().unwrap_or(Watch::NONE),
                _ if Instant::now() < deadline => tokio::time::sleep(RETRY).await,
                _ => return Err(unreachable_source()),
            }
        };
        let loader = Self {
            source,
            boundary: b.boundary.clone(),
            publishers: b.publishers.clone(),
            watch,
            current: RwLock::new(Arc::new(Snapshot::default())),
            reported: Mutex::new(None),
        };
        loop {
            match loader.build(None).await {
                Ok(snapshot) => {
                    *loader
                        .current
                        .write()
                        .unwrap_or_else(PoisonError::into_inner) = Arc::new(snapshot);
                    return Ok(Arc::new(loader));
                }
                Err(e) if e.unreachable && Instant::now() < deadline => {
                    tokio::time::sleep(RETRY).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The client of the config source, for the watchers.
    pub(super) fn source(&self) -> &SourceServiceClient<Transport> {
        &self.source
    }

    /// How the source says that a document changed.
    #[must_use]
    pub fn watch(&self) -> Watch {
        self.watch
    }

    /// The snapshot in force.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Reads every document again and swaps the snapshot if the set is valid and something
    /// changed. On any failure the snapshot in force stays.
    pub async fn reload(&self) -> Reloaded {
        let held = self.snapshot();
        let built = self.build(Some(&held)).await;
        let mut reported = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
        match built {
            Ok(next) => {
                *reported = None;
                if next.summaries() == held.summaries() {
                    return Reloaded::Unchanged;
                }
                let summaries = next.summaries();
                *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
                Reloaded::Applied(summaries)
            }
            Err(error) => {
                // Once per refused document, not at every poll. An unreachable source has no
                // digest: it is reported when it starts to fail.
                let key = if error.unreachable {
                    "unreachable".to_owned()
                } else {
                    format!("{}|{}", error.fingerprint, error.reason)
                };
                let report = reported.as_deref() != Some(key.as_str());
                *reported = Some(key);
                Reloaded::Refused { error, report }
            }
        }
    }

    /// Builds the snapshot of the whole set. `held` is the snapshot in force, for the rule of the
    /// sequence number and for the `if_none_match` of a read.
    async fn build(&self, held: Option<&Snapshot>) -> Result<Snapshot, LoadError> {
        let mut seen = String::new();
        self.build_inner(held, &mut seen).await.map_err(|mut e| {
            e.fingerprint = seen;
            e
        })
    }

    async fn build_inner(
        &self,
        held: Option<&Snapshot>,
        seen: &mut String,
    ) -> Result<Snapshot, LoadError> {
        let boundary = self.document(kind("Boundary"), held, seen).await?;
        let declared = declared_kinds(&boundary)?;
        let mut docs = Vec::with_capacity(declared.len());
        for k in declared {
            docs.push(self.document(k, held, seen).await?);
        }
        assemble(&self.boundary, boundary, docs)
    }

    /// Reads, verifies and decodes the document of `kind` (steps 1 to 6).
    async fn document(
        &self,
        kind: &'static Kind,
        held: Option<&Snapshot>,
        seen: &mut String,
    ) -> Result<Document, LoadError> {
        let in_force = held.and_then(|s| s.docs.get(kind.segment));
        let read = self.source.read(ReadRequest {
            name: kind.segment.to_owned(),
            if_none_match: in_force.map(|d| d.label.clone()).unwrap_or_default(),
            ..ReadRequest::default()
        });
        let got = match tokio::time::timeout(CALL, read).await {
            Ok(Ok(r)) => r.into_owned(),
            Ok(Err(e)) if e.code == ErrorCode::NotFound => {
                return Err(LoadError {
                    absent: true,
                    ..failed(Some(kind.name), "the source has no document of the kind")
                });
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    kind = kind.name,
                    code = e.code.as_str(),
                    "config source failed"
                );
                return Err(unreachable_source());
            }
            Err(_) => return Err(unreachable_source()),
        };
        seen.push_str(&got.version);
        seen.push(';');
        if got.unchanged {
            return in_force
                .filter(|d| d.label == got.version)
                .cloned()
                .ok_or_else(|| LoadError {
                    label: Some(got.version.clone()),
                    ..failed(
                        Some(kind.name),
                        "the source answered unchanged for a document it was not asked about",
                    )
                });
        }
        accept(kind, &got.data, got.version, &self.publishers, in_force)
    }
}

/// Steps 1 to 6 of signed-config.md for the bytes of one document of `kind`, as a source gave them under `label`:
/// the signatures against the pinned `publishers`, the sequence against the document `in_force`, and the payload. The
/// loader and the offline check (`sluis config check`, [`super::offline`]) both run this one function, so that a
/// document the check passes is one store@ loads (REQ-DATA-090).
///
/// # Errors
///
/// [`LoadError`] naming the kind, the label and the step and rule that failed, never a value.
pub(super) fn accept(
    kind: &'static Kind,
    data: &[u8],
    label: String,
    publishers: &[crate::bootstrap::Publisher],
    in_force: Option<&Document>,
) -> Result<Document, LoadError> {
    let with_label = |mut e: LoadError| {
        e.label = Some(label.clone());
        e
    };
    let v = document::verify(data, kind, publishers)
        .map_err(|r| with_label(failed(Some(kind.name), r.to_string())))?;
    // Step 5: a running store takes only a growing sequence (signed-config.md).
    match document::sequence(in_force.map(|d| (d.seq, &d.digest)), &v) {
        Sequence::Newer => {}
        // The same document under another label: nothing changed.
        Sequence::Same => {
            if let Some(d) = in_force {
                return Ok(Document { label, ..d.clone() });
            }
        }
        Sequence::Conflict => {
            return Err(with_label(failed(
                Some(kind.name),
                "step 5: the same seq with another payload",
            )));
        }
        Sequence::Older => {
            return Err(with_label(failed(
                Some(kind.name),
                "step 5: a lower seq than the one in force",
            )));
        }
    }
    let items = payload::decode(kind, &v.payload)
        .map_err(|e| with_label(failed(Some(kind.name), format!("step 6: {e}"))))?;
    Ok(Document {
        kind,
        seq: v.seq,
        digest: v.digest,
        label: label.clone(),
        signed: data.to_vec(),
        items,
    })
}

/// The snapshot of a whole set: the Boundary document and the documents of the kinds it declares, checked as a set
/// for the boundary `boundary` of the bootstrap file. Shared by the loader and the offline check.
///
/// # Errors
///
/// [`LoadError`] for the first rule of the set that fails.
pub(super) fn assemble(
    boundary: &str,
    boundary_doc: Document,
    docs: Vec<Document>,
) -> Result<Snapshot, LoadError> {
    let mut all = BTreeMap::new();
    all.insert(boundary_doc.kind.segment, boundary_doc);
    for d in docs {
        all.insert(d.kind.segment, d);
    }
    let snapshot = Snapshot { docs: all };
    validate_set(&snapshot, boundary)?;
    Ok(snapshot)
}

fn unreachable_source() -> LoadError {
    LoadError {
        unreachable: true,
        ..failed(None, "the config source did not answer")
    }
}

pub(super) fn kind(name: &str) -> &'static Kind {
    // The names are the registry's own: a missing one is a build whose registry changed.
    sluis_registry::kind_by_name(name)
        .unwrap_or_else(|| unreachable!("the kind {name} is not in the registry"))
}

/// The kinds the Boundary document declares, each once, without Boundary itself.
pub(super) fn declared_kinds(boundary: &Document) -> Result<Vec<&'static Kind>, LoadError> {
    let m = boundary_message(boundary)?;
    let mut out: Vec<&'static Kind> = Vec::new();
    for name in &m.declared_kinds {
        // The payload reader checked the name against the registry.
        let k = kind(name);
        if k.name == "Boundary" || out.iter().any(|o| o.name == k.name) {
            continue;
        }
        if !payload::readable(k) {
            return Err(failed(
                Some("Boundary"),
                format!("declared_kinds: {name} has no reader in this build"),
            ));
        }
        out.push(k);
    }
    Ok(out)
}

fn boundary_message(d: &Document) -> Result<pb::Boundary, LoadError> {
    let bytes = d
        .items
        .iter()
        .find(|(id, _)| id == SINGLETON_ID)
        .map(|(_, b)| b.as_slice())
        .unwrap_or_default();
    pb::Boundary::decode_from_slice(bytes).map_err(|_| failed(Some("Boundary"), "not a Boundary"))
}

/// The vocabulary of the set, read as `policy` reads it. The set declares one (checked above).
fn vocabulary(s: &Snapshot) -> Result<sluis_vocab::Vocabulary, LoadError> {
    let bytes = s
        .get(kind("GrantVocabulary").segment, payload::SINGLETON_ID)
        .ok_or_else(|| failed(Some("GrantVocabulary"), "missing"))?;
    let document = pb::GrantVocabulary::decode_from_slice(&bytes)
        .map_err(|_| failed(Some("GrantVocabulary"), "not a GrantVocabulary"))?
        .document;
    sluis_vocab::Vocabulary::parse(&document)
        .map_err(|e| failed(Some("GrantVocabulary"), e.to_string()))
}

/// The checks that span documents (signed-config.md "The snapshot", step 3 of the set).
fn validate_set(s: &Snapshot, boundary: &str) -> Result<(), LoadError> {
    let b = boundary_message(
        s.docs
            .get(kind("Boundary").segment)
            .ok_or_else(|| failed(Some("Boundary"), "missing"))?,
    )?;
    if b.name != boundary {
        return Err(failed(
            Some("Boundary"),
            "name: is not the boundary of the bootstrap file",
        ));
    }
    // An installation declares its grant vocabulary, so that a name nobody declared cannot load (ADR 0020,
    // REQ-POLICY-013).
    if !s.docs.contains_key(kind("GrantVocabulary").segment) {
        return Err(failed(
            Some("Boundary"),
            "declared_kinds: must declare GrantVocabulary",
        ));
    }
    // A development difference is configuration checked against a floor in code (ADR 0011, "The
    // local installation"). Plain HTTP is for a development boundary only, and there only on a
    // loopback IP literal, `127.0.0.1` or `[::1]`, never a name such as `localhost` and never
    // another address (REQ-SEC-037; RFC 8252 section 8.3). The one exception outside development
    // is the loopback redirect of a public client with the `native` profile (ADR 0021; RFC 8252
    // section 7.3): an app on the person's own host. A browser, confidential or exchange client
    // has no such case. The payload rule has already refused every plain-http redirect that is
    // not on loopback (REQ-AUTHN-004).
    let development = b.environment == "development";
    let (why_url, why_redirect) = if development {
        ("must be https, or http on a loopback IP literal", "")
    } else {
        (
            "must be https outside development",
            "redirects: must be https outside development",
        )
    };
    // A URL sluis publishes or fetches: https, or in development http on a loopback IP literal.
    let bad =
        |u: &str| !u.starts_with("https://") && !(development && super::payload::loopback_http(u));
    let native = |c: &pb::InstallationClient| c.kind == "public" && c.profile == "native";
    let mut at: Option<(&'static str, String)> =
        bad(&b.issuer).then(|| ("Boundary", format!("issuer: {why_url}")));
    for (_, bytes) in s.list(kind("Upstream").segment) {
        if let Ok(u) = pb::Upstream::decode_from_slice(&bytes)
            && bad(&u.issuer)
        {
            at = at.or(Some(("Upstream", format!("issuer: {why_url}"))));
        }
    }
    for (_, bytes) in s.list(kind("ExchangeTrust").segment) {
        if let Ok(t) = pb::ExchangeTrust::decode_from_slice(&bytes) {
            for i in &t.issuers {
                if bad(&i.issuer) {
                    at = at.or(Some((
                        "ExchangeTrust",
                        format!("issuers: issuer {why_url}"),
                    )));
                }
                // An empty `jwks_uri` is allowed (the keys come by the issuer's metadata).
                if !i.jwks_uri.is_empty() && bad(&i.jwks_uri) {
                    at = at.or(Some((
                        "ExchangeTrust",
                        format!("issuers: jwks_uri {why_url}"),
                    )));
                }
            }
        }
    }
    if !development {
        for (_, bytes) in s.list(kind("InstallationClient").segment) {
            if let Ok(c) = pb::InstallationClient::decode_from_slice(&bytes)
                && c.redirects.iter().any(|r| {
                    !r.starts_with("https://") && !(native(&c) && super::payload::loopback_http(r))
                })
            {
                at = at.or(Some(("InstallationClient", why_redirect.to_owned())));
            }
        }
    }
    if let Some((k, why)) = at {
        return Err(failed(Some(k), why));
    }
    // One credential namespace for the secret kinds (REQ-ISO-106): a credential that an Upstream names is
    // UpstreamSecret's, served to adapter-upstream-oidc alone, and one that an InstallationClient names is
    // InstallationClientSecret's, served to session and exchange. A name declared by both would let one kind's reader
    // be served the other's secret, so the set is refused.
    let mut client_credentials = std::collections::BTreeSet::new();
    for (_, bytes) in s.list(kind("InstallationClient").segment) {
        if let Ok(c) = pb::InstallationClient::decode_from_slice(&bytes)
            && !c.secret.is_empty()
        {
            client_credentials.insert(c.secret);
        }
    }
    for (_, bytes) in s.list(kind("Upstream").segment) {
        if let Ok(u) = pb::Upstream::decode_from_slice(&bytes)
            && client_credentials.contains(&u.secret)
        {
            return Err(failed(
                Some("Upstream"),
                "secret: names a credential an InstallationClient names",
            ));
        }
    }
    // A grant name that a client requires is a name the boundary's vocabulary declares, so a typo stops the load instead
    // of leaving a client that nobody can satisfy or, worse, a weaker one (ADR 0020; REQ-POLICY-010). The vocabulary is
    // read as `policy` reads it, by the one reader of the kit, and read whether or not a client is declared: a
    // vocabulary that `policy` refuses must not load here.
    let vocabulary = vocabulary(s)?;
    // Whether the KeyPlan lists the RS256 purpose: a client that wants its ID tokens signed with RS256 needs a key for it, and
    // the key exists only where the plan enables the purpose (ADR 0006, "Key purposes": enabled on use).
    let mut rs256_key = false;
    for (_, bytes) in s.list(kind("KeyPlan").segment) {
        if let Ok(plan) = pb::KeyPlan::decode_from_slice(&bytes) {
            rs256_key |= plan
                .purposes
                .iter()
                .any(|p| p.purpose == RS256_PURPOSE && p.algorithm == "RS256");
        }
    }
    for (id, bytes) in s.list(kind("InstallationClient").segment) {
        let c = pb::InstallationClient::decode_from_slice(&bytes)
            .map_err(|_| failed(Some("InstallationClient"), "not an InstallationClient"))?;
        if c.signing_alg == "RS256" && !rs256_key {
            return Err(failed(
                Some("InstallationClient"),
                format!(
                    "{id}.signing_alg: RS256 needs the KeyPlan to list the purpose {RS256_PURPOSE}"
                ),
            ));
        }
        // A client id that the actors use for no client at all is not a client's. session audits a request that names a
        // client which is not registered under the pseudonym of `unregistered`, and exchange asks policy about a stand-in
        // named `unknown-audience`; a registered client of either name would make its records look like those refusals
        // (ADR 0030, "The OCSF attributes a class requires").
        if RESERVED_CLIENT_IDS.contains(&id.as_str()) {
            return Err(failed(
                Some("InstallationClient"),
                format!("{id}: a client id that the actors use for no client"),
            ));
        }
        if let Some(i) = c
            .requires
            .iter()
            .position(|r| vocabulary.parse_name(r).is_none())
        {
            return Err(failed(
                Some("InstallationClient"),
                format!("{id}.requires[{i}]: not a grant name the vocabulary declares"),
            ));
        }
    }
    // The card slot map of the KeyPlan: no two purposes in one slot, no enabled purpose without one (ADR 0006, "The slot
    // plan"). key@ applies the same rules at its start, on the same vectors (REQ-PKI-037, REQ-PKI-038, REQ-PKI-042).
    for (id, bytes) in s.list(kind("KeyPlan").segment) {
        let plan = pb::KeyPlan::decode_from_slice(&bytes)
            .map_err(|_| failed(Some("KeyPlan"), "not a KeyPlan"))?;
        let purposes: Vec<_> = plan
            .purposes
            .iter()
            .map(|p| super::slotplan::Purpose {
                name: &p.purpose,
                algorithm: &p.algorithm,
                slot: &p.slot,
            })
            .collect();
        if let Err(why) = super::slotplan::check(&format!("{id}.purposes"), &purposes) {
            return Err(failed(Some("KeyPlan"), why));
        }
    }
    debug_assert!(s.docs.values().all(|d| d.kind.class == Class::Config));
    Ok(())
}
