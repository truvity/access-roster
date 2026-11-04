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
use super::document::{self, Sequence, hex};
use super::payload::{self, Items, SINGLETON_ID};
use crate::bootstrap::Bootstrap;

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
    items: Items,
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

fn failed(kind: Option<&'static str>, reason: impl Into<String>) -> LoadError {
    LoadError {
        kind,
        label: None,
        reason: reason.into(),
        unreachable: false,
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
        let boundary_kind = kind("Boundary");
        let boundary = self.document(boundary_kind, held, seen).await?;
        let declared = declared_kinds(&boundary)?;

        let mut docs = BTreeMap::new();
        docs.insert(boundary_kind.segment, boundary);
        for k in declared {
            let d = self.document(k, held, seen).await?;
            docs.insert(k.segment, d);
        }
        let snapshot = Snapshot { docs };
        validate_set(&snapshot, &self.boundary)?;
        Ok(snapshot)
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
                return Err(failed(
                    Some(kind.name),
                    "the source has no document of the kind",
                ));
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
        let with_label = |mut e: LoadError| {
            e.label = Some(got.version.clone());
            e
        };
        if got.unchanged {
            return in_force
                .filter(|d| d.label == got.version)
                .cloned()
                .ok_or_else(|| {
                    with_label(failed(
                        Some(kind.name),
                        "the source answered unchanged for a document it was not asked about",
                    ))
                });
        }

        let v = document::verify(&got.data, kind, &self.publishers)
            .map_err(|r| with_label(failed(Some(kind.name), r.to_string())))?;
        // Step 5: a running store takes only a growing sequence (signed-config.md).
        match document::sequence(in_force.map(|d| (d.seq, &d.digest)), &v) {
            Sequence::Newer => {}
            // The same document under another label: nothing changed.
            Sequence::Same => {
                if let Some(d) = in_force {
                    return Ok(Document {
                        label: got.version,
                        ..d.clone()
                    });
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
            label: got.version.clone(),
            items,
        })
    }
}

fn unreachable_source() -> LoadError {
    LoadError {
        unreachable: true,
        ..failed(None, "the config source did not answer")
    }
}

fn kind(name: &str) -> &'static Kind {
    // The names are the registry's own: a missing one is a build whose registry changed.
    sluis_registry::kind_by_name(name)
        .unwrap_or_else(|| unreachable!("the kind {name} is not in the registry"))
}

/// The kinds the Boundary document declares, each once, without Boundary itself.
fn declared_kinds(boundary: &Document) -> Result<Vec<&'static Kind>, LoadError> {
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
    // A development difference is configuration checked against a floor in code: plain HTTP is
    // for a development boundary only.
    if b.environment != "development" {
        let plain = |u: &str| !u.starts_with("https://");
        let mut at: Option<(&'static str, String)> = plain(&b.issuer).then(|| {
            (
                "Boundary",
                "issuer: must be https outside development".to_owned(),
            )
        });
        for (_, bytes) in s.list(kind("Upstream").segment) {
            if let Ok(u) = pb::Upstream::decode_from_slice(&bytes)
                && plain(&u.issuer)
            {
                at = at.or(Some((
                    "Upstream",
                    "issuer: must be https outside development".to_owned(),
                )));
            }
        }
        for (_, bytes) in s.list(kind("InstallationClient").segment) {
            if let Ok(c) = pb::InstallationClient::decode_from_slice(&bytes)
                && c.redirects.iter().any(|r| plain(r))
            {
                at = at.or(Some((
                    "InstallationClient",
                    "redirects: must be https outside development".to_owned(),
                )));
            }
        }
        if let Some((k, why)) = at {
            return Err(failed(Some(k), why));
        }
    }
    debug_assert!(s.docs.values().all(|d| d.kind.class == Class::Config));
    Ok(())
}
