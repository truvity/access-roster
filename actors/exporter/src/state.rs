//! What `exporter` reads and writes in store@.
//!
//! - **Reads, linearizable.** [`Source::read`] lists `SigningRing` and `KeyRevocation` asking for a linearizable read
//!   (`ListRequest.consistency`), after the change that woke `exporter`. A revocation decides whether a key is in the
//!   document, so a listing from a leader that no longer leads, which might miss a revocation acknowledged before it,
//!   is not good enough. It lists, and does not `Get`: a ring that does not exist yet is the normal state before
//!   `signer` has written it, and a `Get` of an absent item is a refusal that store@ audits (REQ-AUDIT-180).
//! - **Writes.** [`Reports`] sets the temp kind `ExportReport` and [`Cursors`] the temp kind `ExportCursor`, both with
//!   `apply`: the writer is the only one, and the item is replaced as a whole.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buffa_types::google::protobuf::Timestamp;
use sluis_kit::Client;
use sluis_proto::sluis::exporter::v2alpha1::export_manifest::Entry;
use sluis_proto::sluis::exporter::v2alpha1::{ExportCursor, ExportManifest, ExportReport};
use sluis_proto::sluis::signer::v2alpha1::SigningRing;
use sluis_store::revocation::KeyRevocations;
use sluis_store::{Error, Kind, ResumePoint, Store, WriteOpts};

/// The singleton id of the ring.
const RING_ID: &str = "default";
/// The singleton id of the manifest.
const MANIFEST_ID: &str = "default";
/// How long one read of store@ may take.
pub const READ: Duration = Duration::from_secs(5);
/// The time to live of a report: the maximum of the kind (kinds.yaml).
pub const REPORT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// More pages than this are not read.
const MAX_PAGES: usize = 1000;

/// The kind `SigningRing`.
pub struct RingKind;
impl Kind for RingKind {
    type Id = String;
    type Value = SigningRing;
    const NAME: &'static str = "SigningRing";
}

/// The kind `ExportCursor`.
pub struct CursorKind;
impl Kind for CursorKind {
    type Id = String;
    type Value = ExportCursor;
    const NAME: &'static str = "ExportCursor";
}

/// The kind `ExportManifest`.
pub struct ManifestKind;
impl Kind for ManifestKind {
    type Id = String;
    type Value = ExportManifest;
    const NAME: &'static str = "ExportManifest";
}

/// The kind `ExportReport`.
pub struct ReportKind;
impl Kind for ReportKind {
    type Id = String;
    type Value = ExportReport;
    const NAME: &'static str = "ExportReport";
}

/// What `exporter` builds a document from.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// The ring.
    pub ring: SigningRing,
    /// Every kid `KeyRevocation` lists.
    pub revoked: HashSet<String>,
}

/// What a read gave.
#[derive(Clone, Debug)]
pub enum Read {
    /// Both kinds were read.
    Snapshot(Snapshot),
    /// The ring does not exist yet: nothing to publish, and nothing wrong.
    NoRing,
    /// A kind could not be read: the closed word names it. The published object stays as it is. The kids that
    /// `KeyRevocation` lists are carried when that kind could be read though the ring could not: a revocation is a fact
    /// whatever else is unknown.
    Unreadable(&'static str, HashSet<String>),
}

/// The reader of the two kinds the key set is built from.
pub struct Source {
    ring: Store<RingKind>,
    revocations: KeyRevocations,
}

impl Source {
    /// A reader over store@'s socket.
    ///
    /// # Errors
    ///
    /// When a kind is not in the registry.
    pub fn new(store: &Client) -> Result<Self, Error> {
        Ok(Self {
            ring: Store::new(store.clone())?,
            revocations: KeyRevocations::new(store)?,
        })
    }

    /// The store's typed client of the ring, for the watch.
    #[must_use]
    pub fn ring_store(&self) -> &Store<RingKind> {
        &self.ring
    }

    /// The revocation reader, for the watch.
    #[must_use]
    pub fn revocations(&self) -> &KeyRevocations {
        &self.revocations
    }

    async fn ring(&self) -> Result<Option<SigningRing>, Error> {
        let mut page = None;
        for _ in 0..MAX_PAGES {
            let (items, next) = self.ring.list_linearizable("", page).await?;
            if let Some(i) = items.into_iter().find(|i| i.id == RING_ID) {
                return Ok(Some(i.value));
            }
            match next {
                Some(n) => page = Some(n),
                None => return Ok(None),
            }
        }
        Err(Error::Protocol(
            "a listing of SigningRing that does not end",
        ))
    }

    /// Reads the ring and then the revocations, both linearizable. The order matters: every key in the ring that was read
    /// is checked against a list of revocations read after it, so a revocation acknowledged before the ring was read is
    /// in the list; one that comes later is a change, and wakes `exporter` again.
    pub async fn read(&self) -> Read {
        let ring = tokio::time::timeout(READ, self.ring()).await;
        // Read also when the ring could not be: what is revoked is wanted most when the rest is unknown.
        let revoked =
            tokio::time::timeout(READ, self.revocations.revoked_kids_linearizable()).await;
        match (ring, revoked) {
            (Ok(Ok(Some(ring))), Ok(Ok(revoked))) => Read::Snapshot(Snapshot { ring, revoked }),
            (Ok(Ok(None)), Ok(Ok(_))) => Read::NoRing,
            (Ok(Ok(_)), _) => Read::Unreadable("key_revocation", HashSet::new()),
            (_, Ok(Ok(revoked))) => Read::Unreadable("signing_ring", revoked),
            _ => Read::Unreadable("signing_ring", HashSet::new()),
        }
    }
}

/// A protobuf timestamp.
#[must_use]
pub fn stamp(t: SystemTime) -> Timestamp {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        ..Timestamp::default()
    }
}

/// The writer of the reports.
#[derive(Clone)]
pub struct Reports {
    store: Store<ReportKind>,
}

impl Reports {
    /// A writer over store@'s socket.
    ///
    /// # Errors
    ///
    /// When the kind is not in the registry.
    pub fn new(store: &Client) -> Result<Self, Error> {
        Ok(Self {
            store: Store::new(store.clone())?,
        })
    }

    /// Sets the report of `<destination>/<document>`.
    ///
    /// # Errors
    ///
    /// When store@ refuses or cannot be reached.
    pub async fn set(
        &self,
        destination: &str,
        document: &str,
        r: &ExportReport,
    ) -> Result<(), Error> {
        let id = format!("{destination}/{document}");
        // The longest the kind allows: `signer` reads a report that is gone as "no key set is published here", so the
        // longer a report lives, the longer a publisher that went quiet keeps `signer` from activating a key. The
        // daily reconcile rewrites it long before.
        let opts = WriteOpts {
            ttl: Some(REPORT_TTL),
            ..WriteOpts::default()
        };
        tokio::time::timeout(READ, self.store.apply("", &id, r, opts))
            .await
            .map_err(|_| Error::Protocol("the write of a report timed out"))??;
        Ok(())
    }

    /// The ids of the reports there are, linearizable. It lists: there are none the first time.
    ///
    /// # Errors
    ///
    /// When store@ cannot be read.
    pub async fn ids(&self) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        let mut page = None;
        for _ in 0..MAX_PAGES {
            let (items, next) = tokio::time::timeout(READ, self.store.list_linearizable("", page))
                .await
                .map_err(|_| Error::Protocol("the read of the reports timed out"))??;
            out.extend(items.into_iter().map(|i| i.id));
            match next {
                Some(n) => page = Some(n),
                None => return Ok(out),
            }
        }
        Err(Error::Protocol(
            "a listing of ExportReport that does not end",
        ))
    }

    /// Removes the report with this id: its document is no longer published, and a report that stayed would be read
    /// as the state of something that is gone.
    ///
    /// # Errors
    ///
    /// When store@ refuses or cannot be reached.
    pub async fn remove(&self, id: &str) -> Result<(), Error> {
        match tokio::time::timeout(READ, self.store.delete("", id, None, WriteOpts::default()))
            .await
            .map_err(|_| Error::Protocol("the removal of a report timed out"))?
        {
            Ok(()) | Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// The writer of the manifest: what `exporter` is configured to publish, for `signer` to know which reports to expect.
#[derive(Clone)]
pub struct Manifest {
    store: Store<ManifestKind>,
}

impl Manifest {
    /// A writer over store@'s socket.
    ///
    /// # Errors
    ///
    /// When the kind is not in the registry.
    pub fn new(store: &Client) -> Result<Self, Error> {
        Ok(Self {
            store: Store::new(store.clone())?,
        })
    }

    /// Sets the manifest.
    ///
    /// # Errors
    ///
    /// When store@ refuses or cannot be reached.
    pub async fn set(&self, entries: Vec<Entry>, now: SystemTime) -> Result<(), Error> {
        let m = ExportManifest {
            entries,
            written_at: stamp(now).into(),
            ..ExportManifest::default()
        };
        tokio::time::timeout(
            READ,
            self.store.apply("", MANIFEST_ID, &m, WriteOpts::default()),
        )
        .await
        .map_err(|_| Error::Protocol("the write of the manifest timed out"))??;
        Ok(())
    }
}

/// The resume points of one destination: for each kind the epoch of its change log and the sequence in it. A point is
/// only used whole, and a point whose epoch is 0 (a cursor saved before epochs, or nothing yet) is no point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Points {
    /// In the change log of `SigningRing`.
    pub signing_ring: ResumePoint,
    /// In the change log of `KeyRevocation`.
    pub key_revocation: ResumePoint,
}

impl Points {
    /// Both points are real ones (store@ gave them): the pair is worth saving.
    #[must_use]
    pub fn known(&self) -> bool {
        [self.signing_ring, self.key_revocation]
            .iter()
            .all(|p| p.epoch != 0 && p.sequence != 0)
    }
}

/// A point a watch can start from, or `None`.
#[must_use]
pub fn usable(p: ResumePoint) -> Option<ResumePoint> {
    (p.epoch != 0 && p.sequence != 0).then_some(p)
}

/// The reader and writer of the cursors.
#[derive(Clone)]
pub struct Cursors {
    store: Store<CursorKind>,
}

impl Cursors {
    /// A client over store@'s socket.
    ///
    /// # Errors
    ///
    /// When the kind is not in the registry.
    pub fn new(store: &Client) -> Result<Self, Error> {
        Ok(Self {
            store: Store::new(store.clone())?,
        })
    }

    /// The saved points of a destination, or `None` when it has none (a first start, or a lost cursor: a full
    /// reconcile follows). It lists and does not `Get`, because an absent cursor is the normal first start.
    ///
    /// # Errors
    ///
    /// When store@ cannot be read; the caller starts without a cursor.
    pub async fn load(&self, destination: &str) -> Result<Option<Points>, Error> {
        let mut page = None;
        for _ in 0..MAX_PAGES {
            let (items, next) = tokio::time::timeout(READ, self.store.list("", page))
                .await
                .map_err(|_| Error::Protocol("the read of the cursors timed out"))??;
            if let Some(i) = items.into_iter().find(|i| i.id == destination) {
                return Ok(Some(Points {
                    signing_ring: ResumePoint {
                        epoch: i.value.signing_ring_epoch,
                        sequence: i.value.signing_ring,
                    },
                    key_revocation: ResumePoint {
                        epoch: i.value.key_revocation_epoch,
                        sequence: i.value.key_revocation,
                    },
                }));
            }
            match next {
                Some(n) => page = Some(n),
                None => return Ok(None),
            }
        }
        Err(Error::Protocol(
            "a listing of ExportCursor that does not end",
        ))
    }

    /// Saves the points of a destination.
    ///
    /// # Errors
    ///
    /// When store@ refuses or cannot be reached; the points are saved at the next publication.
    pub async fn save(&self, destination: &str, p: Points, now: SystemTime) -> Result<(), Error> {
        let c = ExportCursor {
            signing_ring: p.signing_ring.sequence,
            signing_ring_epoch: p.signing_ring.epoch,
            key_revocation: p.key_revocation.sequence,
            key_revocation_epoch: p.key_revocation.epoch,
            saved_at: stamp(now).into(),
            ..ExportCursor::default()
        };
        tokio::time::timeout(
            READ,
            self.store.apply("", destination, &c, WriteOpts::default()),
        )
        .await
        .map_err(|_| Error::Protocol("the write of a cursor timed out"))??;
        Ok(())
    }
}
