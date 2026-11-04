//! Reads a record's entry from the log in the blob and opens it at key@ (ADR 0028 "The reader": "The
//! reader opens a record from the blob at key@, under the record's tenant's `evidence` key and with the
//! grant of the call. It may open and never seal.").
//!
//! The entry is where the writer put it: the entry bundle `tile/entries/<N>` of the log, entry `seq % 256`
//! (C2SP tlog-tiles; the format is the indexer's, `indexer::entry`). A bundle that is not full yet is
//! `<N>.p/<W>`, with `W` the entries it held when it was written: the reader takes the widest one that
//! reaches the entry.

use std::collections::HashMap;

use connectrpc::ConnectError;
use connectrpc::error::ErrorCode;
use indexer::entry::{self, Entry, RecordEntry, TILE};
use sluis_kit::refusal;
use sluis_proto::sluis::key::v2alpha1::{OpenItem, OpenRequest};
use sluis_proto::sluis::r#type::v2alpha1::Address;

use crate::config::Log;
use crate::ports::{CALL, Ports, down, passed};

/// The purpose of the key the records are sealed under.
const EVIDENCE: &str = "evidence";
/// The most envelopes key@ opens in one call.
pub const OPEN_BATCH: usize = 64;
/// The most bundles one call keeps in memory.
const KEEP_BUNDLES: usize = 8;

/// The log or the index is not what the writer made. A closed word, never a value.
fn integrity(path: &str) -> ConnectError {
    refusal(ErrorCode::Internal, "integrity", path)
}

/// The bundles read for one call, so that records of one bundle cost one read.
#[derive(Default)]
pub struct Bundles {
    held: HashMap<(String, u64), Vec<Vec<u8>>>,
}

/// Reads entries of the log and opens them.
#[derive(Clone)]
pub struct Opener {
    ports: Ports,
}

impl Opener {
    #[must_use]
    pub fn new(ports: Ports) -> Self {
        Self { ports }
    }

    /// The record entry at `seq` of the log.
    ///
    /// # Errors
    ///
    /// `unavailable` when the blob does not answer; `internal` / `integrity` when the log has no such record
    /// entry, which an index row never points at.
    pub async fn entry(
        &self,
        log: &Log,
        seq: u64,
        cache: &mut Bundles,
    ) -> Result<RecordEntry, ConnectError> {
        let (n, at) = (
            seq / TILE,
            usize::try_from(seq % TILE).unwrap_or(usize::MAX),
        );
        let key = (log.prefix(), n);
        if !cache.held.contains_key(&key) {
            let bundle = self.bundle(log, n, at).await?;
            if cache.held.len() >= KEEP_BUNDLES {
                cache.held.clear();
            }
            cache.held.insert(key.clone(), bundle);
        }
        let raw = cache
            .held
            .get(&key)
            .and_then(|b| b.get(at))
            .ok_or_else(|| integrity("bundle"))?;
        match entry::parse_entry(raw).map_err(|_| integrity("entry"))? {
            Entry::Record(r) => Ok(r),
            Entry::Seal => Err(integrity("entry")),
        }
    }

    /// The entries of bundle `n`, from the full bundle or the widest partial one that has entry `at`.
    async fn bundle(&self, log: &Log, n: u64, at: usize) -> Result<Vec<Vec<u8>>, ConnectError> {
        let prefix = log.prefix();
        let data = match self
            .ports
            .get(&format!("{prefix}{}", entry::bundle_path(n, TILE)))
            .await?
        {
            Some(d) => d,
            None => {
                let partial = entry::bundle_path(n, 1);
                let dir = partial
                    .strip_suffix('1')
                    .ok_or_else(|| integrity("bundle"))?;
                let widest = self
                    .ports
                    .list(&format!("{prefix}{dir}"))
                    .await?
                    .iter()
                    .filter_map(|p| p.rsplit('/').next()?.parse::<u64>().ok())
                    .filter(|w| *w > at as u64 && *w < TILE)
                    .max()
                    .ok_or_else(|| integrity("bundle"))?;
                self.ports
                    .get(&format!("{prefix}{}", entry::bundle_path(n, widest)))
                    .await?
                    .ok_or_else(|| integrity("bundle"))?
            }
        };
        let parts = entry::parse_bundle(&data).ok_or_else(|| integrity("bundle"))?;
        Ok(parts.into_iter().map(<[u8]>::to_vec).collect())
    }

    /// Opens the sealed records at key@ with one grant. key@ opens all or none: a record of a tenant the grant
    /// does not name refuses the call.
    ///
    /// # Errors
    ///
    /// `permission_denied` when key@ refuses the grant or an envelope, `unavailable` when it does not answer.
    pub async fn open(
        &self,
        log: &Log,
        records: &[&RecordEntry],
        grant: &[u8],
    ) -> Result<Vec<Vec<u8>>, ConnectError> {
        let items = records
            .iter()
            .map(|e| OpenItem {
                purpose: EVIDENCE.into(),
                address: ::buffa::MessageField::some(Address {
                    kind: entry::SEAL_KIND.into(),
                    tenant: e.tenant.clone(),
                    id: entry::seal_id(&log.project, &log.kind, &log.id, &e.uid),
                    ..Address::default()
                }),
                envelope: e.sealed.clone(),
                ..OpenItem::default()
            })
            .collect();
        let res = tokio::time::timeout(
            CALL,
            self.ports.keys.open(OpenRequest {
                items,
                grant: grant.to_vec(),
                ..OpenRequest::default()
            }),
        )
        .await
        .map_err(|_| down("key"))?
        .map_err(|e| passed("key", &e))?
        .into_owned();
        if res.plaintexts.len() != records.len() {
            return Err(integrity("key"));
        }
        Ok(res.plaintexts)
    }
}
