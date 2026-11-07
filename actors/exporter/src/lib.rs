//! `exporter` (exporter@): it publishes the kinds that the kind registry marks exportable to destinations outside
//! sluis, through the destination port (ADR 0009). It holds no signing key and serves no socket: it is a client of
//! store@, of the audit transport and of the driver of each destination.
//!
//! The first version builds one document, the static key set: the JSON Web Key Set of the ring, without a `kid`
//! that `KeyRevocation` lists ([`keyset`]), written whole and atomically to a directory. It watches `SigningRing`
//! and `KeyRevocation` from the resume point in `ExportCursor`, rebuilds on every change and at the start, and again
//! once a day. After a change it does four things in order ([`publish`]): write, purge, read back, report. The report
//! is the temp kind `ExportReport`, which `signer` reads.
//!
//! # When it cannot tell
//!
//! The document is built from two linearizable listings (`SigningRing` and `KeyRevocation`), read after the change
//! that woke it, not from the events: the watch says *when* to look, never *what* is revoked. When either listing
//! cannot be read, or a watch is interrupted so that a change might go unseen, `exporter` leaves the published object
//! exactly as it is, raises an alarm and reports `unverified` (REQ-EXPORT-024). It does not empty or delete the
//! object: a store@ that blinks would stop verification for every relying party, and a revocation it cannot read is
//! one it cannot act on in any case. `entry` makes the other choice for its live key set, a refusal with 503, because
//! it answers a request at a time and a refusal costs one request; here the object lives on between two runs.

pub mod audit;
pub mod config;
pub mod keyset;
pub mod publish;
pub mod run;
pub mod state;
