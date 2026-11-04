//! `indexer`: the audit search index's only writer (ADR 0028, "Search and the index").
//!
//! It follows each audit log of its boundary by signed checkpoint, indexes only the entries a verified
//! checkpoint covers, and writes them to the index through the `index` port. See [`follow`] for the
//! pass, [`note`] and [`merkle`] for what it verifies, and [`entry`] for what the writer made.

pub mod config;
pub mod entry;
pub mod follow;
pub mod merkle;
pub mod note;
pub mod ports;
pub mod run;
