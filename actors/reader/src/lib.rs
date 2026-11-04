//! `reader`: the audit API (ADR 0028, "The reader" and "Access").
//!
//! `Search` is the one call. Each call is decided twice, by two checks that do not depend on each other
//! (0028 "Access"):
//!
//! 1. **policy.** The reader asks `policy` for an `audit.read` grant for each tenant the request names. The
//!    grant is the mandatory filter of the query: the index is asked for those tenants only, and a row of any
//!    other tenant is dropped, whatever the index answered.
//! 2. **key@.** A record is not taken from the index. It is read from the log in the blob and opened at key@
//!    under its tenant's `evidence` key, with the grant of the call, so key@ refuses a record of a tenant the
//!    grant does not name. What is returned is what key@ opened, and it must be the record the index row
//!    stands for (the SHA-384 of its bytes).
//!
//! Every call is itself audited, answered or refused.

pub mod audit;
pub mod config;
pub mod open;
pub mod ports;
pub mod run;
pub mod search;
pub mod service;
