//! The grant vocabulary of a boundary (docs/reference/policy.md "The grant vocabulary"), read by `policy`, which decides
//! with it, and by store@, which refuses a client whose `requires` names a grant nobody declared (ADR 0020, REQ-POLICY-010).
//! One reader means the two cannot read the same document two ways.

pub mod vocab;
pub mod yaml;

pub use vocab::{GrantName, VocabError, Vocabulary};
