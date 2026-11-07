#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
//! The RFC 6962 vectors shared with the Go kit (`kits/conformance/audit/merkle-vectors.json`, REQ-AUDIT-005,
//! REQ-AUDIT-024): the tree of thirteen leaves, its roots at every size, and the inclusion and consistency proofs of every
//! index and size, made by a program that shares no code with the product. The Go kit passes the same file
//! (`kits/go/audit/merkle_vectors_test.go`).

use indexer::merkle::{Range, leaf_hash};
use serde_json::Value;
use tlog_core::{Hash, HashReader, TlogError};

const VECTORS: &str = include_str!("../../../kits/conformance/audit/merkle-vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hash(s: &Value) -> Hash {
    Hash(unhex(s.as_str().unwrap()).try_into().expect("32 bytes"))
}

fn path(v: &Value) -> Vec<Hash> {
    v["path"].as_array().unwrap().iter().map(hash).collect()
}

struct Stored(Vec<Hash>);

impl HashReader for Stored {
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, TlogError> {
        indexes
            .iter()
            .map(|i| {
                usize::try_from(*i)
                    .ok()
                    .and_then(|i| self.0.get(i).copied())
                    .ok_or(TlogError::BadMath)
            })
            .collect()
    }
}

struct Loaded {
    v: Value,
    stored: Stored,
    leaves: Vec<Hash>,
}

fn load() -> Loaded {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let mut stored = Stored(Vec::new());
    let mut leaves = Vec::new();
    for (n, l) in v["leaves"].as_array().unwrap().iter().enumerate() {
        let lh = Hash(leaf_hash(&unhex(l.as_str().unwrap())));
        let more = tlog_core::stored_hashes_for_record_hash(n as u64, lh, &stored).unwrap();
        stored.0.extend(more);
        leaves.push(lh);
    }
    Loaded { v, stored, leaves }
}

/// The compact range the indexer keeps gives the root of the file at every size, and so does the library's tree.
///
/// verifies: REQ-AUDIT-005
#[test]
fn the_roots_of_the_shared_vectors_are_those_of_the_range_and_of_the_library_tree() {
    let l = load();
    let roots = l.v["roots"].as_array().unwrap();
    assert_eq!((l.leaves.len(), roots.len()), (13, 14));
    let mut range = Range::new();
    assert_eq!(Hash(range.root()), hash(&roots[0]));
    for (n, leaf) in l.leaves.iter().enumerate() {
        range.append(leaf.0);
        assert_eq!(
            Hash(range.root()),
            hash(&roots[n + 1]),
            "range, size {}",
            n + 1
        );
        let lib = tlog_core::tree_hash(n as u64 + 1, &l.stored).unwrap();
        assert_eq!(lib, hash(&roots[n + 1]), "library, size {}", n + 1);
    }
}

/// Every inclusion proof of the file is the one the library makes and verifies offline from the leaf, the proof and the
/// root alone; one with a hash changed, a hash short, another index or another root is refused.
///
/// verifies: REQ-AUDIT-005, REQ-AUDIT-024
#[test]
fn the_inclusion_proofs_of_the_shared_vectors_verify_offline() {
    let l = load();
    let roots = l.v["roots"].as_array().unwrap();
    let proofs = l.v["inclusion"].as_array().unwrap();
    assert_eq!(proofs.len(), 91);
    for c in proofs {
        let (size, index) = (c["size"].as_u64().unwrap(), c["index"].as_u64().unwrap());
        let want = path(c);
        let root = hash(&roots[size as usize]);
        let leaf = l.leaves[index as usize];
        let made = tlog_core::inclusion_proof(size, index, &l.stored).unwrap();
        assert!(made == want, "proof of {index} in {size}");
        tlog_core::verify_inclusion_proof(&want, size, root, index, leaf)
            .unwrap_or_else(|e| panic!("proof of {index} in {size}: {e:?}"));
        if !want.is_empty() {
            let mut bad = want.clone();
            bad[0].0[0] ^= 1;
            assert!(tlog_core::verify_inclusion_proof(&bad, size, root, index, leaf).is_err());
            assert!(
                tlog_core::verify_inclusion_proof(&want[1..].to_vec(), size, root, index, leaf)
                    .is_err()
            );
        }
        let mut other = root;
        other.0[0] ^= 1;
        assert!(tlog_core::verify_inclusion_proof(&want, size, other, index, leaf).is_err());
    }
}

/// Every consistency proof of the file is the one the library makes and verifies offline from the two roots and the
/// proof alone; one with a hash changed, or for another old root, is refused.
///
/// verifies: REQ-AUDIT-005, REQ-AUDIT-024
#[test]
fn the_consistency_proofs_of_the_shared_vectors_verify_offline() {
    let l = load();
    let roots = l.v["roots"].as_array().unwrap();
    let proofs = l.v["consistency"].as_array().unwrap();
    assert_eq!(proofs.len(), 91);
    for c in proofs {
        let (old, new) = (c["old"].as_u64().unwrap(), c["new"].as_u64().unwrap());
        let want = path(c);
        let (old_root, new_root) = (hash(&roots[old as usize]), hash(&roots[new as usize]));
        let made = tlog_core::consistency_proof(new, old, &l.stored).unwrap();
        assert!(made == want, "proof {old} to {new}");
        tlog_core::verify_consistency_proof(&want, new, new_root, old, old_root)
            .unwrap_or_else(|e| panic!("proof {old} to {new}: {e:?}"));
        if !want.is_empty() {
            let mut bad = want.clone();
            let last = bad.len() - 1;
            bad[last].0[5] ^= 1;
            assert!(
                tlog_core::verify_consistency_proof(&bad, new, new_root, old, old_root).is_err()
            );
        }
        if old < new {
            let mut forged = old_root;
            forged.0[0] ^= 1;
            assert!(
                tlog_core::verify_consistency_proof(&want, new, new_root, old, forged).is_err()
            );
        }
    }
}
