//! The Merkle tree of a log (RFC 6962 section 2.1), kept as its compact range: the hashes of the
//! complete subtrees that make up the tree, largest first. That is all the indexer needs to prove that
//! a new checkpoint extends the one before it and covers the entries it read:
//!
//! - the range of the last verified checkpoint is stored with the cursor;
//! - the leaf hashes of the entries since are appended to it;
//! - the root of the result is compared with the root the new, signed checkpoint states.
//!
//! If the roots agree, the new tree is the old tree plus exactly those entries, and each entry is
//! covered by the signed root. No hash tile is read, and nothing but the entries is trusted.

use aws_lc_rs::digest;

/// A hash of the tree (SHA-256).
pub type Hash = [u8; 32];

/// The hash of the empty tree: the SHA-256 of the empty string.
#[must_use]
pub fn empty_root() -> Hash {
    sha256(&[&[]])
}

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut c = digest::Context::new(&digest::SHA256);
    for p in parts {
        c.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(c.finish().as_ref());
    out
}

/// The hash of a leaf: the SHA-256 of 0x00 and the entry (RFC 6962 section 2.1).
#[must_use]
pub fn leaf_hash(entry: &[u8]) -> Hash {
    sha256(&[&[0x00], entry])
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[0x01], left, right])
}

/// The compact range of a tree: one complete subtree per set bit of the size, largest first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Range {
    /// `(level, hash)`: the subtree holds `2^level` leaves. Levels strictly decrease.
    nodes: Vec<(u8, Hash)>,
    size: u64,
}

/// The state is not a compact range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadState;

impl Range {
    /// The range of the empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Appends one leaf, by its hash.
    pub fn append(&mut self, leaf: Hash) {
        let mut level = 0u8;
        let mut hash = leaf;
        // A node of the same level on the right end merges with the new one.
        while let Some((l, left)) = self.nodes.last() {
            if *l != level {
                break;
            }
            hash = node_hash(left, &hash);
            level += 1;
            self.nodes.pop();
        }
        self.nodes.push((level, hash));
        self.size += 1;
    }

    /// The root of the tree (RFC 6962 `MTH`): the subtrees folded from the right.
    #[must_use]
    pub fn root(&self) -> Hash {
        let mut it = self.nodes.iter().rev();
        let Some((_, last)) = it.next() else {
            return empty_root();
        };
        it.fold(*last, |acc, (_, left)| node_hash(left, &acc))
    }

    /// The range as bytes: for each subtree its level and its hash.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.nodes.len() * 33);
        for (l, h) in &self.nodes {
            out.push(*l);
            out.extend_from_slice(h);
        }
        out
    }

    /// Reads a range written by [`encode`](Self::encode). The levels must strictly decrease and be
    /// below 64, which is what a range of a real tree is.
    ///
    /// # Errors
    ///
    /// [`BadState`] for anything else.
    pub fn decode(b: &[u8]) -> Result<Self, BadState> {
        if !b.len().is_multiple_of(33) {
            return Err(BadState);
        }
        let (mut nodes, mut size) = (Vec::new(), 0u64);
        for c in b.as_chunks::<33>().0 {
            let level = c[0];
            if level >= 63 || nodes.last().is_some_and(|(l, _): &(u8, Hash)| *l <= level) {
                return Err(BadState);
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&c[1..]);
            size = size.checked_add(1 << level).ok_or(BadState)?;
            nodes.push((level, h));
        }
        Ok(Self { nodes, size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6962 `MTH` of a list of leaf hashes, by the definition (split at the largest power of two
    /// smaller than the size), to check the incremental range against.
    fn mth(leaves: &[Hash]) -> Hash {
        match leaves.len() {
            0 => empty_root(),
            1 => leaves[0],
            n => {
                // The largest power of two smaller than n.
                let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
                node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    #[test]
    fn the_range_gives_the_root_of_the_definition_at_every_size() {
        let leaves: Vec<Hash> = (0..70u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        let mut r = Range::new();
        assert_eq!(r.root(), mth(&[]));
        for (i, l) in leaves.iter().enumerate() {
            r.append(*l);
            assert_eq!(r.size(), i as u64 + 1);
            assert_eq!(r.root(), mth(&leaves[..=i]), "size {}", i + 1);
        }
    }

    #[test]
    fn the_range_survives_its_encoding_and_a_bad_one_is_refused() {
        let mut r = Range::new();
        for i in 0..37u32 {
            r.append(leaf_hash(&i.to_be_bytes()));
        }
        let back = Range::decode(&r.encode()).expect("decode");
        assert_eq!(back, r);
        assert_eq!(back.size(), 37);
        assert!(Range::decode(&r.encode()[..40]).is_err());
        let mut twice = r.encode();
        twice.extend_from_slice(&r.encode()[..33]);
        assert!(Range::decode(&twice).is_err(), "levels must decrease");
        assert_eq!(Range::decode(&[]).expect("empty").root(), empty_root());
    }

    #[test]
    fn the_known_empty_and_one_leaf_roots() {
        // SHA-256 of the empty string, and of 0x00 (RFC 6962 section 2.1; the Go tlog package agrees).
        assert_eq!(
            empty_root()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            leaf_hash(&[])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }
}
