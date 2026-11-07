package audit

import (
	"encoding/hex"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// merkleVectors is kits/conformance/audit/merkle-vectors.json: the RFC 6962 section 2.1 tree of thirteen leaves, its
// roots at every size, and the inclusion and consistency proofs of every index and size, made by a program that shares
// no code with the product. The Rust kit reads the same file (actors/indexer/tests/merkle_vectors.rs).
type merkleVectors struct {
	Leaves    []string `json:"leaves"`
	Roots     []string `json:"roots"`
	Inclusion []struct {
		Size, Index int64
		Path        []string
	} `json:"inclusion"`
	Consistency []struct {
		Old, New int64
		Path     []string
	} `json:"consistency"`
}

type vecStore struct{ hashes []tlog.Hash }

func (s vecStore) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = s.hashes[x]
	}
	return out, nil
}

func hashOf(t *testing.T, s string) tlog.Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != tlog.HashSize {
		t.Fatalf("bad hash %q", s)
	}
	return tlog.Hash(b)
}

func proofOf(t *testing.T, p []string) tlog.RecordProof {
	t.Helper()
	out := make(tlog.RecordProof, len(p))
	for i, s := range p {
		out[i] = hashOf(t, s)
	}
	return out
}

func loadMerkle(t *testing.T) (merkleVectors, vecStore, []tlog.Hash) {
	t.Helper()
	var v merkleVectors
	readVectors(t, "merkle-vectors.json", &v)
	var st vecStore
	var leafHashes []tlog.Hash
	for i, l := range v.Leaves {
		data, err := hex.DecodeString(l)
		if err != nil {
			t.Fatal(err)
		}
		hs, err := tlog.StoredHashes(int64(i), data, st)
		if err != nil {
			t.Fatal(err)
		}
		st.hashes = append(st.hashes, hs...)
		leafHashes = append(leafHashes, tlog.RecordHash(data))
	}
	return v, st, leafHashes
}

// The roots of the RFC 6962 definition, in the form the log is built with, are the roots of the vector file at every
// size, the first eight those of the Certificate Transparency reference tree.
//
// verifies: REQ-AUDIT-005
func TestTheTreeHashesAreTheRFC6962RootsOfTheSharedVectors(t *testing.T) {
	v, st, _ := loadMerkle(t)
	if len(v.Leaves) != 13 || len(v.Roots) != 14 {
		t.Fatalf("%d leaves and %d roots: the vector file changed", len(v.Leaves), len(v.Roots))
	}
	for n := range int64(len(v.Roots)) {
		got, err := tlog.TreeHash(n, st)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got[:]) != v.Roots[n] {
			t.Errorf("root of size %d = %x, want %s", n, got, v.Roots[n])
		}
	}
}

// Every inclusion proof of the file is the proof the library makes, and verifies offline: from the leaf, the proof and
// the root alone. A proof with a hash changed, one hash short, one for another index or size, or against another root
// is refused.
//
// verifies: REQ-AUDIT-005, REQ-AUDIT-024
func TestInclusionProofsOfTheSharedVectorsVerifyOffline(t *testing.T) {
	v, st, leaves := loadMerkle(t)
	if len(v.Inclusion) != 91 {
		t.Fatalf("%d inclusion proofs", len(v.Inclusion))
	}
	for _, c := range v.Inclusion {
		want := proofOf(t, c.Path)
		root := hashOf(t, v.Roots[c.Size])
		made, err := tlog.ProveRecord(c.Size, c.Index, st)
		if err != nil || !slices.Equal(made, want) {
			t.Fatalf("proof of %d in %d = %x (%v), want %x", c.Index, c.Size, made, err, want)
		}
		if err := tlog.CheckRecord(want, c.Size, root, c.Index, leaves[c.Index]); err != nil {
			t.Fatalf("proof of %d in %d does not verify: %v", c.Index, c.Size, err)
		}
		if c.Index > 0 {
			if tlog.CheckRecord(want, c.Size, root, c.Index-1, leaves[c.Index]) == nil && len(want) > 0 {
				t.Errorf("proof of %d in %d verified for index %d", c.Index, c.Size, c.Index-1)
			}
		}
		if len(want) > 0 {
			bad := slices.Clone(want)
			bad[0][0] ^= 1
			if tlog.CheckRecord(bad, c.Size, root, c.Index, leaves[c.Index]) == nil {
				t.Errorf("a changed proof of %d in %d verified", c.Index, c.Size)
			}
			if tlog.CheckRecord(want[1:], c.Size, root, c.Index, leaves[c.Index]) == nil {
				t.Errorf("a short proof of %d in %d verified", c.Index, c.Size)
			}
		}
		other := root
		other[0] ^= 1
		if tlog.CheckRecord(want, c.Size, other, c.Index, leaves[c.Index]) == nil {
			t.Errorf("proof of %d in %d verified against another root", c.Index, c.Size)
		}
	}
}

// Every consistency proof of the file is the proof the library makes, and verifies offline from the two roots and the
// proof alone; one with a hash changed, or between roots of other sizes, is refused.
//
// verifies: REQ-AUDIT-005, REQ-AUDIT-024
func TestConsistencyProofsOfTheSharedVectorsVerifyOffline(t *testing.T) {
	v, st, _ := loadMerkle(t)
	if len(v.Consistency) != 91 {
		t.Fatalf("%d consistency proofs", len(v.Consistency))
	}
	for _, c := range v.Consistency {
		want := tlog.TreeProof(proofOf(t, c.Path))
		oldRoot, newRoot := hashOf(t, v.Roots[c.Old]), hashOf(t, v.Roots[c.New])
		made, err := tlog.ProveTree(c.New, c.Old, st)
		if err != nil || !slices.Equal(made, want) {
			t.Fatalf("proof %d to %d = %x (%v), want %x", c.Old, c.New, made, err, want)
		}
		if err := tlog.CheckTree(want, c.New, newRoot, c.Old, oldRoot); err != nil {
			t.Fatalf("proof %d to %d does not verify: %v", c.Old, c.New, err)
		}
		if len(want) > 0 {
			bad := slices.Clone(want)
			bad[len(bad)-1][5] ^= 1
			if tlog.CheckTree(bad, c.New, newRoot, c.Old, oldRoot) == nil {
				t.Errorf("a changed proof %d to %d verified", c.Old, c.New)
			}
		}
		if c.Old < c.New {
			// The same proof does not show that a log of another history extends the old one.
			forged := oldRoot
			forged[0] ^= 1
			if tlog.CheckTree(want, c.New, newRoot, c.Old, forged) == nil {
				t.Errorf("proof %d to %d verified for another old root", c.Old, c.New)
			}
		}
	}
}
