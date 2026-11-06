# RFC 8785 test corpus

The inputs and expected outputs of the JSON Canonicalization Scheme (RFC 8785) test data by the RFC's author, Anders Rundgren.

- Source: https://github.com/cyberphone/json-canonicalization/tree/master/testdata (commit `32a48195b9b20fe67b1795e39e4509f14d860b45`, fetched 2026-11-06). The files are unchanged copies of `testdata/input` and `testdata/output`; `testdata/outhex` is derived from them and is not copied.
- Licence: Apache License 2.0; the licence notice of the source repository, from the same commit, is `LICENSE` beside this file.
- Used by `kits/go/audit/corpus_test.go` and `kits/rust/sluis-audit/src/tests.rs`, which run each input through the canonicalisation library, and through the sluis profile, and compare the bytes with `output/`. `structures.json` and `values.json` carry numbers that are not integers: the library canonicalises them, and the sluis profile refuses them (a record has no floating point).
- `../jcs-differential.tsv` holds the canonical text, or `!refused`, that both languages must produce for this corpus, for `../jcs-vectors.json` and for the records of `../record-vectors.json`. The Go test writes it (`SLUIS_UPDATE_GOLDEN=1 go test ./kits/go/audit -run TestDifferentialWithRust`); a byte that changes in it is a changed audit record hash and needs a decision, not a regeneration.
