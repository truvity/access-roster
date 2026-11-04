// Package signedconfig verifies a signed config document in Go: steps 1 to 5 of docs/reference/signed-config.md
// ("Verifying a document", "The sequence number"), and reads the publisher keys of the bootstrap file.
//
// store@ verifies every document it loads, in Rust. A caller that must not rely on store@ for what a document says
// (key@, which wraps data keys only to the recipients of the signed KeyPlan) fetches the bytes with
// StoreService.GetSignedConfig and verifies them here, under the publisher keys of its own copy of the bootstrap
// file (principle 4: verify, never trust a claim; ADR 0005, "Signed config documents").
//
// This is a second implementation of the same contract, not shared code (principle 6). The two must agree, and
// tests/testdata/signed-config/vectors.json is the proof: store@'s tests and this package's tests run the same
// documents and expect the same verdicts, step for step.
//
// The kit stops at the signature layer and the sequence. It never reads a payload: what the payload means belongs
// to the caller, which reads the bytes of a Verified and no others.
package signedconfig
