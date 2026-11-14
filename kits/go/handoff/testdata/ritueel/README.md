# ritueel's hand-off vectors, as sluis tests them

These files are a copy of public test material from ritueel (https://github.com/truvity/ritueel, MIT, see `LICENSE`),
taken from commit `ab8c61463f0acfab8070bd9d29b321a77f01c7e7` of its `main` branch (the hand-off contract of ritueel PR 232 and the root list reference
of the same commit), whole and unchanged:

- `hand-off/v1/` is `testdata/hand-off/v1/`: the manifest with its 166 requests (127 of the type `x509-intermediate`,
  20 `openpgp-subkey`, 19 `ssh-ca-key`) and 38 answers (20, 11 and 7), the pinned test roots (A and B on the root list,
  Z on none, and the floor's foreign CA), the test attestation hierarchy, the proofs and the stubs of the KMS cases, and
  the three configurations (`production`, `development` and `development-listed-names`).
- `root-list/v1/` is `testdata/root-list/v1/`: the manifest with its 53 cases, the lists, the removal authorisations,
  the CA bundles and the test roots, with the OpenPGP primaries.

Everything here is public material made with throw-away software keys; no private key was ever written. The vectors
fix the outcome and the reason code, not the wording of a message. A change of a vector that flips its outcome is a
new contract version in ritueel, and the counts in `vectors_test.go` and `rootlist_test.go` (and in the test of the
certifier in `tools/harness/certifier`) then change with this copy, which is the reviewer's cue to read the new version.

sluis builds the type `x509-intermediate` only in the first working version, so the tests of the readers run the
X.509 vectors for their outcome and reason code and say, for each vector of another type, that sluis's reader refuses it
as `malformed` (or `version-unsupported` when the version is the fault), which is what the contract says of a type the
receiver does not know. Nothing was removed from the set to make a test pass. The SSH CA key list and CRL vectors of
ritueel are not copied: sluis reads neither yet.

To refresh the copy, take the same paths from a newer commit of ritueel (`cp -r` of the two `v1` directories, after
removing the old ones), and update the commit above and the counts in the tests. `.gitattributes` here keeps the files
byte for byte: their digests are inside the proofs, the results and the signatures.
