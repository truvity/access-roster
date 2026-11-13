# ritueel's hand-off vectors, as sluis tests them

These files are a copy of public test material from ritueel (https://github.com/truvity/ritueel, MIT, see `LICENSE`),
taken from commit `f965c2481951872c97bd35362e46461ab4ef276f` of its `main` branch:

- `hand-off/v1/` is `testdata/hand-off/v1/` for the type `x509-intermediate` only: the X.509 requests and answers, the
  pinned test roots (A and B on the root list, Z on none, and the floor's foreign CA) and the test attestation
  hierarchy. `manifest.json` is ritueel's manifest with the entries of the other types (`openpgp-subkey`,
  `ssh-ca-key`) and the OpenPGP primaries removed, because sluis builds none of them in the first working version;
  every other member is as ritueel wrote it.
- `root-list/v1/` is `testdata/root-list/v1/` whole, but for the OpenPGP primaries (`*.pgp`), which the X.509 reader
  does not use. Its `manifest.json` still names them.

Everything here is public material made with throw-away software keys; no private key was ever written. The vectors
fix the outcome and the reason code, not the wording of a message. A change of a vector that flips its outcome is a
new contract version in ritueel, and the counts in `vectors_test.go` and `rootlist_test.go` then change with this
copy, which is the reviewer's cue to read the new version.

To refresh the copy, take the same paths from a newer commit of ritueel, apply the same filter, and update the commit
above and the counts in the tests.
