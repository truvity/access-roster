// Package repo builds a THROWAWAY apt repository and a THROWAWAY dnf repository from the packages that tools/release/packages
// built, and serves them on the loopback address, so that a test can install the release from a repository the way a customer
// will: with apt and dnf resolving the dependencies through the metadata, not from files on disk (ADR 0013; the design note of
// the first working version, "install-verify", step 2 of the verify job).
//
// It is NOT the publication site. The site (the apt and dnf trees of the R2 bucket, docs/distribution/packages.md, "The R2
// layout") is v1 parity, signed, and built by code that does not exist yet. The trees made here are UNSIGNED, have no
// InRelease, Release.gpg or repomd.xml.asc, and a client must be told to trust them (`[trusted=yes]` for apt, `gpgcheck=0` and
// `repo_gpgcheck=0` for dnf). Every tree carries a file that says so (UnsignedNotice), and Serve refuses an address that is not
// loopback, so the tool cannot publish by mistake.
//
// The metadata is written in Go, from the packages themselves (the readers of tools/release/pkgs), with the standard library
// alone: no createrepo, no dpkg-scanpackages and no apt-ftparchive. Check reads a tree back by another path (the standard
// library's XML decoder and its own parser of the Packages and Release files) and returns every disagreement between the
// metadata and the files, and Build runs it on what it wrote.
//
// Like tools/release/pkgs, this package imports the standard library and tools/release/pkgs, and a test holds it to that. The
// job that publishes does not link it (tools/release/imports_test.go holds that), so it holds no token and never runs there.
package repo
