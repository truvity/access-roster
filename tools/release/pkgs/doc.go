// Package pkgs plans the .deb and .rpm packages of a release, reads a built package back and checks it (ADR 0013, "Packaging per
// runtime"; docs/distribution/packages.md). The builder, which uses the nfpm library, is the command tools/release/packages, a
// module of its own; this package has no dependency but the standard library and yaml, because tools/release links it into the
// job that holds the write tokens (`tools/release check-packages`), and a test holds it to that.
//
// The plan is Plan: the list of the images (deploy/release/images.yaml, generated from the tree) and the actor registry
// (docs/architecture/actors.yaml) give the packages, their executables and their dependencies. The version of every package is
// computed once, by PackageVersion, and every dependency on a package of the release is written from it in the syntax of the format.
// Check reads the built files (ReadPackage has its own reader of a .deb and of an .rpm) and returns every problem.
package pkgs
