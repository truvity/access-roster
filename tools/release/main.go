// Command release holds the steps and checks of the release train that are programs and not shell. Every one takes
// -config, -images, -dist, -root and, where it talks to a registry, -prefix (see usage).
//
//	check-dist       what GoReleaser left in dist, against the configuration: archives, hashes, static ELF, version, no build path
//	preflight        no image of the list is published at this version yet (before anything is pushed)
//	publish-images   build and push the images from the archives with docker buildx; write dist/digests.txt
//	release-images   write release-images.txt from the digests
//	check-images     the release test of the images against the registry (-fresh for the throwaway one)
//	check-catalogue  the release ships audit-catalogue.yaml for its own version and equal to the tagged tree's schemas and actions (without it the writer refuses the release's records)
//	check-sboms      the SPDX documents of the archives and the images
//	rust-changed     the Cargo packages with a binary that a change can affect (they are checked alone: the release builds each alone)
//	sums-add         append files of dist to SHA256SUMS
//	check-sums       SHA256SUMS lists the archives, release-images.txt and every SBOM, with the hashes of the files
//
// `just release-rehearsal` runs them against a throwaway registry on every pull request, and `just release-publish` against
// ghcr.io on a tag (docs/distribution/packages.md, "Releasing").
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfg := fs.String("config", ".goreleaser.yaml", "the GoReleaser configuration the run used")
	imgs := fs.String("images", "deploy/release/images.yaml", "the list of the images of the release")
	dist := fs.String("dist", "dist/release", "the dist directory of the run")
	prefix := fs.String("prefix", "", "the repository prefix of the images: ghcr.io/truvity/sluis, or localhost:PORT/sluis")
	root := fs.String("root", ".", "the repository root")
	switch os.Args[1] {
	case "check-dist":
		late := fs.Bool("late", false, "after sums-add: SHA256SUMS may also list release-images.txt, the audit catalogue and the SBOMs of the images")
		exact := fs.Bool("exact", false, "dist holds exactly the files of the release, regular files all (the job that publishes sets it: the build's files are not trusted)")
		_ = fs.Parse(os.Args[2:])
		if *exact {
			finish("check-dist: dist holds exactly the files of the release, and every archive, checksum and executable is as the configuration says", CheckDistExact(*cfg, *imgs, *dist, *late))
		}
		finish("check-dist: every archive, checksum and executable is as the configuration says", checkDist(*cfg, *dist, *late))
	case "preflight":
		_ = fs.Parse(os.Args[2:])
		needPrefix(*prefix)
		finish("preflight: no image of the list is published at this version", Preflight(Publish{ImagesPath: *imgs, Dist: *dist, Prefix: *prefix, Root: *root}))
	case "publish-images":
		_ = fs.Parse(os.Args[2:])
		needPrefix(*prefix)
		if err := PublishImages(Publish{ImagesPath: *imgs, Dist: *dist, Prefix: *prefix, Root: *root}); err != nil {
			finish("", []string{err.Error()})
		}
		fmt.Println("release: publish-images: every image is pushed; the digests are in " + filepath.Join(*dist, "digests.txt"))
	case "release-images":
		out := fs.String("out", "", "where release-images.txt goes (default: release-images.txt in -dist)")
		_ = fs.Parse(os.Args[2:])
		lines, _, err := ReleaseImages(*imgs, *dist)
		if err != nil {
			finish("", []string{err.Error()})
		}
		if *out == "" {
			*out = filepath.Join(*dist, "release-images.txt")
		}
		if err := os.WriteFile(*out, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil { //nolint:gosec // a release file, read by everyone
			finish("", []string{err.Error()})
		}
		fmt.Printf("release: release-images: %d images in %s\n", len(lines), *out)
	case "check-images":
		base := fs.String("registry", "", "the base URL of the registry the run pushed to, for example http://127.0.0.1:5000 or https://ghcr.io")
		repoPrefix := fs.String("repo-prefix", "sluis", "the repository prefix of the images below the registry host")
		fresh := fs.Bool("fresh", false, "the registry is a throwaway one that holds this release alone: it lists its repositories, and the version is the only tag")
		_ = fs.Parse(os.Args[2:])
		if *base == "" {
			usage()
		}
		finish("check-images: every image is the release's: the version tag, no floating tag, both platforms, every layer by its hash, the executable of its archive",
			CheckImages(ImageCheck{ImagesPath: *imgs, Dist: *dist, Registry: *base, Prefix: *repoPrefix, Fresh: *fresh, Root: *root}))
	case "check-sboms":
		sboms := fs.String("sboms", "dist/release", "the directory that holds the SBOM documents of the images (<image>.sbom.spdx.json)")
		_ = fs.Parse(os.Args[2:])
		finish("check-sboms: every archive and every image has a valid SPDX document that records its dependencies", CheckSBOMs(*cfg, *imgs, *dist, *sboms))
	case "check-catalogue":
		_ = fs.Parse(os.Args[2:])
		finish("check-catalogue: the release ships the audit catalogue of the tagged tree, for its own version", CheckCatalogue(*dist, *root))
	case "rust-changed":
		base := fs.String("base", "", "the commit the change is compared with")
		_ = fs.Parse(os.Args[2:])
		if *base == "" {
			usage()
		}
		pkgs, err := RustChanged(*base)
		if err != nil {
			finish("", []string{err.Error()})
		}
		for _, p := range pkgs {
			fmt.Println(p)
		}
	case "sums-add":
		_ = fs.Parse(os.Args[2:])
		if err := AddSums(*dist, fs.Args()); err != nil {
			finish("", []string{err.Error()})
		}
		fmt.Printf("release: sums-add: %d files added to SHA256SUMS\n", fs.NArg())
	case "check-sums":
		_ = fs.Parse(os.Args[2:])
		finish("check-sums: SHA256SUMS lists the archives, the list of images and every SBOM, with the hashes of the files", CheckSums(*imgs, *dist))
	default:
		usage()
	}
}

func needPrefix(p string) {
	if p == "" {
		fmt.Fprintln(os.Stderr, "release: -prefix is required")
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: release check-dist [-late] [-exact] | preflight | publish-images | release-images | check-images -registry URL | check-catalogue | check-sboms | sums-add FILE... | check-sums  [-prefix P] [-config F] [-images F] [-dist D]  [-config .goreleaser.yaml] [-dist dist/release]")
	os.Exit(2)
}

func finish(ok string, problems []string) {
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "release: "+p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "release: %d problems\n", len(problems))
		os.Exit(1)
	}
	if ok != "" {
		fmt.Println("release: " + ok)
	}
}
