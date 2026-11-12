// Command release holds the steps and checks of the release train that are programs and not shell. Every one takes
// -config, -images, -dist, -root and, where it talks to a registry, -prefix (see usage).
//
//	check-dist       what GoReleaser left in dist, against the configuration: archives, hashes, static ELF, version, no build path
//	preflight        no image of the list is in the registry at this version unless this run pushed it (before anything is pushed)
//	publish-images   build and push the images from the archives with docker buildx; write dist/digests.txt and, as each image is pushed, the journal
//	recorded         merge the journals that earlier attempts of the run uploaded (zip files) into the record that preflight and publish-images read
//	check-public     pull every image of release-images.txt by digest, without a credential: a private package fails, and the page that makes it public is named
//	release-images   write release-images.txt from the digests
//	check-images     the release test of the images against the registry (-fresh for the throwaway one)
//	check-catalogue  the release ships audit-catalogue.yaml for its own version and equal to the tagged tree's schemas and actions (without it the writer refuses the release's records)
//	check-sboms      the SPDX documents of the archives and the images
//	rust-changed     the Cargo packages with a binary that a change can affect (they are checked alone: the release builds each alone)
//	sums-add         append files of dist to SHA256SUMS
//	check-packages   the .deb and .rpm packages of dist/packages (tools/release/packages builds them): read back and checked against the plan
//	check-candidate  the files to publish are the ones a candidate built and installed (the evidence names them by digest)
//	assets-plan      what makes the assets of a draft the files of the release (a re-run uploads only what is missing); -verify: nothing is left to do
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

	"github.com/truvity/sluis/v2/tools/release/pkgs"
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
		recorded := fs.String("recorded", "", "the digests that earlier attempts of this run recorded (see `recorded`): a tag in the registry is kept only if it is there")
		_ = fs.Parse(os.Args[2:])
		needPrefix(*prefix)
		finish("preflight: every image that is in the registry at this version was pushed by this run",
			Preflight(Publish{ImagesPath: *imgs, Dist: *dist, Prefix: *prefix, Root: *root, Recorded: *recorded}))
	case "recorded":
		out := fs.String("out", "", "where the merged record goes")
		_ = fs.Parse(os.Args[2:])
		if *out == "" {
			usage()
		}
		if err := MergeRecorded(*out, fs.Args()); err != nil {
			finish("", []string{err.Error()})
		}
		fmt.Printf("release: recorded: %d journals merged into %s\n", fs.NArg(), *out)
	case "publish-images":
		recorded := fs.String("recorded", "", "the digests that earlier attempts of this run recorded (see `recorded`): a tag in the registry is kept only if it is there")
		journal := fs.String("journal", "", "where each digest is appended as soon as its image is pushed (the workflow uploads it as the record of this attempt)")
		_ = fs.Parse(os.Args[2:])
		needPrefix(*prefix)
		if err := PublishImages(Publish{ImagesPath: *imgs, Dist: *dist, Prefix: *prefix, Root: *root, Recorded: *recorded, Journal: *journal}); err != nil {
			finish("", []string{err.Error()})
		}
		fmt.Println("release: publish-images: every image is pushed; the digests are in " + filepath.Join(*dist, "digests.txt"))
	case "check-public":
		list := fs.String("list", "dist/release/release-images.txt", "release-images.txt")
		_ = fs.Parse(os.Args[2:])
		finish("check-public: every image of the release can be pulled by its digest without a credential", CheckPublic(*list, nil))
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
	case "check-packages":
		pkgDir := fs.String("packages", "dist/packages", "the directory of the packages tools/release/packages built")
		actors := fs.String("actors", "docs/architecture/actors.yaml", "the actor registry")
		units := fs.String("units", pkgs.UnitsDir, "the units, users and directories tools/gen/units wrote, which the packages ship")
		_ = fs.Parse(os.Args[2:])
		version, err := pkgs.DistVersion(*dist)
		if err != nil {
			finish("", []string{err.Error()})
		}
		specs, acts, err := pkgs.PlanFiles(*imgs, *actors, *units)
		if err != nil {
			finish("", []string{err.Error()})
		}
		finish("check-packages: every package is as the plan says: exact versions, modes, static executables of the archives, no script the plan does not list, deb and rpm alike",
			pkgs.Check(pkgs.CheckInput{Dist: *dist, Out: *pkgDir, Version: version, Specs: specs, Actors: acts}))
	case "check-candidate":
		pkgDir := fs.String("packages", "dist/packages", "the packages of the candidate")
		ev := fs.String("evidence", "dist/candidate/evidence.json", "the evidence of the candidate")
		nodes := fs.String("nodes", "deploy/verify/nodes.tsv", "the systems of the install tier")
		version := fs.String("version", "", "the version of the tag, without the v")
		commit := fs.String("commit", "", "the commit the tag names")
		_ = fs.Parse(os.Args[2:])
		if *version == "" || *commit == "" {
			usage()
		}
		finish("check-candidate: the files to publish are the ones a candidate built and installed on every system and both architectures, by digest",
			CheckCandidate(CandidateCheck{Dist: *dist, Packages: *pkgDir, Evidence: *ev, NodesFile: *nodes, Version: *version, Commit: *commit}))
	case "assets-plan":
		remote := fs.String("remote", "", "the assets of the draft, as JSON (gh api repos/<repo>/releases/<id> --jq .assets)")
		list := fs.String("files", "", "the files of the release, one path on each line")
		verify := fs.Bool("verify", false, "the plan must be empty: the draft holds the release and nothing more")
		uploadedFile := fs.String("uploaded", "", "the names this job uploaded itself, one on each line: for these a size alone is enough when the API gives no digest")
		_ = fs.Parse(os.Args[2:])
		if *remote == "" || *list == "" {
			usage()
		}
		files, err := readLines(*list)
		if err != nil {
			finish("", []string{err.Error()})
		}
		raw, err := os.ReadFile(*remote) //nolint:gosec // the API's answer, which the recipe saved
		if err != nil {
			finish("", []string{err.Error()})
		}
		uploaded, err := readSet(*uploadedFile)
		if err != nil {
			finish("", []string{err.Error()})
		}
		plan, notes, err := PlanAssets(files, raw, uploaded)
		if err != nil {
			finish("", []string{err.Error()})
		}
		for _, n := range notes {
			fmt.Fprintln(os.Stderr, "release: assets-plan: "+n)
		}
		for _, a := range plan {
			if a.Kind == "delete" {
				fmt.Printf("delete\t%d\t%s\n", a.ID, a.Name)
			} else {
				fmt.Printf("upload\t%s\t%s\n", a.Path, a.Name)
			}
			fmt.Fprintf(os.Stderr, "release: assets-plan: %s %s: %s\n", a.Kind, a.Name, a.Why)
		}
		if *verify && len(plan) > 0 {
			finish("", []string{fmt.Sprintf("the draft does not hold the release: %d steps are left", len(plan))})
		}
	case "check-sums":
		cand := fs.Bool("candidate", false, "the release promotes a candidate: SHA256SUMS must also list the sums of its packages and its evidence")
		_ = fs.Parse(os.Args[2:])
		finish("check-sums: SHA256SUMS lists the archives, the list of images and every SBOM, with the hashes of the files", CheckSums(*imgs, *dist, *cand))
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
	fmt.Fprintln(os.Stderr, "usage: release check-dist [-late] [-exact] | preflight [-recorded F] | recorded -out F ZIP... | publish-images [-recorded F] [-journal F] | release-images | check-images -registry URL | check-catalogue | check-public | check-sboms | sums-add FILE... | check-packages | check-candidate -version V -commit C | assets-plan -remote F -files F [-uploaded F] [-verify] | check-sums [-candidate]  [-prefix P] [-config F] [-images F] [-dist D]  [-config .goreleaser.yaml] [-dist dist/release]")
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
