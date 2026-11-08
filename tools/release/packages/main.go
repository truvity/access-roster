package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	acts := fs.String("actors", "docs/architecture/actors.yaml", "the actor registry")
	imgs := fs.String("images", "deploy/release/images.yaml", "the list of the images of the release, which lists every executable built with GoReleaser")
	dist := fs.String("dist", "dist/release", "the dist directory of the GoReleaser run: the archives and metadata.json")
	out := fs.String("out", "dist/packages", "where the packages go (build: empty or absent) and are read from (check)")
	switch os.Args[1] {
	case "build":
		_ = fs.Parse(os.Args[2:])
		version, err := distVersion(*dist)
		if err != nil {
			fail(err)
		}
		specs, err := plan(*imgs, *acts)
		if err != nil {
			fail(err)
		}
		b := Builder{Dist: *dist, Out: *out, Version: version, Specs: specs}
		if err := b.Build(); err != nil {
			fail(err)
		}
		fmt.Printf("packages: build: %d packages of %s in %s\n", len(specs)*len(archList())*len(formats), version, *out)
	case "check":
		_ = fs.Parse(os.Args[2:])
		version, err := distVersion(*dist)
		if err != nil {
			fail(err)
		}
		specs, actors, err := planWithActors(*imgs, *acts)
		if err != nil {
			fail(err)
		}
		problems := Check(CheckInput{Dist: *dist, Out: *out, Version: version, Specs: specs, Actors: actors})
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "packages: "+p)
		}
		if len(problems) > 0 {
			fmt.Fprintf(os.Stderr, "packages: %d problems\n", len(problems))
			os.Exit(1)
		}
		fmt.Println("packages: check: every package is as the plan says: exact versions, modes, static executables of the archives, no start or enable in a script, deb and rpm alike")
	default:
		usage()
	}
}

func plan(imgs, acts string) ([]Spec, error) {
	s, _, err := planWithActors(imgs, acts)
	return s, err
}

func planWithActors(imgs, acts string) ([]Spec, []Actor, error) {
	images, err := loadImages(imgs)
	if err != nil {
		return nil, nil, err
	}
	actors, err := loadActors(acts)
	if err != nil {
		return nil, nil, err
	}
	specs, err := Plan(images, actors)
	return specs, actors, err
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "packages: "+err.Error())
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: packages build|check [-images deploy/release/images.yaml] [-actors docs/architecture/actors.yaml] [-dist dist/release] [-out dist/packages]")
	os.Exit(2)
}
