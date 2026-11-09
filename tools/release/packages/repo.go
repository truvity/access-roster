package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/truvity/sluis/v2/tools/release/repo"
)

// runRepo is `packages repo`: the throwaway apt and dnf trees of the packages in -packages, written into -out. See the package repo:
// the trees are unsigned and for tests, and are not the publication site.
func runRepo(args []string) {
	fs := flag.NewFlagSet("repo", flag.ExitOnError)
	pk := fs.String("packages", "dist/packages", "the directory of `packages build`: the .deb and .rpm files and SHA256SUMS")
	out := fs.String("out", "dist/repo", "where the UNSIGNED throwaway trees go (apt/ and dnf/): empty or absent")
	date := fs.String("date", "", "the date of the metadata, RFC 3339 (default: now)")
	_ = fs.Parse(args)
	o := repo.Options{Packages: *pk, Out: *out}
	if *date != "" {
		d, err := time.Parse(time.RFC3339, *date)
		if err != nil {
			fail(err)
		}
		o.Date = d
	}
	s, err := repo.Build(o)
	if err != nil {
		fail(err)
	}
	if len(s.Problems) > 0 {
		fail(fmt.Errorf("the repository it wrote disagrees with itself:\n%s", repo.ProblemsText(s.Problems)))
	}
	fmt.Printf("packages: repo: %d .deb in %s and %d .rpm in %s: UNSIGNED, for tests only, not the publication site\n",
		s.Debs, filepath.Join(*out, repo.AptDir), s.RPMs, filepath.Join(*out, repo.DnfDir))
}

// runServe is `packages serve`: the files below -dir on a loopback address. The first line it prints, flushed, is
// "serving <dir> on http://127.0.0.1:<port>", which a script reads to learn the port; then it prints a line for each request
// ("GET /apt/dists/stable/Release 200"), and it runs until it is interrupted.
func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("dir", "dist/repo", "the trees of `packages repo`")
	addr := fs.String("addr", "127.0.0.1:0", "a loopback address; port 0 picks a free one")
	_ = fs.Parse(args)
	if st, err := os.Stat(*dir); err != nil || !st.IsDir() {
		fail(fmt.Errorf("%s is not a directory: run `packages repo` first", *dir))
	}
	ln, err := repo.Listen(*addr)
	if err != nil {
		fail(err)
	}
	srv := repo.Server(*dir, os.Stdout)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	fmt.Printf("serving %s on http://%s\n", *dir, ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fail(err)
	}
}
