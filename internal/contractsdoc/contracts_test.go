// Package contractsdoc holds one test: every proto service and RPC is
// named in docs/reference/contracts.md.
//
// The contracts page is the reference a stranger reads to learn what the
// console serves. It fell four services behind once without anyone
// noticing, because nothing compares it with the protos. This does.
package contractsdoc

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// undocumented lists items deliberately absent from contracts.md, each with
// the reason. Keep it empty: an entry here is a promise nobody can read.
var undocumented = map[string]string{
	// "directoryroster.v1.ExampleService/Rpc": "why a reader does not need it",
}

var (
	serviceRe = regexp.MustCompile(`(?m)^\s*service\s+([A-Za-z0-9_]+)\s*\{`)
	rpcRe     = regexp.MustCompile(`(?m)^\s*rpc\s+([A-Za-z0-9_]+)\s*\(`)
	pkgRe     = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;`)
)

func mentions(doc []byte, ident string) bool {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`).Match(doc)
}

func TestEveryServiceAndRPCIsDocumented(t *testing.T) {
	root := filepath.Join("..", "..")
	doc, err := os.ReadFile(filepath.Join(root, "docs", "reference", "contracts.md"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "proto", "*", "*", "*.proto"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no proto files found: %v", err)
	}
	used := map[string]bool{}
	var missing []string
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		pkg := ""
		if m := pkgRe.FindSubmatch(src); m != nil {
			pkg = string(m[1])
		}
		// Split the file at each service so an RPC belongs to its service.
		idx := serviceRe.FindAllSubmatchIndex(src, -1)
		for i, loc := range idx {
			end := len(src)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			svc := string(src[loc[2]:loc[3]])
			key := pkg + "." + svc
			check := func(key, ident string) {
				if reason, ok := undocumented[key]; ok {
					used[key] = true
					if reason == "" {
						t.Errorf("allow-list entry %s has no reason", key)
					}
					return
				}
				if !mentions(doc, ident) {
					missing = append(missing, key)
				}
			}
			check(key, svc)
			for _, m := range rpcRe.FindAllSubmatch(src[loc[1]:end], -1) {
				check(key+"/"+string(m[1]), string(m[1]))
			}
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		t.Errorf("docs/reference/contracts.md does not mention %s", k)
	}
	for k := range undocumented {
		if !used[k] {
			t.Errorf("allow-list entry %s matches nothing in proto/; remove it", k)
		}
	}
}
