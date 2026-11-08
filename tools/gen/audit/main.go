// Command audit generates, from the action table docs/architecture/audit-actions.yaml, the JSON Schema of the audit
// records (a shared defs.schema.json and one slim schema for each action), one example record for each action, and the
// table with its schemas as Go and Rust code for the emitters (ADR 0030, "The action table is code"). Run it from the
// repository root with `just audit-gen`; `just audit-check` fails while a committed file differs from what this makes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

const (
	tablePath  = "docs/architecture/audit-actions.yaml"
	schemaDir  = "kits/conformance/audit/schema"
	vectorsOut = "kits/conformance/audit/action-vectors.json"
	goOut      = "kits/go/audit/zz_table.go"
	rustOut    = "kits/rust/sluis-audit/src/generated.rs"
	// catalogueOut is the AuditCatalogue document of the local installation: the table and its schemas as one item, signed
	// and served by the harness (REQ-AUDIT-147). A release pipeline makes the document of a release with -catalogue.
	catalogueOut = "tests/installations/local/config/audit-catalogue.yaml"
	// localRelease is the release the local installation's document names: no release of sluis is below it.
	localRelease = "0.0.0"
)

// generate returns every generated file by its path below the root.
func generate(root string) (map[string][]byte, error) {
	t, err := load(filepath.Join(root, tablePath))
	if err != nil {
		return nil, err
	}
	schemas, texts, err := schemaTexts(t)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for name, doc := range schemas {
		pretty, err := marshal(doc, true)
		if err != nil {
			return nil, err
		}
		files[filepath.Join(schemaDir, name)] = pretty
	}
	vec, err := buildVectors(t)
	if err != nil {
		return nil, err
	}
	files[vectorsOut] = vec
	if files[goOut], err = emitGo(t, texts); err != nil {
		return nil, err
	}
	if files[rustOut], err = emitRust(t, texts); err != nil {
		return nil, err
	}
	if files[catalogueOut], err = emitCatalogue(t, texts, localRelease); err != nil {
		return nil, err
	}
	return files, nil
}

// schemaTexts returns the schema documents and their compact text (for the emitters and the catalogue), by file name.
func schemaTexts(t *tableFile) (map[string]obj, map[string]string, error) {
	schemas, err := buildSchemas(t)
	if err != nil {
		return nil, nil, err
	}
	texts := map[string]string{}
	for name, doc := range schemas {
		compact, err := marshal(doc, false)
		if err != nil {
			return nil, nil, err
		}
		texts[name] = string(compact)
	}
	return schemas, texts, nil
}

func run(root string, check bool) error {
	files, err := generate(root)
	if err != nil {
		return err
	}
	if check {
		return compare(root, files)
	}
	// The schema directory holds only what the table makes: a file of a removed action goes.
	old, _ := filepath.Glob(filepath.Join(root, schemaDir, "*.schema.json"))
	for _, p := range old {
		rel, _ := filepath.Rel(root, p)
		if _, keep := files[rel]; !keep {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	for rel, src := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, src, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// compare fails when a committed file differs from what the table makes, or a schema file has no action.
func compare(root string, files map[string][]byte) error {
	var bad []string
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // a generated file of the repository
		if err != nil || string(got) != string(want) {
			bad = append(bad, rel)
		}
	}
	old, _ := filepath.Glob(filepath.Join(root, schemaDir, "*.schema.json"))
	for _, p := range old {
		rel, _ := filepath.Rel(root, p)
		if _, ok := files[rel]; !ok {
			bad = append(bad, rel+" (no action makes it)")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("stale, run `just audit-gen`: %v", bad)
	}
	return nil
}

func main() {
	root := flag.String("root", ".", "the repository root")
	check := flag.Bool("check", false, "fail when a generated file is not what the table makes, and write nothing")
	catalogue := flag.String("catalogue", "", "write the AuditCatalogue document of -release to this file (the release pipeline's step, REQ-AUDIT-147) and nothing else")
	release := flag.String("release", "", "the release the -catalogue document is made for, a semantic version")
	tag := flag.String("tag", "", "with -against: the release tag the table is from; a pre-release (v2.0.0-alpha.N) promises nothing (ADR 0013), so its findings are printed and do not fail, and a stable tag's fail")
	against := flag.String("against", "", "the action table of the last release: fail when this table removes or retypes a member of unmapped.sluis against it (REQ-AUDIT-119); nothing is written")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "audit: no arguments, only flags")
		os.Exit(2)
	}
	if *catalogue != "" {
		if err := runCatalogue(*root, *catalogue, *release); err != nil {
			fmt.Fprintf(os.Stderr, "audit: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *against != "" {
		if err := runCompat(*root, *against, *tag); err != nil {
			fmt.Fprintf(os.Stderr, "audit: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*root, *check); err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		os.Exit(1)
	}
}

// runCompat compares the table of the repository with the table of the last release, the one the tag names. Against a pre-release
// (a tag with a hyphen, v2.0.0-alpha.N) nothing is promised between two releases (ADR 0013), so what it finds is printed, as a
// warning for CI, and the check does not fail; against a stable tag, or against none, it fails.
func runCompat(root, oldPath, tag string) error {
	err := runCompatTables(oldPath, filepath.Join(root, tablePath))
	if err != nil && preRelease(tag) && strings.HasPrefix(err.Error(), notCompatible) {
		fmt.Printf("::warning::audit-compat: ADVISORY, %s is a pre-release and promises nothing (ADR 0013)\n%v\n", tag, err)
		return nil
	}
	return err
}

// notCompatible starts the error of a table that is not compatible, as opposed to one that cannot be read or built.
const notCompatible = "the table is not compatible with the last release"

// preRelease says whether a release tag is a pre-release: v2.0.0-alpha.1 is, v2.0.0 is not.
func preRelease(tag string) bool { return strings.Contains(tag, "-") }

// runCompatTables compares two tables: the rules of compat, and the proof that the old table's example records still validate
// against the new schemas, which fails the build even where the rules found nothing.
func runCompatTables(oldPath, curPath string) error {
	old, err := loadOld(oldPath)
	if err != nil {
		return err
	}
	cur, err := load(curPath)
	if err != nil {
		return err
	}
	found := compat(old, cur)
	bad, err := oldRecordsUnder(old, cur)
	if err != nil {
		return err
	}
	for _, a := range bad {
		found = append(found, a+": the example record of the old release fails the schema of the new")
	}
	if len(found) > 0 {
		return fmt.Errorf(notCompatible+" (a change of this kind needs a new major version of sluis):\n  %s", strings.Join(found, "\n  "))
	}
	return nil
}

// runCatalogue writes the AuditCatalogue document of a release.
func runCatalogue(root, out, release string) error {
	if !audit.ValidRelease(release) {
		return fmt.Errorf("-release %q is not a semantic version (MAJOR.MINOR.PATCH, no v)", release)
	}
	t, err := load(filepath.Join(root, tablePath))
	if err != nil {
		return err
	}
	_, texts, err := schemaTexts(t)
	if err != nil {
		return err
	}
	doc, err := emitCatalogue(t, texts, release)
	if err != nil {
		return err
	}
	return os.WriteFile(out, doc, 0o600)
}
