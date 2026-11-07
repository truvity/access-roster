// Command configschema generates the JSON Schema of the configuration files from their Protobuf messages (ADR 0004,
// "Schemas are Protobuf"; REQ-DATA-037): one schema for each root in schema.go, written to
// schema/<name>/<version>/<name>.schema.json. Run it from the repository root with `just config-schema-gen`;
// `just config-schema-check` fails while a committed schema differs from what the messages make. The schema is a
// derived subset of the protovalidate rules, and the file is the golden that CI compares and every binary embeds.
//
// The descriptors come from `buf build`, which resolves the protovalidate dependency in buf.lock and keeps the comments
// that become the descriptions of the schema.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// schemaDir is where the schemas are, below the repository root.
const schemaDir = "schema"

// load builds the descriptors of the module in dir with buf.
func load(dir string) (*protodescFiles, error) {
	tmp, err := os.MkdirTemp("", "configschema")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	out := filepath.Join(tmp, "image.binpb")
	cmd := exec.Command("buf", "build", dir, "--as-file-descriptor-set", "-o", out) //nolint:gosec // a fixed tool and the repository root
	if msg, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("buf build: %w\n%s", err, msg)
	}
	raw, err := os.ReadFile(out) //nolint:gosec // the file made above
	if err != nil {
		return nil, err
	}
	return filesOf(raw)
}

// generate returns every schema by its path below the repository root.
func generate(files *protodescFiles) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, r := range roots {
		d, err := files.FindDescriptorByName(protoreflect.FullName(r.Message))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Message, err)
		}
		md, ok := d.(protoreflect.MessageDescriptor)
		if !ok {
			return nil, fmt.Errorf("%s: not a message", r.Message)
		}
		doc, err := schemaOf(r, md)
		if err != nil {
			return nil, err
		}
		out[filepath.Join(schemaDir, filepath.FromSlash(r.Path()))] = doc
	}
	return out, nil
}

type protodescFiles = protoregistry.Files

func filesOf(raw []byte) (*protodescFiles, error) {
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	return protodesc.NewFiles(&set)
}

func run(root string, check bool) error {
	files, err := load(root)
	if err != nil {
		return err
	}
	made, err := generate(files)
	if err != nil {
		return err
	}
	if check {
		return compare(root, made)
	}
	stale, _ := committed(root)
	for _, rel := range stale {
		if _, keep := made[rel]; !keep {
			if err := os.Remove(filepath.Join(root, rel)); err != nil {
				return err
			}
		}
	}
	for rel, src := range made {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, src, 0o644); err != nil { //nolint:gosec // a public schema, read by editors
			return err
		}
	}
	return nil
}

// committed lists the schema files below the root, by their path from the root.
func committed(root string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(root, schemaDir, "*", "*", "*.schema.json"))
	if err != nil {
		return nil, err
	}
	var rel []string
	for _, p := range paths {
		r, _ := filepath.Rel(root, p)
		rel = append(rel, r)
	}
	return rel, nil
}

// compare fails when a committed schema differs from what the messages make, or no message makes it.
func compare(root string, made map[string][]byte) error {
	var bad []string
	for rel, want := range made {
		got, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // a generated file of the repository
		if err != nil || string(got) != string(want) {
			bad = append(bad, rel)
		}
	}
	have, _ := committed(root)
	for _, rel := range have {
		if _, ok := made[rel]; !ok {
			bad = append(bad, rel+" (no message makes it)")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("stale, run `just config-schema-gen`: %v", bad)
	}
	return nil
}

func main() {
	root := flag.String("root", ".", "the repository root")
	check := flag.Bool("check", false, "fail when a committed schema is not what the messages make, and write nothing")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "configschema: no arguments, only flags")
		os.Exit(2)
	}
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, "configschema:", err)
		os.Exit(1)
	}
}
