// Package keys holds the repository-wide checks of how keys are held: who may hold a PIN or a cloud key permission, and
// which code may import a key-management SDK (ADR 0006, "key@ holds a boundary's keys"). They read the registry and the
// source tree and run no installation.
package keys

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("%s is not the repository root: %v", dir, err)
	}
	return dir
}

type actorRow struct {
	Name   string   `yaml:"name"`
	Family string   `yaml:"family"`
	Holder bool     `yaml:"holder"`
	Holds  []string `yaml:"holds"`
	Egress []string `yaml:"egress"`
}

func readActors(t *testing.T) []actorRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/architecture/actors.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Actors   []actorRow `yaml:"actors"`
		Platform []actorRow `yaml:"platform"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return append(f.Actors, f.Platform...)
}

// A credential that opens a key: a card PIN, or a permission on the cloud key service (KMS).
var pinOrKMS = regexp.MustCompile(`(?i)\b(PIN|KMS|key service|key store|card)\b`)

// verifies: REQ-KEYS-001, REQ-KEYS-028
// key@ is the only actor that holds a card PIN or a permission on a key of the cloud key service. The actor registry
// (docs/architecture/actors.yaml) is read for every actor and platform piece: the one whose `holds` names a PIN or the
// key service is key, the egress class of the key service is key's alone, and no work actor is a credential holder at
// all. The one other credential that opens a key is the restore identity's permission on the backup archive key, which
// the row excepts and the registry words as an archive key; it is named here so that a second exception cannot slip in.
func TestKeyAtIsTheOnlyHolderOfAPINOrAKeyServicePermission(t *testing.T) {
	actors := readActors(t)
	if len(actors) < 15 {
		t.Fatalf("%d actors read: the registry was read wrong", len(actors))
	}
	var holders []string
	for _, a := range actors {
		holds := strings.Join(a.Holds, "; ")
		if a.Name != "key" {
			if a.Family == "work" && (a.Holder || len(a.Holds) > 0) {
				t.Errorf("%s is a work actor and holds a credential: %s", a.Name, holds)
			}
			if pinOrKMS.MatchString(holds) && !strings.Contains(strings.ToLower(holds), "archive key") {
				t.Errorf("%s holds a credential that opens a key, and it is not the backup archive key: %s", a.Name, holds)
			}
			if slices.Contains(a.Egress, "key-service") {
				t.Errorf("%s may reach the cloud key service", a.Name)
			}
			if strings.Contains(strings.ToLower(holds), "archive key") {
				holders = append(holders, a.Name)
			}
			continue
		}
		if !pinOrKMS.MatchString(holds) || !slices.Contains(a.Egress, "key-service") || !strings.Contains(holds, "PIN") {
			t.Errorf("key does not hold the PIN and the key service permission in the registry (holds %q, egress %v): the check would prove nothing", holds, a.Egress)
		}
	}
	// The restore identity of store is the one holder of a permission on the backup archive key.
	if !slices.Equal(holders, []string{"store"}) {
		t.Errorf("actors that hold a permission on an archive key: %v, want store alone", holders)
	}
}

// The packages of key-management SDKs and key-store clients. Business code never imports one: it asks key@ (a call of
// the key service of sluis), and a driver is the one place that talks to a key store.
var forbiddenGo = []string{
	"github.com/go-piv/piv-go",
	"github.com/miekg/pkcs11",
	"github.com/ThalesIgnite/crypto11",
	"github.com/aws/aws-sdk-go-v2/service/kms",
	"github.com/aws/aws-sdk-go/service/kms",
	"cloud.google.com/go/kms",
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault",
	"github.com/hashicorp/vault/api",
	"github.com/google/go-tpm",
	"github.com/google/go-tpm-tools",
}

// The crates of the same.
var forbiddenRust = []string{"aws-sdk-kms", "aws-sdk-cloudhsmv2", "cryptoki", "pkcs11", "yubikey", "pcsc", "google-cloud-kms", "azure_security_keyvault_keys", "vaultrs", "tss-esapi"}

// keyDrivers are the trees whose code is a key driver: the one place a key-store client may be imported, and only the
// client of its own store. The software driver imports none.
var keyDrivers = map[string][]string{
	"drivers/key/yubikey-piv/": {"github.com/go-piv/piv-go"},
}

// forbiddenImport returns the forbidden packages that Go source imports, and does not read the rest of the file.
func forbiddenImport(src []byte, name string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, im := range f.Imports {
		path := strings.Trim(im.Path.Value, "\"`")
		for _, bad := range forbiddenGo {
			if path == bad || strings.HasPrefix(path, bad+"/") {
				out = append(out, path)
			}
		}
	}
	return out, nil
}

// forbiddenCrate returns the forbidden crates a Cargo.toml depends on.
func forbiddenCrate(manifest string) []string {
	var out []string
	section := ""
	for _, l := range strings.Split(manifest, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[") {
			section = strings.Trim(l, "[]")
			continue
		}
		if !strings.Contains(section, "dependencies") {
			continue
		}
		name, _, _ := strings.Cut(l, "=")
		name = strings.TrimSpace(name)
		if slices.Contains(forbiddenRust, name) {
			out = append(out, name)
		}
	}
	return out
}

// verifies: REQ-KEYS-001, REQ-KEYS-013
// Business code imports no key-management SDK. Every Go file of the repository (not a list of packages, so a new package
// is covered when it is made) is read for its imports, and every Cargo manifest for its dependencies: a package of a
// key-store client may appear only in a key driver, and then only the one of its own store; the Rust crates of such
// clients appear nowhere. The checker is shown to catch what it is for on source text that imports one.
func TestNoCodeImportsAKeyManagementSDKOutsideItsDriver(t *testing.T) {
	// The checker catches a business file that imports a client, and passes one that does not.
	bad := "package business\n\nimport (\n\t\"fmt\"\n\t\"github.com/aws/aws-sdk-go-v2/service/kms\"\n\t_ \"github.com/go-piv/piv-go/v2/piv\"\n)\n"
	if got, err := forbiddenImport([]byte(bad), "x.go"); err != nil || len(got) != 2 {
		t.Fatalf("the checker found %v, %v in a file that imports two clients", got, err)
	}
	if got, _ := forbiddenImport([]byte("package business\n\nimport \"crypto/ecdsa\"\n"), "y.go"); len(got) != 0 {
		t.Fatalf("the checker flagged %v in a file that imports the standard library", got)
	}
	if got := forbiddenCrate("[package]\nname = \"x\"\n[dependencies]\ncryptoki = \"1\"\nserde = \"1\"\n[dev-dependencies]\nyubikey = { version = \"1\" }\n"); !slices.Equal(got, []string{"cryptoki", "yubikey"}) {
		t.Fatalf("the crate checker found %v", got)
	}

	root := repoRoot(t)
	var goFiles, manifests, driverImports int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "target", ".devbox", ".venv", "dist":
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		switch {
		case strings.HasSuffix(d.Name(), ".go"):
			goFiles++
			src, err := os.ReadFile(path) //nolint:gosec // a file of this repository
			if err != nil {
				return err
			}
			found, err := forbiddenImport(src, rel)
			if err != nil {
				t.Errorf("%s does not parse: %v", rel, err)
				return nil
			}
			for _, imp := range found {
				allowed := false
				for dir, pkgs := range keyDrivers {
					if strings.HasPrefix(rel, dir) {
						for _, p := range pkgs {
							if imp == p || strings.HasPrefix(imp, p+"/") {
								allowed = true
								driverImports++
							}
						}
					}
				}
				if !allowed {
					t.Errorf("%s imports %s: only a key driver imports the client of its own key store", rel, imp)
				}
			}
		case d.Name() == "Cargo.toml":
			manifests++
			src, err := os.ReadFile(path) //nolint:gosec // a file of this repository
			if err != nil {
				return err
			}
			for _, c := range forbiddenCrate(string(src)) {
				t.Errorf("%s depends on %s: no Rust code uses a key-store client", rel, c)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if goFiles < 300 || manifests < 10 {
		t.Fatalf("the walk read %d Go files and %d manifests: it did not read the repository", goFiles, manifests)
	}
	// The one allowed import is real: the card driver imports piv-go, so the exception is not an unused entry.
	if driverImports == 0 {
		t.Fatal("no key driver imports its client: the exception is unused or the walk missed the driver")
	}
}
