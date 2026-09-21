package secretmanager_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/secretmanager"
)

// The declaration the estate writes, and the shape every other test
// starts from.
const oneStore = `
managers:
  - name: kernel
    address: https://openbao.example.private
    namespaces:
      - name: devel
      - name: stage
`

func TestADeclarationFillsTheDoorItWasNotToldAbout(t *testing.T) {
	t.Parallel()
	c, err := secretmanager.Parse([]byte(oneStore))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, ok := c.Manager("kernel")
	if !ok {
		t.Fatal("the store it declared is not in the catalogue")
	}
	if m.Mount != secretmanager.DefaultMount || m.Role != secretmanager.DefaultRole {
		t.Errorf("mount/role = %q/%q, want the defaults %q/%q",
			m.Mount, m.Role, secretmanager.DefaultMount, secretmanager.DefaultRole)
	}
	if m.Audience != secretmanager.DefaultAudience {
		t.Errorf("audience = %q, want %q", m.Audience, secretmanager.DefaultAudience)
	}
	// A namespace IS an environment here, so one that does not say which
	// environment it mirrors mirrors the one it is named after.
	for _, n := range m.Namespaces {
		if n.Environment != n.Name {
			t.Errorf("namespace %q mirrors environment %q, want its own name", n.Name, n.Environment)
		}
	}
}

// The refusal the chart's negative fixture is about: namespaces declared
// and nowhere to ask. Accepting it would draw a page of namespaces that
// all report unreadable, which reads as an outage rather than as a value
// somebody forgot to set.
func TestNamespacesWithNoAddressAreRefused(t *testing.T) {
	t.Parallel()
	_, err := secretmanager.Parse([]byte(`
managers:
  - name: kernel
    namespaces:
      - name: devel
`))
	if err == nil {
		t.Fatal("a store with namespaces and no address was accepted")
	}
	if !strings.Contains(err.Error(), "no address") {
		t.Errorf("the refusal does not say the address is missing: %v", err)
	}
}

func TestEveryMistakeIsReportedAtOnce(t *testing.T) {
	t.Parallel()
	// Four mistakes in one declaration: a name that is not one, an
	// address with a path, a nested namespace, and a namespace declared
	// twice. A deployment fixing its configuration should need one
	// restart, not one per mistake.
	_, err := secretmanager.Parse([]byte(`
managers:
  - name: Kernel
    address: https://openbao.example.private/v1
    namespaces:
      - name: devel/inner
      - name: stage
      - name: stage
`))
	if err == nil {
		t.Fatal("a declaration with four mistakes was accepted")
	}
	for _, want := range []string{`name "Kernel"`, "the path", "no slash", "declared twice"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

func TestAStoreWithNoNamespacesIsRefused(t *testing.T) {
	t.Parallel()
	_, err := secretmanager.Parse([]byte(`
managers:
  - name: kernel
    address: https://openbao.example.private
`))
	if err == nil || !strings.Contains(err.Error(), "no namespaces") {
		t.Fatalf("a store with nothing to show was accepted or refused for another reason: %v", err)
	}
}

// A key by another name is the mistake this refuses for: `endpoint:`
// would otherwise leave the store with no address at all, and the page
// would report every namespace unreadable rather than the service
// refusing to start.
func TestAKeyByAnotherNameIsRefusedRatherThanIgnored(t *testing.T) {
	t.Parallel()
	_, err := secretmanager.Parse([]byte(`
managers:
  - name: kernel
    endpoint: https://openbao.example.private
    namespaces:
      - name: devel
`))
	if err == nil {
		t.Fatal("a declaration with an unknown key was accepted")
	}
}

func TestTwoStoresOfOneNameAreRefused(t *testing.T) {
	t.Parallel()
	_, err := secretmanager.Parse([]byte(`
managers:
  - name: kernel
    address: https://one.example.private
    namespaces: [{name: devel}]
  - name: kernel
    address: https://two.example.private
    namespaces: [{name: devel}]
`))
	if err == nil || !strings.Contains(err.Error(), "declared twice") {
		t.Fatalf("two stores of one name were accepted: %v", err)
	}
}

// No file declares no store: an installation that runs none has no
// OpenBAO page, and that is configuration rather than an error.
func TestNoFileDeclaresNoStore(t *testing.T) {
	t.Parallel()
	c, err := secretmanager.Load("")
	if err != nil {
		t.Fatalf("no file: %v", err)
	}
	if len(c.Managers) != 0 {
		t.Errorf("no file declared %d stores", len(c.Managers))
	}
}

// A file that was named and is not there stops the service. The
// alternative — carrying on with no stores — is a console that silently
// lost a page an operator is looking for.
func TestAFileThatIsNotThereStopsTheService(t *testing.T) {
	t.Parallel()
	if _, err := secretmanager.Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("a file that is not there was accepted")
	}
}

func TestAFileIsReadAndValidated(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "managers.yaml")
	if err := os.WriteFile(file, []byte(oneStore), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := secretmanager.Load(file)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Managers) != 1 || len(c.Managers[0].Namespaces) != 2 {
		t.Fatalf("read %d stores, the first with %d namespaces", len(c.Managers), len(c.Managers[0].Namespaces))
	}
	if _, ok := c.Managers[0].Namespace("stage"); !ok {
		t.Error("a declared namespace cannot be looked up by name")
	}
}

// The trailing slash a copied URL carries. Kept unfixed it would build
// every call with two, and the store would answer 404 with a message
// about the path rather than about the configuration.
func TestATrailingSlashIsTrimmedFromTheAddress(t *testing.T) {
	t.Parallel()
	c, err := secretmanager.Parse([]byte(`
managers:
  - name: kernel
    address: https://openbao.example.private/
    namespaces: [{name: devel}]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.Managers[0].Address; got != "https://openbao.example.private" {
		t.Errorf("address = %q, want it without the trailing slash", got)
	}
}
