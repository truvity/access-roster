package main

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// The three registries and the uid list, as far as the generator reads them. The headers of
// docs/architecture/{actors,kinds,keys}.yaml say what every field means.
const (
	actorsFile = "docs/architecture/actors.yaml"
	kindsFile  = "docs/architecture/kinds.yaml"
	keysFile   = "docs/architecture/keys.yaml"
	uidsFile   = "tools/gen/registry/uids.yaml"
)

type keyPurposeUse struct {
	Purpose string   `yaml:"purpose"`
	Ops     []string `yaml:"ops"`
}

type actorDoc struct {
	Name        string          `yaml:"name"`
	Family      string          `yaml:"family"`
	Holder      bool            `yaml:"holder"`
	Language    string          `yaml:"language"`
	Contracts   []string        `yaml:"contracts"`
	Ports       []string        `yaml:"ports"`
	Calls       []string        `yaml:"calls"`
	Egress      []string        `yaml:"egress"`
	KeyPurposes []keyPurposeUse `yaml:"key_purposes"`
}

type actorsDoc struct {
	Schema    int        `yaml:"schema"`
	Actors    []actorDoc `yaml:"actors"`
	Platform  []actorDoc `yaml:"platform"`
	Externals []actorDoc `yaml:"external_callers"`
}

type ttlDoc struct {
	Default string `yaml:"default"`
	Max     string `yaml:"max"`
}

type kindDoc struct {
	Name       string   `yaml:"name"`
	Scope      string   `yaml:"scope"`
	Class      string   `yaml:"class"`
	Treatment  string   `yaml:"treatment"`
	Writer     string   `yaml:"writer"`
	Readers    []string `yaml:"readers"`
	WatchedBy  []string `yaml:"watched_by"`
	Exportable string   `yaml:"exportable"`
	BackedUp   string   `yaml:"backed_up"`
	TTL        *ttlDoc  `yaml:"ttl"`
	Indexes    []string `yaml:"indexes"`
	SelfScoped bool     `yaml:"self_scoped"`
	Personal   bool     `yaml:"personal"`
}

type kindsDoc struct {
	Schema int       `yaml:"schema"`
	Kinds  []kindDoc `yaml:"kinds"`
}

type purposeDoc struct {
	Name string   `yaml:"name"`
	Ops  []string `yaml:"ops"`
}

type dataKeyDoc struct {
	Ops []string `yaml:"ops"`
}

type keysDoc struct {
	Schema   int          `yaml:"schema"`
	Purposes []purposeDoc `yaml:"purposes"`
	DataKeys struct {
		Tenant   map[string]dataKeyDoc `yaml:"tenant"`
		Boundary map[string]dataKeyDoc `yaml:"boundary"`
	} `yaml:"data_keys"`
}

type uidsDoc struct {
	Names []string `yaml:"names"`
}

// inputs is what the generator reads.
type inputs struct {
	actors actorsDoc
	kinds  kindsDoc
	keys   keysDoc
	uids   uidsDoc
}

func readYAML(root, rel string, into any) error {
	b, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- the generator reads its own repository
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, into); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

func load(root string) (*inputs, error) {
	in := &inputs{}
	for _, f := range []struct {
		rel  string
		into any
	}{
		{actorsFile, &in.actors},
		{kindsFile, &in.kinds},
		{keysFile, &in.keys},
		{uidsFile, &in.uids},
	} {
		if err := readYAML(root, f.rel, f.into); err != nil {
			return nil, err
		}
	}
	for _, c := range []struct {
		file   string
		schema int
	}{{actorsFile, in.actors.Schema}, {kindsFile, in.kinds.Schema}, {keysFile, in.keys.Schema}} {
		if c.schema != 1 {
			return nil, fmt.Errorf("%s: schema %d is not the schema 1 this generator reads", c.file, c.schema)
		}
	}
	return in, nil
}
