// Package audit is what access-roster tells the audit trail.
//
// The trail is kept by an installation of github.com/truvity/audit of this
// service's own, rendered beside it: a receiver that takes the records and
// answers RegisterCatalogue, a writer that locks and indexes them and whose
// digest job signs each hour, and
// a query service the console's Audit page reads. This package declares what
// is recorded in a catalogue (catalogue/roster.yaml), registers it at
// start-up, and sends each record to the receiver. With no installation
// configured, nothing is kept beyond the log line every record also is.
//
// The vocabulary is fixed here and nowhere else. Every action has one
// constructor in events.go, the catalogue declares every one of them, and the
// gate fails when the two disagree; a caller cannot invent an action, a
// target type or an actor kind.
//
// Recording never fails the thing being recorded, with one deliberate
// exception. A sign-in that could not be written down still happened, and
// refusing it because the trail was slow would turn an audit outage into an
// access outage. So almost every action is delivered `async`: it waits in the
// emitter's own queue, in memory, and is retried until the receiver
// acknowledges it. A recovery sign-in bypasses the directory, so its catalogue
// entry says `block`: [Trail.RecordDurable] returns only once the installation
// has it, and the caller refuses the sign-in when it does not.
package audit

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/truvity/audit/catalogue"
	"github.com/truvity/audit/record"
)

//go:embed catalogue
var files embed.FS

// Source is the catalogue's source: every action is under it.
const Source = "roster"

// Tenant is the tenant every record is written under. An installation of
// access-roster serves one organisation, and its trail is the installation's
// own rather than a customer's.
const Tenant = record.TenantPlatform

// Recorder is what records. [Trail] is the one implementation outside tests.
type Recorder interface {
	// Record hands a record to the trail. It never fails the caller: a record
	// that cannot be kept is logged as such.
	Record(ctx context.Context, r *record.Record)
	// RecordDurable returns only once the record is kept, or says why it is
	// not. It is for an action the catalogue declares `block`, and the caller
	// refuses what it records when this fails.
	RecordDurable(ctx context.Context, r *record.Record) error
}

// Document is the catalogue as it is registered: the YAML document and every
// schema it references, keyed by $id.
type Document struct {
	YAML    []byte
	Schemas map[string][]byte
}

// LoadDocument reads the embedded catalogue.
func LoadDocument() (Document, error) {
	yaml, err := files.ReadFile("catalogue/roster.yaml")
	if err != nil {
		return Document{}, err
	}
	d := Document{YAML: yaml, Schemas: map[string][]byte{}}
	entries, err := fs.ReadDir(files, "catalogue")
	if err != nil {
		return Document{}, err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := files.ReadFile(path.Join("catalogue", e.Name()))
		if err != nil {
			return Document{}, err
		}
		id, err := schemaID(raw)
		if err != nil {
			return Document{}, fmt.Errorf("audit: %s: %w", e.Name(), err)
		}
		d.Schemas[id] = raw
	}
	return d, nil
}

// Catalogue loads the embedded catalogue, validated by the same toolchain the
// installation validates it with.
func Catalogue() (*catalogue.Catalogue, Document, error) {
	d, err := LoadDocument()
	if err != nil {
		return nil, Document{}, err
	}
	schemas := make([][]byte, 0, len(d.Schemas))
	for _, raw := range d.Schemas {
		schemas = append(schemas, raw)
	}
	c, err := catalogue.Load(d.YAML, schemas)
	if err != nil {
		return nil, Document{}, err
	}
	if c.Source != Source {
		return nil, Document{}, fmt.Errorf("audit: the catalogue is for %q, and this package records as %q", c.Source, Source)
	}
	return c, d, nil
}
