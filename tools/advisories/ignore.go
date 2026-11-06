package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// maxIgnoreDays is how far ahead an entry may expire: an exception is reviewed again within a quarter.
const maxIgnoreDays = 90

const dateLayout = "2006-01-02"

type ignoreEntry struct {
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"`
}

type ignoreFile struct {
	Schema  int           `yaml:"schema"`
	Ignores []ignoreEntry `yaml:"ignores"`
}

// loadIgnores reads the ignore list at path and judges it against today: every entry names an id, gives a reason and a
// date that is neither past nor more than maxIgnoreDays ahead. It returns all problems, not the first.
func loadIgnores(path string, today time.Time) (map[string]ignoreEntry, []error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the ignore list of this repository, from a flag
	if err != nil {
		return nil, []error{err}
	}
	return parseIgnores(raw, today)
}

func parseIgnores(raw []byte, today time.Time) (map[string]ignoreEntry, []error) {
	var f ignoreFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, []error{fmt.Errorf("ignore list: %w", err)}
	}
	if f.Schema != 1 {
		return nil, []error{fmt.Errorf("ignore list: schema must be 1, got %d", f.Schema)}
	}
	var errs []error
	out := map[string]ignoreEntry{}
	day := today.UTC().Truncate(24 * time.Hour)
	for i, e := range f.Ignores {
		at := fmt.Sprintf("ignore list entry %d (%q)", i+1, e.ID)
		if strings.TrimSpace(e.ID) == "" {
			errs = append(errs, fmt.Errorf("%s: no id", at))
			continue
		}
		if _, dup := out[e.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: listed twice", at))
		}
		if strings.TrimSpace(e.Reason) == "" {
			errs = append(errs, fmt.Errorf("%s: no reason", at))
		}
		exp, perr := time.Parse(dateLayout, e.Expires)
		switch {
		case perr != nil:
			errs = append(errs, fmt.Errorf("%s: expires must be a date YYYY-MM-DD: %w", at, perr))
		case exp.Before(day):
			errs = append(errs, fmt.Errorf("%s: expired on %s; fix the dependency or renew the entry with a new reason", at, e.Expires))
		case exp.After(day.AddDate(0, 0, maxIgnoreDays)):
			errs = append(errs, fmt.Errorf("%s: expires %s, more than %d days ahead", at, e.Expires, maxIgnoreDays))
		}
		out[e.ID] = e
	}
	return out, errs
}

// finding is one known advisory that affects a dependency of ours, as one tool reported it.
type finding struct {
	Tool    string
	IDs     []string // the advisory's id and its aliases
	Package string
	Version string
	Fixed   string
	Source  string // the module, lock file or tool run that reported it
	Title   string
}

func (f finding) label() string {
	if len(f.IDs) == 0 {
		return "(no id)"
	}
	return strings.Join(f.IDs, " / ")
}

// split divides the findings into those an ignore entry covers and those it does not, and returns the ids of the
// entries no finding used. An empty id never matches.
func split(findings []finding, ignores map[string]ignoreEntry) (open, ignored []finding, unused []string) {
	used := map[string]bool{}
	for _, f := range findings {
		hit := false
		for _, id := range f.IDs {
			if _, ok := ignores[id]; ok && id != "" {
				used[id] = true
				hit = true
			}
		}
		if hit {
			ignored = append(ignored, f)
		} else {
			open = append(open, f)
		}
	}
	for id := range ignores {
		if !used[id] {
			unused = append(unused, id)
		}
	}
	return open, ignored, unused
}

var errNothingToScan = errors.New("nothing to scan: the sweep found no go.mod or Cargo.lock")
