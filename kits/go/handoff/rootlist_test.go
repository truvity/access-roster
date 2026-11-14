package handoff

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

const rootListDir = "testdata/ritueel/root-list/v1"

type rootListManifest struct {
	Clock string `json:"clock"`
	Roots []struct {
		Label string `json:"label"`
		Pin   string `json:"x509_spki_sha256"`
	} `json:"roots"`
	InitialPins []string `json:"initial_pins"`
	Lists       []struct {
		ID    string   `json:"id"`
		Files []string `json:"files"`
	} `json:"lists"`
	Cases []struct {
		ID          string  `json:"id"`
		Held        *string `json:"held"`
		Candidate   *string `json:"candidate"`
		Bundle      string  `json:"bundle"`
		MinSequence int64   `json:"min_sequence"`
		Clock       string  `json:"clock"`
		Expect      string  `json:"expect"`
		Reason      string  `json:"reason"`
		Warning     string  `json:"warning"`
	} `json:"cases"`
	Bundles []struct {
		ID       string   `json:"id"`
		File     string   `json:"file"`
		Sequence int64    `json:"sequence"`
		Roots    []string `json:"roots"`
	} `json:"bundles"`
}

func loadRootListManifest(t testing.TB) *rootListManifest {
	t.Helper()
	var m rootListManifest
	if err := json.Unmarshal(mustRead(t, filepath.Join(rootListDir, "manifest.json")), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func (m *rootListManifest) files(t testing.TB, id string) (list, jws []byte) {
	t.Helper()
	for _, l := range m.Lists {
		if l.ID == id {
			return mustRead(t, filepath.Join(rootListDir, l.Files[0])), mustRead(t, filepath.Join(rootListDir, l.Files[1]))
		}
	}
	t.Fatalf("the manifest lists no list %q", id)
	return nil, nil
}

func (m *rootListManifest) pins() []string {
	var out []string
	for _, label := range m.InitialPins {
		for _, r := range m.Roots {
			if r.Label == label {
				out = append(out, r.Pin)
			}
		}
	}
	return out
}

// readVectorRootList reads a list of the vectors the way a host does that holds nothing but its initial pins, at the time the
// list was signed (a list is refused before then): the held lists of the cases and the list the answers carry.
func readVectorRootList(t testing.TB, id string) *RootList {
	t.Helper()
	m := loadRootListManifest(t)
	list, jws := m.files(t, id)
	var at struct {
		SignedAt string `json:"signed_at"`
	}
	if err := json.Unmarshal(list, &at); err != nil {
		t.Fatalf("list %s: %v", id, err)
	}
	signed, err := time.Parse(time.RFC3339, at.SignedAt)
	if err != nil {
		t.Fatalf("list %s: %v", id, err)
	}
	l, _, err := ReadRootList(list, jws, nil, nil, signed)
	if err != nil {
		t.Fatalf("list %s: %v", id, err)
	}
	return l
}

// Every case of ritueel's root list vectors gives its outcome and reason code: the eleven checks of "How a host reads
// it", in order, the warning of a held list that expired, and the checks of a CA bundle against its list. The held list of a
// case is the list the host read before.
func TestRootListVectors(t *testing.T) {
	m := loadRootListManifest(t)
	const wantCases = 53
	if len(m.Cases) != wantCases {
		t.Fatalf("the manifest lists %d cases, want %d", len(m.Cases), wantCases)
	}
	bundles := map[string]string{}
	for _, b := range m.Bundles {
		bundles[b.ID] = b.File
	}
	defaultClock, _ := time.Parse(time.RFC3339, m.Clock)
	for _, c := range m.Cases {
		t.Run(c.ID, func(t *testing.T) {
			now := defaultClock
			if c.Clock != "" {
				now, _ = time.Parse(time.RFC3339, c.Clock)
			}
			var held *RootList
			if c.Held != nil {
				held = readVectorRootList(t, *c.Held)
			}
			if c.Candidate == nil {
				// The held list expired and no newer one came: the host keeps it and warns.
				if c.Expect != "warn" || held == nil || !held.Expired(now) {
					t.Fatalf("expect %s, held %v", c.Expect, held)
				}
				if w := held.Warnings(now); len(w) != 1 || w[0] != c.Warning {
					t.Fatalf("warnings %v, want %s", w, c.Warning)
				}
				if w := held.Warnings(now.Add(-time.Hour * 24 * 365 * 2)); len(w) != 0 {
					t.Fatalf("a list that has not expired warns: %v", w)
				}
				return
			}
			list, jws := m.files(t, *c.Candidate)
			var pins []string
			if held == nil {
				pins = m.pins()
			}
			got, checks, err := ReadRootListMin(list, jws, held, pins, c.MinSequence, now)
			if !checks.Anchored {
				t.Error("a case with a held list or pins reports the checks that weigh the signers as not run")
			}
			if c.ID == "same-list-again-after-its-expiry" && (len(checks.Warnings) != 1 || checks.Warnings[0] != WarningHeldExpired) {
				t.Errorf("the held list again after its expiry: warnings %v", checks.Warnings)
			}
			if c.Bundle != "" && err == nil {
				err = CheckBundle(mustRead(t, filepath.Join(rootListDir, bundles[c.Bundle])), got)
			}
			switch c.Expect {
			case "accept":
				if err != nil {
					t.Fatalf("a list that must be accepted is refused: %v", err)
				}
				if got.Sequence < 1 || len(got.Roots) == 0 {
					t.Errorf("list = %+v", got)
				}
			case "refuse":
				assertCode(t, err, c.Reason)
			default:
				t.Fatalf("expect %q", c.Expect)
			}
		})
	}
}

// A list read with nothing to compare it with runs only the checks that need nothing else, and says so.
func TestRootListWithoutAnAnchorSaysWhatItDidNotRun(t *testing.T) {
	m := loadRootListManifest(t)
	list, jws := m.files(t, "seq7-a")
	_, checks, err := ReadRootList(list, jws, nil, nil, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if checks.Anchored {
		t.Fatal("a list read against nothing is reported as anchored")
	}
	// A tampered list is still refused: the signatures it carries are checked.
	list, jws = m.files(t, "seq7-a-tampered")
	_, _, err = ReadRootList(list, jws, nil, nil, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	assertCode(t, err, "signature-invalid")
}

// The bundles of the vectors carry the sequence of their list in the first line and the certificates of its roots, in
// its order.
func TestBundleVectors(t *testing.T) {
	m := loadRootListManifest(t)
	if len(m.Bundles) == 0 {
		t.Fatal("the manifest lists no bundle")
	}
	pin := map[string]string{}
	for _, r := range m.Roots {
		pin[r.Label] = r.Pin
	}
	for _, b := range m.Bundles {
		t.Run(b.ID, func(t *testing.T) {
			certs, seq, err := ParseBundle(mustRead(t, filepath.Join(rootListDir, b.File)))
			if err != nil {
				t.Fatal(err)
			}
			if seq != b.Sequence || len(certs) != len(b.Roots) {
				t.Fatalf("sequence %d with %d certificates", seq, len(certs))
			}
			for i, c := range certs {
				if SPKIPin(c) != pin[b.Roots[i]] {
					t.Errorf("certificate %d is not root %s", i, b.Roots[i])
				}
			}
		})
	}
	_, _, err := ParseBundle([]byte("# trust-sequence: x\n"))
	assertCode(t, err, "malformed")
	_, _, err = ParseBundle([]byte("no certificates here"))
	assertCode(t, err, "malformed")
}
