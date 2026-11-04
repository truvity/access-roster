package signedconfig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// The vector file is shared with store@ (actors/store/tests/vectors.rs): both suites must pass on it.
const vectorFile = "../../../tests/testdata/signed-config/vectors.json"

type vectorFileT struct {
	Kind          string `json:"kind"`
	PublisherSets map[string][]struct {
		KID     string   `json:"kid"`
		SPKIDER string   `json:"spki_der"`
		CoSigns []string `json:"co_signs"`
	} `json:"publisher_sets"`
	Cases []struct {
		Name        string `json:"name"`
		Document    string `json:"document"`
		DocumentB64 string `json:"document_base64"`
		Publishers  string `json:"publishers"`
		RefusedStep int    `json:"refused_step"`
		Read        *struct {
			Seq     uint64 `json:"seq"`
			SHA384  string `json:"sha384"`
			Payload string `json:"payload"`
		} `json:"read"`
	} `json:"cases"`
	Sequence []struct {
		Name    string `json:"name"`
		InForce *held  `json:"in_force"`
		Doc     held   `json:"document"`
		Verdict string `json:"verdict"`
	} `json:"sequence"`
}

type held struct {
	Seq    uint64 `json:"seq"`
	SHA384 string `json:"sha384"`
}

func loadVectors(t *testing.T) vectorFileT {
	t.Helper()
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatalf("read the vectors: %v", err)
	}
	var v vectorFileT
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse the vectors: %v", err)
	}
	return v
}

func (v vectorFileT) publishers(t *testing.T, set string) []Publisher {
	t.Helper()
	var out []Publisher
	for _, p := range v.PublisherSets[set] {
		der, err := base64.StdEncoding.DecodeString(p.SPKIDER)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Publisher{KID: p.KID, Key: pub.(*ecdsa.PublicKey), CoSigns: p.CoSigns})
	}
	if len(out) == 0 {
		t.Fatalf("no publisher set %q", set)
	}
	return out
}

// REQ-KEYS-110/signature_vectors: every verdict of the shared vectors, step for step.
func TestVectors(t *testing.T) {
	v := loadVectors(t)
	// The same floor as the Rust test: a sweep over a file that lost its cases proves nothing.
	if len(v.Cases) < 60 {
		t.Fatalf("the vector file holds %d cases, want at least 60", len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc := []byte(c.Document)
			if c.DocumentB64 != "" {
				var err error
				if doc, err = base64.StdEncoding.DecodeString(c.DocumentB64); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Verify(doc, v.Kind, v.publishers(t, c.Publishers))
			if c.Read == nil {
				var r *Refused
				if !errors.As(err, &r) {
					t.Fatalf("want a refusal at step %d, got %v", c.RefusedStep, err)
				}
				if r.Step != c.RefusedStep {
					t.Fatalf("refused at step %d (%s), want step %d", r.Step, r.Rule, c.RefusedStep)
				}
				return
			}
			if err != nil {
				t.Fatalf("want it read, got %v", err)
			}
			if got.Seq != c.Read.Seq || hex.EncodeToString(got.Digest[:]) != c.Read.SHA384 || string(got.Payload) != c.Read.Payload {
				t.Fatalf("read seq %d digest %x, want seq %d digest %s", got.Seq, got.Digest, c.Read.Seq, c.Read.SHA384)
			}
		})
	}
}

func digestOf(t *testing.T, h string) [48]byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 48 {
		t.Fatalf("bad digest %q", h)
	}
	return [48]byte(b)
}

// REQ-KEYS-110/sequence_vectors: step 5 on the shared vectors, through Compare and through a Sequencer.
func TestSequenceVectors(t *testing.T) {
	v := loadVectors(t)
	want := map[string]Sequence{"newer": Newer, "same": Same, "conflict": Conflict, "older": Older}
	for _, c := range v.Sequence {
		t.Run(c.Name, func(t *testing.T) {
			doc := &Verified{Seq: c.Doc.Seq, Digest: digestOf(t, c.Doc.SHA384)}
			var s Sequencer
			if c.InForce != nil {
				if _, err := s.Admit(&Verified{Seq: c.InForce.Seq, Digest: digestOf(t, c.InForce.SHA384)}); err != nil {
					t.Fatal(err)
				}
			}
			inForce := c.InForce != nil
			var seq uint64
			var dg [48]byte
			if inForce {
				seq, dg = c.InForce.Seq, digestOf(t, c.InForce.SHA384)
			}
			if got := Compare(inForce, seq, dg, doc); got != want[c.Verdict] {
				t.Fatalf("Compare = %d, want %s", got, c.Verdict)
			}
			got, err := s.Admit(doc)
			if got != want[c.Verdict] {
				t.Fatalf("Admit = %d, want %s", got, c.Verdict)
			}
			if (err != nil) != (c.Verdict == "older" || c.Verdict == "conflict") {
				t.Fatalf("Admit error = %v for %s", err, c.Verdict)
			}
		})
	}
}

// REQ-KEYS-110/sequence_keeps_highest: a refused document leaves the held one as it was.
func TestSequencerKeepsTheHighest(t *testing.T) {
	var s Sequencer
	if _, err := s.Admit(&Verified{Seq: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Admit(&Verified{Seq: 4}); !errors.Is(err, ErrOlder) {
		t.Fatalf("a lower seq: %v", err)
	}
	if _, err := s.Admit(&Verified{Seq: 5, Digest: [48]byte{1}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("the same seq, another payload: %v", err)
	}
	if seq, ok := s.Held(); !ok || seq != 5 {
		t.Fatalf("held %d %v, want 5", seq, ok)
	}
	if _, err := s.Admit(&Verified{Seq: 6}); err != nil {
		t.Fatalf("a higher seq: %v", err)
	}
}

// REQ-DATA-099: the kind is the registry's name of a config kind. A segment, a kind that is not config and a name that
// is not known are a caller's error, never a refusal of the document and never a way past the co-signer check.
func TestVerifyNeedsAConfigKindOfTheRegistry(t *testing.T) {
	v := loadVectors(t)
	for _, kind := range []string{"", "key-plan", "boundary", "NoSuchKind", "DataKeyWrap"} {
		_, err := Verify([]byte("{}"), kind, v.publishers(t, "plain"))
		var r *Refused
		if err == nil || errors.As(err, &r) {
			t.Errorf("%q: got %v, want an error that is not a refusal of the document", kind, err)
		}
	}
}

// REQ-DATA-099: a document larger than the bound is refused before it is read.
func TestVerifyRefusesADocumentOverTheBound(t *testing.T) {
	v := loadVectors(t)
	_, err := Verify(make([]byte, MaxDocument+1), "KeyPlan", v.publishers(t, "plain"))
	var r *Refused
	if !errors.As(err, &r) || r.Step != 1 {
		t.Fatalf("got %v, want a refusal at step 1", err)
	}
}
