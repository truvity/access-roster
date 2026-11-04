package subject_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/subject"
)

// The vector file is shared (kits/conformance/subject); no Rust unit computes the pairwise input today.
const vectorFile = "../../conformance/subject/pairwise-vectors.json"

func TestPairwiseInputMatchesTheVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Name     string `json:"name"`
			Sector   string `json:"sector"`
			PersonID string `json:"person_id"`
			InputHex string `json:"input_hex"`
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("the vector file holds no vector")
	}
	seen := map[string]string{}
	for _, v := range f.Vectors {
		got := hex.EncodeToString(subject.PairwiseInput(v.Sector, v.PersonID))
		if got != v.InputHex {
			t.Errorf("%s: input = %s, want %s", v.Name, got, v.InputHex)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s give the same input", prev, v.Name)
		}
		seen[got] = v.Name
	}
}
