//go:build sluis_card

package card

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// verifies: REQ-KEYS-228
// piv-go has no error value for a card that answers the empty VERIFY with success (a card that is logged in): the
// driver reads it from the text. The text is read from piv-go's source at the version in go.mod, so that a bump of
// piv-go that changes it fails here and not on a board, and the match is on that text and nothing looser.
func TestTheVerifiedAnswerIsTheTextOfPivGo(t *testing.T) {
	if !isVerifiedAnswer(fmt.Errorf("x: %w", errors.New("expected error code from empty pin"))) {
		t.Fatal("the text of piv-go is not recognised")
	}
	for _, e := range []error{nil, errors.New("verification failed (2 retries remaining)"), errors.New("transmitting request: scard error")} {
		if isVerifiedAnswer(e) {
			t.Fatalf("%v is not a verified card", e)
		}
	}
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/go-piv/piv-go/v2").Output() //nolint:gosec // fixed arguments
	if err != nil || len(out) == 0 {
		t.Skip("piv-go's source is not at hand")
	}
	src, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "piv", "piv.go"))
	if err != nil {
		t.Skip("piv-go's source is not at hand")
	}
	if !strings.Contains(string(src), `fmt.Errorf("`+verifiedAnswer+`")`) {
		t.Fatal("piv-go no longer says " + verifiedAnswer + ": the driver would read a verified card as a failure")
	}
}
