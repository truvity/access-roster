package cad

import (
	"context"
	"encoding/hex"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

// ActionIssue is the audit fact of a certificate that ca made (ADR 0023, "Issuance log and revocation": "Every
// certificate is audited"). It names the requester, the profile, the serial number, the validity and the hash of the
// public key. OCSF class 3004 (Entity Management), activity 1 (Create).
const ActionIssue = "ca.issue"

var actionIssue = audit.Action{Name: ActionIssue, ClassUID: 3004, ActivityID: 1}

// Auditor is where ca sends its audit facts: audit.Emitter, or a recorder in a test.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// Issued describes a certificate for the audit fact.
type Issued struct {
	Profile             string
	Requester           string
	Serial              []byte
	NotBefore, NotAfter int64
	KeySHA256           [32]byte
}

func (i Issued) event() audit.Event {
	return audit.Event{Action: actionIssue, Status: audit.StatusSuccess, Sluis: map[string]any{
		"profile":    i.Profile,
		"requester":  i.Requester,
		"serial":     hex.EncodeToString(i.Serial),
		"not_before": i.NotBefore,
		"not_after":  i.NotAfter,
		"key_sha256": hex.EncodeToString(i.KeySHA256[:]),
	}}
}
