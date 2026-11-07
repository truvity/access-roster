//go:build sluis_test

package writerd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
)

// asProduct returns the message with metadata.product.name changed, in canonical form as an emitter writes it.
func asProduct(t *testing.T, m message, name string) message {
	t.Helper()
	v, err := parseStrict(m.rec)
	if err != nil {
		t.Fatal(err)
	}
	v.(map[string]any)["metadata"].(map[string]any)["product"].(map[string]any)["name"] = name
	return message{m.uid, canonical(t, v)}
}

// A project's log holds the records of the product its AuditLog declares and no other (ADR 0030). The writer of the
// project `sluis` refuses a record of another product, whole: it is quarantined, sealed, reported with the field and
// acknowledged, and nothing of it is in the log. The writer of another project takes that product and refuses
// `sluis`, so the refusal follows the declaration and not a fixed word.
//
// verifies: REQ-AUDIT-148
func TestARecordOfAProductTheProjectDoesNotDeclareIsRefusedAndOneOfItsOwnIsSealed(t *testing.T) {
	for _, project := range []string{"sluis", "billing"} {
		t.Run("project="+project, func(t *testing.T) {
			e := newEnv(t)
			e.store.items["audit-log"].(*configv2alpha1.AuditLog).Project = project
			em := emitterOf(t, e)
			e.start()
			other := "globex"
			if project == "sluis" {
				// the emitter of a product writes product.name: the project it declares
				other = "billing"
			}
			own := asProduct(t, newMessage(t, em, "key.sign", "acme"), project)
			foreign := asProduct(t, newMessage(t, em, "key.sign", "acme"), other)
			e.push(foreign)
			wait(t, "the refusal to be acknowledged", func() bool { return e.tr.ackedCount() == 1 })
			e.push(own)
			wait(t, "the record of the product", func() bool { return e.tr.ackedCount() == 2 })

			reports, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*"))
			if len(reports) != 1 {
				t.Fatalf("%d quarantine objects, want 1", len(reports))
			}
			raw, err := os.ReadFile(reports[0]) //nolint:gosec // a test path
			if err != nil {
				t.Fatal(err)
			}
			var rep map[string]any
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatal(err)
			}
			sealed, _ := base64.StdEncoding.DecodeString(rep["sealed"].(string))
			pt, err := e.key.open(sealed, "acme", quarantineKind, SealID(project, "quarantine", "main", rep["sha384"].(string)))
			if err != nil {
				t.Fatalf("the quarantined message does not open: %v", err)
			}
			var kept transportv2alpha1.AuditMessage
			if err := proto.Unmarshal(pt, &kept); err != nil {
				t.Fatal(err)
			}
			if rep["reason"] != reasonProduct || rep["path"] != "metadata.product.name" || rep["uid"] != foreign.uid || string(kept.GetRecord()) != string(foreign.rec) {
				t.Fatalf("report = %v", rep)
			}
			recs := recordEntries(logEntries(t, e.logDir()))
			if len(recs) != 1 || recs[0]["metadata"].(map[string]any)["uid"] != own.uid {
				t.Fatalf("the log holds %d records, want only the record of %s", len(recs), project)
			}
			if _, err := os.Stat(filepath.Join(e.root, "state", "writer-state")); err != nil {
				t.Fatal(err)
			}
			if remembers(t, e, foreign.uid) {
				t.Fatal("the id of the refused record is registered as sealed")
			}
			e.mustVerify(t)
		})
	}
}
