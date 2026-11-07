//go:build sluis_test

package sessiond_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"connectrpc.com/connect"

	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// said is the answer the vectors compare: ok, or code/reason.
func said(err error) string {
	if err == nil {
		return "ok"
	}
	reason, _ := refusal.Reason(err)
	return connect.CodeOf(err).String() + "/" + reason
}

// verifies: REQ-DATA-045
//
// The fake store of these tests gives the same answers as store@ to the calls session makes. The vectors in
// kits/conformance/store/session-vectors.json are run against the real service by actors/store/tests/session_fidelity.rs and
// here against the fake: a rule that one has and the other lacks fails a test on one side. Two bugs hid behind a fake that
// disagreed with store@ (a boundary-scoped kind given a tenant, and an update that kept the old indexes).
func TestTheFakeStoreAnswersAsStoreDoes(t *testing.T) {
	raw, err := os.ReadFile("../../../../kits/conformance/store/session-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name  string `json:"name"`
			Steps []struct {
				Write *struct {
					Verb      string   `json:"verb"`
					Kind      string   `json:"kind"`
					Tenant    string   `json:"tenant"`
					ID        string   `json:"id"`
					Indexes   []string `json:"indexes"`
					IfVersion uint64   `json:"if_version"`
				} `json:"write"`
				Grant bool   `json:"grant"`
				Want  string `json:"want"`
				List  *struct {
					Kind       string `json:"kind"`
					Tenant     string `json:"tenant"`
					Index      string `json:"index"`
					IndexValue string `json:"index_value"`
				} `json:"list"`
				WantIDs json.RawMessage `json:"want_ids"`
			} `json:"steps"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	steps := 0
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			e := passkeyEnv(t)
			for n, s := range c.Steps {
				steps++
				if w := s.Write; w != nil {
					op := &storev2alpha1.Operation{Address: &typev2alpha1.Address{Kind: w.Kind, Tenant: w.Tenant, Id: w.ID}, Value: []byte("x"), IfVersion: w.IfVersion}
					op.Verb = map[string]storev2alpha1.Verb{"create": storev2alpha1.Verb_CREATE, "update": storev2alpha1.Verb_UPDATE}[w.Verb]
					for _, ix := range w.Indexes {
						op.Indexes = append(op.Indexes, &typev2alpha1.IndexEntry{Name: ix, Value: []byte("v:" + ix)})
					}
					req := &storev2alpha1.WriteRequest{Operations: []*storev2alpha1.Operation{op}}
					if s.Grant {
						req.Grant = e.grant()
					}
					_, err := e.store.Write(ctx, connect.NewRequest(req))
					if got := said(err); got != s.Want {
						t.Errorf("step %d: the fake says %q, store@ says %q", n, got, s.Want)
					}
					continue
				}
				l := s.List
				res, err := e.store.List(ctx, connect.NewRequest(&storev2alpha1.ListRequest{
					Kind: l.Kind, Tenant: l.Tenant, Index: l.Index, IndexValue: []byte(l.IndexValue),
				}))
				var want []string
				if json.Unmarshal(s.WantIDs, &want) != nil {
					var code string
					_ = json.Unmarshal(s.WantIDs, &code)
					if got := said(err); got != code {
						t.Errorf("step %d: the fake says %q, store@ says %q", n, got, code)
					}
					continue
				}
				if err != nil {
					t.Errorf("step %d: %v", n, err)
					continue
				}
				var ids []string
				for _, it := range res.Msg.GetItems() {
					ids = append(ids, it.GetAddress().GetId())
				}
				slices.Sort(ids)
				if !slices.Equal(ids, want) && (len(ids) != 0 || len(want) != 0) {
					t.Errorf("step %d: the fake lists %v, store@ lists %v", n, ids, want)
				}
			}
		})
	}
	if steps < 30 {
		t.Fatalf("%d steps: the vectors lost a case", steps)
	}
}
