package audit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// The vector files are shared with kits/rust/sluis-audit (kits/conformance/audit): both suites must pass on them.
const vectorDir = "../../conformance/audit/"

func readVectors(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(vectorDir + name) //nolint:gosec // a fixed directory of the repository
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

// decode parses JSON keeping numbers exact.
func decode(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return convert(v, false)
}

// convert turns decoded JSON into the types Canonical and Event.Sluis take: an integer is int64, a number that is
// not an integer (or does not fit int64) is float64, which the library must refuse, and with strict a list of
// strings is []string.
func convert(v any, strict bool) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return n
		}
		f, _ := strconv.ParseFloat(string(x), 64)
		if math.IsInf(f, 0) {
			f = math.MaxFloat64
		}
		return f
	case []any:
		out := make([]any, len(x))
		allStr := len(x) > 0
		for i, e := range x {
			out[i] = convert(e, strict)
			if _, ok := out[i].(string); !ok {
				allStr = false
			}
		}
		if strict && allStr {
			ss := make([]string, len(out))
			for i := range out {
				ss[i] = out[i].(string)
			}
			return ss
		}
		return out
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = convert(e, strict)
		}
		return m
	default:
		return v
	}
}

// sluisFrom converts the sluis member of a vector into Event.Sluis. {"$repeat": "a", "times": n} is a string of n
// copies, so a vector can hold a long string without being long.
func sluisFrom(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return expandRepeat(convert(v, true)).(map[string]any)
}

func expandRepeat(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if s, ok := x["$repeat"].(string); ok {
			n, _ := x["times"].(int64)
			return strings.Repeat(s, int(n))
		}
		for k, e := range x {
			x[k] = expandRepeat(e)
		}
	case []string, []any:
	}
	return v
}

type jcsFile struct {
	Vectors []struct {
		Name     string          `json:"name"`
		Input    json.RawMessage `json:"input"`
		Expected string          `json:"expected"`
	} `json:"vectors"`
	Refused []struct {
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"refused"`
}

func TestCanonicalVectors(t *testing.T) {
	var f jcsFile
	readVectors(t, "jcs-vectors.json", &f)
	if len(f.Vectors) == 0 || len(f.Refused) == 0 {
		t.Fatal("the vector file is empty")
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := Canonical(decode(t, v.Input))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != v.Expected {
				t.Fatalf("got  %q\nwant %q", got, v.Expected)
			}
		})
	}
	for _, v := range f.Refused {
		t.Run("refused "+v.Name, func(t *testing.T) {
			if got, err := Canonical(decode(t, v.Input)); err == nil {
				t.Fatalf("accepted: %s", got)
			}
		})
	}
}

func TestCanonicalRefusesWhatIsNotJSONData(t *testing.T) {
	for name, v := range map[string]any{
		"float64": 1.5, "float32": float32(1), "uint": uint(1), "struct": struct{}{}, "map of another type": map[string]int{"a": 1},
		"invalid UTF-8 string": "a\xffb", "invalid UTF-8 key": map[string]any{"a\xff": 1},
		"int64 above the bound": int64(1) << 53, "int below the bound": -(1 << 53),
	} {
		if got, err := Canonical(v); err == nil {
			t.Errorf("%s accepted: %s", name, got)
		}
	}
	// A value nested deeper than the bound is refused, not recursed into.
	deep := any("x")
	for range maxDepth + 2 {
		deep = []any{deep}
	}
	if _, err := Canonical(deep); err == nil {
		t.Error("a deeply nested value was accepted")
	}
}

// repeatable is a string, or {"$repeat": "a", "times": n} for n copies, so a vector can hold a long string.
type repeatable string

func (r *repeatable) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*r = repeatable(s)
		return nil
	}
	var m struct {
		Repeat string `json:"$repeat"`
		Times  int    `json:"times"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*r = repeatable(strings.Repeat(m.Repeat, m.Times))
	return nil
}

type eventJSON struct {
	Action struct {
		Name         string     `json:"name"`
		ClassUID     int        `json:"class_uid"`
		ActivityID   int        `json:"activity_id"`
		ActivityName repeatable `json:"activity_name"`
	} `json:"action"`
	Subject *struct {
		Tenant string     `json:"tenant"`
		Kind   repeatable `json:"kind"`
		Value  repeatable `json:"value"`
	} `json:"subject"`
	Status     int             `json:"status"`
	StatusCode string          `json:"status_code"`
	Tenant     string          `json:"tenant"`
	Sluis      json.RawMessage `json:"sluis"`
	Policy     *struct {
		DecisionID string   `json:"decision_id"`
		Digest     string   `json:"digest"`
		PolicyIDs  []string `json:"policy_ids"`
		Decision   int      `json:"decision"`
	} `json:"policy"`
}

func (e eventJSON) event(t *testing.T) Event {
	t.Helper()
	ev := Event{
		Action: Action{Name: e.Action.Name, ClassUID: e.Action.ClassUID, ActivityID: e.Action.ActivityID, ActivityName: string(e.Action.ActivityName)},
		Status: Status(e.Status), StatusCode: e.StatusCode, Tenant: e.Tenant, Sluis: sluisFrom(t, e.Sluis),
	}
	if e.Policy != nil {
		ev.Policy = &PolicyRef{DecisionID: e.Policy.DecisionID, Digest: e.Policy.Digest, PolicyIDs: e.Policy.PolicyIDs, Decision: Decision(e.Policy.Decision)}
	}
	if e.Subject != nil {
		ev.Subject = &Subject{Tenant: e.Subject.Tenant, Kind: string(e.Subject.Kind), Value: string(e.Subject.Value)}
	}
	return ev
}

type recordFile struct {
	Cases []struct {
		Name        string    `json:"name"`
		Actor       string    `json:"actor"`
		Boundary    string    `json:"boundary"`
		Release     string    `json:"release"`
		UID         string    `json:"uid"`
		TimeMS      int64     `json:"time_ms"`
		Correlation string    `json:"correlation"`
		Pseudonym   string    `json:"pseudonym"`
		Event       eventJSON `json:"event"`
		Expected    string    `json:"expected"`
	} `json:"cases"`
	Pseudonyms []struct {
		TimeMS   int64  `json:"time_ms"`
		MacHex   string `json:"mac_hex"`
		Epoch    string `json:"epoch"`
		Expected string `json:"expected"`
	} `json:"pseudonyms"`
	UUIDs []struct {
		MS       uint64 `json:"ms"`
		Counter  uint16 `json:"counter"`
		RandBHex string `json:"rand_b_hex"`
		Expected string `json:"expected"`
	} `json:"uuids"`
	Refusals []struct {
		Name   string          `json:"name"`
		Sluis  json.RawMessage `json:"sluis"`
		Reason string          `json:"reason"`
		Path   string          `json:"path"`
	} `json:"refusals"`
	Accepted []struct {
		Name  string          `json:"name"`
		Sluis json.RawMessage `json:"sluis"`
	} `json:"accepted"`
	EventRefusals []struct {
		Name   string    `json:"name"`
		Event  eventJSON `json:"event"`
		Reason string    `json:"reason"`
		Path   string    `json:"path"`
	} `json:"event_refusals"`
	EventAccepted []struct {
		Name  string    `json:"name"`
		Event eventJSON `json:"event"`
	} `json:"event_accepted"`
	MacLabel  string `json:"mac_label"`
	MacInputs []struct {
		Boundary, Tenant, Kind, Value string
		InputHex                      string `json:"input_hex"`
	} `json:"mac_inputs"`
	Email struct {
		Match   []string `json:"match"`
		NoMatch []string `json:"no_match"`
	} `json:"email"`
	RecordMax int `json:"record_max_bytes"`
}

func TestRecordVectors(t *testing.T) {
	var f recordFile
	readVectors(t, "record-vectors.json", &f)
	if len(f.Cases) == 0 {
		t.Fatal("the vector file is empty")
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := buildRecord(recordInput{
				actor: c.Actor, boundary: c.Boundary, release: c.Release, uid: c.UID, timeMS: c.TimeMS,
				correlation: c.Correlation, pseudonym: c.Pseudonym, ev: c.Event.event(t),
			})
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.Expected {
				t.Fatalf("got  %s\nwant %s", got, c.Expected)
			}
		})
	}
}

func TestUUIDVectors(t *testing.T) {
	var f recordFile
	readVectors(t, "record-vectors.json", &f)
	if len(f.UUIDs) == 0 {
		t.Fatal("no uuid vectors")
	}
	for _, v := range f.UUIDs {
		var rb [8]byte
		if len(v.RandBHex) != 16 {
			t.Fatal("bad vector")
		}
		for i := range rb {
			n, _ := strconv.ParseUint(v.RandBHex[2*i:2*i+2], 16, 8)
			rb[i] = byte(n)
		}
		if got := uuidV7(v.MS, v.Counter, rb); got != v.Expected {
			t.Errorf("uuidV7(%d,%d,%s) = %s, want %s", v.MS, v.Counter, v.RandBHex, got, v.Expected)
		}
	}
}

func TestRefusalVectors(t *testing.T) {
	var f recordFile
	readVectors(t, "record-vectors.json", &f)
	base := Event{Action: Action{Name: "key.sign", ClassUID: 6003, ActivityID: 99, ActivityName: "Sign"}, Status: StatusSuccess}
	if len(f.Refusals) == 0 {
		t.Fatal("no refusal vectors")
	}
	for _, r := range f.Refusals {
		t.Run(r.Name, func(t *testing.T) {
			ev := base
			ev.Sluis = sluisFrom(t, r.Sluis)
			err := validateEvent(ev)
			if err == nil {
				t.Fatal("accepted")
			}
			if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
				t.Errorf("code = %v", code)
			}
			if reason, _ := refusal.Reason(err); reason != r.Reason {
				t.Errorf("reason = %q, want %q", reason, r.Reason)
			}
			if path, _ := refusal.FieldPath(err); path != r.Path {
				t.Errorf("path = %q, want %q", path, r.Path)
			}
			// An error never shows a value.
			if strings.Contains(err.Error(), "example") {
				t.Errorf("the error shows a value: %v", err)
			}
		})
	}
	for _, a := range f.Accepted {
		ev := base
		ev.Sluis = sluisFrom(t, a.Sluis)
		if err := validateEvent(ev); err != nil {
			t.Errorf("%s: %v", a.Name, err)
		}
	}
}

func TestEmailShape(t *testing.T) {
	var f recordFile
	readVectors(t, "record-vectors.json", &f)
	for _, s := range f.Email.Match {
		if !emailShaped(s) {
			t.Errorf("%q should match", s)
		}
	}
	for _, s := range f.Email.NoMatch {
		if emailShaped(s) {
			t.Errorf("%q should not match", s)
		}
	}
}

func TestRecordIsRefusedAboveItsBound(t *testing.T) {
	// 20 strings of 1,024 bytes are each within bounds and together above 16 KiB.
	sluis := map[string]any{}
	for i := range 20 {
		sluis["k"+strconv.Itoa(i)] = strings.Repeat("a", StringMax)
	}
	ev := Event{Action: Action{Name: "x", ClassUID: 6003, ActivityID: 99, ActivityName: "Sign"}, Status: StatusSuccess, Sluis: sluis}
	if err := validateEvent(ev); err != nil {
		t.Fatal(err)
	}
	_, err := buildRecord(recordInput{actor: "a", boundary: "dev", release: "r", uid: "u", ev: ev})
	if reason, _ := refusal.Reason(err); reason != "bound" {
		t.Fatalf("err = %v", err)
	}
	if path, _ := refusal.FieldPath(err); path != "record" {
		t.Fatalf("path = %q", path)
	}
}

func TestEventRefusalVectors(t *testing.T) {
	var f recordFile
	readVectors(t, "record-vectors.json", &f)
	if len(f.EventRefusals) == 0 || len(f.EventAccepted) == 0 {
		t.Fatal("no event vectors")
	}
	for _, r := range f.EventRefusals {
		t.Run(r.Name, func(t *testing.T) {
			err := validateEvent(r.Event.event(t))
			if err == nil {
				t.Fatal("accepted")
			}
			if reason, _ := refusal.Reason(err); reason != r.Reason {
				t.Errorf("reason = %q, want %q", reason, r.Reason)
			}
			if path, _ := refusal.FieldPath(err); path != r.Path {
				t.Errorf("path = %q, want %q", path, r.Path)
			}
		})
	}
	for _, a := range f.EventAccepted {
		if err := validateEvent(a.Event.event(t)); err != nil {
			t.Errorf("%s: %v", a.Name, err)
		}
	}
}

func TestPseudonymInputVectors(t *testing.T) {
	var f recordFile
	readVectors(t, "record-vectors.json", &f)
	if len(f.MacInputs) == 0 || f.MacLabel != pseudonymLabel {
		t.Fatalf("label %q, %d inputs", f.MacLabel, len(f.MacInputs))
	}
	seen := map[string]string{}
	for _, v := range f.MacInputs {
		got := hex.EncodeToString(pseudonymInput(v.Boundary, Subject{Tenant: v.Tenant, Kind: v.Kind, Value: v.Value}))
		if got != v.InputHex {
			t.Errorf("input of %+v = %s, want %s", v, got, v.InputHex)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("%+v and %s give the same input", v, other)
		}
		seen[got] = v.Boundary + "/" + v.Tenant
	}
}
