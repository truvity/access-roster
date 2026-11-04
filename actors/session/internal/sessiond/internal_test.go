//go:build sluis_test

package sessiond

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
)

func TestAssuranceNeverInventsAnACR(t *testing.T) {
	// 0031: a multi-factor method never raises acr by itself. The upstream said none, so there is none.
	a := assuranceOf(&integrationv2alpha1.Assertion{Amr: []string{"pwd", "otp", "mfa", "hwk"}, AmrPresent: true})
	if a.acr != nil {
		t.Fatalf("acr = %q", *a.acr)
	}
	if strings.Join(a.amr, ",") != "pwd,otp,mfa,hwk" || !a.amrPresent {
		t.Errorf("amr = %v present %v", a.amr, a.amrPresent)
	}
	// What the upstream said as its acr passes through unchanged, and an empty one is none.
	acr := "urn:example:acr:2"
	if got := assuranceOf(&integrationv2alpha1.Assertion{Acr: &acr}); got.acr == nil || *got.acr != acr {
		t.Errorf("acr = %v", got.acr)
	}
	empty := ""
	if got := assuranceOf(&integrationv2alpha1.Assertion{Acr: &empty}); got.acr != nil {
		t.Errorf("empty acr kept: %v", *got.acr)
	}
	long := strings.Repeat("a", maxACRLen+1)
	if got := assuranceOf(&integrationv2alpha1.Assertion{Acr: &long}); got.acr != nil {
		t.Error("an acr past the signer's bound was kept")
	}
	// Nothing at all stays nothing: unknown is not a default.
	none := assuranceOf(&integrationv2alpha1.Assertion{})
	if none.acr != nil || none.amrPresent || len(none.amr) != 0 || none.hasAuthTime {
		t.Errorf("assurance of nothing = %+v", none)
	}
	// Present and empty is not absent: policy tells them apart.
	if got := assuranceOf(&integrationv2alpha1.Assertion{AmrPresent: true}); !got.amrPresent || len(got.amr) != 0 {
		t.Errorf("empty amr list = %+v", got)
	}
}

func TestAMRIsCutToRFC8176Tokens(t *testing.T) {
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, "m"+strings.Repeat("x", i%5)+string(rune('a'+i%20)))
	}
	cases := map[string][]string{
		"upper case dropped":  {"PWD", "otp"},
		"space dropped":       {"two words", "mfa"},
		"empty dropped":       {"", "mfa"},
		"repeat dropped":      {"mfa", "mfa", "otp"},
		"too long dropped":    {strings.Repeat("a", maxAMRLen+1), "otp"},
		"quote dropped":       {`a"b`, "otp"},
		"at most 16 are kept": many,
		"hyphen and digit":    {"sms", "pop-2", "x_1"},
	}
	for name, in := range cases {
		got := cleanAMR(in)
		if len(got) > maxAMR {
			t.Errorf("%s: %d methods", name, len(got))
		}
		for _, m := range got {
			if m == "" || len(m) > maxAMRLen || !amrToken(m) {
				t.Errorf("%s: kept %q", name, m)
			}
		}
	}
	if got := cleanAMR([]string{"PWD", "otp"}); strings.Join(got, ",") != "otp" {
		t.Errorf("got %v", got)
	}
}

func TestAuthAge(t *testing.T) {
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		at   *timestamppb.Timestamp
		age  int64
		ok   bool
	}{
		{"none is unknown", nil, 0, false},
		{"a minute ago", timestamppb.New(now.Add(-time.Minute)), 60, true},
		{"now", timestamppb.New(now), 0, true},
		{"a little ahead is skew", timestamppb.New(now.Add(30 * time.Second)), 0, true},
		{"far ahead is unknown", timestamppb.New(now.Add(3 * time.Hour)), 0, false},
	}
	for _, c := range cases {
		a := assuranceOf(&integrationv2alpha1.Assertion{AuthTime: c.at})
		age, ok := a.authAge(now)
		if age != c.age || ok != c.ok {
			t.Errorf("%s: %d, %v", c.name, age, ok)
		}
	}
}

func TestStepUpReadsOnlyTheTwoKnownKeys(t *testing.T) {
	r := func(v string) []*policyv2alpha1.Reason {
		return []*policyv2alpha1.Reason{{PolicyId: "p", Annotations: map[string]string{"step_up": v}}}
	}
	cases := []struct {
		in   string
		want map[string]string
	}{
		{"acr_values=urn:example:acr:mfa max_age=900", map[string]string{"acr_values": "urn:example:acr:mfa", "max_age": "900"}},
		{"max_age=0", map[string]string{"max_age": "0"}},
		{"max_age=-1", nil},
		{"max_age=soon", nil},
		{"max_age=99999999999999", nil},
		{"error=evil acr_values=a", map[string]string{"acr_values": "a"}},
		{"redirect_uri=https://evil.example", nil},
		{"acr_values=", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := stepUpOf(r(c.in))
		if len(got) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%q: %s = %q, want %q", c.in, k, got[k], v)
			}
		}
	}
	if stepUpOf([]*policyv2alpha1.Reason{{PolicyId: "p"}}) != nil {
		t.Error("a reason with no annotation gave a step-up")
	}
}

func TestGrantedScope(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"openid", "openid", true},
		{"openid profile email", "openid profile email", true},
		{"profile  openid", "profile openid", true},
		{"openid openid", "openid", true},
		{"openid offline_access admin", "openid", true},
		{"profile", "", false},
		{"", "", false},
		{"OPENID", "", false},
		{strings.Repeat("openid ", 100), "", false},
	}
	for _, c := range cases {
		got, ok := grantedScope(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("%q: %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSecretIDsAreHashes(t *testing.T) {
	id := secretID("a-code")
	if len(id) != 96 || strings.Contains(id, "a-code") || id != secretID("a-code") || id == secretID("a-codf") {
		t.Errorf("id = %q", id)
	}
	if len(secretHash("x")) != 48 {
		t.Error("the stored form of a refresh token is not SHA-384")
	}
}

func TestCappedAppliesTheMaximaAndDefaults(t *testing.T) {
	cases := []struct{ v, maximum, def, want time.Duration }{
		{2 * time.Hour, time.Hour, time.Hour, time.Hour},
		{0, time.Hour, 5 * time.Minute, 5 * time.Minute},
		{-time.Minute, time.Hour, 5 * time.Minute, 5 * time.Minute},
		{time.Minute, time.Hour, time.Hour, time.Minute},
	}
	for _, c := range cases {
		if got := capped(c.v, c.maximum, c.def); got != c.want {
			t.Errorf("capped(%v, %v, %v) = %v, want %v", c.v, c.maximum, c.def, got, c.want)
		}
	}
}
