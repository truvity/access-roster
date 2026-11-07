//go:build sluis_test

package sessiond_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	passkeyOrigin = "https://sluis.dev.local.test" //nolint:gosec // a web origin of the tests
	passkeyRPID   = "local.test"
	passkeyACR    = "urn:sluis:acr:passkey" //nolint:gosec // an acr value
)

// passkeyEnv is an env with the passkey configuration of the local installation: the relying party local.test and one
// origin.
func passkeyEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, nil)
	putPasskeyConfig(e, []string{passkeyOrigin})
	return e
}

func putPasskeyConfig(e *env, origins []string) {
	e.store.put("front-host", "", "default", &configv2alpha1.FrontHost{RpId: passkeyRPID, RpName: "sluis local", Origins: origins})
	e.store.put("sign-in-methods", "", "default", &configv2alpha1.SignInMethods{PasskeyAcr: passkeyACR, UpstreamRecheck: durationpb.New(14 * 24 * time.Hour)})
}

// grant is what policy gives a sign-in it admits, as far as the passkey code uses it: create and update of the tenant's
// items. (The caps of the real policy allow these for token.issue: actors/policy decide.rs.)
func (e *env) grant() []byte {
	g := fakeGrant{id: "d-pk", tenant: testTenant, verbs: []string{"create", "update"}, ops: []string{"seal", "open"}, expires: e.clk.now().Add(time.Minute)}
	return []byte(g.encode())
}

// addPerson makes a Person the way the first sign-in does.
func (e *env) addPerson(subject string) {
	e.t.Helper()
	env, err := e.key.sealForTest("data", &typev2alpha1.Address{Kind: "person", Tenant: testTenant, Id: subject},
		&sessionv2alpha1.Person{Subject: subject, CreatedAt: timestamppb.New(e.clk.now())})
	if err != nil {
		e.t.Fatal(err)
	}
	e.store.putRaw("person", testTenant, subject, env)
}

func (e *env) person(subject string) *sessionv2alpha1.Person {
	e.t.Helper()
	raw, _, ok := e.store.raw("person", testTenant, subject)
	if !ok {
		e.t.Fatalf("no person %s", subject)
	}
	pt, err := e.key.openForTest("data", &typev2alpha1.Address{Kind: "person", Tenant: testTenant, Id: subject}, raw)
	if err != nil {
		e.t.Fatal(err)
	}
	p := &sessionv2alpha1.Person{}
	if err := proto.Unmarshal(pt, p); err != nil {
		e.t.Fatal(err)
	}
	return p
}

var ctx = context.Background()

// register runs a registration of k for subject.
func (e *env) register(k *softKey, subject string) (*sessiond.PasskeyRecord, error) {
	e.t.Helper()
	opts, sealed, err := e.svc.RegisterBegin(ctx, testTenant, subject, "workforce/"+subject, e.grant())
	if err != nil {
		return nil, err
	}
	if k.origin == "" {
		k.origin = passkeyOrigin
	}
	return e.svc.RegisterFinish(ctx, testTenant, sealed, k.Create(opts), e.grant())
}

// mustRegister registers k for a new person and returns the person's subject.
func (e *env) mustRegister(k *softKey, subject string) *sessiond.PasskeyRecord {
	e.t.Helper()
	if _, _, ok := e.store.raw("person", testTenant, subject); !ok {
		e.addPerson(subject)
	}
	rec, err := e.register(k, subject)
	if err != nil {
		e.t.Fatalf("register: %v", err)
	}
	return rec
}

// assert runs a sign-in with k.
func (e *env) assert(k *softKey) (*sessiond.PasskeyRecord, error) {
	e.t.Helper()
	opts, sealed, err := e.svc.AssertBegin(ctx)
	if err != nil {
		return nil, err
	}
	if k.origin == "" {
		k.origin = passkeyOrigin
	}
	return e.svc.AssertFinish(ctx, testTenant, sealed, k.Get(opts), e.grant())
}

func (e *env) stored(subject string) []*sessiond.PasskeyRecord {
	e.t.Helper()
	var out []*sessiond.PasskeyRecord
	for _, id := range e.store.ids("staff-passkey", testTenant) {
		raw, _, _ := e.store.raw("staff-passkey", testTenant, id)
		pt, err := e.key.openForTest("credential", &typev2alpha1.Address{Kind: "staff-passkey", Tenant: testTenant, Id: id}, raw)
		if err != nil {
			e.t.Fatal(err)
		}
		r := &sessiond.PasskeyRecord{}
		if err := proto.Unmarshal(pt, r); err != nil {
			e.t.Fatal(err)
		}
		if subject == "" || r.GetSubject() == subject {
			out = append(out, r)
		}
	}
	return out
}

// The class, the AAGUID, the raw attestation object and the outcome of the check are stored with each passkey
// (REQ-AUTHN-080): a key that sets the backup eligible flag is synced, one that does not is hardware whatever statement it
// sends, and the object is what the authenticator sent. The item is sealed under the credential key, and nothing of the
// credential is in the clear in the store.
//
// verifies: REQ-AUTHN-080
func TestRegistrationStoresTheClassAndTheRawAttestation(t *testing.T) {
	for _, c := range []struct {
		name          string
		be            bool
		attestation   string
		class, format string
	}{
		{"device-bound, no attestation", false, "none", "hardware", "none"},
		{"device-bound, a self-attested statement", false, "packed", "hardware", "packed"},
		{"synced, no attestation", true, "none", "synced", "none"},
		{"synced, with a statement: BE wins", true, "packed", "synced", "packed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := passkeyEnv(t)
			k := newSoftKey(t, 32, c.be)
			k.attestation = c.attestation
			k.aaguid = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			rec := e.mustRegister(k, "alice")
			if rec.GetClass() != c.class || rec.GetAttestationFormat() != c.format || rec.GetAttestationOutcome() != "not-verified" {
				t.Errorf("class %q format %q outcome %q", rec.GetClass(), rec.GetAttestationFormat(), rec.GetAttestationOutcome())
			}
			if !bytes.Equal(rec.GetAaguid(), k.aaguid[:]) || !bytes.Equal(rec.GetCredentialId(), k.id) || rec.GetBackupEligible() != c.be {
				t.Errorf("aaguid, credential id or BE not kept: %+v", rec)
			}
			if o := rec.GetAttestationObject(); len(o) == 0 || !bytes.Contains(o, []byte(c.format)) {
				t.Errorf("the raw attestation object is not kept: %x", o)
			}
			if rec.GetAccount() != "workforce/alice" || rec.GetSubject() != "alice" {
				t.Errorf("subject %q account %q", rec.GetSubject(), rec.GetAccount())
			}
			// What the store holds is the one stored record, and it opens only under the credential key.
			ids := e.store.ids("staff-passkey", testTenant)
			if len(ids) != 1 || len(ids[0]) != 52 {
				t.Fatalf("ids = %v, want one keyed hash of 52 characters", ids)
			}
			raw, _, _ := e.store.raw("staff-passkey", testTenant, ids[0])
			addr := &typev2alpha1.Address{Kind: "staff-passkey", Tenant: testTenant, Id: ids[0]}
			if _, err := e.key.openForTest("data", addr, raw); err == nil {
				t.Error("the item opens under the data key")
			}
			for _, secret := range [][]byte{k.id, rec.GetPublicKey(), []byte("alice")} {
				if bytes.Contains(raw, secret) {
					t.Error("the item holds a credential or the subject in the clear")
				}
			}
			if !strings.Contains(strings.Join(e.key.called(), ","), "seal credential") {
				t.Errorf("key calls: %v", e.key.called())
			}
		})
	}
}

// Both ceremonies require user verification and a discoverable credential, and registration asks for the attestation
// directly and never as enterprise (REQ-AUTHN-018, REQ-AUTHN-084); a response whose authenticator did not verify the user is
// refused at both.
//
// verifies: REQ-AUTHN-018
func TestUserVerificationIsRequired(t *testing.T) {
	e := passkeyEnv(t)
	e.addPerson("alice")
	ropts, _, err := e.svc.RegisterBegin(ctx, testTenant, "alice", "workforce/alice", e.grant())
	if err != nil {
		t.Fatal(err)
	}
	o := parseOptions(t, ropts)
	if o.AuthenticatorSelection.UserVerification != "required" || o.AuthenticatorSelection.ResidentKey != "required" || o.Attestation != "direct" {
		t.Errorf("registration options: %+v", o)
	}
	aopts, _, err := e.svc.AssertBegin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if o := parseOptions(t, aopts); o.UserVerification != "required" {
		t.Errorf("assertion options: %+v", o)
	}
	// UV=0 at registration, and at an assertion of a credential that was registered properly.
	k := newSoftKey(t, 32, false)
	k.uv = false
	if _, err := e.register(k, "alice"); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("a registration with UV=0: %v", err)
	}
	if len(e.stored("")) != 0 {
		t.Error("a credential was stored")
	}
	good := newSoftKey(t, 32, false)
	e.mustRegister(good, "alice")
	good.uv = false
	if _, err := e.assert(good); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("an assertion with UV=0: %v", err)
	}
	// And user presence.
	good.uv, good.up = true, false
	if _, err := e.assert(good); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("an assertion with UP=0: %v", err)
	}
}

// A response works once, a refused one included (REQ-AUTHN-019, REQ-AUTHN-051): the second use of a challenge is a replay,
// at both ceremonies, and a replay writes nothing. The challenge is spent by a create, so nothing Gets an item that is not
// there (REQ-AUDIT-180).
//
// verifies: REQ-AUTHN-019, REQ-AUTHN-051
func TestAChallengeWorksOnce(t *testing.T) {
	e := passkeyEnv(t)
	k := newSoftKey(t, 32, false)
	e.addPerson("alice")
	ropts, rsealed, err := e.svc.RegisterBegin(ctx, testTenant, "alice", "workforce/alice", e.grant())
	if err != nil {
		t.Fatal(err)
	}
	k.origin = passkeyOrigin
	body := k.Create(ropts)
	if _, err := e.svc.RegisterFinish(ctx, testTenant, rsealed, body, e.grant()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RegisterFinish(ctx, testTenant, rsealed, body, e.grant()); !errors.Is(err, sessiond.ErrPasskeyReplay) {
		t.Errorf("a registration replayed: %v", err)
	}
	if n := len(e.stored("")); n != 1 {
		t.Errorf("%d credentials after a replay", n)
	}
	aopts, asealed, err := e.svc.AssertBegin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	abody := k.Get(aopts)
	if _, err := e.svc.AssertFinish(ctx, testTenant, asealed, abody, e.grant()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AssertFinish(ctx, testTenant, asealed, abody, e.grant()); !errors.Is(err, sessiond.ErrPasskeyReplay) {
		t.Errorf("an assertion replayed: %v", err)
	}
	// A refused response spends the challenge too: the same ceremony cannot be tried again with a better one.
	aopts, asealed, _ = e.svc.AssertBegin(ctx)
	k.rpID = "other.test"
	if _, err := e.svc.AssertFinish(ctx, testTenant, asealed, k.Get(aopts), e.grant()); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Fatalf("a wrong relying-party ID: %v", err)
	}
	k.rpID = ""
	if _, err := e.svc.AssertFinish(ctx, testTenant, asealed, k.Get(aopts), e.grant()); !errors.Is(err, sessiond.ErrPasskeyReplay) {
		t.Errorf("a refused ceremony tried again: %v", err)
	}
	if len(e.store.absentGets) != 0 {
		t.Errorf("Gets of items that were not there, which store@ audits as refusals: %v", e.store.absentGets)
	}
	// A challenge other than the ceremony's is refused.
	aopts, asealed, _ = e.svc.AssertBegin(ctx)
	k.challenge = b64([]byte("a challenge that was never issued 32 bytes"))
	if _, err := e.svc.AssertFinish(ctx, testTenant, asealed, k.Get(aopts), e.grant()); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("another challenge: %v", err)
	}
	k.challenge = ""
}

// The origin of the response must be one of the exact origins of the configuration, and the relying-party ID hash the
// configured one: another host under the same relying-party ID, another scheme or port, and a verifier whose list lacks the
// origin all refuse (REQ-AUTHN-050, REQ-ISO-034, T-6).
//
// verifies: REQ-AUTHN-050, REQ-ISO-034
func TestOnlyTheListedOriginsAreAccepted(t *testing.T) {
	for _, c := range []struct {
		origin string
		ok     bool
	}{
		{passkeyOrigin, true},
		{"https://other.local.test", false},       // same relying-party ID, another host
		{"https://sluis.devel.local.test", false}, // a host the verifier's list lacks
		{"https://local.test", false},
		{"http://sluis.dev.local.test", false},
		{"https://sluis.dev.local.test:8443", false},
		{"https://sluis.dev.local.test.evil.test", false},
		{"https://SLUIS.dev.local.test.", false},
		{"", false},
	} {
		t.Run(c.origin, func(t *testing.T) {
			e := passkeyEnv(t)
			e.addPerson("alice")
			k := newSoftKey(t, 32, false)
			k.origin = c.origin
			if c.origin == "" {
				k.origin = "null"
			}
			_, err := e.register(k, "alice")
			if c.ok != (err == nil) {
				t.Fatalf("registration from %q: %v", c.origin, err)
			}
			if !c.ok {
				if !errors.Is(err, sessiond.ErrPasskeyResp) {
					t.Errorf("err = %v", err)
				}
				// And an assertion from that origin, of a credential registered from the right one.
				good := newSoftKey(t, 32, false)
				e.mustRegister(good, "alice")
				good.origin = k.origin
				if _, err := e.assert(good); !errors.Is(err, sessiond.ErrPasskeyResp) {
					t.Errorf("assertion from %q: %v", c.origin, err)
				}
			}
		})
	}
	// The list is the configuration's: a verifier whose list names two hosts accepts both, and one that names a host
	// accepts no other.
	e := newEnv(t, nil)
	putPasskeyConfig(e, []string{passkeyOrigin, "https://sluis.local.test"})
	e.addPerson("alice")
	k := newSoftKey(t, 32, false)
	k.origin = "https://sluis.local.test"
	if _, err := e.register(k, "alice"); err != nil {
		t.Errorf("the second listed origin: %v", err)
	}
	if _, err := e.assert(k); err != nil {
		t.Errorf("an assertion from the second listed origin: %v", err)
	}
}

// The relying-party ID hash must be the configured one.
//
// verifies: REQ-AUTHN-050
func TestTheRelyingPartyIDMustBeTheConfiguredOne(t *testing.T) {
	e := passkeyEnv(t)
	e.addPerson("alice")
	for _, rp := range []string{"other.test", "sluis.dev.local.test", "dev.local.test"} {
		k := newSoftKey(t, 32, false)
		k.rpID = rp
		if _, err := e.register(k, "alice"); !errors.Is(err, sessiond.ErrPasskeyResp) {
			t.Errorf("a registration for %q: %v", rp, err)
		}
	}
}

// The signature counter of a credential that is not synced must rise; 0 then 0 is "no counter"; a counter that was above 0
// and falls, or that stays, is refused; a synced credential's counter is stored and not judged (REQ-AUTHN-052).
//
// verifies: REQ-AUTHN-052
func TestTheCounterRuleFollowsTheClass(t *testing.T) {
	t.Run("hardware: a rising counter", func(t *testing.T) {
		e := passkeyEnv(t)
		k := newSoftKey(t, 32, false)
		e.mustRegister(k, "alice")
		for i := 1; i <= 3; i++ {
			rec, err := e.assert(k)
			if err != nil || rec.GetSignCount() != uint32(i) {
				t.Fatalf("assertion %d: %v %d", i, err, rec.GetSignCount())
			}
		}
		if got := e.stored("alice")[0].GetSignCount(); got != 3 {
			t.Errorf("the stored counter is %d", got)
		}
		// A regression, and a repeat, are refused, and the stored counter does not move.
		k.count = 1
		if _, err := e.assert(k); !errors.Is(err, sessiond.ErrPasskeyClone) {
			t.Errorf("a counter that fell: %v", err)
		}
		k.count = 2 // the next assertion reports 3: the stored value
		if _, err := e.assert(k); !errors.Is(err, sessiond.ErrPasskeyClone) {
			t.Errorf("a counter that stayed: %v", err)
		}
		if got := e.stored("alice")[0].GetSignCount(); got != 3 {
			t.Errorf("the stored counter moved to %d", got)
		}
		k.count = 9
		if _, err := e.assert(k); err != nil {
			t.Errorf("a counter that rose again: %v", err)
		}
	})
	t.Run("hardware: a device that always reports 0", func(t *testing.T) {
		e := passkeyEnv(t)
		k := newSoftKey(t, 32, false)
		k.counting = false
		e.mustRegister(k, "alice")
		for range 3 {
			if _, err := e.assert(k); err != nil {
				t.Fatalf("0 then 0: %v", err)
			}
		}
	})
	t.Run("hardware: a counter that was above 0 and reports 0", func(t *testing.T) {
		e := passkeyEnv(t)
		k := newSoftKey(t, 32, false)
		e.mustRegister(k, "alice")
		if _, err := e.assert(k); err != nil {
			t.Fatal(err)
		}
		k.counting = false
		if _, err := e.assert(k); !errors.Is(err, sessiond.ErrPasskeyClone) {
			t.Errorf("a counter that fell to 0: %v", err)
		}
	})
	t.Run("synced: counter 0 is accepted, and a counter that falls too", func(t *testing.T) {
		e := passkeyEnv(t)
		k := newSoftKey(t, 32, true)
		e.mustRegister(k, "alice")
		for range 3 {
			if _, err := e.assert(k); err != nil {
				t.Fatalf("synced, counter 0: %v", err)
			}
		}
		k.counting, k.count = true, 50
		if _, err := e.assert(k); err != nil {
			t.Fatal(err)
		}
		k.count = 4
		if _, err := e.assert(k); err != nil {
			t.Errorf("a synced counter that fell: %v", err)
		}
	})
}

// The backup eligible flag is fixed for the life of a credential, and backup state without eligibility is invalid
// (ADR 0017; the library refuses both, and this holds it to that).
//
// verifies: REQ-AUTHN-080
func TestTheBackupFlagsAreHeldToTheRegisteredClass(t *testing.T) {
	e := passkeyEnv(t)
	k := newSoftKey(t, 32, false)
	e.mustRegister(k, "alice")
	k.be = true
	if _, err := e.assert(k); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("BE set on a credential registered without it: %v", err)
	}
	k.be, k.bs = false, true
	if _, err := e.assert(k); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("BS set with BE clear: %v", err)
	}
	// BS at registration with BE clear is refused as well.
	bad := newSoftKey(t, 32, false)
	bad.bs = true
	if _, err := e.register(bad, "alice"); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("a registration with BS and no BE: %v", err)
	}
	// A synced credential follows its backup state.
	s := newSoftKey(t, 32, true)
	e.mustRegister(s, "alice")
	s.bs = false
	rec, err := e.assert(s)
	if err != nil || rec.GetBackupState() {
		t.Errorf("a synced credential not backed up: %v %v", err, rec.GetBackupState())
	}
}

// A passkey of any class signs in: the class is recorded, and no class is refused (REQ-AUTHN-083). The amr that the class
// gives is mfa, with swk for a synced one.
//
// verifies: REQ-AUTHN-083
func TestAPasskeyOfAnyClassSignsIn(t *testing.T) {
	e := passkeyEnv(t)
	for i, c := range []struct {
		be          bool
		attestation string
		class       string
	}{{false, "none", "hardware"}, {false, "packed", "hardware"}, {true, "none", "synced"}} {
		k := newSoftKey(t, 32, c.be)
		k.attestation = c.attestation
		subject := "person" + string(rune('a'+i))
		e.mustRegister(k, subject)
		rec, err := e.assert(k)
		if err != nil || rec.GetClass() != c.class || rec.GetSubject() != subject {
			t.Errorf("%s: %v %v", c.class, err, rec)
		}
		if got := sessiond.AMROfClass(rec.GetClass()); strings.Join(got, ",") != map[string]string{"hardware": "mfa", "synced": "mfa,swk"}[c.class] {
			t.Errorf("amr of %s = %v", c.class, got)
		}
	}
}

// The credential is found by its id and held to the user handle: an id nobody registered, and a known id with another
// user handle, are refused, and neither is a Get of an item that is not there.
//
// verifies: REQ-AUTHN-020
func TestAnUnknownCredentialIsRefusedQuietly(t *testing.T) {
	e := passkeyEnv(t)
	good := newSoftKey(t, 32, false)
	e.mustRegister(good, "alice")
	stranger := newSoftKey(t, 32, false)
	stranger.handle = good.handle
	if _, err := e.assert(stranger); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("an unknown credential: %v", err)
	}
	other := newSoftKey(t, 32, false)
	other.id, other.priv = good.id, good.priv
	other.handle = bytes.Repeat([]byte{7}, 32)
	if _, err := e.assert(other); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("a known credential with another user handle: %v", err)
	}
	if len(e.store.absentGets) != 0 {
		t.Errorf("absent Gets: %v", e.store.absentGets)
	}
}

// The options of an assertion carry nothing of any person and are the same for every request but the challenge: no allowed
// credentials, no user handle, no hint of an account (REQ-AUTHN-020).
//
// verifies: REQ-AUTHN-020
func TestTheAssertionOptionsCarryNothingOfAPerson(t *testing.T) {
	empty := passkeyEnv(t)
	full := passkeyEnv(t)
	full.mustRegister(newSoftKey(t, 32, false), "alice")
	strip := func(raw []byte) string {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "challenge")
		b, _ := json.Marshal(m)
		return string(b)
	}
	a, _, err := empty.svc.AssertBegin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := full.svc.AssertBegin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := full.svc.AssertBegin(ctx)
	if strip(a) != strip(b) || strip(b) != strip(c) {
		t.Errorf("the options differ:\n%s\n%s\n%s", strip(a), strip(b), strip(c))
	}
	for _, field := range []string{"allowCredentials", "userHandle", "user"} {
		if strings.Contains(strip(a), `"`+field+`"`) {
			t.Errorf("the options have %s: %s", field, strip(a))
		}
	}
	if parseOptions(t, a).Challenge == parseOptions(t, b).Challenge {
		t.Error("two ceremonies have one challenge")
	}
	if len(empty.store.writes) != 0 && len(full.store.writes) != 1 {
		t.Error("beginning an assertion wrote")
	}
}

// The WebAuthn user handle is 32 random bytes, kept on the person, made at the first registration and stable after it, and
// derived from nothing (REQ-SUBJ-029, REQ-SUBJ-030).
//
// verifies: REQ-SUBJ-029, REQ-SUBJ-030
func TestTheUserHandleIs32RandomBytesOnThePerson(t *testing.T) {
	e := passkeyEnv(t)
	handles := map[string]bool{}
	for _, subject := range []string{"alice", "bob", "carol", "dave"} {
		e.addPerson(subject)
		if h := e.person(subject).GetUserHandle(); len(h) != 0 {
			t.Fatalf("%s has a handle before a passkey", subject)
		}
		k := newSoftKey(t, 32, false)
		e.mustRegister(k, subject)
		h := e.person(subject).GetUserHandle()
		if len(h) != 32 || handles[string(h)] {
			t.Fatalf("%s: handle of %d bytes, repeated %v", subject, len(h), handles[string(h)])
		}
		handles[string(h)] = true
		if !bytes.Equal(k.handle, h) {
			t.Errorf("%s: the authenticator got another handle than the person's", subject)
		}
		// A second passkey of the person has the same handle.
		k2 := newSoftKey(t, 32, false)
		e.mustRegister(k2, subject)
		if !bytes.Equal(k2.handle, h) || !bytes.Equal(e.person(subject).GetUserHandle(), h) {
			t.Errorf("%s: the handle changed at the second passkey", subject)
		}
		// It is derived from neither the subject nor its hashes.
		sum := sha256.Sum256([]byte(subject))
		for _, d := range [][]byte{[]byte(subject), sum[:], bytes.Repeat([]byte(subject), 32)[:32], []byte(testTenant + subject)} {
			if bytes.Equal(h, d) || (len(d) >= 8 && bytes.Contains(h, d[:8])) {
				t.Errorf("%s: the handle is derived from the subject", subject)
			}
		}
	}
	// Derived from nothing: the same subject in two installations has two handles.
	other := passkeyEnv(t)
	other.addPerson("alice")
	other.mustRegister(newSoftKey(t, 32, false), "alice")
	if bytes.Equal(other.person("alice").GetUserHandle(), e.person("alice").GetUserHandle()) {
		t.Error("two persons with one subject have one handle: it is derived")
	}
	// The handle is not in the clear in the store.
	raw, _, _ := e.store.raw("person", testTenant, "alice")
	if bytes.Contains(raw, e.person("alice").GetUserHandle()) {
		t.Error("the handle is in the clear")
	}
}

// A credential id is base64url and can begin with - or _; one such id registers and signs in, and every audit-visible name
// made from it is a valid id of the store. One over 255 bytes is not stored (random values, not one fixed id).
//
// verifies: REQ-AUTHN-018
func TestCredentialIDsThatBeginWithAHyphenOrAnUnderscore(t *testing.T) {
	e := passkeyEnv(t)
	want := map[byte]bool{'-': false, '_': false}
	for i := 0; i < 5000 && (!want['-'] || !want['_']); i++ {
		k := newSoftKey(t, 16+i%48, false)
		c := b64(k.id)[0]
		if _, ok := want[c]; !ok || want[c] {
			continue
		}
		want[c] = true
		subject := "hy" + string(rune('a'+i%26)) + string(rune('a'+i/26%26))
		e.mustRegister(k, subject)
		rec, err := e.assert(k)
		if err != nil || rec.GetSubject() != subject {
			t.Fatalf("id %q: %v", b64(k.id), err)
		}
	}
	if !want['-'] || !want['_'] {
		t.Fatalf("no random credential id began with both - and _: %v", want)
	}
	e.addPerson("longid")
	long := newSoftKey(t, 256, false)
	if _, err := e.register(long, "longid"); !errors.Is(err, sessiond.ErrPasskeyBadID) {
		t.Errorf("a credential id of 256 bytes: %v", err)
	}
}

// A credential id that is registered is refused again, for the same person or another, and a person has at most ten
// passkeys; the options of a registration exclude the credentials the person has.
//
// verifies: REQ-AUTHN-080
func TestACredentialIsRegisteredOnceAndAPersonHasTen(t *testing.T) {
	e := passkeyEnv(t)
	k := newSoftKey(t, 32, false)
	e.mustRegister(k, "alice")
	e.addPerson("bob")
	if _, err := e.register(k, "bob"); !errors.Is(err, sessiond.ErrPasskeyTaken) {
		t.Errorf("the same credential for another person: %v", err)
	}
	if n := len(e.stored("bob")); n != 0 {
		t.Errorf("bob has %d passkeys", n)
	}
	opts, _, err := e.svc.RegisterBegin(ctx, testTenant, "alice", "workforce/alice", e.grant())
	if err != nil {
		t.Fatal(err)
	}
	ex := parseOptions(t, opts).ExcludeCreds
	if len(ex) != 1 || ex[0].ID != b64(k.id) {
		t.Errorf("excludeCredentials = %+v", ex)
	}
	for i := 1; i < 10; i++ {
		e.mustRegister(newSoftKey(t, 32, false), "alice")
	}
	if _, _, err := e.svc.RegisterBegin(ctx, testTenant, "alice", "workforce/alice", e.grant()); !errors.Is(err, sessiond.ErrPasskeyTaken) {
		t.Errorf("an eleventh passkey: %v", err)
	}
}

// A held person registers no passkey and signs in with none (the instruction: a hold refuses at the sign-in, the refresh and
// the exchange, and a passkey is a sign-in).
//
// verifies: REQ-SUBJ-043
func TestAHeldPersonNeitherRegistersNorSignsIn(t *testing.T) {
	e := passkeyEnv(t)
	k := newSoftKey(t, 32, false)
	e.mustRegister(k, "alice")
	e.store.putRaw("person-hold", testTenant, "alice", []byte{1})
	if _, err := e.assert(k); !errors.Is(err, sessiond.ErrPasskeyHeld) {
		t.Errorf("a held person signs in: %v", err)
	}
	if got := e.stored("alice")[0].GetSignCount(); got != 0 {
		t.Errorf("a refused sign-in moved the counter to %d", got)
	}
	if _, err := e.register(newSoftKey(t, 32, false), "alice"); !errors.Is(err, sessiond.ErrPasskeyHeld) {
		t.Errorf("a held person registers: %v", err)
	}
	if n := len(e.stored("alice")); n != 1 {
		t.Errorf("alice has %d passkeys", n)
	}
	// Each step refuses on its own: a hold placed between the two steps of a registration stops the second, and one placed
	// before stops the first.
	e.addPerson("carol")
	copts, csealed, err := e.svc.RegisterBegin(ctx, testTenant, "carol", "workforce/carol", e.grant())
	if err != nil {
		t.Fatal(err)
	}
	e.store.putRaw("person-hold", testTenant, "carol", []byte{1})
	ck := newSoftKey(t, 32, false)
	ck.origin = passkeyOrigin
	if _, err := e.svc.RegisterFinish(ctx, testTenant, csealed, ck.Create(copts), e.grant()); !errors.Is(err, sessiond.ErrPasskeyHeld) {
		t.Errorf("a hold placed between the steps: %v", err)
	}
	if n := len(e.stored("carol")); n != 0 {
		t.Errorf("carol has %d passkeys", n)
	}
	if _, _, err := e.svc.RegisterBegin(ctx, testTenant, "carol", "workforce/carol", e.grant()); !errors.Is(err, sessiond.ErrPasskeyHeld) {
		t.Errorf("a held person begins a registration: %v", err)
	}
	// A person who is not held is not touched by the hold of another.
	e.mustRegister(newSoftKey(t, 32, false), "bob")
	// The hold is looked up with a listing: no Get of an absent hold.
	if len(e.store.absentGets) != 0 {
		t.Errorf("absent Gets: %v", e.store.absentGets)
	}
}

// An installation without FrontHost or SignInMethods has passkeys off, and asking is not a refusal of store@.
func TestPasskeysAreOffWithoutConfiguration(t *testing.T) {
	e := newEnv(t, nil)
	e.addPerson("alice")
	if _, _, err := e.svc.AssertBegin(ctx); !errors.Is(err, sessiond.ErrPasskeysOff) {
		t.Errorf("AssertBegin: %v", err)
	}
	if _, _, err := e.svc.RegisterBegin(ctx, testTenant, "alice", "workforce/alice", e.grant()); !errors.Is(err, sessiond.ErrPasskeysOff) {
		t.Errorf("RegisterBegin: %v", err)
	}
	e.store.put("front-host", "", "default", &configv2alpha1.FrontHost{RpId: passkeyRPID, RpName: "x", Origins: []string{passkeyOrigin}})
	if _, _, err := e.svc.AssertBegin(ctx); !errors.Is(err, sessiond.ErrPasskeysOff) {
		t.Errorf("with a FrontHost and no SignInMethods: %v", err)
	}
	if len(e.store.absentGets) != 0 {
		t.Errorf("absent Gets: %v", e.store.absentGets)
	}
}

// A ceremony ends after five minutes, is for its own kind, and is not a ceremony if it was altered.
func TestACeremonyExpiresAndIsOfItsOwnKind(t *testing.T) {
	e := passkeyEnv(t)
	k := newSoftKey(t, 32, false)
	e.mustRegister(k, "alice")
	k.origin = passkeyOrigin
	opts, sealed, _ := e.svc.AssertBegin(ctx)
	body := k.Get(opts)
	e.clk.advance(5*time.Minute + time.Second)
	if _, err := e.svc.AssertFinish(ctx, testTenant, sealed, body, e.grant()); !errors.Is(err, sessiond.ErrPasskeyExpired) {
		t.Errorf("a late response: %v", err)
	}
	// An assertion ceremony does not finish a registration, and the reverse.
	e.addPerson("bob")
	ropts, rsealed, _ := e.svc.RegisterBegin(ctx, testTenant, "bob", "workforce/bob", e.grant())
	if _, err := e.svc.AssertFinish(ctx, testTenant, rsealed, k.Get(ropts), e.grant()); !errors.Is(err, sessiond.ErrPasskeyExpired) {
		t.Errorf("a registration ceremony finishing an assertion: %v", err)
	}
	_, asealed, _ := e.svc.AssertBegin(ctx)
	k2 := newSoftKey(t, 32, false)
	k2.origin = passkeyOrigin
	if _, err := e.svc.RegisterFinish(ctx, testTenant, asealed, k2.Create(ropts), e.grant()); !errors.Is(err, sessiond.ErrPasskeyExpired) {
		t.Errorf("an assertion ceremony finishing a registration: %v", err)
	}
	// An altered, an empty and a truncated ceremony.
	for _, bad := range [][]byte{nil, []byte("x"), append([]byte{}, asealed[:len(asealed)-1]...), append(append([]byte{}, asealed[:len(asealed)-2]...), 'a', 'b')} {
		if _, err := e.svc.AssertFinish(ctx, testTenant, bad, body, e.grant()); !errors.Is(err, sessiond.ErrPasskeyExpired) {
			t.Errorf("a bad ceremony %q: %v", bad, err)
		}
	}
}

// Another boundary's session does not accept a response made over the challenge of this one, even for a credential it
// knows: the challenge is issued and held by each verifier (REQ-ISO-033, T-5).
//
// verifies: REQ-ISO-033
func TestAResponseOverAnotherVerifiersChallengeIsRefused(t *testing.T) {
	front, prod := passkeyEnv(t), passkeyEnv(t)
	k := newSoftKey(t, 32, false)
	front.mustRegister(k, "alice")
	// The same authenticator is known at the other boundary under its own registration.
	prod.addPerson("alice")
	k.origin = passkeyOrigin
	ropts, rsealed, _ := prod.svc.RegisterBegin(ctx, testTenant, "alice", "workforce/alice", prod.grant())
	if _, err := prod.svc.RegisterFinish(ctx, testTenant, rsealed, k.Create(ropts), prod.grant()); err != nil {
		t.Fatal(err)
	}
	fopts, _, _ := front.svc.AssertBegin(ctx)
	popts, psealed, _ := prod.svc.AssertBegin(ctx)
	if parseOptions(t, fopts).Challenge == parseOptions(t, popts).Challenge {
		t.Fatal("two verifiers issued one challenge")
	}
	if _, err := prod.svc.AssertFinish(ctx, testTenant, psealed, k.Get(fopts), prod.grant()); !errors.Is(err, sessiond.ErrPasskeyResp) {
		t.Errorf("an assertion over the front's challenge at the other boundary: %v", err)
	}
}

// The library's refusal reaches the caller as one closed error, never a value of the response.
func TestAMalformedResponseIsRefusedWithoutItsValue(t *testing.T) {
	e := passkeyEnv(t)
	k := newSoftKey(t, 32, false)
	e.mustRegister(k, "alice")
	for _, body := range []string{"", "{", "null", `{"id":"x"}`, strings.Repeat("a", 9000), `{"id":"a","rawId":"a","type":"public-key","response":{}}`} {
		_, sealed, _ := e.svc.AssertBegin(ctx)
		_, err := e.svc.AssertFinish(ctx, testTenant, sealed, []byte(body), e.grant())
		if err == nil || strings.Contains(err.Error(), "aaaa") {
			t.Errorf("body %.20q: %v", body, err)
		}
	}
}
