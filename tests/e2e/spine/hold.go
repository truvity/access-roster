package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// A hold on the persons of the installation, for the browser test of the passkeys (tests/e2e/passkey). An operator holds a
// person by a PersonHold that the console routes to session; the first version has no console, so the test does what the
// console would: a harness client under the uid of session asks policy for a grant, seals the hold under the tenant's data
// key at key@ and creates it through store@. It is test code, run in a container with the sockets session may reach, and it
// writes kinds that session writes. `spine hold` holds every person of the tenant, `spine unhold` lifts the holds, and a test that
// holds must lift them: a hold left behind refuses every later sign-in. `spine forget` deletes EVERY passkey of the tenant, the ones a test did not make as well; a test that
// registers passkeys runs it before and after, and says how many it found at the start.

// holdSpec is the identity and the mounts of the container: the uid of session and the sockets it reaches.
func holdSpec() spec {
	return spec{user: "session", groups: []string{"policy", "store", ownKeyDir},
		mounts: []string{"run-policy:/run/sluis/policy", "run-store:/run/sluis/store", "key-session:/run/sluis/key/" + boundary}}
}

// holdMain is `spine hold` and `spine unhold`: it prints the number of holds it placed or lifted.
func holdMain(command string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := requireHealthy(); err != nil {
		return err
	}
	d := &docker{self: self}
	args := []string{"--boundary", boundary, "--tenant", tenant}
	step, noun := "hold-persons", "persons"
	verb := "held"
	switch command {
	case "unhold":
		args = append(args, "--release")
		verb = "released"
	case "forget":
		step, noun, verb = "forget-passkeys", "passkeys", "deleted"
	}
	var out holdOut
	if err := d.step(&out, holdSpec(), step, args...); err != nil {
		return err
	}
	fmt.Printf("%s %d %s of the tenant %s\n", verb, out.Count, noun, tenant)
	return nil
}

// holdOut is what the step reports: how many holds it made or lifted, never a subject.
type holdOut struct {
	Count int `json:"count"`
}

// grantFor asks policy for the decision of a sign-in, as the spine asks it (decideAndSign): the person holds the grant of the example
// application and signed in with a second factor a minute ago. What it needs of the grant is the store verbs it writes with and the
// key operations it uses.
func grantFor(ctx context.Context, sk map[string]string, tenantID string, verbs, ops []string) ([]byte, error) {
	hc, url := rpc.Dial(sk["policy"])
	pol := policyv2alpha1connect.NewPolicyServiceClient(hc, url, rpc.ClientOptions()...)
	const principal = "p-alice"
	res, err := pol.Decide(ctx, connect.NewRequest(&policyv2alpha1.DecideRequest{
		Action:    "token.issue",
		Principal: &policyv2alpha1.EntityRef{Type: "Person", Id: principal},
		Resource:  &policyv2alpha1.EntityRef{Type: "Client", Id: audience},
		Tenant:    tenantID,
		Context:   &policyv2alpha1.Authentication{Amr: []string{"pwd", "mfa"}, AmrPresent: true, AuthAge: proto.Int64(60)},
		Person:    &policyv2alpha1.PersonFacts{Subject: principal, Accounts: []string{"workforce/u-1001"}, State: "live", Org: tenantID},
		Client:    &policyv2alpha1.ClientFacts{Id: audience, Requires: []string{"dev:example-app:user"}, Kind: "public"},

		GrantStoreVerbs: verbs,
		GrantKeyOps:     ops,
	}))
	if err != nil {
		return nil, describe("policy Decide", err)
	}
	if res.Msg.GetDecision() != policyv2alpha1.Decision_ALLOW || len(res.Msg.GetSealedGrant()) == 0 {
		return nil, errors.New("policy did not allow the decision the local config allows")
	}
	return res.Msg.GetSealedGrant(), nil
}

// idsOf lists the ids of a kind in the tenant.
func idsOf(ctx context.Context, st storev2alpha1connect.StoreServiceClient, kind, tenantID string) ([]string, error) {
	var ids []string
	token := ""
	for {
		l, err := st.List(ctx, connect.NewRequest(&storev2alpha1.ListRequest{Kind: kind, Tenant: tenantID, PageSize: 100, PageToken: token}))
		if err != nil {
			return nil, describe("store List "+kind, err)
		}
		for _, it := range l.Msg.GetItems() {
			ids = append(ids, it.GetAddress().GetId())
		}
		if token = l.Msg.GetNextPageToken(); token == "" {
			break
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// holdPersons places a hold on every Person of the tenant, or lifts them (release).
func holdPersons(ctx context.Context, sk map[string]string, tenantID string, release bool) (*holdOut, error) {
	verbs := []string{"create"}
	if release {
		verbs = []string{"delete"}
	}
	grant, err := grantFor(ctx, sk, tenantID, verbs, []string{"seal"})
	if err != nil {
		return nil, err
	}
	hc, url := rpc.Dial(sk["store"])
	st := storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...)
	ids, err := idsOf(ctx, st, "person", tenantID)
	if err != nil {
		return nil, err
	}
	hc, url = rpc.Dial(sk["key"])
	kc := keyv2alpha1connect.NewKeyServiceClient(hc, url, rpc.ClientOptions()...)
	out := &holdOut{}
	for _, id := range ids {
		a := &typev2alpha1.Address{Kind: "person-hold", Tenant: tenantID, Id: id}
		op := &storev2alpha1.Operation{Address: a}
		if release {
			op.Verb = storev2alpha1.Verb_DELETE
		} else {
			s, err := kc.Seal(ctx, connect.NewRequest(&keyv2alpha1.SealRequest{Purpose: "data", Address: a, Plaintext: []byte("held for the browser test"), Grant: grant}))
			if err != nil {
				return nil, describe("key Seal", err)
			}
			op.Verb, op.Value = storev2alpha1.Verb_CREATE, s.Msg.GetEnvelope()
		}
		if _, err := st.Write(ctx, connect.NewRequest(&storev2alpha1.WriteRequest{Operations: []*storev2alpha1.Operation{op}, Grant: grant})); err != nil {
			// A hold that is not there is not an error of a release.
			if release && connect.CodeOf(err) == connect.CodeNotFound {
				continue
			}
			return nil, describe("store Write person-hold", err)
		}
		out.Count++
	}
	return out, nil
}

// forgetPasskeys deletes every StaffPasskey of the tenant, so that a browser test that registers passkeys leaves none and can run
// again (a person has at most ten).
func forgetPasskeys(ctx context.Context, sk map[string]string, tenantID string) (*holdOut, error) {
	grant, err := grantFor(ctx, sk, tenantID, []string{"delete"}, []string{"open"})
	if err != nil {
		return nil, err
	}
	hc, url := rpc.Dial(sk["store"])
	st := storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...)
	ids, err := idsOf(ctx, st, "staff-passkey", tenantID)
	if err != nil {
		return nil, err
	}
	out := &holdOut{}
	for _, id := range ids {
		op := &storev2alpha1.Operation{Verb: storev2alpha1.Verb_DELETE, Address: &typev2alpha1.Address{Kind: "staff-passkey", Tenant: tenantID, Id: id}}
		if _, err := st.Write(ctx, connect.NewRequest(&storev2alpha1.WriteRequest{Operations: []*storev2alpha1.Operation{op}, Grant: grant})); err != nil {
			return nil, describe("store Write staff-passkey", err)
		}
		out.Count++
	}
	return out, nil
}
