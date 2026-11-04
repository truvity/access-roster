package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// The steps run inside a container that has the uid of one actor of the installation and only the sockets that actor
// may reach (PLAN.md "Socket layout"). Each prints one JSON object on standard output and nothing else; the host
// side of the smoke prints what a person reads. No step prints a secret: not the grant, not the signature.

// runDir is where the sockets are mounted in a step's container (the same paths the actors use).
const runDir = "/run/sluis"

func sockets(boundary string) map[string]string {
	return map[string]string{
		"policy": filepath.Join(runDir, "policy", boundary+".sock"),
		"signer": filepath.Join(runDir, "signer", boundary+".sock"),
		"store":  filepath.Join(runDir, "store", boundary+".sock"),
		"key":    filepath.Join(runDir, "key", boundary, "key.sock"),
	}
}

// runStep dispatches `spine step <name> ...` and prints its result.
func runStep(args []string) error {
	if len(args) == 0 {
		return errors.New("step: a name is required")
	}
	name, rest := args[0], args[1:]
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	boundary := fs.String("boundary", "dev", "the boundary")
	tenant := fs.String("tenant", "", "the tenant")
	issuer := fs.String("issuer", "", "the issuer URL")
	audience := fs.String("audience", "", "the client id the token is for")
	correlation := fs.String("correlation", "", "the correlation id of the calls")
	kind := fs.String("kind", "", "the kind to read")
	blob := fs.String("blob", "", "the directory of the log")
	logOrigin := fs.String("project", "sluis", "the project of the log")
	decisionID := fs.String("decision-id", "", "the decision to look for")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctx = rpc.WithCorrelationID(ctx, *correlation)
	sk := sockets(*boundary)

	var out any
	var err error
	switch name {
	case "decide-sign":
		out, err = decideAndSign(ctx, sk, *tenant, *issuer, *audience)
	case "store-read":
		out, err = storeRead(ctx, sk["store"], *kind, *tenant)
	case "audit-find":
		out, err = auditFind(ctx, sk, *boundary, *blob, *logOrigin, *decisionID, *correlation)
	default:
		return fmt.Errorf("step: unknown step %q", name)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// describe turns a Connect error into a line that has a reason and a path and never a value.
func describe(what string, err error) error {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return fmt.Errorf("%s: %w", what, err)
	}
	reason, _ := refusal.Reason(err)
	path, _ := refusal.FieldPath(err)
	return fmt.Errorf("%s: %s, reason %q, field %q", what, cerr.Code(), reason, path)
}

// decideOut is what the exchange step reports of the decision and of the token.
type decideOut struct {
	Decision      string   `json:"decision"`
	GrantNames    []string `json:"grant_names"`
	PolicyIDs     []string `json:"policy_ids"`
	DecisionID    string   `json:"decision_id"`
	Digest        string   `json:"digest"`
	SealedGrant   int      `json:"sealed_grant_bytes"`
	Token         string   `json:"token"`
	KeyID         string   `json:"key_id"`
	CorrelationID string   `json:"correlation_id"`
}

// decideAndSign is the harness client of M1: running under the uid of exchange, it asks policy for a token.exchange
// decision for a person of the local installation, and then asks signer for an access token that carries the grant
// names policy found (ADR 0020 "The claims of a token").
func decideAndSign(ctx context.Context, sk map[string]string, tenant, issuer, audience string) (*decideOut, error) {
	hc, url := rpc.Dial(sk["policy"])
	pol := policyv2alpha1connect.NewPolicyServiceClient(hc, url, rpc.ClientOptions()...)
	const subject = "p-alice"
	res, err := pol.Decide(ctx, connect.NewRequest(&policyv2alpha1.DecideRequest{
		Action:    "token.exchange",
		Principal: &policyv2alpha1.EntityRef{Type: "Person", Id: subject},
		Resource:  &policyv2alpha1.EntityRef{Type: "Client", Id: audience},
		Tenant:    tenant,
		// The person signed in with a second factor a minute ago (policy.md "Context").
		Context: &policyv2alpha1.Authentication{Amr: []string{"pwd", "mfa"}, AmrPresent: true, AuthAge: proto.Int64(60)},
		// The account is bound to dev:example-app:user by tests/installations/local/config/policy.cedar.
		Person: &policyv2alpha1.PersonFacts{Subject: subject, Accounts: []string{"workforce/u-1001"}, State: "live", Org: tenant},
		Client: &policyv2alpha1.ClientFacts{Id: audience, Requires: []string{"dev:example-app:user"}, Kind: "public"},
		// What an exchange needs of its grant: policy narrows to what the action allows and never widens.
		GrantStoreVerbs: []string{"get", "list"},
		GrantKeyOps:     []string{"seal", "open"},
	}))
	if err != nil {
		return nil, describe("policy Decide", err)
	}
	d := res.Msg
	out := &decideOut{
		Decision:      d.GetDecision().String(),
		GrantNames:    d.GetGrantNames(),
		DecisionID:    d.GetDecisionId(),
		Digest:        d.GetDigest(),
		SealedGrant:   len(d.GetSealedGrant()),
		CorrelationID: rpc.CorrelationID(ctx),
	}
	for _, r := range d.GetReasons() {
		out.PolicyIDs = append(out.PolicyIDs, r.GetPolicyId())
	}
	if d.GetDecision() != policyv2alpha1.Decision_ALLOW {
		return out, nil // the host side refuses with the answer it printed
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": issuer, "sub": subject, "aud": audience, "client_id": audience,
		"iat": now, "exp": now + 300, "jti": uuid4(), "groups": d.GetGrantNames(),
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	hc, url = rpc.Dial(sk["signer"])
	sg := signerv2alpha1connect.NewSignerServiceClient(hc, url, rpc.ClientOptions()...)
	st, err := sg.SignToken(ctx, connect.NewRequest(&signerv2alpha1.SignTokenRequest{Typ: "at+jwt", ClaimsJson: cj}))
	if err != nil {
		return nil, describe("signer SignToken", err)
	}
	out.Token, out.KeyID = st.Msg.GetToken(), st.Msg.GetKeyId()
	return out, nil
}

// uuid4 is a random identifier for the jti claim (RFC 7519 section 4.1.7).
func uuid4() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on the supported systems
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// itemOut is one item as a step reports it: where it is and how it changed, never its value.
type itemOut struct {
	ID      string   `json:"id"`
	Version uint64   `json:"version"`
	Detail  []string `json:"detail,omitempty"`
}

type readOut struct {
	Kind  string    `json:"kind"`
	Items []itemOut `json:"items"`
}

// storeRead reads a kind through store@ with the uid of the container, which store@ checks against the rule of the
// kind (kinds.yaml readers). The value is decoded only to report names and counts.
func storeRead(ctx context.Context, socket, kind, tenant string) (*readOut, error) {
	hc, url := rpc.Dial(socket)
	c := storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...)
	out := &readOut{Kind: kind}
	switch kind {
	case "signing-ring":
		res, err := c.Get(ctx, connect.NewRequest(&storev2alpha1.GetRequest{Address: &typev2alpha1.Address{Kind: kind, Id: "default"}}))
		if err != nil {
			return nil, describe("store Get "+kind, err)
		}
		it := res.Msg.GetItem()
		var ring signerv2alpha1.SigningRing
		if err := proto.Unmarshal(it.GetValue(), &ring); err != nil {
			return nil, fmt.Errorf("store Get %s: the value is not a SigningRing", kind)
		}
		o := itemOut{ID: it.GetAddress().GetId(), Version: it.GetVersion()}
		for _, k := range ring.GetKeys() {
			o.Detail = append(o.Detail, k.GetKeyId()+" "+k.GetAlgorithm()+" "+k.GetState())
		}
		out.Items = append(out.Items, o)
	case "data-key-wrap":
		var token string
		for {
			res, err := c.List(ctx, connect.NewRequest(&storev2alpha1.ListRequest{Kind: kind, Tenant: tenant, PageSize: 100, PageToken: token}))
			if err != nil {
				return nil, describe("store List "+kind, err)
			}
			for _, it := range res.Msg.GetItems() {
				out.Items = append(out.Items, itemOut{ID: it.GetAddress().GetId(), Version: it.GetVersion()})
			}
			if token = res.Msg.GetNextPageToken(); token == "" {
				break
			}
		}
		sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
	default:
		return nil, fmt.Errorf("store-read: kind %q is not one this smoke reads", kind)
	}
	return out, nil
}

// readFile reads a file of the log below the limit of one entry bundle.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the smoke names the log directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, 1<<25))
}

// foundEntry is what the smoke learned of one record of the log by opening it.
type foundEntry struct {
	Event       string `json:"event"`
	Actor       string `json:"actor"`
	Status      string `json:"status,omitempty"`
	Correlation string `json:"correlation,omitempty"`
	DecisionID  string `json:"decision_id,omitempty"`
}

type auditOut struct {
	Size    int64        `json:"size"`
	Records int          `json:"records"`
	Found   []foundEntry `json:"found"`
}

// complete reports whether every record the M1 spine must have written is there.
func (a auditOut) complete() bool {
	for _, w := range wanted {
		ok := false
		for _, f := range a.Found {
			ok = ok || f.Event == w
		}
		if !ok {
			return false
		}
	}
	return true
}

// auditFind reads the entries of the log, opens the records under the evidence key as the indexer does (policy gives
// the indexer an audit.index grant by a built-in permit, and key@ opens it for the indexer; the local config binds no
// reader to audit.read, so the indexer is the one opener of evidence the installation allows), and reports the records of this run: those that carry the correlation
// id of the client's calls, and the policy decision with its decision id.
func auditFind(ctx context.Context, sk map[string]string, boundary, blob, project, decisionID, correlation string) (*auditOut, error) {
	hc, url := rpc.Dial(sk["policy"])
	pol := policyv2alpha1connect.NewPolicyServiceClient(hc, url, rpc.ClientOptions()...)
	res, err := pol.Decide(ctx, connect.NewRequest(&policyv2alpha1.DecideRequest{
		Action:      "audit.index",
		Principal:   &policyv2alpha1.EntityRef{Type: "Actor", Id: "indexer"},
		Resource:    &policyv2alpha1.EntityRef{Type: "Boundary", Id: boundary},
		Tenant:      "*",
		Actor:       &policyv2alpha1.ActorFacts{Name: "indexer"},
		GrantKeyOps: []string{"open"},
	}))
	if err != nil {
		return nil, describe("policy Decide audit.index", err)
	}
	if res.Msg.GetDecision() != policyv2alpha1.Decision_ALLOW || len(res.Msg.GetSealedGrant()) == 0 {
		return nil, errors.New("policy gave the indexer no grant to open audit records")
	}
	grant := res.Msg.GetSealedGrant()
	hc, url = rpc.Dial(sk["key"])
	kc := keyv2alpha1connect.NewKeyServiceClient(hc, url, rpc.ClientOptions()...)

	out, err := scanLog(ctx, kc, grant, blob, project, decisionID, correlation)
	if err != nil {
		return nil, err
	}
	return out.out, nil
}

// scan is one pass over the log.
type scan struct {
	out *auditOut
	has map[string]bool
}

// wanted are the records the M1 spine must have written: the policy decision, the signer's sign, and key@'s sign for
// the signer's call (PLAN.md §2, "M1": every step is audited).
var wanted = []string{"policy.decide", "signer.sign", "key.sign"}

func scanLog(ctx context.Context, kc keyv2alpha1connect.KeyServiceClient, grant []byte, blob, project, decisionID, correlation string) (*scan, error) {
	s := &scan{out: &auditOut{}, has: map[string]bool{}}
	head, err := readFile(filepath.Join(blob, "checkpoint"))
	if err != nil {
		return nil, fmt.Errorf("the log has no checkpoint yet: %w", err)
	}
	// A checkpoint is origin, size and root hash, one to a line (C2SP tlog-checkpoint); the signature is the CLI's to
	// verify, this pass only needs the size.
	lines := strings.Split(string(head), "\n")
	if len(lines) < 3 {
		return nil, errors.New("the checkpoint is not a checkpoint")
	}
	if _, err := fmt.Sscanf(lines[1], "%d", &s.out.Size); err != nil {
		return nil, errors.New("the checkpoint has no size")
	}
	entries, err := readEntries(blob, s.out.Size)
	if err != nil {
		return nil, err
	}
	for _, raw := range entries {
		var e struct {
			Entry    string `json:"entry"`
			Sealed   string `json:"sealed"`
			Metadata struct {
				UID    string `json:"uid"`
				Tenant string `json:"tenant_uid"`
			} `json:"metadata"`
		}
		if json.Unmarshal(raw, &e) != nil || e.Entry != "record" {
			continue
		}
		s.out.Records++
		env, err := base64.StdEncoding.DecodeString(e.Sealed)
		if err != nil {
			return nil, errors.New("an entry's sealed record is not base64")
		}
		// The address is the one the writer sealed at (writerd.SealID): <project>/audit/main/<record id>.
		res, err := kc.Open(ctx, connect.NewRequest(&keyv2alpha1.OpenRequest{
			Items: []*keyv2alpha1.OpenItem{{
				Purpose:  "evidence",
				Address:  &typev2alpha1.Address{Kind: "audit-entry", Tenant: e.Metadata.Tenant, Id: project + "/audit/main/" + e.Metadata.UID},
				Envelope: env,
			}},
			Grant: grant,
		}))
		if err != nil {
			return nil, describe("key Open", err)
		}
		var rec struct {
			Metadata struct {
				EventCode   string `json:"event_code"`
				Correlation string `json:"correlation_uid"`
			} `json:"metadata"`
			Actor struct {
				User struct {
					UID string `json:"uid"`
				} `json:"user"`
			} `json:"actor"`
			Status string `json:"status"`
			Policy struct {
				UID string `json:"uid"`
			} `json:"policy"`
		}
		if json.Unmarshal(res.Msg.GetPlaintexts()[0], &rec) != nil {
			return nil, errors.New("an opened record is not JSON")
		}
		ev := rec.Metadata.EventCode
		mine := correlation != "" && rec.Metadata.Correlation == correlation
		if ev == "policy.decide" && decisionID != "" && rec.Policy.UID == decisionID {
			mine = true
		}
		if !mine {
			continue
		}
		s.has[ev] = true
		s.out.Found = append(s.out.Found, foundEntry{Event: ev, Actor: rec.Actor.User.UID, Status: rec.Status, Correlation: rec.Metadata.Correlation, DecisionID: rec.Policy.UID})
	}
	return s, nil
}
