//go:build sluis_test

package keyd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/base64"
	"slices"
	"sort"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// verifies: REQ-KEYS-063
// The issuance log of ca is signed with the issuance-log key purpose, a P-384 key that exists in a boundary whose
// KeyPlan enables it (the boundary that runs ca) and in no other. The boundary without it has no key for the purpose:
// the public key and a signature are refused as a purpose with no key, and the driver holds the baseline keys and no
// more. The boundary with it has a P-384 key of its own, distinct from the audit-log key (P-256) and from the
// token-signing key, that signs a checkpoint body of the log as ES384 over SHA-384, signs nothing that is not a
// checkpoint, and is open to the writer, which holds the log, and to no actor that has no rule for it.
func TestTheIssuanceLogKeyExistsOnlyWhereTheKeyPlanEnablesIt(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := []byte("example.com/issuance-log\n12\n" + root + "\n")

	without := newTestEnv(t, "development")
	a, _ := without.spiedNode("node-1")
	baseline := []string{"audit-log", "token-signing", "wrapping"}
	if got := driverPurposes(a.driver); !slices.Equal(got, baseline) {
		t.Fatalf("a boundary without ca holds %v, want %v", got, baseline)
	}
	_, err := a.client("writer").PublicKey(t.Context(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "issuance-log"}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "purpose")
	_, err = a.client("writer").Sign(t.Context(), signReq("issuance-log", body))
	wantRefusal(t, err, connect.CodeInvalidArgument, "purpose")

	with := newTestEnv(t, "development")
	plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
	plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "issuance-log", Algorithm: "ES384", Slot: "88"})
	with.putPlan(plan)
	b, _ := with.spiedNode("node-1")
	want := append(slices.Clone(baseline), "issuance-log")
	sort.Strings(want)
	if got := driverPurposes(b.driver); !slices.Equal(got, want) {
		t.Fatalf("a boundary with ca holds %v, want %v", got, want)
	}
	pub, kid := publicKey(t, b, "writer", "issuance-log")
	if pub.Curve != elliptic.P384() {
		t.Fatalf("the issuance-log key is on %s, want P-384", pub.Curve.Params().Name)
	}
	if auditPub, auditKid := publicKey(t, b, "writer", "audit-log"); auditKid == kid || auditPub.Equal(pub) {
		t.Fatal("the issuance-log key is the audit-log key")
	}
	res, err := b.client("writer").Sign(t.Context(), signReq("issuance-log", body))
	if err != nil {
		t.Fatalf("Sign of a checkpoint with the issuance-log key: %v", err)
	}
	digest := sha512.Sum384(body)
	if !ecdsa.VerifyASN1(pub, digest[:], res.Msg.GetSignatureDer()) || res.Msg.GetKeyId() != kid || len(res.Msg.GetSignatureRaw()) != 96 {
		t.Fatal("the issuance-log signature does not verify as ES384 over the body")
	}
	// It signs a checkpoint and nothing else, and ES256 is not its algorithm.
	for _, bad := range [][]byte{[]byte("hello"), tokenInput(kid, "", ""), []byte("x\n7\nAAAA\n")} {
		_, err := b.client("writer").Sign(t.Context(), signReq("issuance-log", bad))
		wantRefusal(t, err, connect.CodeInvalidArgument, "content")
	}
	_, err = b.client("writer").Sign(t.Context(), connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: "issuance-log", Content: body, Algorithm: "ES256"}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "algorithm")
	// An actor with no rule for the purpose cannot use it.
	for _, actor := range []string{"signer", "session", "exchange"} {
		_, err := b.client(actor).Sign(t.Context(), signReq("issuance-log", body))
		wantRefusalNamed(t, actor+" signs with the issuance-log key", err, connect.CodePermissionDenied, "rule")
	}
}
