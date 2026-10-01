package access_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/access"
)

// The owner a flow will record is chosen where the flow begins and rides in
// the signed state to the callback that creates the record.
func TestAStateCarriesTheOwnerTheFlowWillRecord(t *testing.T) {
	t.Parallel()
	codec := access.NewStateCodec([]byte("a-test-key-for-signing-state"), time.Minute)
	state, err := codec.IssueAs(access.Binding{Bind: "github:globex", Actor: "ada@example.com", Owner: "C0north"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := codec.VerifyBinding(state)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bind != "github:globex" || got.Actor != "ada@example.com" || got.Owner != "C0north" {
		t.Errorf("binding = %+v", got)
	}
	// A browser cannot change the owner on the way: the state is signed.
	body, signature, _ := strings.Cut(state, ".")
	parts := strings.Split(body, ":")
	parts[3] = base64.RawURLEncoding.EncodeToString([]byte("C0south"))
	if _, err = codec.VerifyBinding(strings.Join(parts, ":") + "." + signature); err == nil {
		t.Error("a state with another owner verified")
	}
	// An empty owner is "none", and reads back as none.
	state, _ = codec.IssueAs(access.Binding{Bind: "github:globex", Actor: "ada@example.com"})
	if got, err = codec.VerifyBinding(state); err != nil || got.Owner != "" {
		t.Errorf("binding = %+v, %v", got, err)
	}
}

// A state issued before owners were carried (four parts) still verifies, as
// one with no owner: a flow begun just before a rollout is not stranded.
func TestAStateIssuedBeforeOwnersWereCarriedStillVerifies(t *testing.T) {
	t.Parallel()
	key := []byte("a-test-key-for-signing-state")
	codec := access.NewStateCodec(key, time.Minute)
	body := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte("nonce")),
		base64.RawURLEncoding.EncodeToString([]byte("github:globex")),
		base64.RawURLEncoding.EncodeToString([]byte("ada@example.com")),
		strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10),
	}, ":")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	legacy := body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	got, err := codec.VerifyBinding(legacy)
	if err != nil {
		t.Fatalf("a four-part state: %v", err)
	}
	if got.Bind != "github:globex" || got.Actor != "ada@example.com" || got.Owner != "" {
		t.Errorf("binding = %+v", got)
	}
}
