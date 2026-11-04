package sessiond

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// errNotOurs says an envelope did not open: a forged, altered, expired-key or foreign cookie or sealed value. key@
// gives one answer for every cause (permission_denied, reason open), so the caller cannot tell which.
var errNotOurs = errors.New("sessiond: the sealed value does not open")

// keys is session's use of key@. Every call is a Connect call on the socket key@ opens for session alone.
type keys struct {
	c keyv2alpha1connect.KeyServiceClient
}

// The labels session gives to Mac (0006 "Sign and Mac": a label separates two uses of one purpose).
const (
	labelUpstreamLink = "sluis-upstream-link-v1"
	labelPairwise     = "pairwise"
)

// mac is a keyed hash with HMAC-SHA384 at key@. purpose is "mac" (the boundary's key, tenant "") or "pairwise" (a
// tenant's).
func (k keys) mac(ctx context.Context, purpose, tenant, label string, input []byte) ([]byte, error) {
	res, err := k.c.Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: purpose, Tenant: tenant, Label: label, Input: input}))
	if err != nil {
		return nil, fmt.Errorf("key mac %s: %w", purpose, err)
	}
	if len(res.Msg.GetMac()) < 32 {
		return nil, refusal.New(connect.CodeInternal, "mac", "mac")
	}
	return res.Msg.GetMac(), nil
}

// linkID is the id of an UpstreamLink: a keyed hash of the issuer, the claim name and the claim value, made over the
// boundary's mac key (0019 "Linking an upstream account"). The id holds no personal data, and session never holds
// the key. It is 256 bits in lower-case base32, 52 characters.
func (k keys) linkID(ctx context.Context, issuer, claim, value string) (string, error) {
	m, err := k.mac(ctx, "mac", "", labelUpstreamLink, lengthPrefixed(issuer, claim, value))
	if err != nil {
		return "", err
	}
	return lowerBase32(m[:32]), nil
}

// flowAddress is the address a short-lived piece of sign-in state is sealed to. The cookie key is the boundary's, so
// the tenant of the address is empty (tenant "-" in the text form). The kind and the id bind the envelope to one
// item: an envelope cut out of one cookie or code does not open as another.
func flowAddress(kind, id string) *typev2alpha1.Address {
	return &typev2alpha1.Address{Kind: kind, Id: id}
}

// sealFlow seals the message under the boundary's cookie key. It is for state that exists before any person is
// decided, or that policy needs in order to decide: key@ checks the cookie purpose by rule only, with no grant (D-5),
// because a tenant's data key would need the decision these facts are for.
func (k keys) sealFlow(ctx context.Context, kind, id string, m proto.Message) ([]byte, error) {
	pt, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, refusal.New(connect.CodeInternal, "schema", "value")
	}
	res, err := k.c.Seal(ctx, connect.NewRequest(&keyv2alpha1.SealRequest{Purpose: "cookie", Address: flowAddress(kind, id), Plaintext: pt}))
	clear(pt)
	if err != nil {
		return nil, fmt.Errorf("key seal cookie: %w", err)
	}
	return res.Msg.GetEnvelope(), nil
}

// openFlow opens an envelope made by sealFlow into m. errNotOurs says it did not open; any other error is key@
// unavailable.
func (k keys) openFlow(ctx context.Context, kind, id string, envelope []byte, m proto.Message) error {
	res, err := k.c.Open(ctx, connect.NewRequest(&keyv2alpha1.OpenRequest{Items: []*keyv2alpha1.OpenItem{{
		Purpose: "cookie", Address: flowAddress(kind, id), Envelope: envelope,
	}}}))
	if err != nil {
		return openError(err)
	}
	if len(res.Msg.GetPlaintexts()) != 1 {
		return errNotOurs
	}
	pt := res.Msg.GetPlaintexts()[0]
	defer clear(pt)
	if err := proto.Unmarshal(pt, m); err != nil {
		return errNotOurs
	}
	return nil
}

// sealData seals the message under the tenant's data key. key@ requires the sealed grant of the decision that allows
// the write (D-5: a tenant purpose on a tenant address).
func (k keys) sealData(ctx context.Context, kind, tenant, id string, m proto.Message, grant []byte) ([]byte, error) {
	pt, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, refusal.New(connect.CodeInternal, "schema", "value")
	}
	res, err := k.c.Seal(ctx, connect.NewRequest(&keyv2alpha1.SealRequest{
		Purpose: "data", Address: &typev2alpha1.Address{Kind: kind, Tenant: tenant, Id: id}, Plaintext: pt, Grant: grant,
	}))
	clear(pt)
	if err != nil {
		return nil, fmt.Errorf("key seal data: %w", err)
	}
	return res.Msg.GetEnvelope(), nil
}

// openData opens an envelope that store@ holds for a sealed kind.
func (k keys) openData(ctx context.Context, kind, tenant, id string, envelope []byte, m proto.Message, grant []byte) error {
	res, err := k.c.Open(ctx, connect.NewRequest(&keyv2alpha1.OpenRequest{Items: []*keyv2alpha1.OpenItem{{
		Purpose: "data", Address: &typev2alpha1.Address{Kind: kind, Tenant: tenant, Id: id}, Envelope: envelope,
	}}, Grant: grant}))
	if err != nil {
		return openError(err)
	}
	if len(res.Msg.GetPlaintexts()) != 1 {
		return errNotOurs
	}
	pt := res.Msg.GetPlaintexts()[0]
	defer clear(pt)
	if err := proto.Unmarshal(pt, m); err != nil {
		return errNotOurs
	}
	return nil
}

// openError maps the refusal of Open: reason "open" is a value that is not ours, anything else is key@ failing.
func openError(err error) error {
	if r, ok := refusal.Reason(err); ok && r == "open" && connect.CodeOf(err) == connect.CodePermissionDenied {
		return errNotOurs
	}
	return fmt.Errorf("key open: %w", err)
}
