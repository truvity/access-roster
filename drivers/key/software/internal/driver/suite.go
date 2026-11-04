package driver

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"

	"connectrpc.com/connect"

	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// Case is one case of the port suite.
type Case struct {
	Name string
	Run  func(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error
}

// Conformance runs the port suite against the driver on socket and writes one line for each case to out. The
// caller must be the owner of the driver. The suite makes the keys of the purposes token-signing and wrapping
// when they are absent, so a run belongs on a state directory that is not an installation's.
func Conformance(ctx context.Context, socket string, out io.Writer) error {
	hc, url := rpc.Dial(socket)
	c := keystorev2alpha1connect.NewKeyStoreServiceClient(hc, url, rpc.ClientOptions()...)
	return RunCases(ctx, c, Suite(), out)
}

// RunCases runs the cases in order. A suite in which no case ran fails: a green result that tested nothing is not
// green. A failed case fails the run, and the run goes on so that the report is complete.
func RunCases(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient, cases []Case, out io.Writer) error {
	if len(cases) == 0 {
		return cli.Refused("no case ran")
	}
	var failed []string
	for _, tc := range cases {
		if err := tc.Run(ctx, c); err != nil {
			_, _ = fmt.Fprintf(out, "FAIL %s: %v\n", tc.Name, err)
			failed = append(failed, tc.Name)
			continue
		}
		_, _ = fmt.Fprintf(out, "ok   %s\n", tc.Name)
	}
	_, _ = fmt.Fprintf(out, "%d cases, %d failed\n", len(cases), len(failed))
	if len(failed) > 0 {
		return cli.Refused(failed...)
	}
	return nil
}

// Suite returns the cases of the key-store port.
func Suite() []Case {
	return []Case{
		{"capabilities", caseCapabilities},
		{"ensure, sign and verify", caseSign},
		{"public key", casePublicKey},
		{"ecdh against a reference", caseEcdh},
		{"unknown purpose is refused", caseUnknownPurpose},
		{"unknown algorithm is refused", caseUnknownAlgorithm},
	}
}

func caseCapabilities(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	res, err := c.Capabilities(ctx, connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil {
		return err
	}
	if res.Msg.GetStore() != "software" || res.Msg.GetAttests() ||
		!slices.Equal(res.Msg.GetAlgorithms(), []string{"ES384", "ECDH-P384"}) {
		return errors.New("capabilities differ from software, no attestation, ES384 and ECDH-P384")
	}
	return nil
}

func caseSign(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	first, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "ES384"}))
	if err != nil {
		return err
	}
	again, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "ES384"}))
	if err != nil {
		return err
	}
	if again.Msg.GetCreated() || !bytes.Equal(first.Msg.GetSpkiDer(), again.Msg.GetSpkiDer()) {
		return errors.New("a second Ensure made a key or returned another public key")
	}
	pub, err := parseECDSA(again.Msg.GetSpkiDer())
	if err != nil {
		return err
	}
	digest := sha512.Sum384([]byte("sluis key-store suite"))
	sig, err := c.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "token-signing", Digest: digest[:], Algorithm: "ES384"}))
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig.Msg.GetSignatureDer()) {
		return errors.New("the signature does not verify with the public key")
	}
	_, err = c.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "token-signing", Digest: digest[:47], Algorithm: "ES384"}))
	return wantRefusal(err, connect.CodeInvalidArgument, "digest")
}

func casePublicKey(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	ens, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "ES384"}))
	if err != nil {
		return err
	}
	res, err := c.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: "token-signing"}))
	if err != nil {
		return err
	}
	if !bytes.Equal(ens.Msg.GetSpkiDer(), res.Msg.GetSpkiDer()) {
		return errors.New("PublicKey differs from Ensure")
	}
	return nil
}

func caseEcdh(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	ens, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "wrapping", Algorithm: "ECDH-P384"}))
	if err != nil {
		return err
	}
	pub, err := parseECDSA(ens.Msg.GetSpkiDer())
	if err != nil {
		return err
	}
	driverPub, err := pub.ECDH()
	if err != nil {
		return err
	}
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	want, err := eph.ECDH(driverPub)
	if err != nil {
		return err
	}
	res, err := c.Ecdh(ctx, connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: "wrapping", PeerPublic: eph.PublicKey().Bytes()}))
	if err != nil {
		return err
	}
	if !bytes.Equal(want, res.Msg.GetSharedSecret()) {
		return errors.New("the shared secret differs from the reference computation")
	}
	off := bytes.Clone(eph.PublicKey().Bytes())
	off[len(off)-1] ^= 0x01 // a point off the curve
	_, err = c.Ecdh(ctx, connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: "wrapping", PeerPublic: off}))
	return wantRefusal(err, connect.CodeInvalidArgument, "peer_public")
}

func caseUnknownPurpose(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	_, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "no-such-purpose", Algorithm: "ES384"}))
	return wantRefusal(err, connect.CodeInvalidArgument, reasonPurpose)
}

func caseUnknownAlgorithm(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	_, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "RS256"}))
	return wantRefusal(err, connect.CodeInvalidArgument, reasonAlgorithm)
}

// wantRefusal is nil when err is the refusal with the code and reason, and an error that says what came instead.
func wantRefusal(err error, code connect.Code, reason string) error {
	if err == nil {
		return fmt.Errorf("want %s/%s, got success", code, reason)
	}
	if got := connect.CodeOf(err); got != code {
		return fmt.Errorf("want code %s, got %s", code, got)
	}
	if got, _ := refusal.Reason(err); got != reason {
		return fmt.Errorf("want reason %q, got %q", reason, got)
	}
	return nil
}

func parseECDSA(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("the public key is not SubjectPublicKeyInfo in DER")
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-384" {
		return nil, errors.New("the public key is not a P-384 key")
	}
	return pub, nil
}
