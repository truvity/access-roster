package driver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
// caller must be the owner of the driver, and the driver must be unlocked: a case that signs with a key that needs
// the PIN fails with the reason "locked" otherwise. In development the suite makes the keys of the slots it uses
// when they are absent, so a run belongs on a test card.
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

// Suite returns the cases of the key-store port for a card.
func Suite() []Case {
	return []Case{
		{"capabilities", caseCapabilities},
		{"ensure, sign and verify (token-signing, ES384)", caseSign384},
		{"ensure, sign and verify (audit-log, ES256)", caseSign256},
		{"ensure, sign and verify (token-signing-rs256, RS256)", caseSignRS256},
		{"the PIN release key signs no digest of the caller's", casePinRelease},
		{"public key", casePublicKey},
		{"ecdh against a reference", caseEcdh},
		{"unknown purpose is refused", caseUnknownPurpose},
		{"unknown algorithm is refused", caseUnknownAlgorithm},
		{"a digest of the wrong length is refused", caseDigest},
		{"the algorithm of another purpose is refused", caseOtherAlgorithm},
	}
}

func ensure(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient, purpose, alg string) ([]byte, error) {
	res, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
	if err != nil {
		return nil, fmt.Errorf("Ensure %s: %w", purpose, err)
	}
	return res.Msg.GetSpkiDer(), nil
}

func caseCapabilities(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	res, err := c.Capabilities(ctx, connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil {
		return err
	}
	if res.Msg.GetStore() != StoreName || !res.Msg.GetAttests() ||
		!slices.Equal(res.Msg.GetAlgorithms(), []string{ES384, ES256, RS256, ECDHP384}) {
		return errors.New("capabilities differ from yubikey-piv, attestation, ES384, ES256, RS256 and ECDH-P384")
	}
	return nil
}

func signAndVerify(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient, purpose, alg string, digest []byte) error {
	spki, err := ensure(ctx, c, purpose, alg)
	if err != nil {
		return err
	}
	again, err := ensure(ctx, c, purpose, alg)
	if err != nil {
		return err
	}
	if !bytes.Equal(spki, again) {
		return errors.New("a second Ensure returned another public key")
	}
	pub, err := parseECDSA(again)
	if err != nil {
		return err
	}
	sig, err := c.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: purpose, Digest: digest, Algorithm: alg}))
	if err != nil {
		return fmt.Errorf("Sign %s: %w", purpose, err)
	}
	if !ecdsa.VerifyASN1(pub, digest, sig.Msg.GetSignatureDer()) {
		return errors.New("the signature does not verify with the public key")
	}
	return nil
}

// caseSignRS256 makes the RSA key of the RS256 purpose (slot 88) and has it sign a SHA-256 digest: RSASSA-PKCS1-v1_5, which
// verifies with the standard library, and not PSS. It takes seconds on a real card, and a key made on one in development.
func caseSignRS256(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	spki, err := ensure(ctx, c, "token-signing-rs256", RS256)
	if err != nil {
		return err
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return errors.New("the public key is not SubjectPublicKeyInfo in DER")
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 || pub.E != 65537 {
		return errors.New("the public key is not RSA-2048 with the exponent 65537")
	}
	d := sha256.Sum256([]byte("sluis key-store suite"))
	sig, err := c.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "token-signing-rs256", Digest: d[:], Algorithm: RS256}))
	if err != nil {
		return fmt.Errorf("Sign token-signing-rs256: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig.Msg.GetSignatureDer()); err != nil {
		return errors.New("the signature does not verify as PKCS#1 v1.5 over SHA-256")
	}
	return nil
}

func caseSign384(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	d := sha512.Sum384([]byte("sluis key-store suite"))
	return signAndVerify(ctx, c, "token-signing", ES384, d[:])
}

func caseSign256(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	d := sha256.Sum256([]byte("sluis key-store suite"))
	return signAndVerify(ctx, c, "audit-log", ES256, d[:])
}

// casePinRelease: the PIN release key signs only the texts the driver writes itself (BeginPinRelease, SealPin), never
// a digest of the caller's, because it signs without the PIN.
func casePinRelease(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	if _, err := ensure(ctx, c, "pin-release", ES384); err != nil {
		return err
	}
	d := sha512.Sum384([]byte("sluis key-store suite"))
	_, err := c.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "pin-release", Digest: d[:], Algorithm: ES384}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		return fmt.Errorf("Sign with the pin-release key: want invalid_argument, got %s", connect.CodeOf(err))
	}
	return nil
}

func casePublicKey(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	ens, err := ensure(ctx, c, "token-signing", ES384)
	if err != nil {
		return err
	}
	res, err := c.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: "token-signing"}))
	if err != nil {
		return err
	}
	if !bytes.Equal(ens, res.Msg.GetSpkiDer()) {
		return errors.New("PublicKey differs from Ensure")
	}
	return nil
}

func caseEcdh(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	spki, err := ensure(ctx, c, "wrapping", ECDHP384)
	if err != nil {
		return err
	}
	pub, err := parseECDSA(spki)
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
		return fmt.Errorf("Ecdh: %w", err)
	}
	if !bytes.Equal(want, res.Msg.GetSharedSecret()) {
		return errors.New("the shared secret differs from the reference computation")
	}
	off := bytes.Clone(eph.PublicKey().Bytes())
	off[len(off)-1] ^= 0x01 // a point off the curve
	_, err = c.Ecdh(ctx, connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: "wrapping", PeerPublic: off}))
	return wantRefusal(err, connect.CodeInvalidArgument, reasonPeer)
}

func caseUnknownPurpose(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	_, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "no-such-purpose", Algorithm: ES384}))
	return wantRefusal(err, connect.CodeInvalidArgument, reasonPurpose)
}

func caseUnknownAlgorithm(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	_, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "PS256"}))
	return wantRefusal(err, connect.CodeInvalidArgument, reasonAlgorithm)
}

func caseDigest(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	d := sha512.Sum384([]byte("x"))
	_, err := c.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "token-signing", Digest: d[:47], Algorithm: ES384}))
	if e := wantRefusal(err, connect.CodeInvalidArgument, reasonDigest); e != nil {
		return e
	}
	// A SHA-384 digest is not an audit-log digest: that key is P-256 and signs SHA-256.
	_, err = c.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "audit-log", Digest: d[:], Algorithm: ES256}))
	return wantRefusal(err, connect.CodeInvalidArgument, reasonDigest)
}

func caseOtherAlgorithm(ctx context.Context, c keystorev2alpha1connect.KeyStoreServiceClient) error {
	_, err := c.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "audit-log", Algorithm: ES384}))
	return wantRefusal(err, connect.CodeFailedPrecondition, reasonAlgorithm)
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
	if !ok {
		return nil, errors.New("the public key is not an EC key")
	}
	return pub, nil
}
