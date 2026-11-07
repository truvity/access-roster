// Package cad is ca, the X.509 certificate authority, in the form of the first working version: it makes one certificate,
// the token certificate (ADR 0023, "Leaf profiles", the row "Token signing (non-CA)"; ADR 0006, "The token-signing
// key"). The node's intermediate certifies the token-signing key with a certificate that is not a CA and allows digital
// signatures only, and the key set carries it as the x5c chain of the key.
//
// ca holds no key. It builds the TBSCertificate (kits/go/tokencert), asks key@ to sign it with the x509-intermediate
// purpose, assembles the certificate and hands it back to key@, which checks it again and keeps it. key@ signs only the
// token certificate and ca chooses only the serial number and the validity, so a compromised ca can make no other
// certificate (REQ-ISO-006). The leaf profiles, the issuance log (REQ-KEYS-063) and the CRL are version 1 parity, and
// so is the service that other actors call: until a caller exists, ca has no socket (principle 8, "Nothing without a
// consumer"), and its work is a loop.
//
// The loop does not poll for something that is absent with Get: store@ audits a refusal for an absent item (ADR 0005),
// and an idle board writes at most 60 audit records an hour (REQ-AUDIT-180). It asks key@ for the chain of the token
// key (which key@ gives or does not), lists KeyCertificate, and acts when an intermediate is there and the chain is not.
// When a call fails it waits twice as long as the last time, up to a quarter of an hour, so that a refusal that repeats
// is not a record every few seconds.
package cad

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/store"
	"github.com/truvity/sluis/v2/kits/go/tokencert"
)

// Actor is the name of this actor in the registry.
const Actor = "ca"

// The purposes ca works with.
const (
	intermediatePurpose = "x509-intermediate"
	tokenPurpose        = "token-signing"
	algES384            = "ES384"
	// requester is the actor that uses the certified key: the requester of the token certificate.
	requester = "signer"
	profile   = "token-signing"
)

// Timing of the loop. Waiting is how long to wait before looking again for an intermediate that is not installed yet;
// Settled is how long to wait when the chain is in place (a renewal of the intermediate is looked for then); a failure
// doubles the wait from Waiting up to MaxBackoff.
const (
	Waiting    = 15 * time.Second
	Settled    = 5 * time.Minute
	MaxBackoff = 15 * time.Minute
	// callTimeout bounds one call to key@ or store@.
	callTimeout = 10 * time.Second
	// minLifetime is the least a token certificate is made for (key@'s rule).
	minLifetime = time.Hour
	// backdate: a verifier whose clock is a little behind still accepts the certificate (never before the intermediate).
	backdate = 5 * time.Minute
)

// Options configure a Worker.
type Options struct {
	Boundary string
	Store    storev2alpha1connect.StoreServiceClient
	Keys     keyv2alpha1connect.KeyServiceClient
	Audit    Auditor
	// Now is the clock; nil means time.Now. Rand is the source of the serial numbers; nil means crypto/rand.
	Now  func() time.Time
	Rand io.Reader
}

// Worker makes the token certificate when it is due.
type Worker struct {
	o     Options
	certs *store.Client[*keyv2alpha1.KeyCertificate]
	now   func() time.Time
}

// New returns a Worker.
func New(o Options) (*Worker, error) {
	if o.Boundary == "" || o.Store == nil || o.Keys == nil || o.Audit == nil {
		return nil, errors.New("cad: boundary, store, keys and audit are required")
	}
	certs, err := store.New(o.Store, "KeyCertificate", func() *keyv2alpha1.KeyCertificate { return &keyv2alpha1.KeyCertificate{} })
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Worker{o: o, certs: certs, now: now}, nil
}

// State says what one pass found.
type State int

const (
	// StateWaiting says that no intermediate is installed for this node's key yet, or it is not valid. Nothing was asked of key@
	// to sign.
	StateWaiting State = iota
	// StateSettled says that key@ gives a chain for the token key. Nothing to do.
	StateSettled
	// StateIssued says that a certificate was made and kept in this pass.
	StateIssued
)

// Once is one pass: it makes the certificate when there is an intermediate and key@ gives no chain for the token key.
// It never asks for an item by id.
func (w *Worker) Once(ctx context.Context) (State, error) {
	tok, err := w.tokenKey(ctx)
	if err != nil {
		return StateWaiting, fmt.Errorf("the token-signing key: %w", err)
	}
	// key@ gives the chain only when it fits: the certificate is for this key, has not ended, and ends in the intermediate
	// that is installed now. That is the whole test of whether there is work.
	if upToDate(tok.GetChain()) {
		return StateSettled, nil
	}
	inter, err := w.publicKey(ctx, intermediatePurpose)
	if err != nil {
		return StateWaiting, fmt.Errorf("public key of the intermediate: %w", err)
	}
	have, err := w.installed(ctx, inter.GetSpkiDer(), tok.GetSpkiDer())
	if err != nil {
		return StateWaiting, err
	}
	cert := have.intermediate
	now := w.now().UTC().Truncate(time.Second)
	// An intermediate that has an hour or less left gets no certificate: key@ would refuse one (it has no use), and nothing
	// is asked of it. The renewal of the intermediate is what ca waits for.
	if cert == nil || now.Before(cert.NotBefore) || cert.NotAfter.Sub(now) < minLifetime {
		return StateWaiting, nil
	}
	// key@ gave no chain, yet the certificate is stored and fits: its own read of the store failed a moment ago. Nothing
	// is made twice for that.
	if have.tokenFits(now) {
		return StateSettled, nil
	}
	serial, err := tokencert.NewSerial(w.o.Rand)
	if err != nil {
		return StateWaiting, err
	}
	// Five minutes back, so that a verifier whose clock is a little behind accepts it; key@ allows ten, and never before the
	// intermediate began.
	notBefore := now.Add(-backdate)
	if notBefore.Before(cert.NotBefore) {
		notBefore = cert.NotBefore
	}
	tbs, err := tokencert.TBS(tokencert.Params{
		Serial: serial, Issuer: cert.RawSubject, IssuerKeyID: cert.SubjectKeyId, SPKI: tok.GetSpkiDer(), Boundary: w.o.Boundary,
		NotBefore: notBefore, NotAfter: cert.NotAfter,
	})
	if err != nil {
		return StateWaiting, err
	}
	sig, err := w.sign(ctx, tbs)
	if err != nil {
		return StateWaiting, err
	}
	der := tokencert.Assemble(tbs, sig)
	// Read it as a verifier would before it is handed on: a mistake here is caught here, and not stored.
	leaf, err := x509.ParseCertificate(der)
	if err != nil || leaf.CheckSignatureFrom(cert) != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, tok.GetSpkiDer()) {
		return StateWaiting, errors.New("cad: key@ returned a signature that does not make a certificate of the intermediate for the token key")
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := w.o.Keys.PutCertificate(cctx, connect.NewRequest(&keyv2alpha1.PutCertificateRequest{Purpose: tokenPurpose, Certificate: der})); err != nil {
		return StateWaiting, fmt.Errorf("key@ did not keep the certificate: %w", err)
	}
	// The fact is best effort, counted when lost: key@ made its own facts for the signature and the write durable.
	issued := Issued{Profile: profile, Requester: requester, Serial: serial, NotBefore: leaf.NotBefore.Unix(), NotAfter: leaf.NotAfter.Unix(), KeySHA256: sha256.Sum256(tok.GetSpkiDer())}
	if err := w.o.Audit.Emit(ctx, issued.event()); err != nil {
		slog.Warn("the audit fact of the token certificate was not delivered", "err", err)
	}
	slog.Info("token certificate made", "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return StateIssued, nil
}

// tokenKey asks key@ for the key the token certificate certifies, and for the chain it gives for it now.
func (w *Worker) tokenKey(ctx context.Context) (*keyv2alpha1.TokenKeyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	res, err := w.o.Keys.TokenKey(ctx, connect.NewRequest(&keyv2alpha1.TokenKeyRequest{}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func (w *Worker) publicKey(ctx context.Context, purpose string) (*keyv2alpha1.PublicKeyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	res, err := w.o.Keys.PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: purpose}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func (w *Worker) sign(ctx context.Context, tbs []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	res, err := w.o.Keys.Sign(ctx, connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: intermediatePurpose, Content: tbs, Algorithm: algES384}))
	if err != nil {
		return nil, fmt.Errorf("key@ did not sign: %w", err)
	}
	return res.Msg.GetSignatureDer(), nil
}

// upToDate says that key@'s chain for the token key is in place and not older than the intermediate: its certificate ends
// when the intermediate that follows it does. After a renewal key@ still gives the old certificate while it verifies
// under the renewed intermediate, so that the key set has no gap, and ca makes the certificate again then (ADR 0023: the
// chain is never older than the intermediate); the replacement ends later, which key@ allows.
func upToDate(chain [][]byte) bool {
	if len(chain) < 2 {
		return false
	}
	leaf, err1 := x509.ParseCertificate(chain[0])
	inter, err2 := x509.ParseCertificate(chain[1])
	return err1 == nil && err2 == nil && leaf.NotAfter.Equal(inter.NotAfter)
}

// holdings is what the kind KeyCertificate holds for this node's two keys.
type holdings struct {
	intermediate *x509.Certificate
	chain        [][]byte // the installed chain of the intermediate
	token        [][]byte // the stored chain of the token key, or nil
	tokenSPKI    []byte
}

// tokenFits says that the stored token certificate is for the token key, has not ended and ends in the installed chain.
func (h holdings) tokenFits(now time.Time) bool {
	if len(h.token) != 1+len(h.chain) {
		return false
	}
	for i, der := range h.chain {
		if !bytes.Equal(h.token[1+i], der) {
			return false
		}
	}
	c, err := x509.ParseCertificate(h.token[0])
	return err == nil && bytes.Equal(c.RawSubjectPublicKeyInfo, h.tokenSPKI) && !now.Before(c.NotBefore) && now.Before(c.NotAfter) && upToDate(h.token)
}

// installed reads what KeyCertificate holds for the intermediate key and the token key with these public keys. The kind
// is listed, never read by id.
func (w *Worker) installed(ctx context.Context, interSPKI, tokenSPKI []byte) (holdings, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	h := holdings{tokenSPKI: tokenSPKI}
	for token := ""; ; {
		items, next, err := w.certs.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return holdings{}, fmt.Errorf("KeyCertificate cannot be listed: %w", err)
		}
		for _, it := range items {
			v := it.Value
			switch {
			case v.GetPurpose() == intermediatePurpose && len(v.GetChain()) > 0 && bytes.Equal(v.GetSpkiDer(), interSPKI):
				if c, err := x509.ParseCertificate(v.GetChain()[0]); err == nil && bytes.Equal(c.RawSubjectPublicKeyInfo, interSPKI) {
					h.intermediate, h.chain = c, v.GetChain()
				}
			case v.GetPurpose() == tokenPurpose && len(v.GetChain()) > 0 && bytes.Equal(v.GetSpkiDer(), tokenSPKI):
				h.token = v.GetChain()
			}
		}
		if next == "" {
			return h, nil
		}
		token = next
	}
}

// nextWait is how long to wait after a pass: a failure doubles the wait of the last failure (from Waiting, up to
// MaxBackoff), an intermediate not installed yet is looked for again soon, and a chain in place is looked at rarely.
func nextWait(last time.Duration, st State, err error) time.Duration {
	switch {
	case err != nil:
		return min(max(2*last, Waiting), MaxBackoff)
	case st == StateWaiting:
		return Waiting
	default:
		return Settled
	}
}

// Run is the loop of the process: a pass, then a wait that depends on what it found. It returns when ctx ends.
func (w *Worker) Run(ctx context.Context) error {
	wait := Waiting
	for {
		st, err := w.Once(ctx)
		if ctx.Err() != nil {
			return nil
		}
		wait = nextWait(wait, st, err)
		if err != nil {
			slog.Warn("token certificate not made", "err", err, "retry_in", wait.String())
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// Check reports what ca cannot do now: the paths that fail, by name.
func (w *Worker) Check(ctx context.Context) []string {
	var bad []string
	if _, err := w.tokenKey(ctx); err != nil {
		bad = append(bad, "key."+tokenPurpose)
	}
	if _, err := w.publicKey(ctx, intermediatePurpose); err != nil {
		bad = append(bad, "key."+intermediatePurpose)
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, _, err := w.certs.List(cctx, "", store.PageSize(1)); err != nil {
		bad = append(bad, "store.KeyCertificate")
	}
	return bad
}
