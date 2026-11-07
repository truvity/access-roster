// Package jwtbcp makes the negative vectors of the JSON Web Token best current practices (RFC 8725) for a verifier of
// compact JWS tokens, and one valid token as the positive control.
//
// A vector is a token that differs from the valid one in exactly one respect, so a verifier that refuses it refuses
// it for that respect. A vector of the rules "format", "alg" and "key" breaks the signature or the header; a vector
// of the rules "typ", "iss", "aud" and "time" carries a signature that verifies under the legitimate key and breaks a
// claim or the type, so the verifier's own claim check is the only thing that can refuse it.
//
// The package holds no verifier. A test of a verifier describes it by a [Profile] (the key it trusts, the algorithm it
// pins, the type it requires, the claims of a good token), hands each vector to the verifier and requires a refusal,
// and hands [Valid] to it and requires an acceptance.
//
// The vectors follow RFC 8725 section 3 (3.1 algorithm verification, 3.2 appropriate algorithms, 3.8 validate the
// issuer and the subject, 3.9 use and validate the audience, 3.11 use explicit typing, 3.10 do not trust received
// claims, as for jku, x5u and an embedded jwk), RFC 7515 section 4.1.11 (a crit header with an extension the verifier
// does not understand) and RFC 7797 (b64 false). They are made at run time from fresh keys, so there is no file to go
// stale; the signature of a vector is random, and what a vector breaks is not.
package jwtbcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Rule names what a vector breaks.
type Rule string

// The rules a vector can break.
const (
	// RuleFormat is a token that is not a compact JWS of one signature, or that carries a header the verifier must
	// refuse (crit, b64 false).
	RuleFormat Rule = "format"
	// RuleAlg is an algorithm the verifier does not pin: none, the HMAC family, or an asymmetric one that is not its.
	RuleAlg Rule = "alg"
	// RuleKey is a signature that the trusted key did not make, or a key the token supplies for itself.
	RuleKey Rule = "key"
	// RuleTyp is a type header other than the one required.
	RuleTyp Rule = "typ"
	// RuleIss is an issuer other than the trusted one.
	RuleIss Rule = "iss"
	// RuleAud is an audience other than the verifier's own.
	RuleAud Rule = "aud"
	// RuleTime is a token outside its time window.
	RuleTime Rule = "time"
)

// Vector is a token that a verifier must refuse.
type Vector struct {
	Name  string
	Rule  Rule
	Token string
}

// Profile describes the verifier under test and the token it accepts.
type Profile struct {
	// Alg is the algorithm the verifier pins. Key signs with it: an ECDSA key on the curve of Alg (ES256 on P-256,
	// ES384 on P-384).
	Alg jose.SignatureAlgorithm
	Key *ecdsa.PrivateKey
	KID string
	// Typ is the type header the verifier requires, such as "at+jwt". Empty when it requires none: the vectors of
	// RuleTyp are then left out.
	Typ string
	// Claims is a claim set the verifier accepts. The vectors change it one claim at a time.
	Claims map[string]any
	// IssuerClaim and AudienceClaim name the claims of Claims that the verifier checks, such as "iss" and "aud". A
	// claim left empty is not checked, and its vectors are left out.
	IssuerClaim, AudienceClaim string
	// CheckExp says whether the verifier checks the expiry, and so whether the expiry vectors apply.
	CheckExp bool
	// Now is the verifier's clock; the time vectors are placed around it.
	Now time.Time
	// SpareRSA is an RSA key that the verifier's key set also holds, under the kid SpareKID, with no algorithm
	// declared. With it the vectors can sign with an algorithm the verifier does not pin and still have a key that
	// fits, so the pin is what refuses them and not the mismatch of key types. Leave it nil when the key set cannot
	// hold one.
	SpareRSA *rsa.PrivateKey
	// RSAPinned says that the verifier accepts RS256, so that the RS256 vector is left out.
	RSAPinned bool
}

// SpareKID is the kid of Profile.SpareRSA in the key set.
const SpareKID = "spare-rsa"

// Spare is the public JWK of Profile.SpareRSA, for the key set of the verifier. It declares no algorithm, as a key
// set that a careless issuer publishes does not.
func (p Profile) Spare() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &p.SpareRSA.PublicKey, KeyID: SpareKID, Use: "sig"}
}

// Public is the legitimate public key as a JWK, the key set of the verifier's issuer.
func (p Profile) Public() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &p.Key.PublicKey, KeyID: p.KID, Algorithm: string(p.Alg), Use: "sig"}
}

// Valid is a token that the verifier must accept.
func Valid(t testing.TB, p Profile) string {
	t.Helper()
	return sign(t, p.Key, p.Alg, p.header(), mustJSON(t, p.Claims))
}

func (p Profile) header() map[string]any {
	h := map[string]any{"alg": string(p.Alg), "kid": p.KID}
	if p.Typ != "" {
		h["typ"] = p.Typ
	}
	return h
}

// Negative returns the vectors, each of which the verifier must refuse.
func Negative(t testing.TB, p Profile) []Vector {
	t.Helper()
	var out []Vector
	add := func(name string, r Rule, token string) { out = append(out, Vector{Name: name, Rule: r, Token: token}) }
	payload := mustJSON(t, p.Claims)
	signed := func(h map[string]any, body []byte) string { return sign(t, p.Key, p.Alg, h, body) }
	with := func(name string, v any) []byte {
		m := map[string]any{}
		for k, x := range p.Claims {
			m[k] = x
		}
		if v == nil {
			delete(m, name)
		} else {
			m[name] = v
		}
		return mustJSON(t, m)
	}
	valid := Valid(t, p)
	parts := strings.Split(valid, ".")

	// ---- format: a compact JWS of one signature (RFC 7515 section 7.1), and nothing the verifier cannot honour.
	add("the signature part is missing", RuleFormat, parts[0]+"."+parts[1])
	add("the signature part is empty", RuleFormat, parts[0]+"."+parts[1]+".")
	add("four parts", RuleFormat, valid+".AAAA")
	add("five parts, as a JWE is shaped", RuleFormat, valid+".AAAA.AAAA")
	add("the general JSON serialization", RuleFormat, `{"payload":"`+parts[1]+`","signatures":[{"protected":"`+parts[0]+`","signature":"`+parts[2]+`"}]}`)
	add("the flattened JSON serialization", RuleFormat, `{"payload":"`+parts[1]+`","protected":"`+parts[0]+`","signature":"`+parts[2]+`"}`)
	add("the token is a bare dot", RuleFormat, ".")
	add("the header is not JSON", RuleFormat, b64([]byte("not json"))+"."+parts[1]+"."+parts[2])
	// RFC 7515 section 4.1.11: a verifier that does not understand an extension named by crit must reject the token.
	// The signature is the legitimate key's, so only the header is wrong.
	h := p.header()
	h["crit"] = []string{"https://example.invalid/ext"}
	h["https://example.invalid/ext"] = true
	add("crit names an extension the verifier does not understand", RuleFormat, signed(h, payload))
	h = p.header()
	h["crit"] = []string{"exp"}
	add("crit names a registered claim", RuleFormat, signed(h, payload))
	// RFC 7797: with b64 false the payload is not base64url, and the signing input changes shape.
	h = p.header()
	h["b64"] = false
	h["crit"] = []string{"b64"}
	add("b64 false, the unencoded payload of RFC 7797", RuleFormat, unencoded(t, p.Key, p.Alg, h, payload))

	// ---- alg: the algorithm is the verifier's, not the token's (RFC 8725 section 3.1).
	for _, a := range []string{"none", "None", "NONE", "nOnE"} {
		add("alg "+a+" with no signature", RuleAlg, b64(mustJSON(t, withAlg(p.header(), a)))+"."+parts[1]+".")
		add("alg "+a+" with the valid signature kept", RuleAlg, b64(mustJSON(t, withAlg(p.header(), a)))+"."+parts[1]+"."+parts[2])
	}
	add("alg is empty", RuleAlg, b64(mustJSON(t, withAlg(p.header(), "")))+"."+parts[1]+"."+parts[2])
	hNoAlg := p.header()
	delete(hNoAlg, "alg")
	add("alg is absent", RuleAlg, b64(mustJSON(t, hNoAlg))+"."+parts[1]+"."+parts[2])
	add("alg is not a string", RuleAlg, b64(mustJSON(t, withAlg(p.header(), 384)))+"."+parts[1]+"."+parts[2])
	// The key-confusion attack of RFC 8725 section 2.1: an HMAC over the public key, which the attacker has.
	pubDER, err := x509.MarshalPKIXPublicKey(&p.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubJWK, err := json.Marshal(p.Public())
	if err != nil {
		t.Fatal(err)
	}
	size := (p.Key.Curve.Params().BitSize + 7) / 8
	pubRaw := append(pad(p.Key.X, size), pad(p.Key.Y, size)...)
	for _, hs := range []struct {
		alg string
		h   func() hash.Hash
	}{{"HS256", sha256.New}, {"HS384", sha512.New384}, {"HS512", sha512.New}} {
		for _, s := range []struct {
			name   string
			secret []byte
		}{{"the DER public key", pubDER}, {"the PEM public key", pubPEM}, {"the JWK of the public key", pubJWK}, {"the raw point", pubRaw}} {
			add(hs.alg+" over "+s.name, RuleAlg, hmacToken(p, hs.alg, hs.h, s.secret, payload))
		}
	}
	// An asymmetric algorithm that is not the verifier's. Each is signed by a key of its own family with the
	// legitimate kid, so only the algorithm is wrong; a verifier that pins its algorithm refuses all of them.
	other := jose.ES256
	otherCurve := elliptic.P256()
	if p.Alg == jose.ES256 {
		other, otherCurve = jose.ES384, elliptic.P384()
	}
	ok2, err := ecdsa.GenerateKey(otherCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	add("an ECDSA algorithm that the verifier does not pin", RuleAlg, sign(t, ok2, other, withAlg(p.header(), string(other)), payload))
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	add("RS256 signed by a key of the attacker, with the legitimate kid", RuleAlg, signRSA(t, rk, jose.RS256, withAlg(p.header(), "RS256"), payload))
	add("PS256 signed by a key of the attacker, with the legitimate kid", RuleAlg, signRSA(t, rk, jose.PS256, withAlg(p.header(), "PS256"), payload))
	if p.SpareRSA != nil {
		hs := p.header()
		hs["kid"] = SpareKID
		add("PS256 signed by an RSA key that the key set holds", RuleAlg, signRSA(t, p.SpareRSA, jose.PS256, withAlg(hs, "PS256"), payload))
		add("RS384 signed by an RSA key that the key set holds", RuleAlg, signRSA(t, p.SpareRSA, jose.RS384, withAlg(hs, "RS384"), payload))
		if !p.RSAPinned {
			add("RS256 signed by an RSA key that the key set holds", RuleAlg, signRSA(t, p.SpareRSA, jose.RS256, withAlg(hs, "RS256"), payload))
		}
	}
	// The header names the pinned algorithm, and the signature is another algorithm's: its length alone is wrong.
	add("the header names the pinned algorithm and the signature is of "+string(other), RuleAlg,
		b64(mustJSON(t, p.header()))+"."+b64(payload)+"."+rawECSignature(t, ok2, other, b64(mustJSON(t, p.header()))+"."+b64(payload)))

	// ---- key: the key is the verifier's, not the token's (RFC 8725 section 3.10).
	attacker, err := ecdsa.GenerateKey(p.Key.Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	add("signed by another key, with the legitimate kid", RuleKey, sign(t, attacker, p.Alg, p.header(), payload))
	hk := p.header()
	delete(hk, "kid")
	add("signed by another key, with no kid", RuleKey, sign(t, attacker, p.Alg, hk, payload))
	hk = p.header()
	hk["kid"] = "no-such-key"
	add("signed by another key, with a kid the key set does not hold", RuleKey, sign(t, attacker, p.Alg, hk, payload))
	hk = p.header()
	hk["jwk"] = jose.JSONWebKey{Key: &attacker.PublicKey, KeyID: p.KID, Algorithm: string(p.Alg), Use: "sig"}
	add("signed by another key, which the token carries in its jwk header", RuleKey, sign(t, attacker, p.Alg, hk, payload))
	delete(hk, "kid")
	add("the same, with no kid at all", RuleKey, sign(t, attacker, p.Alg, hk, payload))
	hk = p.header()
	hk["jku"] = "https://attacker.example.invalid/jwks"
	hk["x5u"] = "https://attacker.example.invalid/cert"
	add("signed by another key, whose set the token names in jku and x5u", RuleKey, sign(t, attacker, p.Alg, hk, payload))
	add("the payload changed, the signature kept", RuleKey, parts[0]+"."+b64(with("sub", "someone-else"))+"."+parts[2])
	hh := p.header()
	hh["kid"] = p.KID + "-x"
	add("the header changed, the signature kept", RuleKey, b64(mustJSON(t, hh))+"."+parts[1]+"."+parts[2])
	add("the signature truncated", RuleKey, parts[0]+"."+parts[1]+"."+parts[2][:len(parts[2])-8])
	add("the signature flipped in one bit", RuleKey, parts[0]+"."+parts[1]+"."+flip(t, parts[2]))

	// ---- typ: explicit typing (RFC 8725 section 3.11), where the verifier requires a type.
	if p.Typ != "" {
		for _, typ := range []string{"", "JWT", "id_token+jwt", "at+jwt+x", "jwt"} {
			if typ == p.Typ {
				continue
			}
			h := p.header()
			if typ == "" {
				delete(h, "typ")
			} else {
				h["typ"] = typ
			}
			name := "typ " + `"` + typ + `"`
			if typ == "" {
				name = "no typ"
			}
			add(name, RuleTyp, signed(h, payload))
		}
	}

	// ---- iss, aud, time: the claims of a token whose signature verifies.
	if c := p.IssuerClaim; c != "" {
		iss, _ := p.Claims[c].(string)
		add("another issuer", RuleIss, signed(p.header(), with(c, "https://attacker.example.invalid")))
		add("no issuer", RuleIss, signed(p.header(), with(c, nil)))
		add("the issuer with a trailing slash", RuleIss, signed(p.header(), with(c, iss+"/")))
		add("the issuer in upper case", RuleIss, signed(p.header(), with(c, strings.ToUpper(iss))))
		add("the issuer as a list", RuleIss, signed(p.header(), with(c, []string{iss})))
		add("the issuer as a number", RuleIss, signed(p.header(), with(c, 7)))
	}
	if c := p.AudienceClaim; c != "" {
		aud, _ := p.Claims[c].(string)
		add("another audience", RuleAud, signed(p.header(), with(c, "someone-else")))
		add("no audience", RuleAud, signed(p.header(), with(c, nil)))
		add("an empty audience", RuleAud, signed(p.header(), with(c, "")))
		add("an audience list without ours", RuleAud, signed(p.header(), with(c, []string{"someone-else", "another"})))
		add("the audience in upper case", RuleAud, signed(p.header(), with(c, strings.ToUpper(aud))))
		add("the audience with a suffix", RuleAud, signed(p.header(), with(c, aud+"-x")))
	}
	if p.CheckExp {
		add("expired a minute ago", RuleTime, signed(p.header(), with("exp", p.Now.Add(-time.Minute).Unix())))
		add("no expiry", RuleTime, signed(p.header(), with("exp", nil)))
		add("an expiry that is a string", RuleTime, signed(p.header(), with("exp", "9999999999")))
	}
	return out
}

func withAlg(h map[string]any, alg any) map[string]any {
	h["alg"] = alg
	return h
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pad(n *big.Int, size int) []byte {
	b := n.Bytes()
	return append(make([]byte, size-len(b)), b...)
}

// flip changes one bit in the first byte of a base64url value.
func flip(t testing.TB, s string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 1
	return b64(b)
}

func hashOf(alg jose.SignatureAlgorithm) (crypto.Hash, hash.Hash) {
	switch alg {
	case jose.ES256, jose.RS256, jose.PS256:
		return crypto.SHA256, sha256.New()
	case jose.ES384, jose.RS384:
		return crypto.SHA384, sha512.New384()
	default:
		return crypto.SHA512, sha512.New()
	}
}

// rawECSignature signs the signing input with an ECDSA key as RFC 7518 section 3.4 says: R and S, each as wide as
// the curve.
func rawECSignature(t testing.TB, key *ecdsa.PrivateKey, alg jose.SignatureAlgorithm, input string) string {
	t.Helper()
	_, h := hashOf(alg)
	h.Write([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	return b64(append(pad(r, size), pad(s, size)...))
}

// sign makes a compact JWS with an ECDSA key and the header exactly as given.
func sign(t testing.TB, key *ecdsa.PrivateKey, alg jose.SignatureAlgorithm, header map[string]any, payload []byte) string {
	t.Helper()
	in := b64(mustJSON(t, header)) + "." + b64(payload)
	return in + "." + rawECSignature(t, key, alg, in)
}

// unencoded makes the token of RFC 7797 with b64 false: the payload is in the signing input as it is.
func unencoded(t testing.TB, key *ecdsa.PrivateKey, alg jose.SignatureAlgorithm, header map[string]any, payload []byte) string {
	t.Helper()
	protected := b64(mustJSON(t, header))
	in := protected + "." + string(payload)
	return in + "." + rawECSignature(t, key, alg, in)
}

func signRSA(t testing.TB, key *rsa.PrivateKey, alg jose.SignatureAlgorithm, header map[string]any, payload []byte) string {
	t.Helper()
	in := b64(mustJSON(t, header)) + "." + b64(payload)
	ch, h := hashOf(alg)
	h.Write([]byte(in))
	var sig []byte
	var err error
	if alg == jose.PS256 {
		sig, err = rsa.SignPSS(rand.Reader, key, ch, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, ch, h.Sum(nil))
	}
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func hmacToken(p Profile, alg string, h func() hash.Hash, secret, payload []byte) string {
	in := b64(mustJSONNoT(withAlg(p.header(), alg))) + "." + b64(payload)
	m := hmac.New(h, secret)
	m.Write([]byte(in))
	return in + "." + b64(m.Sum(nil))
}

func mustJSONNoT(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
