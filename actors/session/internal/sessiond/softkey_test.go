//go:build sluis_test

package sessiond_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// softKey is a software authenticator for the tests of the passkey ceremonies: an ES256 credential that answers the options
// of a registration and of an assertion the way a browser and a security key do, with the knobs a negative test needs. It
// is test code: it is in no binary (the build tag sluis_test) and it holds no secret that matters. The attestation format
// is "none" or a self-attested "packed".
type softKey struct {
	t        *testing.T
	id       []byte
	priv     *ecdsa.PrivateKey
	handle   []byte // the user handle the registration was given; empty until then
	count    uint32 // the counter the next assertion reports, after the increment
	counting bool   // the authenticator keeps a counter; false reports 0 every time
	aaguid   [16]byte
	// The flags the authenticator reports. A device-bound security key has BE and BS clear; a synced passkey has both set.
	up, uv, be, bs bool
	attestation    string // "none" or "packed"
	format         string // when set, the format named in the attestation object, with a statement of that format's shape
	// Overrides for negative tests, applied to the next response only.
	rpID      string // the relying-party ID the authenticator hashes (default: the one in the options)
	origin    string // the origin the client puts in clientDataJSON (required)
	challenge string // a challenge to answer instead of the one in the options
}

// newSoftKey makes a credential with a random id of n bytes. Its id can begin with - or _ when written in base64url.
func newSoftKey(t *testing.T, n int, be bool) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, n)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softKey{t: t, id: id, priv: priv, up: true, uv: true, be: be, bs: be, counting: !be, attestation: "none"}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ceremonyOptions are the fields of the JSON options of both ceremonies that the authenticator reads.
type ceremonyOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	RPID string `json:"rpId"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	AuthenticatorSelection struct {
		ResidentKey      string `json:"residentKey"`
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	UserVerification string `json:"userVerification"`
	Attestation      string `json:"attestation"`
	AllowCredentials []any  `json:"allowCredentials"`
	ExcludeCreds     []struct {
		ID string `json:"id"`
	} `json:"excludeCredentials"`
}

func parseOptions(t *testing.T, raw []byte) ceremonyOptions {
	t.Helper()
	var o ceremonyOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func (k *softKey) flags(extra byte) byte {
	f := extra
	if k.up {
		f |= 0x01
	}
	if k.uv {
		f |= 0x04
	}
	if k.be {
		f |= 0x08
	}
	if k.bs {
		f |= 0x10
	}
	return f
}

// cose is the COSE_Key of an ES256 public key, as CBOR.
func (k *softKey) cose() []byte {
	pt, err := k.priv.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		k.t.Fatal(err)
	}
	x, y := pt[1:33], pt[33:65]
	out := []byte{0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, y...)
}

func cborText(s string) []byte { return append([]byte{0x60 | byte(len(s))}, s...) } //nolint:gosec // a text of at most 23 bytes, in the tests

func cborBytes(b []byte) []byte {
	switch {
	case len(b) < 24:
		return append([]byte{0x40 | byte(len(b))}, b...) //nolint:gosec // under 24, in the tests
	case len(b) < 256:
		return append([]byte{0x58, byte(len(b))}, b...) //nolint:gosec // under 256, in the tests
	}
	return append(append([]byte{0x59}, binary.BigEndian.AppendUint16(nil, uint16(len(b)))...), b...) //nolint:gosec // under 65536, in the tests
}

func (k *softKey) rpHash(optsRP string) [32]byte {
	if k.rpID != "" {
		return sha256.Sum256([]byte(k.rpID))
	}
	return sha256.Sum256([]byte(optsRP))
}

func (k *softKey) clientData(typ, challenge string) []byte {
	if k.challenge != "" {
		challenge = k.challenge
	}
	cd, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	if err != nil {
		k.t.Fatal(err)
	}
	return cd
}

// Create answers a registration: the JSON of the PublicKeyCredential the browser would return.
func (k *softKey) Create(optsJSON []byte) []byte {
	k.t.Helper()
	o := parseOptions(k.t, optsJSON)
	user, err := base64.RawURLEncoding.DecodeString(o.User.ID)
	if err != nil {
		k.t.Fatal(err)
	}
	k.handle = user
	rp := k.rpHash(o.RP.ID)
	authData := append(rp[:], k.flags(0x40)) // attested credential data follows
	authData = binary.BigEndian.AppendUint32(authData, k.reportedCount(false))
	authData = append(authData, k.aaguid[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(k.id))) //nolint:gosec // a test credential id
	authData = append(authData, k.id...)
	authData = append(authData, k.cose()...)
	cd := k.clientData("webauthn.create", o.Challenge)
	var stmt []byte
	fmtName := "none"
	if k.attestation == "packed" {
		// Self attestation: the credential key signs authData || SHA-256(clientDataJSON), with no certificate.
		fmtName = "packed"
		h := sha256.Sum256(cd)
		sig, err := ecdsa.SignASN1(rand.Reader, k.priv, hash(append(append([]byte{}, authData...), h[:]...)))
		if err != nil {
			k.t.Fatal(err)
		}
		stmt = append([]byte{0xA2}, cborText("alg")...)
		stmt = append(stmt, 0x26)
		stmt = append(stmt, cborText("sig")...)
		stmt = append(stmt, cborBytes(sig)...)
	} else {
		stmt = []byte{0xA0}
	}
	if k.format != "" {
		fmtName = k.format
		stmt = k.statementOf(k.format)
	}
	obj := []byte{0xA3}
	obj = append(obj, cborText("fmt")...)
	obj = append(obj, cborText(fmtName)...)
	obj = append(obj, cborText("attStmt")...)
	obj = append(obj, stmt...)
	obj = append(obj, cborText("authData")...)
	obj = append(obj, cborBytes(authData)...)
	out, err := json.Marshal(map[string]any{
		"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "authenticatorAttachment": "cross-platform",
		"response": map[string]any{
			"clientDataJSON": b64(cd), "attestationObject": b64(obj), "transports": []string{"usb"},
		},
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		k.t.Fatal(err)
	}
	return out
}

func hash(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// reportedCount is the counter the next response reports: one more than the last when the authenticator counts, else 0.
func (k *softKey) reportedCount(step bool) uint32 {
	if !k.counting {
		return 0
	}
	if step {
		k.count++
	}
	return k.count
}

// Get answers an assertion: the JSON of the PublicKeyCredential the browser would return, with the user handle.
func (k *softKey) Get(optsJSON []byte) []byte {
	k.t.Helper()
	o := parseOptions(k.t, optsJSON)
	rp := k.rpHash(o.RPID)
	authData := append(rp[:], k.flags(0))
	authData = binary.BigEndian.AppendUint32(authData, k.reportedCount(true))
	cd := k.clientData("webauthn.get", o.Challenge)
	h := sha256.Sum256(cd)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, hash(append(append([]byte{}, authData...), h[:]...)))
	if err != nil {
		k.t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{
		"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "authenticatorAttachment": "cross-platform",
		"response": map[string]any{
			"clientDataJSON": b64(cd), "authenticatorData": b64(authData), "signature": b64(sig), "userHandle": b64(k.handle),
		},
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		k.t.Fatal(err)
	}
	return out
}

// statementOf is an attestation statement with the shape of the format, enough for the library to start reading it: for
// android-safetynet a version and a response that is a JWT, which the library would hand to a JWT parser.
func (k *softKey) statementOf(format string) []byte {
	switch format {
	case "android-safetynet":
		stmt := []byte{0xA2}
		stmt = append(stmt, cborText("ver")...)
		stmt = append(stmt, cborText("14366037")...)
		stmt = append(stmt, cborText("response")...)
		return append(stmt, cborBytes([]byte("eyJhbGciOiJSUzI1NiJ9.eyJ0aW1lc3RhbXBNcyI6MX0.c2ln"))...)
	case "compound":
		// One nested statement, in the format the library hands to a JWT parser.
		stmt := []byte{0x81, 0xA2}
		stmt = append(stmt, cborText("fmt")...)
		stmt = append(stmt, cborText("android-safetynet")...)
		stmt = append(stmt, cborText("attStmt")...)
		return append(stmt, k.statementOf("android-safetynet")...)
	default:
		return []byte{0xA0}
	}
}
