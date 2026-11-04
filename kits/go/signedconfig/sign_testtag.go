//go:build sluis_test

package signedconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Sign makes a signed config document of payload: a JWS in the general JSON serialisation with one signature,
// ES384, and the protected header alg, kid, seq and kind, the registry name of the kind (signed-config.md, "The
// document").
//
// It exists for tests, which need documents under a key made at test time, and only in a build with the tag
// sluis_test: a normal build has no signer here, because sluis signs config in its pipeline and not in a kit.
func Sign(key *ecdsa.PrivateKey, kid string, seq uint64, kind string, payload []byte) ([]byte, error) {
	if key.Curve != elliptic.P384() {
		return nil, errors.New("signedconfig: the key is not on P-384")
	}
	header, err := json.Marshal(struct {
		Alg  string `json:"alg"`
		KID  string `json:"kid"`
		Seq  uint64 `json:"seq"`
		Kind string `json:"kind"`
	}{"ES384", kid, seq, kind})
	if err != nil {
		return nil, err
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha512.Sum384([]byte(protected + "." + p))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, signatureLen)
	r.FillBytes(sig[:signatureLen/2])
	s.FillBytes(sig[signatureLen/2:])
	return json.Marshal(map[string]any{
		"payload":    p,
		"signatures": []map[string]string{{"protected": protected, "signature": base64.RawURLEncoding.EncodeToString(sig)}},
	})
}
