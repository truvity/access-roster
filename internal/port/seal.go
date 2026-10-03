package port

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// envelope is a sealed value: AES-GCM under a fresh data key, with the data
// key wrapped by the Sealer's key-encryption key.
type envelope struct {
	KeyID      string `json:"kid"`
	Wrapped    []byte `json:"wk"`
	Nonce      []byte `json:"n"`
	Ciphertext []byte `json:"ct"`
}

// Seal encrypts plaintext under a fresh data key and wraps that key with the
// sealer. The context is authenticated additional data.
func Seal(ctx context.Context, s Sealer, plaintext []byte, binding string) ([]byte, error) {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	wrapped, err := s.Wrap(ctx, dataKey, binding)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{
		KeyID: wrapped.KeyID, Wrapped: wrapped.Blob, Nonce: nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, []byte(binding)),
	})
}

// Open reverses [Seal]. A wrong context, a foreign key or a damaged
// envelope is [ErrUnwrap].
func Open(ctx context.Context, s Sealer, sealed []byte, binding string) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		return nil, fmt.Errorf("%w: the envelope is not readable", ErrUnwrap)
	}
	dataKey, err := s.Unwrap(ctx, Wrapped{KeyID: env.KeyID, Blob: env.Wrapped}, binding)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnwrap, err)
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: the envelope is damaged", ErrUnwrap)
	}
	plain, err := gcm.Open(nil, env.Nonce, env.Ciphertext, []byte(binding))
	if err != nil {
		return nil, fmt.Errorf("%w: the value does not open under this context", ErrUnwrap)
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnwrap, err)
	}
	return cipher.NewGCM(block)
}
