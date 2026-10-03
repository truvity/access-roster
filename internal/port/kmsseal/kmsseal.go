// Package kmsseal is the AWS KMS adapter of port.Sealer (docs/design/ports.md,
// "Sealing").
//
// port.Seal makes a fresh 32-byte data key, encrypts the value under it with
// AES-GCM, and asks the Sealer to wrap that key. The port hands the Sealer a
// key it already has, so the adapter uses Encrypt (not GenerateDataKey):
//
//   - Wrap is kms:Encrypt of the data key under the configured key, with the
//     EncryptionContext {"access-roster:binding": <binding>}. Wrapped.KeyID is
//     the ARN KMS reports, and Wrapped.Blob is the ciphertext.
//   - Unwrap is kms:Decrypt with the same EncryptionContext and the configured
//     key as KeyId. KMS refuses a context that differs, and refuses a
//     ciphertext that another key made, so a sealed value copied under another
//     key does not open and neither does one wrapped by a different KEK. Every
//     such refusal, and a disabled, scheduled-for-deletion or unknown key, is
//     port.ErrUnwrap. Anything else (throttling, a missing permission, the
//     network) is port.ErrUnavailable.
//
// Credentials are ambient (Pod Identity, IRSA, a Lambda role). The role needs
// kms:Encrypt and kms:Decrypt on the key, nothing more.
//
// There is no cache of unwrapped keys. Every Unwrap is a kms:Decrypt that
// CloudTrail records, which is the audit trail of who opened which secret, and
// the port allows no caching of a data key past the call. A caller that reads
// a sealed value on every request pays one KMS call for it.
//
// Rotation of the KEK is KMS's own: automatic rotation keeps the key id and
// KMS decrypts under the old material. Moving to a different key is a rewrap
// of the envelopes, with the old key configured to read and the new one to
// write; this adapter reads and writes under one key.
package kmsseal

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/truvity/access-roster/internal/port"
)

// ContextKey is the EncryptionContext key that carries the binding.
const ContextKey = "access-roster:binding"

// Config names the key.
type Config struct {
	// KeyID is a key id, a key ARN, or an alias (alias/name). Required.
	KeyID string
	// Region defaults to the SDK's own resolution.
	Region string
	// Endpoint overrides the service address, for LocalStack.
	Endpoint string
}

// API is the part of the KMS client the adapter calls.
type API interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Sealer is the adapter.
type Sealer struct {
	api   API
	keyID string
}

var _ port.Sealer = (*Sealer)(nil)

// New builds the adapter over the SDK's default credential chain.
func New(ctx context.Context, cfg Config) (*Sealer, error) {
	if cfg.KeyID == "" {
		return nil, errors.New("kmsseal: keyId is required")
	}
	var loaders []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loaders = append(loaders, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loaders...)
	if err != nil {
		return nil, fmt.Errorf("kmsseal: loading the AWS configuration: %w", err)
	}
	client := kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return NewWithAPI(client, cfg)
}

// NewWithAPI builds the adapter over a client the caller made.
func NewWithAPI(api API, cfg Config) (*Sealer, error) {
	if cfg.KeyID == "" {
		return nil, errors.New("kmsseal: keyId is required")
	}
	return &Sealer{api: api, keyID: cfg.KeyID}, nil
}

func bindingContext(binding string) map[string]string {
	return map[string]string{ContextKey: binding}
}

// Wrap implements port.Sealer.
func (s *Sealer) Wrap(ctx context.Context, dataKey []byte, binding string) (port.Wrapped, error) {
	out, err := s.api.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             &s.keyID,
		Plaintext:         dataKey,
		EncryptionContext: bindingContext(binding),
	})
	if err != nil {
		return port.Wrapped{}, fmt.Errorf("%w: kms encrypt: %w", port.ErrUnavailable, err)
	}
	return port.Wrapped{KeyID: aws.ToString(out.KeyId), Blob: out.CiphertextBlob}, nil
}

// Unwrap implements port.Sealer.
func (s *Sealer) Unwrap(ctx context.Context, w port.Wrapped, binding string) ([]byte, error) {
	out, err := s.api.Decrypt(ctx, &kms.DecryptInput{
		KeyId:             &s.keyID,
		CiphertextBlob:    w.Blob,
		EncryptionContext: bindingContext(binding),
	})
	if err != nil {
		if refused(err) {
			return nil, fmt.Errorf("%w: kms refused the key: %w", port.ErrUnwrap, err)
		}
		return nil, fmt.Errorf("%w: kms decrypt: %w", port.ErrUnavailable, err)
	}
	// The envelope's key id is not authenticated by KMS, so a damaged one is
	// checked against the key KMS actually used.
	if w.KeyID != "" && aws.ToString(out.KeyId) != w.KeyID {
		return nil, fmt.Errorf("%w: the envelope names another key", port.ErrUnwrap)
	}
	return out.Plaintext, nil
}

// refused is KMS saying this ciphertext, context or key will not open, as
// opposed to KMS being unreachable or the caller being unauthorised.
func refused(err error) bool {
	var invalid *types.InvalidCiphertextException
	var wrongKey *types.IncorrectKeyException
	var state *types.KMSInvalidStateException
	var disabled *types.DisabledException
	var missing *types.NotFoundException
	return errors.As(err, &invalid) || errors.As(err, &wrongKey) || errors.As(err, &state) ||
		errors.As(err, &disabled) || errors.As(err, &missing)
}
