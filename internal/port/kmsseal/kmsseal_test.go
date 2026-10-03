package kmsseal_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/kmsseal"
	"github.com/truvity/access-roster/internal/port/porttest"
)

const arn = "arn:aws:kms:eu-west-1:111122223333:key/1234"

// fake is a KMS that "encrypts" by prefixing the context, so a different
// context, key or ciphertext is refused the way KMS refuses it.
type fake struct {
	keyID   string
	err     error
	encrypt []*kms.EncryptInput
	decrypt []*kms.DecryptInput
}

func (f *fake) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.encrypt = append(f.encrypt, in)
	if f.err != nil {
		return nil, f.err
	}
	blob := append([]byte(f.keyID+"|"+in.EncryptionContext[kmsseal.ContextKey]+"|"), in.Plaintext...)
	id := f.keyID
	return &kms.EncryptOutput{CiphertextBlob: blob, KeyId: &id}, nil
}

func (f *fake) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decrypt = append(f.decrypt, in)
	if f.err != nil {
		return nil, f.err
	}
	parts := bytes.SplitN(in.CiphertextBlob, []byte("|"), 3)
	if len(parts) != 3 {
		return nil, &types.InvalidCiphertextException{}
	}
	if string(parts[1]) != in.EncryptionContext[kmsseal.ContextKey] {
		return nil, &types.InvalidCiphertextException{}
	}
	id := string(parts[0])
	return &kms.DecryptOutput{Plaintext: parts[2], KeyId: &id}, nil
}

func sealer(t *testing.T, f *fake) *kmsseal.Sealer {
	t.Helper()
	s, err := kmsseal.NewWithAPI(f, kmsseal.Config{KeyID: "alias/access-roster"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConformanceAgainstAFake(t *testing.T) {
	porttest.RunGroups(t, func(t *testing.T) porttest.Env {
		return porttest.Env{Set: port.Set{Sealer: sealer(t, &fake{keyID: arn})}}
	}, "sealing/")
}

func TestTheBindingIsTheEncryptionContext(t *testing.T) {
	f := &fake{keyID: arn}
	s := sealer(t, f)
	ctx := context.Background()
	w, err := s.Wrap(ctx, []byte("0123456789abcdef0123456789abcdef"), "gh.org.acme")
	if err != nil {
		t.Fatal(err)
	}
	if w.KeyID != arn {
		t.Errorf("KeyID %q, want the ARN KMS reported", w.KeyID)
	}
	if got := f.encrypt[0].EncryptionContext[kmsseal.ContextKey]; got != "gh.org.acme" || *f.encrypt[0].KeyId != "alias/access-roster" {
		t.Errorf("Encrypt was asked for context %q key %q", got, *f.encrypt[0].KeyId)
	}
	if _, err = s.Unwrap(ctx, w, "gh.org.other"); !errors.Is(err, port.ErrUnwrap) {
		t.Fatalf("Unwrap under another binding: %v, want ErrUnwrap", err)
	}
	if got, err := s.Unwrap(ctx, w, "gh.org.acme"); err != nil || !strings.HasPrefix(string(got), "0123") {
		t.Fatalf("Unwrap: %q %v", got, err)
	}
	if *f.decrypt[len(f.decrypt)-1].KeyId != "alias/access-roster" {
		t.Error("Decrypt did not pin the configured key")
	}
}

func TestADamagedKeyIDInTheEnvelopeIsRefused(t *testing.T) {
	f := &fake{keyID: arn}
	s := sealer(t, f)
	w, _ := s.Wrap(context.Background(), []byte("k"), "b")
	w.KeyID = "arn:aws:kms:eu-west-1:111122223333:key/other"
	if _, err := s.Unwrap(context.Background(), w, "b"); !errors.Is(err, port.ErrUnwrap) {
		t.Fatalf("%v, want ErrUnwrap", err)
	}
}

func TestRefusalsAreUnwrapAndOutagesAreUnavailable(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"revoked":       {&types.KMSInvalidStateException{}, port.ErrUnwrap},
		"disabled":      {&types.DisabledException{}, port.ErrUnwrap},
		"wrong key":     {&types.IncorrectKeyException{}, port.ErrUnwrap},
		"unknown key":   {&types.NotFoundException{}, port.ErrUnwrap},
		"access denied": {errors.New("AccessDeniedException"), port.ErrUnavailable},
		"throttled":     {&types.LimitExceededException{}, port.ErrUnavailable},
	} {
		s := sealer(t, &fake{keyID: arn, err: tc.err})
		if _, err := s.Unwrap(context.Background(), port.Wrapped{KeyID: arn, Blob: []byte("x")}, "b"); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	s := sealer(t, &fake{keyID: arn, err: &types.DisabledException{}})
	if _, err := s.Wrap(context.Background(), []byte("k"), "b"); !errors.Is(err, port.ErrUnavailable) {
		t.Errorf("Wrap with a disabled key: %v, want ErrUnavailable", err)
	}
}

func TestEveryUnwrapIsOneKMSCall(t *testing.T) {
	f := &fake{keyID: arn}
	s := sealer(t, f)
	ctx := context.Background()
	sealed, err := port.Seal(ctx, s, []byte("secret"), "app.x")
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err = port.Open(ctx, s, sealed, "app.x"); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.decrypt) != 3 {
		t.Fatalf("%d Decrypt calls for 3 opens: a data key must not be cached past the call", len(f.decrypt))
	}
}

func TestTheKeyIsRequired(t *testing.T) {
	if _, err := kmsseal.NewWithAPI(&fake{}, kmsseal.Config{}); err == nil {
		t.Fatal("an empty key was accepted")
	}
}
