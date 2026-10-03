// Package portstoretest is the harness every test of a domain store on the
// ports runs over: State in memory and on an embedded NATS JetStream, sealed by
// the in-process Sealer and by the KMS adapter over a fake KMS, each with a
// way to open another "process" onto the same State.
package portstoretest

import (
	"bytes"
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/kmsseal"
	"github.com/truvity/access-roster/internal/port/memory"
	natsport "github.com/truvity/access-roster/internal/port/nats"
)

// kmsFake is a KMS that "encrypts" by prefixing the context, so a different
// context or ciphertext is refused the way KMS refuses it.
type kmsFake struct{ calls atomic.Int64 }

const kmsARN = "arn:aws:kms:eu-west-1:111122223333:key/1234"

func (f *kmsFake) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.calls.Add(1)
	blob := append([]byte(kmsARN+"|"+in.EncryptionContext[kmsseal.ContextKey]+"|"), in.Plaintext...)
	id := kmsARN
	return &kms.EncryptOutput{CiphertextBlob: blob, KeyId: &id}, nil
}

func (f *kmsFake) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.calls.Add(1)
	parts := bytes.SplitN(in.CiphertextBlob, []byte("|"), 3)
	if len(parts) != 3 || string(parts[1]) != in.EncryptionContext[kmsseal.ContextKey] {
		return nil, &types.InvalidCiphertextException{}
	}
	id := string(parts[0])
	return &kms.DecryptOutput{Plaintext: parts[2], KeyId: &id}, nil
}

// env is one composition under test: a State, a Sealer, and how to open
// another "process" onto the same State and Sealer (two replicas of the
// service, or the host's runner and the guest's).
type Env struct {
	Name string
	// Open is a new "process" onto the same State and Sealer.
	Open func(t *testing.T) port.Set
	// Advance moves every process's clock forward, so a lifetime can be
	// crossed without sleeping.
	Advance func(time.Duration)
}

var buckets atomic.Int64

// Envs are the compositions every domain store runs over: memory and an
// embedded NATS JetStream for State, the in-process Sealer and the KMS adapter
// (over a fake KMS) for sealing.
func Envs(t *testing.T) []Env {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(20 * time.Second) {
		t.Fatal("the test server did not start")
	}
	t.Cleanup(srv.Shutdown)

	kmsSealer, err := kmsseal.NewWithAPI(&kmsFake{}, kmsseal.Config{KeyID: "alias/access-roster"})
	if err != nil {
		t.Fatal(err)
	}

	// memory: every "process" is the same store.
	mem := func(sealer func(*memory.Store) port.Sealer) func(*testing.T) Env {
		return func(*testing.T) Env {
			m := memory.New()
			set := m.Set()
			set.Sealer = sealer(m)
			return Env{Open: func(*testing.T) port.Set { return set }, Advance: m.Advance}
		}
	}
	// nats: every "process" is its own connection to the same bucket, so
	// what one writes the other reads over the server, and a clock advance
	// moves every connection's.
	natsEnv := func(sealer port.Sealer) Env {
		bucket := "ds" + strconv.FormatInt(buckets.Add(1), 10)
		var stores []*natsport.Store
		return Env{
			Open: func(t *testing.T) port.Set {
				s, err := natsport.Open(context.Background(), natsport.Config{URL: srv.ClientURL(), Bucket: bucket, Replicas: 1})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(s.Close)
				stores = append(stores, s)
				set := s.Set()
				set.Sealer = sealer
				return set
			},
			Advance: func(d time.Duration) {
				for _, s := range stores {
					s.Advance(d)
				}
			},
		}
	}

	memSealer := memory.New().Set().Sealer
	out := []Env{
		mem(func(m *memory.Store) port.Sealer { return m })(t),
		mem(func(*memory.Store) port.Sealer { return kmsSealer })(t),
		natsEnv(memSealer),
		natsEnv(kmsSealer),
	}
	out[0].Name, out[1].Name, out[2].Name, out[3].Name = "memory+memory-sealer", "memory+kms-fake", "nats+memory-sealer", "nats+kms-fake"
	return out
}

// Each runs a test over every composition.
func Each(t *testing.T, test func(t *testing.T, e Env)) {
	t.Helper()
	for _, e := range Envs(t) {
		t.Run(e.Name, func(t *testing.T) { test(t, e) })
	}
}
