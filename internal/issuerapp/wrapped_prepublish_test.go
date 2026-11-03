package issuerapp

import (
	"testing"
	"time"

	"github.com/truvity/sluis/internal/config"
	"github.com/truvity/sluis/storage/keys"
)

// Unset, `signingKey.kmsWrapped.prepublish` is half of `rotateEvery` (12h with
// the default 24h), and never shorter than `signingKey.activationDelay`; a value
// set is kept.
func TestKMSWrappedPrepublishDefaultsToHalfTheRotation(t *testing.T) {
	d := func(s string) *config.Duration {
		v, err := time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
		c := config.Duration(v)
		return &c
	}
	for name, tc := range map[string]struct {
		wrapped    config.SigningKeyKMSWrapped
		activation *config.Duration
		prepublish time.Duration
		retain     time.Duration
	}{
		"the defaults":      {config.SigningKeyKMSWrapped{}, nil, 12 * time.Hour, time.Hour + 5*time.Minute},
		"a weekly rotation": {config.SigningKeyKMSWrapped{RotateEvery: d("168h")}, nil, 84 * time.Hour, time.Hour + 5*time.Minute},
		"a short rotation":  {config.SigningKeyKMSWrapped{RotateEvery: d("20m")}, nil, 15 * time.Minute, time.Hour + 5*time.Minute},
		"a long activation": {config.SigningKeyKMSWrapped{}, d("13h"), 13 * time.Hour, time.Hour + 5*time.Minute},
		"set":               {config.SigningKeyKMSWrapped{Prepublish: d("15m"), Retain: d("25h")}, nil, 15 * time.Minute, 25 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			k := tc.wrapped
			k.StateSecret = "issuer/state-secret"
			f := &config.Serve{
				IssuerURL: "https://issuer.example", Instance: "acme",
				Keys:       &keys.Config{Adapter: "kms", Keys: map[keys.Purpose]keys.Entry{keys.Sign: {Key: "alias/sluis-acme-sign"}}},
				SigningKey: &config.SigningKey{KMSWrapped: &k, ActivationDelay: tc.activation},
			}
			cfg, err := FromConfig(withPolicy(t, f))
			if err != nil {
				t.Fatal(err)
			}
			wc, err := cfg.wrappedConfig()
			if err != nil {
				t.Fatal(err)
			}
			if wc.Prepublish != tc.prepublish || wc.Retain != tc.retain {
				t.Errorf("prepublish %s, retain %s; want %s and %s", wc.Prepublish, wc.Retain, tc.prepublish, tc.retain)
			}
		})
	}
}
