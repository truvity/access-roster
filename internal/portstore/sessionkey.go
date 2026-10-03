package portstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/truvity/access-roster/internal/port"
)

const sessionKeyKey = "rec.console.session-key"

// SessionKey returns the key the console signs its sessions with, creating it
// the first time. It is sealed in State under one key, so every replica reads
// the same one: the first writer wins the Create and the others read what it
// wrote.
func (b *Base) SessionKey(ctx context.Context, generate func() ([]byte, error)) ([]byte, error) {
	for range attempts {
		rec, err := b.State.Get(ctx, sessionKeyKey)
		switch {
		case err == nil:
			key, oerr := b.open(ctx, sessionKeyKey, rec.Value)
			if oerr != nil {
				return nil, fmt.Errorf("portstore: open the session key: %w", oerr)
			}
			return key, nil
		case !errors.Is(err, port.ErrNotFound):
			return nil, err
		}
		key, err := generate()
		if err != nil {
			return nil, err
		}
		sealed, err := b.seal(ctx, sessionKeyKey, key)
		if err != nil {
			return nil, err
		}
		if _, err = b.State.Create(ctx, sessionKeyKey, sealed, 0); err == nil {
			return key, nil
		} else if !errors.Is(err, port.ErrExists) {
			return nil, err
		}
	}
	return nil, ErrBusy
}

// PutSessionKey replaces the key the console signs its sessions with, which a
// migration does when it carries the source's key over a different one.
func (b *Base) PutSessionKey(ctx context.Context, key []byte) error {
	sealed, err := b.seal(ctx, sessionKeyKey, key)
	if err != nil {
		return err
	}
	_, err = b.State.Put(ctx, sessionKeyKey, sealed, 0)
	return err
}

// CheckSealer proves the Sealer can seal and open, so that a deployment whose
// adapter has none (the legacy one, whose Sealer is refused on purpose) stops
// at start naming the setting, instead of failing on the first credential an
// operator connects.
func (b *Base) CheckSealer(ctx context.Context) error {
	const probe = "rec.console.probe"
	sealed, err := b.seal(ctx, probe, []byte("probe"))
	if err == nil {
		var plain []byte
		if plain, err = b.open(ctx, probe, sealed); err == nil && string(plain) != "probe" {
			err = errors.New("the sealer opened another value than it sealed")
		}
	}
	if err != nil {
		return fmt.Errorf("the credentials are sealed before they are stored, and this adapter's Sealer cannot: "+
			"set ports.sealer (for example kms): %w", err)
	}
	return nil
}
