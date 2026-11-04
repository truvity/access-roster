//go:build !sluis_card

package card

// HasCardSupport is false in a build without the tag sluis_card: the driver's logic runs, over a fake card in the
// tests, and Open says why it cannot open a real one.
const HasCardSupport = false

// Open always fails in a build without card support.
func Open(uint32) (Card, error) { return nil, ErrNoCardSupport }
