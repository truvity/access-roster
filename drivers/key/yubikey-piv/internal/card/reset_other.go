//go:build sluis_card && !(linux || darwin)

package card

import "errors"

// resetReader is not available on this platform: the boards are Linux, and the driver fails closed elsewhere.
func resetReader(string) error { return errors.New("card: reset: not supported on this platform") }
