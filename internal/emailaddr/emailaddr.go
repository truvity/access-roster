// Package emailaddr splits addresses the way the hub routes them: by the
// domain after the last '@', lower-cased. Routing by domain is the whole
// contract, so the one place that decides what "the domain of an address"
// means lives here.
package emailaddr

import "strings"

// Domain returns the lower-cased domain of an address and true, or "" and
// false when the input has no '@' with something on both sides. Leading and
// trailing white space is ignored; nothing else is normalised — the
// backend, not the hub, decides what a valid local part is.
func Domain(address string) (string, bool) {
	address = strings.TrimSpace(address)
	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 {
		return "", false
	}
	return strings.ToLower(address[at+1:]), true
}
