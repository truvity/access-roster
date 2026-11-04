package store

import (
	"fmt"
	"strings"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// The limits of an address (docs/reference/store-api.md, "Address encoding").
const (
	maxPart    = 128
	maxAddress = 300

	// NoTenant is the tenant part of the text form of the address of a kind that has none. It is never on the wire.
	NoTenant = "-"
)

func partChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// validPart reports whether s is a part of an address: 1 to 128 characters of lower-case letters, digits, "-", "_"
// and ".", and never "." or "..".
func validPart(s string) bool {
	if s == "" || len(s) > maxPart || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !partChar(s[i]) {
			return false
		}
	}
	return true
}

func badAddress(path string) error {
	return refusal.New(connect.CodeInvalidArgument, "address", path)
}

// ValidateID checks the id of an address: one or more parts separated by "/", each a valid part
// (store-api.md, "Address encoding"). The error is a Connect error, invalid_argument with the reason "address",
// as the store would refuse it.
func ValidateID(id string) error {
	if id == "" {
		return badAddress("id")
	}
	for _, part := range strings.Split(id, "/") {
		if !validPart(part) {
			return badAddress("id")
		}
	}
	return nil
}

// ValidateAddress checks a whole address <boundary>/<tenant | ->/<kind>/<id>: every part by the rules of
// ValidateID, the tenant "-" when the kind has none, and at most 300 bytes in all. The client sends no boundary;
// this function is for tools and the shared vectors, which test the whole text.
func ValidateAddress(boundary, tenant, kind, id string) error {
	if !validPart(boundary) {
		return badAddress("boundary")
	}
	if !validPart(tenant) {
		return badAddress("tenant")
	}
	if !validPart(kind) {
		return badAddress("kind")
	}
	if err := ValidateID(id); err != nil {
		return err
	}
	if n := len(boundary) + len(tenant) + len(kind) + len(id) + 3; n > maxAddress {
		return badAddress("address")
	}
	return nil
}

// wireTenant checks the tenant of a call and returns it as the Address field carries it: empty for a kind that has
// none (type.proto, Address). Only the text form of an address, <boundary>/<tenant | ->/<kind>/<id>, carries "-"
// there; a tenant id is never "-".
func wireTenant(tenant string) (string, error) {
	if tenant == "" {
		return "", nil
	}
	if tenant == NoTenant || !validPart(tenant) {
		return "", badAddress("tenant")
	}
	return tenant, nil
}

func describe(op string, err error) error {
	return fmt.Errorf("store %s: %w", op, err)
}
