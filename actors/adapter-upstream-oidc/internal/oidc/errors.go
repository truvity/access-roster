// Package oidc is the part of adapter-upstream-oidc that speaks OpenID Connect to an upstream provider: discovery,
// the code exchange, and the strict check of the ID token. It decides nothing about who may do what (ADR 0025).
//
// Every network call passes an egress policy: the address is checked after the name is resolved (REQ-FED-008), and a
// call goes only to the host the Upstream declares (REQ-ISO-110). An error names the path of the field at fault and
// never a value, and no error text of the upstream crosses the package (ADR 0025, "Adapters and connections").
package oidc

import (
	"errors"
	"net/url"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// The Refusal reasons of the integration contracts (docs/reference/contracts.md, "Connect codes"), each with its one
// Connect code.
const (
	ReasonUnavailable = "UNAVAILABLE"       // unavailable: the upstream or a dependency is down
	ReasonRejected    = "UPSTREAM_REJECTED" // failed_precondition: the upstream said no, or what it said does not verify
	ReasonInvalid     = "INVALID"           // invalid_argument: the request does not fit the contract
	ReasonNotFound    = "NOT_FOUND"         // not_found: no such upstream
	ReasonRateLimited = "RATE_LIMITED"      // resource_exhausted
	ReasonUnsupported = "UNSUPPORTED"       // unimplemented: outside what this adapter does
)

// Unavailable is the refusal for a dependency that is down.
func Unavailable(path string) error {
	return refusal.New(connect.CodeUnavailable, ReasonUnavailable, path)
}

// Rejected is the refusal for an answer of the upstream that does not verify, or that says no.
func Rejected(path string) error {
	return refusal.New(connect.CodeFailedPrecondition, ReasonRejected, path)
}

// Invalid is the refusal for a request that does not fit the contract.
func Invalid(path string) error {
	return refusal.New(connect.CodeInvalidArgument, ReasonInvalid, path)
}

// NotFound is the refusal for an upstream that does not exist.
func NotFound(path string) error { return refusal.New(connect.CodeNotFound, ReasonNotFound, path) }

// RateLimited is the refusal for an upstream that asks to slow down.
func RateLimited(path string) error {
	return refusal.New(connect.CodeResourceExhausted, ReasonRateLimited, path)
}

// Unsupported is the refusal for something this adapter does not do.
func Unsupported(path string) error {
	return refusal.New(connect.CodeUnimplemented, ReasonUnsupported, path)
}

// transport turns an error of the HTTP client into a refusal. The error of the client holds the URL, which may hold a
// query, so nothing of it is kept; the egress refusals are told apart because they are a policy decision, not an outage.
func transport(path string, err error) error {
	var blocked *blockedError
	if errors.As(err, &blocked) {
		return Unsupported(path)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.As(err, &blocked) {
		return Unsupported(path)
	}
	return Unavailable(path)
}
