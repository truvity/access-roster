// Package refusal makes and reads the Connect errors of sluis: a Connect code plus the
// sluis.type.v2alpha1.Refusal detail, which names the rule that refused and the path of the field at fault, and
// never a value (docs/reference/contracts.md, "Errors").
//
// Inside sluis the detail travels with the error so that the calling actor can act on it. At entry it is removed
// with Strip, because a public caller gets the code and a fixed message only ("Uniform refusals at the edge").
package refusal

import (
	"errors"
	"strings"

	"connectrpc.com/connect"

	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// New returns a Connect error with the code and the Refusal detail. The reason is a word from the closed list of
// the contract that refuses (contracts.md, store-api.md "Refusals"), and fieldPath is the path of the field at
// fault, or "" when none is. The message of the error is the reason: it never holds a value of the request.
func New(code connect.Code, reason, fieldPath string) *connect.Error {
	err := connect.NewError(code, errors.New(reason))
	if d, derr := connect.NewErrorDetail(&typev2alpha1.Refusal{Reason: reason, FieldPath: fieldPath}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

// Reason returns the reason of the Refusal detail of err, or false when err is not a Connect error or carries none.
func Reason(err error) (reason string, ok bool) {
	r, ok := detail(err)
	if !ok {
		return "", false
	}
	return r.GetReason(), true
}

// FieldPath returns the field path of the Refusal detail of err, or false when there is none.
func FieldPath(err error) (path string, ok bool) {
	r, ok := detail(err)
	if !ok {
		return "", false
	}
	return r.GetFieldPath(), true
}

func detail(err error) (*typev2alpha1.Refusal, bool) {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return nil, false
	}
	for _, d := range cerr.Details() {
		v, derr := d.Value()
		if derr != nil {
			continue
		}
		if r, ok := v.(*typev2alpha1.Refusal); ok {
			return r, true
		}
	}
	return nil, false
}

// Strip returns the error for an entry-facing reply: the code of err and a fixed message for that code, with no
// detail, no metadata and nothing of the cause. An error that is not a Connect error becomes internal
// (contracts.md, "Uniform refusals at the edge").
func Strip(err error) *connect.Error {
	code := connect.CodeInternal
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		code = cerr.Code()
	}
	return connect.NewError(code, errors.New(fixedMessage(code)))
}

func fixedMessage(code connect.Code) string {
	return strings.ReplaceAll(code.String(), "_", " ")
}
