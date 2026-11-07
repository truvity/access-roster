package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	krefusal "github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// The key commands of the hand-off (ADR 0024, "The hand-off"; cli.md, "sluis key request" and "sluis key install"). This
// file holds what they share: the exit code of a refusal by key@, the call to key@'s admin socket, the files they write
// and read.

// exitKeyRefused is exit code 4 of cli.md: key@ or the card refused.
const exitKeyRefused = 4

// defaultRequestDir is where `key request` writes and `key install` looks for the requests it made (cli.md).
const defaultRequestDir = "/var/lib/sluis/keys/request"

// handoffPurpose is the one purpose the first working version hands off.
const handoffPurpose = "x509-intermediate"

// keyRefusedError is a refusal by key@ (or by the card behind it): exit code 4, with key@'s closed reason and the place
// it names.
type keyRefusedError struct {
	reasons []string
}

func (e *keyRefusedError) Error() string {
	return "key@ refused: " + strings.Join(e.reasons, ", ")
}

func (e *keyRefusedError) Reasons() []string { return e.reasons }

// handoffClient dials key@'s admin socket of the boundary.
func (a *app) handoffClient(socket string) keyv2alpha1connect.KeyHandoffServiceClient {
	if socket == "" {
		socket = filepath.Join(keyAdminSocketPrefix, a.boundary, "admin.sock")
	}
	hc, url := rpc.Dial(socket)
	return keyv2alpha1connect.NewKeyHandoffServiceClient(hc, url, rpc.ClientOptions()...)
}

// keyCallError turns an error of a call to key@ into the error of the command: a refusal (exit 4) when key@ answered
// with a reason of its own, and a failure otherwise.
func keyCallError(command string, err error) error {
	if reason, ok := krefusal.Reason(err); ok {
		reasons := []string{reason}
		if p, _ := krefusal.FieldPath(err); p != "" && p != reason {
			reasons = append(reasons, p)
		}
		return &keyRefusedError{reasons: reasons}
	}
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied:
		return &keyRefusedError{reasons: []string{"caller"}}
	case connect.CodeUnavailable:
		return fmt.Errorf("%s: key@'s admin socket cannot be reached (is key@ running, and are you root?)", command)
	}
	return fmt.Errorf("%s: key@ answered %s", command, connect.CodeOf(err))
}

// fingerprint is the fingerprint of an X.509 key in the hand-off: the SHA-256 of its DER SubjectPublicKeyInfo, which the
// person at the ceremony compares with the one the certifier shows (contract, "Messages and files").
func fingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

func fileDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// repeated is a flag that may be given more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// writeNew writes a file that is read by others, 0644, through a temporary name, and refuses to replace an existing one
// unless replace is set.
func writeNew(path string, data []byte, replace bool) error {
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s exists (remove it, or use --replace)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".handoff-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !replace {
		// link fails when the name appeared since the check: a request is never silently replaced.
		if err := os.Link(tmp.Name(), path); err != nil {
			return err
		}
		return nil
	}
	return os.Rename(tmp.Name(), path)
}
