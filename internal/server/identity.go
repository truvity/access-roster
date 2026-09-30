package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/internal/access"
)

type identityKey struct{}

// WithIdentity puts an authorized identity in the context. The console's
// middleware does it once per request; handlers only read.
func WithIdentity(ctx context.Context, id access.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the identity a request carries.
func IdentityFrom(ctx context.Context) (access.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(access.Identity)
	return id, ok
}

// requireRole is the gate every operator handler opens with.
func requireRole(ctx context.Context, want access.Role) (access.Identity, error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return access.Identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	if !id.Can(want) {
		return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("this needs the %s role", want))
	}
	return id, nil
}

// requireWorkspace is requireRole for something done TO one workspace: it
// passes for an installation-wide role, and for a role held over that
// workspace alone.
//
// The refusal names the workspace. An operator of one tenant told simply
// "this needs the operator role" would reasonably think their role had
// been lost, rather than that they had acted on somebody else's directory.
func requireWorkspace(ctx context.Context, want access.Role, workspace string) (access.Identity, error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return access.Identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	if !id.CanFor(want, workspace) {
		return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("this needs the %s role over %s", want, workspace))
	}
	return id, nil
}

// requireAnywhere is the gate on a page that lists workspaces and then
// shows only the ones the caller may see.
func requireAnywhere(ctx context.Context, want access.Role) (access.Identity, error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return access.Identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	if !id.CanAnywhere(want) {
		return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("this needs the %s role", want))
	}
	return id, nil
}

// requireOwner is the gate on something done TO a thing another party owns:
// a GitHub organisation, and — with the same mechanism — a Slack
// workspace. It is the one rule for "who may operate this":
//
//   - owner empty: nobody owns it, so only the installation-wide role
//     passes ([requireRole]);
//   - owner set: the installation-wide role passes, and so does the same
//     role held over that one directory workspace ([requireWorkspace]).
//
// owner is a directory workspace id, read from the policy (for a GitHub
// organisation, `github.<org>.owner`). subject names the thing acted on
// — the organisation's login — so the refusal says whose directory the
// caller was missing rather than that a role was lost.
func requireOwner(ctx context.Context, want access.Role, owner, subject string) (access.Identity, error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return access.Identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	if owner == "" {
		if !id.Can(want) {
			return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
				fmt.Errorf("this needs the installation-wide %s role: %s names no owning directory", want, subject))
		}
		return id, nil
	}
	if !id.CanFor(want, owner) {
		return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("this needs the %s role over %s's directory", want, subject))
	}
	return id, nil
}
