package main

import "strings"

// envBaoLoginNamespace is accessctl's OWN variable, read only when
// --login-ns is not given -- and named apart from BAO_NAMESPACE /
// VAULT_NAMESPACE (envOpenBAONamespace, envVaultNamespace in
// openbao.go) on purpose. Those two name the namespace `bao`/`pg`/`psql`
// are about to OPERATE in, read the same way bao itself reads them; an
// installation that keeps every login at one parent namespace while the
// data a caller asks for lives in a child
// (docs/connect/openbao.md#logins-at-a-parent-namespace) needs a SECOND
// setting, not a second meaning piled onto the first one -- reusing
// BAO_NAMESPACE for it would collide with bao's own reading of that
// variable the moment the two ever differ, which is the whole reason
// this exists. The ACCESSCTL_ prefix says plainly that this is
// accessctl's own idea, not OpenBAO's or bao's.
const envBaoLoginNamespace = "ACCESSCTL_BAO_LOGIN_NAMESPACE"

// resolveLoginNamespace is where the login happens: --login-ns (already
// read into flagValue by the caller's own flag set), else
// $ACCESSCTL_BAO_LOGIN_NAMESPACE, else target -- the same precedence
// order (flag, then environment) every other setting in this tool uses.
// Falling back to target, unchanged, is what keeps today's behaviour
// exactly as it was for a caller who has never heard of this flag: the
// login happens in the namespace the command targets, same as before
// this existed.
func resolveLoginNamespace(flagValue, target string) string {
	if flagValue = strings.TrimSpace(flagValue); flagValue != "" {
		return flagValue
	}
	if envValue := firstEnv(envBaoLoginNamespace); envValue != "" {
		return envValue
	}
	return target
}

// namespaceCovers reports whether target is loginNamespace itself or a
// DESCENDANT of it, one path segment at a time: OpenBAO namespaces nest
// on "/", so "dev" is not a parent of "devel" even though it reads as a
// string prefix of it -- only a full segment, followed by "/", counts.
// An empty loginNamespace is root, the parent of every namespace there
// is, which is why root always covers.
func namespaceCovers(loginNamespace, target string) bool {
	if loginNamespace == "" || loginNamespace == target {
		return true
	}
	return strings.HasPrefix(target, loginNamespace+"/")
}

// checkNamespaceLogin refuses, as a usage error and before any exchange
// is made, a target namespace the login namespace could not mint a
// token for. A token minted by logging in to one OpenBAO namespace is
// only valid there and in its children, never in a sibling
// (docs/decisions/0013-openbao-access-through-the-bao-cli.md) -- so
// letting this through would only fail later, at OpenBAO's own login
// call, as a permission-denied that reads as an outage rather than as
// the namespace mismatch it actually is.
func checkNamespaceLogin(loginNamespace, target string) error {
	if namespaceCovers(loginNamespace, target) {
		return nil
	}
	label := loginNamespace
	if label == "" {
		label = "root"
	}
	return badUsage(
		"-ns=%s is not %s or a descendant of it, so a token from logging in at %s would not be valid there "+
			"-- pass --login-ns=%s (or a namespace that is a parent of both), or drop --login-ns/$%s "+
			"to log in at %s directly",
		target, label, label, target, envBaoLoginNamespace, target)
}
