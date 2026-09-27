package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// bao authenticates to OpenBAO and then runs the real `bao` binary,
// unchanged from there on. See docs/decisions/0013-openbao-access-through-the-bao-cli.md
// for why: accessctl stopped reimplementing OpenBAO's own features one
// `accessctl credential` kind at a time, and instead authenticates once
// and gets out of the way.
//
// Two authentication paths share this file with `accessctl credential`
// and `accessctl token`: the sign-in (or a job's own identity) is
// exchanged for `--audience` (openbao by default), and the result logs
// in on the JWT mount. What is different from `credential` is what
// happens to the login afterwards -- it is cached rather than revoked,
// because this command is meant to be run often, and it is handed to a
// CHILD process rather than consumed by one call this binary makes
// itself.
func bao(args []string) error {
	request, rest, err := parseBaoFlags(args)
	if err != nil {
		return err
	}
	if request.forget {
		return forgetBaoToken(request)
	}
	if len(rest) == 0 {
		return badUsage("no bao command: `accessctl bao <args…>`, e.g. `accessctl bao kv get -mount=team secret/path`")
	}

	binary, err := exec.LookPath("bao")
	if err != nil {
		return fmt.Errorf("%w: no `bao` on PATH -- install OpenBAO's CLI "+
			"(https://openbao.org/docs/install) and try again", errUnreachable)
	}

	cfg, err := loadConfig(request.issuer, request.clientID)
	if err != nil {
		return err
	}
	token, err := baoToken(context.Background(), cfg, request)
	if err != nil {
		return err
	}

	if intercepted, err := interceptFormatEnv(binary, rest, request, token); intercepted {
		return err
	}

	return runChild(binary, rest, baoChildEnv(request, token))
}

// runChild is execChildProcess (bao_exec_unix.go, bao_exec_windows.go) --
// a variable only so a test can substitute something that does not
// replace the test binary's own process image, the same seam io.go's
// `stdout` is for capturing what a command printed. `accessctl bao` and
// `accessctl pg`/`psql` (pg.go) both take over the process this way: an
// arbitrary command handed a certificate is no different, at the exec
// layer, from `bao` handed a token.
var runChild = execChildProcess

// baoRequest is accessctl's OWN half of the command line -- everything
// before the bao subcommand. `rest`, the bao subcommand and every
// argument after it, is never parsed as flags here: see parseBaoFlags.
type baoRequest struct {
	issuer   string
	clientID string
	audience string

	address string
	caCert  string
	roots   *x509.CertPool

	mount     string
	loginRole string

	// namespace is read out of `rest` (bao's own -namespace flag) or the
	// environment -- see intendedNamespace. It is where the real `bao`
	// command is about to OPERATE, which is not necessarily where the
	// login happens any more -- see loginNamespace.
	namespace string

	// loginNamespace is where the LOGIN happens: --login-ns, else
	// $ACCESSCTL_BAO_LOGIN_NAMESPACE, else namespace itself (today's
	// behaviour, unchanged when neither is set) -- see
	// resolveLoginNamespace. It is always namespace itself or an ancestor
	// of it (checkNamespaceLogin refuses anything else before any
	// exchange is made), because a token minted at loginNamespace is only
	// valid there and in its children.
	loginNamespace string

	forget bool
}

// parseBaoFlags reads accessctl's own flags and returns everything after
// them unparsed, for `bao` itself to make of what it will.
//
// The separation rule is exactly Go's flag package's own default
// behaviour: parsing stops at the first argument that is not one of
// accessctl's declared flags, which for this command is the bao
// subcommand (`kv`, `ssh`, `write`, `login`, ...) -- an ordinary word,
// never a flag. Accessctl's own flags therefore go BEFORE the
// subcommand; bao's own flags, including its `-namespace`, go AFTER it,
// exactly where bao has always accepted them
// (`bao kv get -namespace=dev secret/foo`). There is one rule to
// remember, and it costs nothing new to a `bao` invocation that never
// put a global flag before its subcommand in the first place.
func parseBaoFlags(args []string) (baoRequest, []string, error) {
	var request baoRequest
	flags := flag.NewFlagSet("bao", flag.ContinueOnError)
	flags.StringVar(&request.issuer, "issuer", "", "the issuer, when not configured")
	flags.StringVar(&request.clientID, "client", "", "the client to present")
	flags.StringVar(&request.audience, "audience", openbaoAudience, "the exchange client OpenBAO accepts")
	flags.StringVar(&request.address, "address", "",
		"the OpenBAO API, e.g. https://openbao.example:8200 (default: $"+envOpenBAOAddress+", then $"+envVaultAddress+")")
	flags.StringVar(&request.caCert, "ca-cert", "",
		"a PEM bundle to trust for the OpenBAO connection, added to the system's roots "+
			"(default: $"+envOpenBAOCACert+", then $"+envVaultCACert+")")
	flags.StringVar(&request.mount, "mount", rosterMount, "the JWT auth mount to log in on")
	flags.StringVar(&request.loginRole, "login-role", rosterLoginRole, "the role on that mount")
	var loginNS string
	flags.StringVar(&loginNS, "login-ns", "",
		"the OpenBAO namespace to log in at, when it differs from the namespace bao is about to operate "+
			"in -- must be that namespace or a parent of it (default: bao's own namespace; then $"+envBaoLoginNamespace+")")
	flags.BoolVar(&request.forget, "forget", false,
		"revoke the cached OpenBAO token and forget it, then exit (no bao command needed)")

	if err := flags.Parse(args); err != nil {
		return baoRequest{}, nil, usageError{err}
	}
	rest := flags.Args()

	if request.address = strings.TrimSpace(request.address); request.address == "" {
		request.address = firstEnv(envOpenBAOAddress, envVaultAddress)
	}
	if request.address == "" {
		return baoRequest{}, nil, badUsage("no OpenBAO address: pass --address https://openbao.example:8200, "+
			"or export %s=https://openbao.example:8200 (%s is read too)", envOpenBAOAddress, envVaultAddress)
	}
	request.address = strings.TrimSuffix(request.address, "/")

	if request.caCert = strings.TrimSpace(request.caCert); request.caCert == "" {
		request.caCert = firstEnv(envOpenBAOCACert, envVaultCACert)
	}
	if request.caCert != "" {
		roots, err := openbaoRoots(request.caCert)
		if err != nil {
			return baoRequest{}, nil, err
		}
		request.roots = roots
	}

	if strings.TrimSpace(request.audience) == "" {
		return baoRequest{}, nil,
			badUsage("--audience cannot be empty: a token for nothing in particular is what an audience prevents")
	}

	request.namespace = intendedNamespace(rest)
	request.loginNamespace = resolveLoginNamespace(loginNS, request.namespace)
	// --forget runs no bao command at all, so `rest` (and therefore
	// request.namespace, which is read out of it) names no real target --
	// intendedNamespace's default of root is not "about to operate at
	// root", just "nothing to read a target from". Validating it against
	// --login-ns here would refuse a perfectly good
	// `--login-ns=devel --forget`, which only ever clears devel's own
	// cache entry and touches no target namespace at all.
	if !request.forget {
		if err := checkNamespaceLogin(request.loginNamespace, request.namespace); err != nil {
			return baoRequest{}, nil, err
		}
	}
	return request, rest, nil
}

// intendedNamespace is the namespace the REAL bao command is about to
// operate in, read the same way bao itself would resolve it: its own
// `-namespace`/`--namespace` flag, or bao's own documented shortcut
// `-ns`/`--ns` (bao's own `-h` names it: "-ns can be used as shortcut"),
// wherever either appears among the arguments handed to it, then
// BAO_NAMESPACE, then VAULT_NAMESPACE, then root -- a flag beating the
// environment, exactly as it does for bao's every other setting. The
// two spellings are ONE setting, so whichever was typed LAST wins,
// regardless of which of the two it was (readFlagValue's own rule).
//
// This is the ONE piece of bao's own syntax this file reads, and it
// reads it rather than guessing because the login has to happen HERE, or
// somewhere that covers it: a token minted by logging in to one OpenBAO
// namespace is only valid there and in its children, never in a sibling
// (docs/decisions/0013-openbao-access-through-the-bao-cli.md) -- by
// default the login happens in exactly this namespace (--login-ns and
// $ACCESSCTL_BAO_LOGIN_NAMESPACE let it happen at a parent instead, see
// login_namespace.go). Missing the `-ns` shortcut here would log in to
// the wrong namespace silently -- bao then refuses every call with a
// permission-denied that reads as an outage, not as a namespace
// mismatch.
func intendedNamespace(args []string) string {
	if value, ok := readFlagValue(args, "namespace", "ns"); ok {
		return value
	}
	return firstEnv(envOpenBAONamespace, envVaultNamespace)
}

// baoToken returns a usable OpenBAO token for `accessctl bao` itself --
// openBAOLogin, below, applied to this request's own fields. The LOGIN
// happens at request.loginNamespace, which defaults to request.namespace
// (the namespace bao is about to operate in) and is never anything the
// caller did not ask for: checkNamespaceLogin already refused, during
// parsing, any request.namespace loginNamespace would not cover.
func baoToken(ctx context.Context, cfg Config, request baoRequest) (cachedBaoToken, error) {
	return openBAOLogin(ctx, cfg, request.address, request.loginNamespace, request.mount, request.loginRole, request.audience, request.roots)
}

// openBAOLogin is the authentication `accessctl bao` and `accessctl
// pg`/`psql` (pg.go) both need: the sign-in (or a job's own identity)
// exchanged for audience, then logged in to the JWT mount, in namespace.
// Minting one only when nothing cached is good enough -- the same
// "mint, cache, lock" shape kube_cache.go and aws_cache.go already use,
// applied to a login instead of an exchange -- and the cache is shared:
// a `bao` invocation and a `psql` one that agree on the address,
// namespace, mount and login role reuse the same login, because it IS
// the same login.
func openBAOLogin(
	ctx context.Context, cfg Config, address, namespace, mount, loginRole, audience string, roots *x509.CertPool,
) (cachedBaoToken, error) {
	identity := baoIdentity(cfg)
	path, cacheErr := baoCachePath(address, namespace, mount, loginRole, identity)
	if cacheErr == nil {
		if cached, ok := readBaoCache(path); ok {
			return cached, nil
		}
	}

	mint := func() (cachedBaoToken, error) {
		// Re-read under the lock: a caller that waited here while another
		// logged in finds the answer already written, which is the whole
		// point -- one login, not one per caller.
		if cacheErr == nil {
			if cached, ok := readBaoCache(path); ok {
				return cached, nil
			}
		}

		held, err := proofFor(ctx, cfg, audience)
		if err != nil {
			return cachedBaoToken{}, err
		}
		issued, err := exchangeAs(ctx, cfg.Issuer, held.Client, held.Subject, held.Type, audience)
		if err != nil {
			return cachedBaoToken{}, err
		}

		client := &openbao{Address: address, Namespace: namespace, Client: retryingClientTrusting(roots)}
		expires, ok, err := client.loginExpiry(ctx, mount, loginRole, issued.AccessToken)
		if err != nil {
			return cachedBaoToken{}, err
		}
		cached := cachedBaoToken{Token: client.token}
		if ok {
			cached.Expires = expires
			// A cache that cannot be written is not a reason to withhold
			// a token the caller already has.
			if cacheErr == nil {
				_ = writeBaoCache(path, cached)
			}
		}
		return cached, nil
	}

	if cacheErr != nil {
		return mint()
	}

	var result cachedBaoToken
	err := withCacheLock(path, func() error {
		var mintErr error
		result, mintErr = mint()
		return mintErr
	})
	return result, err
}

// baoIdentity is the subject half of the cache key, found without a
// network round trip: it mirrors proofFor's own Name exactly (a job by
// its repository, a person by the sign-in already cached), because that
// is the name the same login would present, and reading it locally is
// what lets `--forget` work without reaching the network at all.
func baoIdentity(cfg Config) string {
	if requestURL, grant := os.Getenv(envGitHubTokenURL), os.Getenv(envGitHubTokenGrant); requestURL != "" && grant != "" {
		return githubSessionName()
	}
	session, _ := loadSession(cfg.Issuer)
	if session.Email != "" {
		return session.Email
	}
	return session.Subject
}

// forgetBaoToken is `accessctl bao --forget`: best-effort revoke, then
// remove the cache entry regardless of whether the revoke succeeded --
// mirroring bao.revokeSelf's own reasoning in openbao.go, a batch token
// cannot be revoked and that must not stop this from forgetting it.
func forgetBaoToken(request baoRequest) error {
	cfg, err := loadConfig(request.issuer, request.clientID)
	if err != nil {
		return err
	}
	path, err := baoCachePath(request.address, request.loginNamespace, request.mount, request.loginRole, baoIdentity(cfg))
	if err != nil {
		return err
	}

	if cached, ok := readBaoCacheFile(path); ok {
		client := &openbao{Address: request.address, Namespace: request.loginNamespace, Client: retryingClientTrusting(request.roots)}
		client.token = cached.Token
		client.revokeSelf(context.Background())
	}
	if err = removeBaoCache(path); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(stdout, "Forgot the cached OpenBAO token.")
	return nil
}

// baoChildEnv is the environment `bao` runs in: the caller's own
// environment, with BAO_ADDR, BAO_TOKEN and (when named) BAO_CACERT set
// or replaced -- and nothing else touched, so BAO_NAMESPACE and every
// other variable the caller already has flow through unchanged.
func baoChildEnv(request baoRequest, token cachedBaoToken) []string {
	env := os.Environ()
	env = setEnv(env, "BAO_ADDR", request.address)
	env = setEnv(env, "BAO_TOKEN", token.Token)
	if request.caCert != "" {
		env = setEnv(env, "BAO_CACERT", request.caCert)
	}
	return env
}

// setEnv replaces every existing entry for key with one entry, key=value
// -- rather than appending a second one and leaving it to whichever the
// C library the child links happens to prefer, unspecified in general.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	kept := env[:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			kept = append(kept, kv)
		}
	}
	return append(kept, prefix+value)
}

// readFlagValue scans args for any of names, each given as `-name value`,
// `-name=value`, or the same with two leading dashes, and returns the
// value from whichever occurrence appears LAST -- the same as a flag
// repeated on a real command line, where the last one wins regardless
// of which alias it was spelled with. names lets a caller read a flag
// bao itself accepts under more than one name (`-namespace`'s own
// shortcut `-ns`) as a single setting, exactly as bao's own flag parser
// does: whichever of the two was typed last decides the value.
func readFlagValue(args []string, names ...string) (string, bool) {
	value, found := "", false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		for _, name := range names {
			for _, dash := range [2]string{"-" + name, "--" + name} {
				switch {
				case arg == dash:
					if i+1 < len(args) {
						value, found = args[i+1], true
					}
				case strings.HasPrefix(arg, dash+"="):
					value, found = strings.TrimPrefix(arg, dash+"="), true
				}
			}
		}
	}
	return value, found
}

// exitCodeError is an exit code chosen by something accessctl wrapped
// rather than by accessctl itself -- bao's own exit, passed through
// unchanged rather than replaced with accessctl's usual 1. Its message is
// empty on purpose: whatever ran already wrote its own error to stderr,
// and main() knows, from the type, to print nothing more.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return "" }

// codeForExit is read by codeFor and main in main.go.
func codeForExit(err error) (int, bool) {
	var code exitCodeError
	if errors.As(err, &code) {
		return code.code, true
	}
	return 0, false
}
