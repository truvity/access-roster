package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// pg authenticates to OpenBAO, mints (or reuses) a Postgres client
// certificate, and runs an arbitrary command with libpq's own
// environment variables pointed at it.
//
// It shares its whole authentication step with `accessctl bao`
// (bao.go's openBAOLogin): the sign-in (or a job's own identity)
// exchanged for the OpenBAO audience, then logged in on the JWT mount --
// in the SAME namespace the certificate is signed in by default, or at a
// parent of it when `--login-ns`/`$ACCESSCTL_BAO_LOGIN_NAMESPACE` says so
// (login_namespace.go). What is different from `bao` is what happens
// after the login -- a `pki/sign/<role>` call rather than a passthrough,
// and the certificate is handed to the command as environment variables
// rather than the login token itself.
func pg(args []string) error {
	request, command, err := parsePgFlags("pg", args)
	if err != nil {
		return err
	}
	if len(command) == 0 {
		return badUsage("no command: `accessctl pg [flags] -- <command> [args…]`, e.g. `accessctl pg -- psql`")
	}
	return runPg(request, command)
}

// psql is `pg -- psql [psql args…]`: a shorthand for the one command
// this exists for. psql's own arguments pass through unchanged; a
// `service=<name>` from a libpq service file, or plain `-h`/`-d`, both
// work exactly as they do run directly.
func psql(args []string) error {
	request, psqlArgs, err := parsePgFlags("psql", args)
	if err != nil {
		return err
	}
	return runPg(request, append([]string{"psql"}, psqlArgs...))
}

// pgRequest is accessctl's own half of the command line for `pg` and
// `psql` alike -- everything before `--` (or before the first argument
// that is not one of accessctl's own flags, exactly as bao.go's own
// separation rule works, since psql's own arguments usually start with
// a flag and need the explicit `--` to avoid being read as accessctl's).
type pgRequest struct {
	issuer   string
	clientID string
	audience string

	address string
	caCert  string
	roots   *x509.CertPool

	// ns is the OpenBAO namespace the PKI mount lives in, and where the
	// certificate is SIGNED -- the flag is spelled short, mirroring bao's
	// own `-namespace`.
	ns string
	// loginNS is where the JWT LOGIN happens: --login-ns, else
	// $ACCESSCTL_BAO_LOGIN_NAMESPACE, else ns itself (today's behaviour,
	// unchanged when neither is set) -- see resolveLoginNamespace. It is
	// always ns itself or an ancestor of it (checkNamespaceLogin refuses
	// anything else before any exchange is made), because a token minted
	// at loginNS is only valid there and in its children, and the sign
	// call is still made in ns.
	loginNS    string
	role       string
	mount      string
	commonName string
}

// parsePgFlags reads accessctl's own flags for `pg`/`psql` and returns
// everything after them (or after a literal `--`) unparsed, for the
// command to make of what it will -- go's own flag.FlagSet.Parse stops
// at the first argument it does not recognise as one of ITS flags, and
// specially stops (and is consumed) at a literal `--`, which is the
// separator to use whenever the command's own first argument is itself
// a flag (`accessctl psql -ns=dev -- -h db.example -d orders`); a bare
// positional argument (a database name, `service=name`) needs no `--`.
func parsePgFlags(name string, args []string) (pgRequest, []string, error) {
	var request pgRequest
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.StringVar(&request.issuer, "issuer", "", "the issuer, when not configured")
	flags.StringVar(&request.clientID, "client", "", "the client to present")
	flags.StringVar(&request.audience, "audience", openbaoAudience, "the exchange client OpenBAO accepts")
	flags.StringVar(&request.address, "address", "",
		"the OpenBAO API, e.g. https://openbao.example:8200 (default: $"+envOpenBAOAddress+", then $"+envVaultAddress+")")
	flags.StringVar(&request.caCert, "ca-cert", "",
		"a PEM bundle to trust for the OpenBAO connection, added to the system's roots "+
			"(default: $"+envOpenBAOCACert+", then $"+envVaultCACert+")")
	flags.StringVar(&request.ns, "ns", "",
		"the OpenBAO namespace the PKI mount lives in (default: $"+envOpenBAONamespace+", then $"+envVaultNamespace+")")
	var loginNS string
	flags.StringVar(&loginNS, "login-ns", "",
		"the OpenBAO namespace to log in at, when it differs from -ns -- must be -ns or a parent of it "+
			"(default: -ns; then $"+envBaoLoginNamespace+")")
	flags.StringVar(&request.role, "role", defaultDBRole, "the OpenBAO PKI role to sign with")
	flags.StringVar(&request.mount, "mount", pkiMount, "the OpenBAO PKI mount")
	flags.StringVar(&request.commonName, "common-name", "", "the common name to ask for (default: the signed-in identity)")

	if err := flags.Parse(args); err != nil {
		return pgRequest{}, nil, usageError{err}
	}
	rest := flags.Args()

	if request.address = strings.TrimSpace(request.address); request.address == "" {
		request.address = firstEnv(envOpenBAOAddress, envVaultAddress)
	}
	if request.address == "" {
		return pgRequest{}, nil, badUsage("no OpenBAO address: pass --address https://openbao.example:8200, "+
			"or export %s=https://openbao.example:8200 (%s is read too)", envOpenBAOAddress, envVaultAddress)
	}
	request.address = strings.TrimSuffix(request.address, "/")

	if request.caCert = strings.TrimSpace(request.caCert); request.caCert == "" {
		request.caCert = firstEnv(envOpenBAOCACert, envVaultCACert)
	}
	if request.caCert != "" {
		roots, err := openbaoRoots(request.caCert)
		if err != nil {
			return pgRequest{}, nil, err
		}
		request.roots = roots
	}

	if request.ns = strings.TrimSpace(request.ns); request.ns == "" {
		request.ns = firstEnv(envOpenBAONamespace, envVaultNamespace)
	}
	if strings.TrimSpace(request.audience) == "" {
		return pgRequest{}, nil,
			badUsage("--audience cannot be empty: a token for nothing in particular is what an audience prevents")
	}

	request.loginNS = resolveLoginNamespace(loginNS, request.ns)
	if err := checkNamespaceLogin(request.loginNS, request.ns); err != nil {
		return pgRequest{}, nil, err
	}

	return request, rest, nil
}

// defaultDBRole is the OpenBAO PKI role `pg`/`psql` signs with when
// `--role` does not say otherwise -- the same name `accessctl credential
// db` always used.
const defaultDBRole = "db-client"

// runPg mints (or reuses) the certificate and hands the command to
// runChild, which takes over this process the same way `accessctl bao`
// does.
func runPg(request pgRequest, command []string) error {
	binary, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("%w: no `%s` on PATH", errUnreachable, command[0])
	}

	cfg, err := loadConfig(request.issuer, request.clientID)
	if err != nil {
		return err
	}

	dir, err := credentialDir(request.address, request.ns, request.role)
	if err != nil {
		return err
	}
	base := filepath.Join(dir, "client")

	issued, err := postgresCertificate(context.Background(), cfg, request, base)
	if err != nil {
		return err
	}

	return runChild(binary, command[1:], pgChildEnv(base, issued.Parsed.Subject.CommonName, issued.Authority != ""))
}

// certReuseMargin is how much life a cached Postgres client certificate
// must still have to be reused rather than re-minted.
//
// Five minutes -- the same margin the AWS credential cache already uses
// (aws_cache.go's awsCacheMargin), reused rather than redeclared, and
// chosen for the same reason: a certificate is handed to a connection
// that is about to authenticate with it and possibly keep using it for a
// while (an interactive `psql` session, a long-running command), so the
// margin has to be wide enough that it is not moments from expiring when
// the connection is made, not just wide enough for one round trip the
// way the OpenBAO login token's own margin (bao_cache.go's
// baoTokenMargin) only needs to be.
const certReuseMargin = awsCacheMargin

// postgresCertificate returns a client certificate for request.role in
// request.ns, at base, reusing one already on disk while it has enough
// life left AND was minted for the SAME common name, minting a fresh
// one under a lock otherwise.
//
// The name is resolved BEFORE the cache is ever read, and a cached leaf
// is only reused when its own `Parsed.Subject.CommonName` still equals
// it: the cache is keyed by path (namespace and role), not by identity,
// so without this check `--common-name other`, or simply signing in as
// someone else against the same `-ns`/`-role`, would silently reuse the
// previous identity's certificate.
func postgresCertificate(ctx context.Context, cfg Config, request pgRequest, base string) (leaf, error) {
	// Resolved BEFORE the cache is read, but a name this cheap to find
	// locally (no network) not existing yet is not, on its own, reason
	// to refuse before login is even attempted: a laptop that is not
	// signed in should hear "sign in" (from the login below), not "no
	// common name", when both are true at once -- the same ordering
	// this had before the cache learned to check identity at all.
	name := strings.TrimSpace(request.commonName)
	if name == "" {
		name = baoIdentity(cfg)
	}

	if name != "" {
		if cached, ok := readCachedLeaf(base, name); ok {
			return cached, nil
		}
	}

	var result leaf
	err := withCacheLock(base+".lock", func() error {
		// Re-read under the lock: a caller that waited here while another
		// minted finds the answer already written.
		if name != "" {
			if cached, ok := readCachedLeaf(base, name); ok {
				result = cached
				return nil
			}
		}

		// The LOGIN happens at request.loginNS (request.ns itself unless
		// --login-ns/$ACCESSCTL_BAO_LOGIN_NAMESPACE says otherwise); the
		// certificate is still SIGNED in request.ns, below -- a token
		// minted at a parent namespace is valid in its children, so the
		// same login can sign in more than one child without logging in
		// again (see bao.go's openBAOLogin, shared with `accessctl bao`).
		token, err := openBAOLogin(ctx, cfg, request.address, request.loginNS, rosterMount, rosterLoginRole, request.audience, request.roots)
		if err != nil {
			return err
		}
		bao := &openbao{Address: request.address, Namespace: request.ns, Client: retryingClientTrusting(request.roots)}
		bao.token = token.Token

		if name == "" {
			return badUsage("no common name to ask for: sign in again, or pass --common-name")
		}

		issued, err := issue(ctx, bao, request.mount+"/sign/"+request.role, name, nil)
		if err != nil {
			return err
		}
		if err = writeLeaf(base, issued); err != nil {
			return err
		}
		mintedInfo(issued)
		result = issued
		return nil
	})
	return result, err
}

// readCachedLeaf reads back a certificate this command wrote before, and
// says whether it is still worth presenting: parsed, minted for the
// SAME common name this call is about to ask for, matched against its
// own key (a defensive re-check of what `issue` already verified once,
// in case the pair on disk was ever touched by anything else), and with
// enough life left (certReuseMargin).
//
// Every failure is a miss rather than an error, the same rule every
// cache in this tool keeps: a half-written pair, one from an older
// version of this command, one minted for a different identity, or one
// whose key and certificate no longer match is not a reason to fail
// outright when minting a fresh one is always available.
func readCachedLeaf(base, wantCommonName string) (leaf, bool) {
	certPEM, err := os.ReadFile(base + ".crt")
	if err != nil {
		return leaf{}, false
	}
	keyPEM, err := os.ReadFile(base + ".key")
	if err != nil {
		return leaf{}, false
	}
	// The CA file is optional: a role that returned no chain and no
	// issuing certificate leaves it unwritten (writeLeaf), and that is
	// not a reason to mint a new certificate.
	caPEM, _ := os.ReadFile(base + "-ca.crt")

	parsed, err := parseLeaf(string(certPEM))
	if err != nil {
		return leaf{}, false
	}
	if parsed.Subject.CommonName != wantCommonName {
		return leaf{}, false
	}
	if time.Until(parsed.NotAfter) <= certReuseMargin {
		return leaf{}, false
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return leaf{}, false
	}
	private, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return leaf{}, false
	}
	ecdsaKey, ok := private.(*ecdsa.PrivateKey)
	if !ok || !ecdsaKey.PublicKey.Equal(parsed.PublicKey) {
		return leaf{}, false
	}

	return leaf{Certificate: string(certPEM), Key: string(keyPEM), Authority: string(caPEM), Parsed: parsed}, true
}

// mintedInfo is what the audit trail will show for a freshly minted
// certificate, to stderr and nowhere else: `pg`/`psql` hand their whole
// stdout to the command they run, which may be piped or parsed by a
// script (`accessctl pg -- psql -tAc "select 1"`), so nothing accessctl
// prints can share it. Printed only when a certificate was actually
// minted, not on every reuse -- a script running this often would
// otherwise see one more line on stderr per run for no new information.
// The key is never printed.
func mintedInfo(issued leaf) {
	_, _ = fmt.Fprintf(os.Stderr, "accessctl: minted a certificate — common_name %s, serial %s, expires %s\n",
		issued.Parsed.Subject.CommonName, colonHex(issued.Parsed.SerialNumber.Bytes()), issued.Parsed.NotAfter.UTC().Format(time.RFC3339))
}

// pgChildEnv sets libpq's standard variables so any command using libpq
// -- psql, or an application linked against it -- picks up the
// certificate without a connection string naming it.
//
// Environment variables are the right channel because libpq treats each
// one strictly as a DEFAULT: verified against libpq's own documentation
// (Environment Variables, and the Connection Service File page) --
// "[environment variables] can be used to select default connection
// parameter values, which will be used ... if no value is directly
// specified", and separately, for a service file, "a service file
// setting overrides the corresponding environment variable, and in turn
// can be overridden by a value given directly in the connection string".
// So the full precedence, lowest first, is: built-in default, THIS
// environment variable, a service file's setting (PGSERVICEFILE or
// `service=` in a connection string), an explicit keyword -- `-U`, or
// `user=` on the command line. Nothing here can win over any of those;
// it only supplies what nothing else already decided.
//
// PGSSLCERT and PGSSLKEY are always set to the certificate this command
// just minted or reused: there is no other reasonable value for them,
// since minting exactly this pair is the whole point of running it.
//
// PGSSLROOTCERT, PGSSLMODE and PGUSER are set ONLY when not already in
// the environment. PGUSER: a caller's own PGUSER (or a service file's
// `user=`, which already outranks it) names who they mean to connect
// as, and this must never second-guess that. PGSSLROOTCERT: the PKI's
// CA -- what this command's certificate chains to -- is not necessarily
// the CA that signed the DATABASE SERVER's own certificate; a server
// behind a different CA needs its root named some other way (a
// repository's own service file `sslrootcert=`, or the caller's own
// PGSSLROOTCERT), and this must not shadow that. It is also skipped
// entirely when no CA file was written at all (hasCA false: the role
// returned no chain and no issuing certificate to write), rather than
// pointed at a file that does not exist. PGSSLMODE follows the same
// rule as PGSSLROOTCERT, for the same reason: `verify-full` against the
// wrong root is not what a caller who already chose their own mode or
// root asked for.
func pgChildEnv(base, commonName string, hasCA bool) []string {
	env := os.Environ()
	env = setEnv(env, "PGSSLCERT", base+".crt")
	env = setEnv(env, "PGSSLKEY", base+".key")
	if hasCA && envValue(env, "PGSSLROOTCERT") == "" {
		env = setEnv(env, "PGSSLROOTCERT", base+"-ca.crt")
	}
	if envValue(env, "PGSSLMODE") == "" {
		env = setEnv(env, "PGSSLMODE", "verify-full")
	}
	if envValue(env, "PGUSER") == "" {
		env = setEnv(env, "PGUSER", commonName)
	}
	return env
}
