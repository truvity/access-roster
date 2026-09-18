package main

import (
	"context"
	"flag"
	"slices"
	"strings"
)

// credential mints a short-lived credential for something that speaks
// neither OIDC nor the cloud's own protocol: an SSH server, a database,
// a service that wants a client certificate.
//
// It is the same sentence as every other command here — the sign-in is
// exchanged for one audience, and what that audience opens is decided
// elsewhere — with one more hop on the end: OpenBAO's JWT mount takes
// the exchanged token and its role mints the certificate. Three parties
// record the same subject afterwards, which is the point: the issuer
// recorded the exchange, OpenBAO the signing, and the server the
// certificate's `key_id` or common name.
//
// What this tool does NOT decide is worth listing, because each one was a
// way for a CLI to become the security boundary:
//
//   - the lifetime. accessctl never sends a TTL. The role's `ttl` and
//     `max_ttl` are the whole answer, so shortening them shortens every
//     credential already in flight, and no flag here can ask for longer.
//   - who may ask. The exchange refuses before OpenBAO is reached.
//   - what is in the certificate. Principals and a common name are
//     REQUESTED; a role that does not allow them refuses.
//
// And it keeps nothing: the OpenBAO token lives in memory for the length
// of one command and is revoked on the way out.
func credential(args []string) error {
	request, err := parseCredentialFlags(args)
	if err != nil {
		return err
	}

	cfg, err := loadConfig(request.issuer, request.clientID)
	if err != nil {
		return err
	}

	ctx := context.Background()
	held, err := proofFor(ctx, cfg, request.audience)
	if err != nil {
		return err
	}
	issued, err := exchangeAs(ctx, cfg.Issuer, held.Client, held.Subject, held.Type, request.audience)
	if err != nil {
		return err
	}

	bao := &openbao{Address: request.address, Namespace: request.namespace, Client: retryingClient()}
	if err = bao.login(ctx, request.mount, request.loginRole, issued.AccessToken); err != nil {
		return err
	}
	// Whatever happens next, the login ends here: delivered, refused or
	// failed, nothing that could mint a second credential outlives the
	// command.
	defer bao.revokeSelf(ctx)

	switch request.kind {
	case kindSSH:
		return sshCredential(ctx, bao, request)
	case kindDB:
		return dbCredential(ctx, bao, request, held.Name)
	default:
		return clientCredential(ctx, bao, request, held.Name)
	}
}

// The three kinds, which are three different things to deliver rather
// than three flavours of one.
const (
	kindSSH    = "ssh"
	kindDB     = "db"
	kindClient = "client"
)

// The defaults that make the common command short. Each is overridable,
// because a second installation is allowed to name things differently and
// a tool that hard-codes a layout is a tool nobody else can deploy.
const (
	// openbaoAudience is the exchange client OpenBAO accepts tokens of.
	openbaoAudience = "openbao"
	// rosterMount is the JWT auth mount people and jobs log in through.
	rosterMount = "jwt-roster"
	// rosterLoginRole is the one role on that mount; groups decide the rest.
	rosterLoginRole = "roster"
	// sshMount and pkiMount are the engines the roles live on.
	sshMount = "ssh"
	pkiMount = "pki"
)

// credentialRequest is the whole command line, resolved.
type credentialRequest struct {
	kind string
	env  string
	role string

	address   string
	namespace string
	project   string

	issuer    string
	clientID  string
	audience  string
	mount     string
	loginRole string

	// ssh
	principals []string
	identity   string

	// db
	service string
	host    string
	port    string
	dbname  string

	// db and client
	commonName string
	out        string
	uris       []string
}

// defaultRole is the role each kind signs with when nothing says
// otherwise: the ordinary one, never the privileged one. `admin` exists
// for SSH and has to be asked for by name.
//
// The two SSH roles are two classes of login rather than two strengths
// of the same one: `user` signs for the ordinary account a host admits
// everybody who may use it as, `admin` for the account that administers
// the host. Which OS accounts each role will sign for is the role's to
// say, not this tool's.
func defaultRole(kind string) string {
	switch kind {
	case kindSSH:
		return "user"
	case kindDB:
		return "db-client"
	default:
		return "client"
	}
}

// path is the one endpoint this command calls. Every kind SIGNS: a
// public key for SSH, a certificate request for the PKI kinds. None of
// them asks the manager to make a key.
func (r credentialRequest) path() string {
	if r.kind == kindSSH {
		return sshMount + "/sign/" + r.role
	}
	return pkiMount + "/sign/" + r.role
}

// parseCredentialFlags reads the command line into a request.
//
// The flags are declared per kind, so asking for `--principal` on a
// database credential is a usage error rather than a flag that is quietly
// ignored — which is how somebody ends up believing they narrowed a
// credential they did not narrow.
func parseCredentialFlags(args []string) (credentialRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return credentialRequest{}, badUsage("which credential: %s", strings.Join(credentialKinds(), ", "))
	}
	request := credentialRequest{kind: args[0]}
	if !slices.Contains(credentialKinds(), request.kind) {
		return credentialRequest{}, badUsage("%q is not a kind of credential: %s",
			request.kind, strings.Join(credentialKinds(), ", "))
	}

	flags := flag.NewFlagSet("credential "+request.kind, flag.ContinueOnError)
	flags.StringVar(&request.env, "env", "", "the environment to mint in")
	flags.StringVar(&request.role, "role", defaultRole(request.kind), roleUsage(request.kind))
	flags.StringVar(&request.address, "address", "",
		"the OpenBAO API, e.g. https://openbao.example:8200 (default: $"+envOpenBAOAddress+", then $"+envVaultAddress+")")
	flags.StringVar(&request.namespace, "namespace", "",
		"the OpenBAO namespace (default: $"+envOpenBAONamespace+", then $"+envVaultNamespace+", then the --env value itself)")
	flags.StringVar(&request.mount, "mount", rosterMount, "the JWT auth mount to log in on")
	flags.StringVar(&request.loginRole, "login-role", rosterLoginRole, "the role on that mount")
	flags.StringVar(&request.issuer, "issuer", "", "the issuer, when not configured")
	flags.StringVar(&request.clientID, "client", "", "the client to present")
	flags.StringVar(&request.audience, "audience", openbaoAudience, "the exchange client OpenBAO accepts")

	var principals, uris repeated
	switch request.kind {
	case kindSSH:
		flags.Var(&principals, "principal", "an OS account to ask the certificate for (repeatable)")
		flags.StringVar(&request.identity, "identity", "",
			"write the key and certificate here instead of into the agent (a bare name means ~/.ssh)")
	case kindDB:
		flags.StringVar(&request.project, "project", "",
			"a project whose own namespace, <project>/<env>, holds the database role (default: the environment's)")
		flags.StringVar(&request.service, "service", "", "the psql service entry to write (default: the environment)")
		flags.StringVar(&request.host, "host", "", "the database host the service entry points at")
		flags.StringVar(&request.port, "port", "5432", "its port")
		flags.StringVar(&request.dbname, "dbname", "", "the database the service entry opens")
		flags.StringVar(&request.commonName, "common-name", "", "the common name to ask for (default: you)")
	default:
		flags.StringVar(&request.out, "out", "", "where to write the certificate; the key goes beside it")
		flags.StringVar(&request.commonName, "common-name", "", "the common name to ask for (default: you)")
		flags.Var(&uris, "uri-san", "a URI SAN to ask the certificate for (repeatable)")
	}

	if err := flags.Parse(args[1:]); err != nil {
		return credentialRequest{}, usageError{err}
	}
	if flags.NArg() > 0 {
		return credentialRequest{}, badUsage("%q is not a flag of `credential %s`", flags.Arg(0), request.kind)
	}
	request.principals, request.uris = cleaned(principals), cleaned(uris)

	return request.resolve()
}

// resolve fills in what was not typed and refuses what cannot be.
func (r credentialRequest) resolve() (credentialRequest, error) {
	r.env = strings.TrimSpace(r.env)
	if r.env == "" {
		return r, badUsage("--env is required: which environment mints this credential")
	}
	if r.role = strings.TrimSpace(r.role); r.role == "" {
		r.role = defaultRole(r.kind)
	}
	if r.address = strings.TrimSpace(r.address); r.address == "" {
		r.address = firstEnv(envOpenBAOAddress, envVaultAddress)
	}
	if r.address == "" {
		return r, badUsage("no OpenBAO address: pass --address https://openbao.example:8200, "+
			"or export %s=https://openbao.example:8200 (%s is read too)", envOpenBAOAddress, envVaultAddress)
	}
	r.address = strings.TrimSuffix(r.address, "/")

	if r.namespace = strings.TrimSpace(r.namespace); r.namespace == "" {
		r.namespace = firstEnv(envOpenBAONamespace, envVaultNamespace)
	}
	if r.namespace == "" {
		// One namespace per environment, named for it, holds every role
		// this command signs with: the SSH CA, the database client role
		// and the machine client role. An installation that keeps a
		// project's database role in a namespace of the project's own
		// says so with --project, and one laid out any other way with
		// --namespace.
		r.namespace = r.env
		if project := strings.TrimSpace(r.project); r.kind == kindDB && project != "" {
			r.namespace = project + "/" + r.env
		}
	}

	switch r.kind {
	case kindDB:
		if r.service = strings.TrimSpace(r.service); r.service == "" {
			r.service = r.env
		}
		if strings.TrimSpace(r.host) == "" {
			return r, badUsage("--host is required: where the psql service entry points")
		}
		if strings.TrimSpace(r.dbname) == "" {
			return r, badUsage("--dbname is required: which database the service entry opens")
		}
	case kindClient:
		if strings.TrimSpace(r.out) == "" {
			return r, badUsage("--out is required: where to write the certificate and its key")
		}
	}

	if strings.TrimSpace(r.audience) == "" {
		return r, badUsage("--audience cannot be empty: a token for nothing in particular is what an audience prevents")
	}
	return r, nil
}

func credentialKinds() []string { return []string{kindSSH, kindDB, kindClient} }

// roleUsage is the --role line of each kind's help. For SSH it says what
// the two roles are FOR, because the flag is where somebody deciding
// whether they need the privileged one looks.
func roleUsage(kind string) string {
	if kind == kindSSH {
		// No backquotes: the flag package reads the first backquoted word
		// of a usage line as the name of the flag's argument.
		return "the SSH role: 'user' for everyday logins as the host's ordinary account; " +
			"'admin' for administering the host, granted separately and signed only when asked for by name"
	}
	return "the OpenBAO role, when not the usual one for this kind"
}

// cleaned drops the empty values a repeatable flag can be given, so that
// a stray `--principal ""` asks for nothing rather than for a principal
// with no name.
func cleaned(values repeated) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			kept = append(kept, value)
		}
	}
	return kept
}
