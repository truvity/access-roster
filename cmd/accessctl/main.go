// Command accessctl is what a person on a laptop runs.
//
// It exists for one reason that survived the design: the cloud CLI has
// no interactive login. kubectl has kubelogin for the same job; AWS has
// nothing that will open a browser, so somebody has to run the flow once
// and then answer as a credential process. Everything else here shares
// that login's cache and the issuer's address, which is why it is one
// binary with subcommands rather than several tools.
//
// Machines do not run this. A job's exchange is one call to the token
// endpoint that any `curl` can make, and the GitHub Action does it in
// shell.
package main

import (
	"errors"
	"fmt"
	"os"
)

// Exit codes, which are a contract: a script reading them should be able
// to tell "you are not signed in" from "the issuer is down" without
// parsing English.
const (
	exitOK          = 0
	exitUsage       = 2
	exitNotSignedIn = 3
	exitNotGranted  = 4
	exitUnreachable = 5
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "accessctl: "+err.Error())
		os.Exit(codeFor(err))
	}
}

// usageError is a mistake in what was typed, rather than a failure of
// what was asked for.
type usageError struct{ error }

func badUsage(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

func codeFor(err error) int {
	var usage usageError
	switch {
	case errors.As(err, &usage):
		return exitUsage
	case errors.Is(err, errNotSignedIn):
		return exitNotSignedIn
	case errors.Is(err, errNotGranted):
		return exitNotGranted
	case errors.Is(err, errUnreachable):
		return exitUnreachable
	default:
		return 1
	}
}

var (
	// errNotSignedIn is no cached login, or one that has expired. The
	// answer is always `accessctl login`, so it is worth a code of its
	// own: a wrapper script can run that and retry.
	errNotSignedIn = errors.New("not signed in — run `accessctl login`")
	// errNotGranted is a refusal by the issuer: the groups this identity
	// holds do not admit it to what it asked for. Retrying will not help
	// and a script should stop.
	errNotGranted = errors.New("that audience is not granted to you")
	// errUnreachable is the issuer being down or unresolvable, which is
	// the one a script SHOULD retry.
	errUnreachable = errors.New("the issuer could not be reached")
)

func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return badUsage("no command")
	}

	switch args[0] {
	case "login":
		return login(args[1:])
	case "whoami":
		return whoami(args[1:])
	case "exchange":
		return exchange(args[1:])
	case "kube-token":
		return kubeToken(args[1:])
	case "aws":
		return awsCredentials(args[1:])
	case "kubeconfig":
		return kubeconfig(args[1:])
	case "aws-config":
		return awsConfig(args[1:])
	case "setup":
		return setup(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return badUsage("%q is not a command", args[0])
	}
}

func usage(to *os.File) {
	_, _ = fmt.Fprint(to, `accessctl — access for a person on a laptop

  login         sign in at the issuer, once, in a browser
  whoami        who you are, and what your groups open
  setup         kubeconfig and aws-config together

  kubeconfig    a context per cluster you are granted
  aws-config    a profile per cloud role you are granted

  kube-token    a Kubernetes exec credential      (run by kubectl)
  aws           an AWS credential process answer  (run by the AWS SDKs)
  exchange      the raw exchange: a token in, a token for an audience out

Exit codes: 0 ok, 2 usage, 3 not signed in, 4 audience not granted,
5 issuer unreachable.
`)
}
