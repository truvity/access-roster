package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// githubTokenCommand prints a GitHub App installation token for a catalogue App,
// minted under the grants this identity's groups hold. Like `token` it
// answers from the job's own identity in CI and from the sign-in on a
// laptop, so one line serves both.
//
// `--repository` narrows the token to repositories of the App's
// organisation, by name; without one, only a grant of every repository
// allows a token, and it reaches what the installation reaches.
// `--permission name=level` narrows what it may do; without one it
// carries exactly what the grant allows.
func githubTokenCommand(args []string) error {
	request, err := parseGitHubTokenFlags(args)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(request.issuer, request.client)
	if err != nil {
		return err
	}
	ctx := context.Background()
	held, err := proofFor(ctx, cfg, tokens.GitHubAppAudiencePrefix+request.app)
	if err != nil {
		return err
	}

	exchanger := &tokens.Exchanger{Issuer: cfg.Issuer, ClientID: held.Client, Client: retryingClient()}
	minted, err := exchanger.GitHubInstallationToken(ctx, held.Subject, held.Type, request.app,
		request.repositories, request.permissions)
	switch {
	case errors.Is(err, tokens.ErrRefused):
		return fmt.Errorf("%w: %w", errNotGranted, err)
	case err != nil:
		return fmt.Errorf("%w: %w", errUnreachable, err)
	}

	if !request.json {
		_, _ = fmt.Fprintln(stdout, minted.AccessToken)
		return nil
	}
	answer := githubTokenAnswer{
		Token: minted.AccessToken, Repositories: minted.Repositories, Permissions: minted.Permissions,
	}
	if !minted.Expires.IsZero() {
		answer.ExpiresAt = minted.Expires.UTC().Format(time.RFC3339)
	}
	if answer.Repositories == nil {
		answer.Repositories = []string{}
	}
	if answer.Permissions == nil {
		answer.Permissions = map[string]string{}
	}
	return json.NewEncoder(stdout).Encode(answer)
}

// githubTokenAnswer is `--json`: what a script reads.
type githubTokenAnswer struct {
	Token        string            `json:"token"`
	ExpiresAt    string            `json:"expires_at,omitempty"`
	Repositories []string          `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
}

// githubTokenRequest is the command line, read.
type githubTokenRequest struct {
	app, issuer, client string
	repositories        []string
	permissions         map[string]string
	json                bool
}

var (
	appIDPattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

func parseGitHubTokenFlags(args []string) (githubTokenRequest, error) {
	var out githubTokenRequest
	var repositories, permissions repeated
	flags := flag.NewFlagSet("github-token", flag.ContinueOnError)
	flags.StringVar(&out.app, "app", "", "the catalogue App, e.g. publisher")
	flags.Var(&repositories, "repository", "a repository of the App's organisation, by name; repeat for more")
	flags.Var(&permissions, "permission", "name=level, e.g. contents=read; repeat for more")
	flags.BoolVar(&out.json, "json", false, "print {token, expires_at, repositories, permissions}")
	flags.StringVar(&out.issuer, "issuer", "", "the issuer, when not configured")
	flags.StringVar(&out.client, "client", "", "the client to present")
	if err := flags.Parse(args); err != nil {
		return out, usageError{err}
	}
	if flags.NArg() > 0 {
		return out, badUsage("unexpected %q: repositories are named with --repository", flags.Arg(0))
	}
	out.app = strings.TrimPrefix(strings.TrimSpace(out.app), tokens.GitHubAppAudiencePrefix)
	if !appIDPattern.MatchString(out.app) {
		return out, badUsage("--app is required: the catalogue id of a GitHub App")
	}
	for _, name := range repositories {
		name = strings.TrimSpace(name)
		if name == "" || strings.Contains(name, "/") {
			return out, badUsage("--repository %q: name it without the owner", name)
		}
		out.repositories = append(out.repositories, name)
	}
	for _, spelled := range permissions {
		name, level, ok := strings.Cut(strings.TrimSpace(spelled), "=")
		if !ok || !permissionPattern.MatchString(name) || (level != "read" && level != "write" && level != "admin") {
			return out, badUsage("--permission %q: spell it name=read, name=write or name=admin", spelled)
		}
		if out.permissions == nil {
			out.permissions = map[string]string{}
		}
		if previous, seen := out.permissions[name]; seen && previous != level {
			return out, badUsage("--permission %s is given as both %s and %s", name, previous, level)
		}
		out.permissions[name] = level
	}
	return out, nil
}

// repeated is a flag that may be given more than once.
type repeated []string

func (r *repeated) String() string { return strings.Join(*r, ",") }

func (r *repeated) Set(value string) error {
	*r = append(*r, value)
	return nil
}
