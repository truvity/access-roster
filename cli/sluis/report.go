package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// result is the end of a command. Its JSON form is the object of cli.md "JSON output": the members every command
// has, and the one object of the command (token, login or audit).
type result struct {
	Output   int       `json:"output"`
	Command  string    `json:"command"`
	ExitCode int       `json:"exit_code"`
	Outcome  string    `json:"outcome"`
	Reasons  []string  `json:"reasons,omitempty"`
	Error    string    `json:"error,omitempty"`
	Token    *tokenOut `json:"token,omitempty"`
	Login    *loginOut `json:"login,omitempty"`
	Audit    *auditOut `json:"audit,omitempty"`

	// Text is what a person reads on standard output when the command is done.
	Text string `json:"-"`
}

// tokenOut is the `token` member of cli.md.
type tokenOut struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"`
	Audience    string `json:"audience"`
	Issuer      string `json:"issuer"`
}

// loginOut is what `sluis login` reports. It holds no token.
type loginOut struct {
	Issuer    string `json:"issuer"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject,omitempty"`
	ExpiresAt string `json:"expires_at"`
}

// finish maps the error of a command to its exit code and prints the end of it.
func (a *app) finish(res *result, err error, jsonOut bool) int {
	res.Output = 1
	switch {
	case err == nil:
		res.ExitCode, res.Outcome = cli.ExitOK, "done"
	case errors.Is(err, cli.ErrUsage):
		res.ExitCode, res.Outcome, res.Error = cli.ExitUsage, "usage", err.Error()
	case errors.Is(err, cli.ErrRefused):
		res.ExitCode, res.Outcome, res.Error = cli.ExitRefused, "refused", err.Error()
		var re interface{ Reasons() []string }
		if errors.As(err, &re) {
			res.Reasons = re.Reasons()
		}
	default:
		res.ExitCode, res.Outcome, res.Error = cli.ExitFailed, "failed", err.Error()
	}
	if jsonOut {
		b, _ := json.Marshal(res)
		_, _ = fmt.Fprintln(a.stdout, string(b))
		return res.ExitCode
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.stderr, "sluis %s: %v\n", res.Command, err)
		return res.ExitCode
	}
	if res.Text != "" {
		_, _ = fmt.Fprintln(a.stdout, res.Text)
	}
	return res.ExitCode
}

// refusal is a refused result with the reasons of cli.md: the codes or paths of the checks that failed, never a value.
// It is the kit's Refused, with the reasons readable for the JSON object.
type refusal struct {
	error
	reasons []string
}

func refused(reasons ...string) error {
	return &refusal{error: cli.Refused(reasons...), reasons: reasons}
}

func (r *refusal) Unwrap() error     { return r.error }
func (r *refusal) Reasons() []string { return r.reasons }
