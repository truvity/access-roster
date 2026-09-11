package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/truvity/access-roster/tokens"
)

// kubeToken answers kubectl's exec plugin.
//
// kubectl runs this on every API call it has no cached credential for,
// so everything here is silent on success: anything written to stdout
// that is not the credential is parsed as the credential.
func kubeToken(args []string) error {
	flags := flag.NewFlagSet("kube-token", flag.ContinueOnError)
	audience := flags.String("audience", "", "the cluster's client id, e.g. k8s:kernel")
	issuer := flags.String("issuer", "", "the issuer, when not configured")
	clientID := flags.String("client", "", "the client to present")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if strings.TrimSpace(*audience) == "" {
		return badUsage("--audience is required: which cluster this token is for")
	}

	cfg, err := loadConfig(*issuer, *clientID)
	if err != nil {
		return err
	}
	own, err := refresh(context.Background(), cfg)
	if err != nil {
		return err
	}
	token, err := exchangeFor(context.Background(), cfg, own.AccessToken, *audience)
	if err != nil {
		return err
	}

	// kubectl says which apiVersion it wants in KUBERNETES_EXEC_INFO,
	// and a plugin answering a different one is refused with a message
	// about the version rather than about the token.
	return tokens.WriteExecCredential(stdout, requestedExecVersion(), token)
}

// requestedExecVersion reads what kubectl asked for, falling back to the
// current one when this is run by hand.
func requestedExecVersion() string {
	raw := os.Getenv("KUBERNETES_EXEC_INFO")
	if raw == "" {
		return tokens.ExecCredentialVersion
	}
	var info struct {
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal([]byte(raw), &info); err != nil || info.APIVersion == "" {
		return tokens.ExecCredentialVersion
	}
	return info.APIVersion
}

// awsCredentials answers the AWS SDKs' credential process.
//
// Two exchanges, and the second is AWS's: this issuer's token is traded
// for one audienced at the role, and STS trades that for keys. Neither
// step stores anything, which is why an AWS profile written by this tool
// holds a command and no secret.
func awsCredentials(args []string) error {
	flags := flag.NewFlagSet("aws", flag.ContinueOnError)
	audience := flags.String("audience", "", "the role's client id, e.g. aws:1111:power")
	roleARN := flags.String("role", "", "the role to assume, when it is not in the audience")
	issuer := flags.String("issuer", "", "the issuer, when not configured")
	clientID := flags.String("client", "", "the client to present")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if strings.TrimSpace(*audience) == "" {
		return badUsage("--audience is required: which role this credential is for")
	}

	cfg, err := loadConfig(*issuer, *clientID)
	if err != nil {
		return err
	}
	own, err := refresh(context.Background(), cfg)
	if err != nil {
		return err
	}
	token, err := exchangeFor(context.Background(), cfg, own.AccessToken, *audience)
	if err != nil {
		return err
	}

	arn := strings.TrimSpace(*roleARN)
	if arn == "" {
		if arn, err = roleFromAudience(*audience); err != nil {
			return err
		}
	}

	session, _ := loadSession()
	name := session.Email
	if name == "" {
		name = session.Subject
	}
	creds, err := tokens.AssumeRoleWithWebIdentity(context.Background(), nil, arn, sessionName(name), token.AccessToken)
	if err != nil {
		return err
	}
	return tokens.WriteCredentialProcess(stdout, creds)
}

// roleFromAudience turns `aws:<account>:<role>` into an ARN.
//
// The audience is the client id in the policy and it already names both
// halves, so a profile needs nothing a person has to look up. An
// audience that is not in that shape is a usage error rather than a
// guess: an ARN assembled from the wrong pieces fails at STS with a
// message about the role, not about the audience.
func roleFromAudience(audience string) (string, error) {
	parts := strings.Split(audience, ":")
	if len(parts) != 3 || parts[0] != "aws" || parts[1] == "" || parts[2] == "" {
		return "", badUsage(
			"cannot tell which role %q means: pass --role, or use an audience shaped aws:<account>:<role>", audience)
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", parts[1], parts[2]), nil
}

// sessionName is what appears in CloudTrail against every call these
// credentials make, so it names the person rather than the tool.
func sessionName(who string) string {
	who = strings.TrimSpace(who)
	if who == "" {
		return "accessctl"
	}
	// STS allows a narrow set and truncates at 64, and a name it refuses
	// fails the whole call with a validation error naming the field.
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '@', r == '-', r == '_', r == '.', r == '=', r == ',':
			return r
		default:
			return '-'
		}
	}, who)
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean
}
