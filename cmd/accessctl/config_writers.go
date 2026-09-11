package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// kubeconfig writes a context per cluster this identity is granted.
//
// It writes through `kubectl config`, not by editing the file: a
// kubeconfig is somebody's own, with contexts this tool knows nothing
// about, and rewriting it wholesale is how a person loses the cluster
// they were using this morning.
func kubeconfig(args []string) error {
	cfg, token, err := signedIn(args, "kubeconfig")
	if err != nil {
		return err
	}
	grants, err := grantsOf(context.Background(), cfg, token.AccessToken)
	if err != nil {
		return err
	}

	binary, err := os.Executable()
	if err != nil {
		// Falling back to the name on PATH is right: a person who ran
		// `accessctl` has one, and an absolute path is only nicer.
		binary = "accessctl"
	}

	written := 0
	for _, one := range grants {
		name, ok := strings.CutPrefix(one.Audience, "k8s:")
		if !ok {
			continue
		}
		user := "accessctl:" + name
		// The exec plugin, which kubectl runs when it needs a token. The
		// audience is the cluster's client id, so one plugin serves
		// every cluster and nothing is duplicated per context.
		if err = kubectl("config", "set-credentials", user,
			"--exec-api-version="+execAPIVersion,
			"--exec-command="+binary,
			"--exec-arg=kube-token",
			"--exec-arg=--audience="+one.Audience,
			"--exec-arg=--issuer="+cfg.Issuer,
		); err != nil {
			return err
		}
		if err = kubectl("config", "set-context", name, "--user="+user, "--cluster="+name); err != nil {
			return err
		}
		written++
		_, _ = fmt.Fprintf(stdout, "context %s\n", name)
	}

	if written == 0 {
		_, _ = fmt.Fprintln(stdout, "No clusters are granted to you.")
		return nil
	}
	// The cluster entry itself — the API server's address and its CA —
	// is not ours to write: it comes from the platform's own kubeconfig
	// or from `aws eks update-kubeconfig`, and inventing one would be
	// inventing an address to trust.
	_, _ = fmt.Fprintln(stdout, "\nEach context expects a cluster entry of the same name.")
	return nil
}

// execAPIVersion is what the contexts declare. kubectl passes its own
// choice at run time and the plugin answers that; this is only what the
// entry is created with.
const execAPIVersion = "client.authentication.k8s.io/v1"

func kubectl(args ...string) error {
	command := exec.Command("kubectl", args...) //nolint:gosec // arguments this tool built
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// awsConfig writes a profile per cloud role this identity is granted.
//
// Appended to `~/.aws/config` rather than written over it, for the same
// reason kubeconfig goes through kubectl: that file is the person's own.
// A profile this tool already wrote is replaced; anything else is left
// exactly as it was.
func awsConfig(args []string) error {
	cfg, token, err := signedIn(args, "aws-config")
	if err != nil {
		return err
	}
	grants, err := grantsOf(context.Background(), cfg, token.AccessToken)
	if err != nil {
		return err
	}

	binary, err := os.Executable()
	if err != nil {
		binary = "accessctl"
	}

	var profiles strings.Builder
	written := 0
	for _, one := range grants {
		rest, ok := strings.CutPrefix(one.Audience, "aws:")
		if !ok {
			continue
		}
		account, role, split := strings.Cut(rest, ":")
		if !split || account == "" || role == "" {
			continue
		}
		// `<role>@<account>`, which reads the way a person says it and
		// sorts by role rather than by a number nobody remembers.
		name := role + "@" + account
		_, _ = fmt.Fprintf(&profiles, "\n[profile %s]\n", name)
		_, _ = fmt.Fprintf(&profiles, "credential_process = %s aws --audience %s --issuer %s\n",
			binary, one.Audience, cfg.Issuer)
		written++
		_, _ = fmt.Fprintf(stdout, "profile %s\n", name)
	}

	if written == 0 {
		_, _ = fmt.Fprintln(stdout, "No cloud roles are granted to you.")
		return nil
	}

	path, err := awsConfigPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	existing, err := os.ReadFile(path) //nolint:gosec // the caller's own AWS configuration
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	body := strip(string(existing)) + marker + profiles.String() + endMarker + "\n"
	if err = os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(stdout, "\nWritten to %s.\n", path)
	return nil
}

// The block this tool owns. Everything between the two markers is
// rewritten each time; everything outside them is somebody else's and is
// never touched.
const (
	marker    = "# >>> accessctl >>>"
	endMarker = "# <<< accessctl <<<"
)

// strip removes a block this tool wrote before, so profiles for roles
// somebody no longer holds do not survive as entries that fail only when
// used.
func strip(body string) string {
	start := strings.Index(body, marker)
	if start >= 0 {
		if end := strings.Index(body[start:], endMarker); end >= 0 {
			body = body[:start] + body[start+end+len(endMarker):]
		} else {
			// A half-written block: interrupted, or edited by hand. What
			// follows it is ours too, so it goes with it rather than
			// being left to merge into the next one.
			body = body[:start]
		}
	}
	// Exactly one trailing newline, whatever was there. Without this
	// every run adds a blank line to a file people read, which is a
	// small wrongness that accumulates into an obvious one.
	body = strings.TrimRight(body, "\n\t ")
	if body == "" {
		return ""
	}
	return body + "\n"
}

func awsConfigPath() (string, error) {
	if named := strings.TrimSpace(os.Getenv("AWS_CONFIG_FILE")); named != "" {
		return named, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find the home directory: %w", err)
	}
	return filepath.Join(home, ".aws", "config"), nil
}

// setup is both of the above, for somebody who has just signed in.
func setup(args []string) error {
	if err := kubeconfig(args); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout)
	return awsConfig(args)
}
