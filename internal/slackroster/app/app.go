// Package app assembles the Slack controller from its configuration: the
// policy's slack table, the console it reads with its own ServiceAccount
// token, the report it writes, and the credentials and records mounted
// beside it.
//
// A package rather than the body of main, for the reason the service's
// equivalents are: this is where the decisions a deployment can get wrong
// are made, and main() cannot be tested.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackroster/controller"
	"github.com/truvity/access-roster/internal/version"
	"github.com/truvity/access-roster/policy"
)

// Config is what a deployment decides. It is read from the environment,
// which is what the chart sets.
type Config struct {
	release        string
	policyDir      string
	console        string
	tokenFile      string
	credentialsDir string
	recordsDir     string
	interval       time.Duration
	enabled        map[string]bool
	logLevel       slog.Level
	// audit is the audit installation the controller records to, with its
	// own identity; without one it only logs what it did.
	audit audit.Config
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// Load reads the configuration from the environment.
func Load() (Config, error) {
	c := Config{
		release:        envString("RELEASE_NAME", "access-issuer"),
		policyDir:      envString("POLICY_DIR", ""),
		console:        strings.TrimSuffix(envString("CONSOLE_URL", ""), "/"),
		tokenFile:      envString("TOKEN_FILE", "/var/run/secrets/slack-roster/token"),
		credentialsDir: envString("CREDENTIALS_DIR", "/var/run/slack-roster/credentials"),
		recordsDir:     envString("RECORDS_DIR", "/var/run/slack-roster/workspaces"),
		enabled:        map[string]bool{},
		audit: audit.Config{
			Writer:    envString("AUDIT_WRITER_URL", ""),
			TokenFile: envString("AUDIT_TOKEN_FILE", ""),
			Instance:  envString("POD_NAME", ""),
			Version:   version.String(),
		},
	}
	for _, workspace := range strings.Split(envString("ENABLED_WORKSPACES", ""), ",") {
		if workspace = strings.TrimSpace(workspace); workspace != "" {
			c.enabled[workspace] = true
		}
	}
	interval, err := time.ParseDuration(envString("INTERVAL", "15m"))
	if err != nil || interval <= 0 {
		return Config{}, fmt.Errorf("INTERVAL %q is not a positive duration", os.Getenv("INTERVAL"))
	}
	c.interval = interval
	if err = c.logLevel.UnmarshalText([]byte(envString("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("LOG_LEVEL: %w", err)
	}
	switch {
	case c.policyDir == "":
		return Config{}, errors.New("POLICY_DIR is required: the bindings are the policy's slack table")
	case c.console == "":
		return Config{}, errors.New("CONSOLE_URL is required: who holds a group is the console's to answer")
	}
	return c, nil
}

// App is an assembled controller.
type App struct {
	controller *controller.Controller
	trail      *audit.Trail
	// fatal carries the one error that ends the process from outside a
	// pass: the audit installation refusing the catalogue after the start.
	fatal chan error
}

// Close closes the audit emitter, which delivers what its queue holds within
// its timeout and drops the rest, saying so. Nothing survives the process.
func (a *App) Close() error { return a.trail.Close() }

// The cluster's status store reads back what it wrote, so a restarted
// controller does not record every hold and leaver again.
var _ controller.StatusReader = (*kube.SlackStatus)(nil)

// New assembles the controller.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	declared, err := policy.LoadDeclared(cfg.policyDir)
	if err != nil {
		return nil, err
	}
	// Validated with the service's own loader: a controller acting on a
	// policy the service would refuse is acting on a different model.
	set, err := policy.NewSet(declared)
	if err != nil {
		return nil, fmt.Errorf("the policy: %w", err)
	}
	if len(declared.Slack.Workspaces) == 0 {
		log.WarnContext(ctx, "the policy declares no Slack workspace: every pass will do nothing")
	}
	for workspace := range cfg.enabled {
		if _, bound := declared.Slack.Workspaces[workspace]; !bound {
			return nil, fmt.Errorf("ENABLED_WORKSPACES names %s, which the policy does not declare", workspace)
		}
	}

	client, err := kube.InCluster(cfg.release)
	if err != nil {
		return nil, err
	}

	// Every call to the console carries this pod's own projected token,
	// read fresh each time: the kubelet rotates it under the pod.
	bearer := connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			token, err := os.ReadFile(cfg.tokenFile)
			if err != nil {
				return nil, fmt.Errorf("read this pod's ServiceAccount token: %w", err)
			}
			req.Header().Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
			return next(ctx, req)
		}
	}))
	web := &http.Client{Timeout: 30 * time.Second}

	log.InfoContext(ctx, "the Slack controller is assembled",
		"workspaces", len(declared.Slack.Workspaces), "enabled", slices.Sorted(maps.Keys(cfg.enabled)),
		"interval", cfg.interval, "console", cfg.console, "policy", set.Digest())
	// A refusal found after the start is fatal the way one at the start is:
	// the process ends rather than running with records nobody accepts.
	fatal := make(chan error, 1)
	cfg.audit.Log = log
	cfg.audit.OnFatal = func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	trail, err := audit.Open(ctx, cfg.audit)
	if err != nil {
		return nil, err
	}
	return &App{
		trail: trail,
		fatal: fatal,
		controller: controller.New(controller.Config{
			Interval: cfg.interval, Enabled: cfg.enabled, CredentialsDir: cfg.credentialsDir, RecordsDir: cfg.recordsDir,
		}, controller.Deps{
			Log:    log,
			Access: directoryrosterv1connect.NewAccessServiceClient(web, cfg.console, bearer),
			Audit:  trail,
			Status: kube.NewSlackStatus(client),
			Policy: declared,
			Digest: set.Digest(),
		}),
	}, nil
}

// Run passes until the context is done, or the audit installation refuses
// the catalogue after the start, which ends the process the way a refusal
// at the start would have.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.controller.Run(ctx) }()
	select {
	case err := <-a.fatal:
		cancel()
		<-done
		return fmt.Errorf("audit: %w", err)
	case err := <-done:
		return err
	}
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
