// Package app assembles the GitHub controller from its configuration: the
// policy's GitHub table, the console it reads with its own ServiceAccount
// token, the report it writes, and the credentials mounted beside it.
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
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/githubroster/controller"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/policy"
)

// Config is what a deployment decides. It is read from the environment,
// which is what the chart sets.
type Config struct {
	release   string
	policyDir string
	console   string
	tokenFile string
	appsDir   string
	interval  time.Duration
	enabled   map[string]bool
	logLevel  slog.Level
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// Load reads the configuration from the environment.
func Load() (Config, error) {
	c := Config{
		release:   envString("RELEASE_NAME", "access-issuer"),
		policyDir: envString("POLICY_DIR", ""),
		console:   strings.TrimSuffix(envString("CONSOLE_URL", ""), "/"),
		tokenFile: envString("TOKEN_FILE", "/var/run/secrets/github-roster/token"),
		appsDir:   envString("APPS_DIR", "/var/run/github-roster/apps"),
		enabled:   map[string]bool{},
	}
	for _, org := range strings.Split(envString("ENABLED_ORGS", ""), ",") {
		if org = strings.TrimSpace(org); org != "" {
			c.enabled[org] = true
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
		return Config{}, errors.New("POLICY_DIR is required: the bindings are the policy's github table")
	case c.console == "":
		return Config{}, errors.New("CONSOLE_URL is required: who holds a group is the console's to answer")
	}
	return c, nil
}

// App is an assembled controller.
type App struct {
	controller *controller.Controller
	log        *slog.Logger
}

// New assembles the controller.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	declared, err := policy.LoadDeclared(cfg.policyDir)
	if err != nil {
		return nil, err
	}
	// Validated with the service's own loader: a controller acting on a
	// policy the service would refuse is acting on a different model.
	if _, err = policy.NewSet(declared); err != nil {
		return nil, fmt.Errorf("the policy: %w", err)
	}
	if len(declared.GitHub) == 0 {
		log.WarnContext(ctx, "the policy binds no GitHub organisation: every pass will do nothing")
	}
	for org := range cfg.enabled {
		if _, bound := declared.GitHub[org]; !bound {
			return nil, fmt.Errorf("ENABLED_ORGS names %s, which the policy does not bind", org)
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

	log.InfoContext(ctx, "the GitHub controller is assembled",
		"organisations", len(declared.GitHub), "enabled", keys(cfg.enabled), "interval", cfg.interval, "console", cfg.console)
	return &App{
		log: log,
		controller: controller.New(controller.Config{Interval: cfg.interval, Enabled: cfg.enabled, AppsDir: cfg.appsDir}, controller.Deps{
			Log:      log,
			GitHub:   web,
			Access:   directoryrosterv1connect.NewAccessServiceClient(web, cfg.console, bearer),
			Audit:    directoryrosterv1connect.NewAuditServiceClient(web, cfg.console, bearer),
			Status:   kube.NewGitHubStatus(client),
			Links:    kube.NewGitHubLinks(client),
			Bindings: declared.GitHub,
		}),
	}, nil
}

// Run passes until the context is done.
func (a *App) Run(ctx context.Context) error { return a.controller.Run(ctx) }

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
