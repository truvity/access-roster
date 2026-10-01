// Command resource-proxy fronts a service that knows nothing about
// access-roster with an access-roster resource server's front door: it
// verifies the caller's token, serves the RFC 9728 metadata, writes an
// audit line per request, and proxies to the service -- and, optionally,
// gives the service an identity of its own for what it calls in turn.
//
// See docs/connect/mcp.md, "Fronting a stock MCP server with
// resource-proxy". Every flag has an environment variable of the same
// name in upper case with underscores (--outbound-listen is
// OUTBOUND_LISTEN); a flag given wins.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/truvity/access-roster/internal/resourceproxy"
	"github.com/truvity/access-roster/internal/version"
)

func main() { os.Exit(run()) }

func run() int {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := parse(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("starting", slog.String("version", version.String()))
	if err := resourceproxy.Run(ctx, cfg, log); err != nil {
		log.Error("stopped", slog.String("error", err.Error()))
		return 1
	}
	return 0
}

// parse reads flags, each defaulting to its environment variable.
func parse(args []string, getenv func(string) string) (resourceproxy.Config, error) {
	var cfg resourceproxy.Config
	fs := flag.NewFlagSet("resource-proxy", flag.ContinueOnError)

	env := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}
	str := func(p *string, name, def, usage string) {
		key := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		fs.StringVar(p, name, env(key, def), usage+" ($"+key+")")
	}
	var badEnv []string
	dur := func(p *time.Duration, name string, def time.Duration, usage string) {
		key := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		d := def
		if v := getenv(key); v != "" {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				badEnv = append(badEnv, key)
			} else {
				d = parsed
			}
		}
		fs.DurationVar(p, name, d, usage+" ($"+key+")")
	}
	boolean := func(p *bool, name, usage string) {
		key := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		def := false
		if v := getenv(key); v != "" {
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				badEnv = append(badEnv, key)
			}
			def = parsed
		}
		fs.BoolVar(p, name, def, usage+" ($"+key+")")
	}

	str(&cfg.Listen, "listen", ":8080", "inbound listen address")
	str(&cfg.Upstream, "upstream", "", "the stock server, e.g. http://127.0.0.1:8081/mcp (required)")
	str(&cfg.IssuerURL, "issuer-url", "", "access-roster issuer URL, as in a token's iss (required)")
	str(&cfg.ResourceURL, "resource-url", "", "this resource's own public URL, the token audience (required)")
	str(&cfg.Scope, "scope", "openid", "scope advertised in metadata and in the 401 challenge; empty omits it")
	fs.Int64Var(&cfg.MaxRequestBytes, "max-request-bytes", envInt(getenv, "MAX_REQUEST_BYTES", resourceproxy.DefaultMaxRequestBytes, &badEnv),
		"largest request body accepted ($MAX_REQUEST_BYTES)")
	dur(&cfg.BodyReadTimeout, "body-read-timeout", resourceproxy.DefaultBodyTimeout, "time allowed to read one request body")
	dur(&cfg.UpstreamTimeout, "upstream-timeout", resourceproxy.DefaultUpstreamTimeout, "time allowed for the upstream's response headers")

	str(&cfg.OutboundListen, "outbound-listen", "", "loopback listener that injects this workload's identity, e.g. 127.0.0.1:8429; empty = outbound off")
	str(&cfg.OutboundTarget, "outbound-target", "", "where the outbound listener forwards to")
	str(&cfg.OutboundTokenEndpoint, "outbound-token-endpoint", "", "the issuer's token endpoint (ends in /token)")
	str(&cfg.OutboundClientID, "outbound-client-id", "", "the exchange client this workload presents")
	str(&cfg.OutboundAudience, "outbound-audience", "", "the audience to exchange for")
	str(&cfg.OutboundSATokenFile, "outbound-sa-token-file", "", "projected ServiceAccount token (audience: the issuer), re-read for every exchange")
	str(&cfg.OutboundCAFile, "outbound-ca-file", "", "PEM bundle appended to the system roots for the connection to the outbound target only (a private CA); read at start")
	boolean(&cfg.OutboundAllowNonLoopback, "outbound-allow-non-loopback", "let the outbound listener bind a non-loopback address")
	dur(&cfg.RefreshBefore, "refresh-before", resourceproxy.DefaultRefreshBefore, "exchange again this long before a token expires")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if len(badEnv) > 0 {
		return cfg, fmt.Errorf("resource-proxy: unparseable value in: %s", strings.Join(badEnv, ", "))
	}
	return cfg, cfg.Validate()
}

func envInt(getenv func(string) string, key string, def int64, bad *[]string) int64 {
	v := getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		*bad = append(*bad, key)
		return def
	}
	return n
}
