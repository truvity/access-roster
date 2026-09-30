package main

import "testing"

func TestEnvironmentIsTheDefaultAndAFlagWins(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"UPSTREAM": "http://127.0.0.1:8081/mcp", "ISSUER_URL": "https://i.example",
		"RESOURCE_URL": "https://mcp.example.com/metrics", "SCOPE": "profile", "MAX_REQUEST_BYTES": "2048",
		"REFRESH_BEFORE": "30s",
	}
	cfg, err := parse([]string{"--listen", ":9000"}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9000" || cfg.Upstream != env["UPSTREAM"] || cfg.Scope != "profile" ||
		cfg.MaxRequestBytes != 2048 || cfg.RefreshBefore.Seconds() != 30 {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.OutboundEnabled() {
		t.Error("outbound is on by default")
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	env := map[string]string{"UPSTREAM": "http://127.0.0.1:8081", "ISSUER_URL": "https://i.example", "RESOURCE_URL": "https://h.example/x"}
	cfg, err := parse(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.Scope != "openid" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestMissingAndMalformedAreRefused(t *testing.T) {
	t.Parallel()
	if _, err := parse(nil, func(string) string { return "" }); err == nil {
		t.Error("nothing set was accepted")
	}
	env := map[string]string{"UPSTREAM": "http://u", "ISSUER_URL": "https://i", "RESOURCE_URL": "https://h/x", "REFRESH_BEFORE": "soon"}
	if _, err := parse(nil, func(k string) string { return env[k] }); err == nil {
		t.Error("an unparseable duration was accepted")
	}
}
