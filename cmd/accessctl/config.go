package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is what `login` writes and every other command reads.
type Config struct {
	// Issuer is the access-roster issuer this laptop signs in at.
	Issuer string `yaml:"issuer"`
	// ClientID is the public client the flow runs as.
	ClientID string `yaml:"clientId"`
}

// Session is the cached login: the refresh token, and enough about the
// person to answer `whoami` without a round trip.
type Session struct {
	RefreshToken string    `json:"refresh_token"`
	Subject      string    `json:"sub,omitempty"`
	Email        string    `json:"email,omitempty"`
	Expires      time.Time `json:"expires,omitempty"`
}

// configDir is where both live.
//
// Under the OS config directory rather than the home directory, so it
// sits beside every other tool's and is covered by whatever already
// backs that up or excludes it.
func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find the configuration directory: %w", err)
	}
	return filepath.Join(base, "accessctl"), nil
}

func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func sessionPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "session.json"), nil
}

// loadConfig reads what login wrote, with the flags overriding it.
//
// A flag wins so that one laptop can talk to a second installation
// without losing the first: `--issuer` is enough for a one-off, and
// nothing is written unless login is what was asked for.
func loadConfig(issuer, clientID string) (Config, error) {
	cfg := Config{}
	path, err := configPath()
	if err != nil {
		return cfg, err
	}
	raw, err := os.ReadFile(path) //nolint:gosec // a path this tool owns
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return cfg, fmt.Errorf("read %s: %w", path, err)
	default:
		if err = yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("parse %s: %w", path, err)
		}
	}

	if issuer = strings.TrimSpace(issuer); issuer != "" {
		cfg.Issuer = issuer
	}
	if clientID = strings.TrimSpace(clientID); clientID != "" {
		cfg.ClientID = clientID
	}
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")

	if cfg.Issuer == "" {
		return cfg, badUsage("no issuer: pass --issuer, or run `accessctl login --issuer ...` once")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = DefaultClientID
	}
	return cfg, nil
}

// DefaultClientID is what a laptop signs in as when nothing says
// otherwise. It has to be declared in the policy with a loopback
// redirect; the reference names the same string.
const DefaultClientID = "accessctl"

// saveConfig writes what login learned.
func saveConfig(cfg Config) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("render the configuration: %w", err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// loadSession reads the cached login.
func loadSession() (Session, error) {
	path, err := sessionPath()
	if err != nil {
		return Session{}, err
	}
	raw, err := os.ReadFile(path) //nolint:gosec // a path this tool owns
	if errors.Is(err, os.ErrNotExist) {
		return Session{}, errNotSignedIn
	}
	if err != nil {
		return Session{}, fmt.Errorf("read %s: %w", path, err)
	}
	var session Session
	if err = json.Unmarshal(raw, &session); err != nil {
		// A cache that cannot be read is a cache to replace, not an
		// error to stop at: signing in again fixes it and nothing is
		// lost.
		return Session{}, errNotSignedIn
	}
	if session.RefreshToken == "" {
		return Session{}, errNotSignedIn
	}
	return session, nil
}

// saveSession writes the cached login, readable only by this account.
//
// A file rather than the OS keyring, and deliberately: the keyring means
// a platform-specific dependency on every laptop and a prompt in the
// middle of a `kubectl` call on some of them. A refresh token in a
// 0600 file beside the configuration is the same secret the browser
// already keeps in a cookie jar, and `login` replaces it in one command
// if it leaks.
func saveSession(session Session) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	body, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("render the session: %w", err)
	}
	path := filepath.Join(dir, "session.json")
	if err = os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
