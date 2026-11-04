package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// tokenSet is one cache file: the tokens of one issuer (cli.md, "sluis login and sluis token").
type tokenSet struct {
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	TokenEndpoint string `json:"token_endpoint"`
	Subject       string `json:"subject,omitempty"`

	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`

	// Exchanged holds the tokens of RFC 8693 exchanges, by boundary and audience.
	Exchanged map[string]exchanged `json:"exchanged,omitempty"`
}

type exchanged struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func exchangeKey(boundary, audience string) string { return boundary + "\x00" + audience }

// cacheDir is $XDG_CONFIG_HOME/sluis/tokens, or ~/.config/sluis/tokens when the variable is unset (cli.md).
func (a *app) cacheDir() (string, error) {
	if x := a.getenv("XDG_CONFIG_HOME"); x != "" {
		if !filepath.IsAbs(x) {
			return "", errors.New("XDG_CONFIG_HOME is not an absolute path")
		}
		return filepath.Join(x, "sluis", "tokens"), nil
	}
	home := a.getenv("HOME")
	if home == "" {
		return "", errors.New("neither XDG_CONFIG_HOME nor HOME is set")
	}
	return filepath.Join(home, ".config", "sluis", "tokens"), nil
}

// cacheFile is the file of an issuer: one file per issuer, named by a hash so that the name is a safe path.
func cacheFile(dir, issuer string) string {
	sum := sha256.Sum256([]byte(issuer))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".json")
}

// readSet reads a cache file. A file that the group or others can read, or that is not a regular file, is refused and
// not used. The checks run on the open descriptor, so the file cannot change between the check and the read.
func readSet(path string) (*tokenSet, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the path is the cache directory and a hash
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, refused("cache.type")
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, refused("cache.type")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, refused("cache.mode")
	}
	var s tokenSet
	if err := json.NewDecoder(io.LimitReader(f, maxBody)).Decode(&s); err != nil {
		return nil, errors.New("the token cache file is not JSON")
	}
	return &s, nil
}

// writeSet stores a token set: the directory is made 0700, the file is written 0600 to a new name in the same
// directory and renamed over the old one, so a reader never sees half a file.
func writeSet(dir string, s *tokenSet) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(s) //nolint:gosec // the cache file exists to hold the tokens; it is written 0600
	if err != nil {
		return err
	}
	suffix, err := randomString(9)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+suffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the name is made here in the cache directory
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, cacheFile(dir, s.Issuer)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// loadSet finds the token set of an issuer. With no issuer named, the cache must hold exactly one (cli.md:
// "afterwards it comes from the cache").
func (a *app) loadSet(issuer string) (string, *tokenSet, error) {
	dir, err := a.cacheDir()
	if err != nil {
		return "", nil, err
	}
	if issuer != "" {
		s, err := readSet(cacheFile(dir, issuer))
		if errors.Is(err, os.ErrNotExist) {
			return dir, nil, refused("cache.login")
		}
		return dir, s, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return dir, nil, refused("cache.login")
	}
	if err != nil {
		return dir, nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	switch len(names) {
	case 0:
		return dir, nil, refused("cache.login")
	case 1:
		s, err := readSet(filepath.Join(dir, names[0]))
		return dir, s, err
	default:
		return dir, nil, cli.Usage(fmt.Errorf("%d issuers are signed in: name one with --issuer", len(names)))
	}
}
