package legacy

import (
	"strings"

	"github.com/truvity/access-roster/internal/githubroster/connection"
)

// families maps a layout prefix onto the Valkey key prefix the issuer writes
// it under today. The order matters only for the reverse mapping, where the
// Valkey prefixes are disjoint.
var families = []struct{ port, valkey string }{
	{"req.", "issuer:request:"},
	{"code.", "issuer:code:"},
	{"codesess.", "issuer:code-session:"},
	{"tok.", "issuer:token:"},
	{"sso.", "issuer:sso:"},
	{"rt.", "issuer:session-token:"},
	{"rtrot.", "issuer:session-rotated:"},
	{"keyring.", "issuer:keyring:entry:"},
}

// unmapped are the layout families with no object of their own today.
var unmapped = []string{
	"ses.", "sid.", "ws.", "gh.link.", "app.", "gate.", "share.", "cache.", "dedupe.", "notify.", "gh.",
}

const (
	leasePrefix = "lease."
	orgPrefix   = "gh.org."
)

// target is where a key lives.
type target struct {
	// valkey is the key in Valkey, or "" for a ConfigMap entry.
	valkey string
	// entry is the ConfigMap entry key of a gh.org record.
	entry string
	// back reverses a Valkey key found by listing this target's prefix to
	// the port key it is reached by.
	back func(valkey string) (string, bool)
}

// route maps a port key (or prefix) to where it lives.
func route(key string) (target, error) {
	switch {
	case strings.HasPrefix(key, leasePrefix):
		return target{
			valkey: leaseKey(strings.TrimPrefix(key, leasePrefix)),
			back: func(v string) (string, bool) {
				name, ok := fromLease(v)
				return leasePrefix + name, ok
			},
		}, nil
	case strings.HasPrefix(key, orgPrefix):
		org := strings.TrimPrefix(key, orgPrefix)
		if _, ok := connection.OrgOfKey(connection.Key(org)); !ok {
			// A key the console would never show: refuse rather than write
			// an entry no domain store reads.
			return target{}, unsupported("%q is not a GitHub organisation login", org)
		}
		return target{entry: connection.Key(org)}, nil
	}
	for _, f := range families {
		if rest, ok := strings.CutPrefix(key, f.port); ok {
			return target{valkey: f.valkey + rest, back: func(v string) (string, bool) {
				rest, ok := strings.CutPrefix(v, f.valkey)
				return f.port + rest, ok
			}}, nil
		}
	}
	for _, prefix := range unmapped {
		if strings.HasPrefix(key, prefix) {
			return target{}, unsupported("%s keys have no object of their own in today's storage", prefix)
		}
	}
	if strings.Contains(key, ":") {
		// The legacy namespace: a key the issuer already writes, as itself.
		return target{valkey: key, back: func(v string) (string, bool) { return v, true }}, nil
	}
	return target{}, unsupported("%q is not a key of today's storage", key)
}

// leaseKey is where the hub keeps a refresh lease: in the slot of the
// workspace's snapshot for a name of the form kind:workspace.
func leaseKey(name string) string {
	kind, workspace, found := strings.Cut(name, ":")
	if !found {
		return "lease:" + name
	}
	return "{" + workspace + "}:lease:" + kind
}

// fromLease reverses [leaseKey].
func fromLease(key string) (string, bool) {
	if rest, ok := strings.CutPrefix(key, "lease:"); ok {
		return rest, true
	}
	if workspace, rest, ok := strings.Cut(strings.TrimPrefix(key, "{"), "}:lease:"); ok && strings.HasPrefix(key, "{") {
		return rest + ":" + workspace, true
	}
	return "", false
}
