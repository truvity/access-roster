// Package spec is the deny matrix of the local installation: the sockets that are served, what each one is for, who
// may call it, and how a probe tells the layer that refused it. The orchestrator (tests/deny) and the probe
// (tests/deny/probe) share it; the expectations come from the registry, not from a table written beside it.
//
// There are two layers (ADR 0002, "Enforcement is tested"):
//
//   - the socket: the caller's uid, with the groups its unit has, cannot open the socket (EACCES), because of the
//     mode and group of the socket and of the directories above it;
//   - the guard: the socket opens, the callee reads the peer uid, and the call graph (or the owner, or the exact caller
//     of a key@ socket) says no, as permission_denied with the reason call_graph.
package spec

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/blob/v2alpha1/blobv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/item/v2alpha1/itemv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/source/v2alpha1/sourcev2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// Kind is the protocol of a socket.
type Kind string

const (
	// Connect is a Connect service over h2c; the probe makes one unary call of a read-only procedure with an empty
	// request, which a callee that lets it through refuses as invalid or answers harmlessly.
	Connect Kind = "connect"
	// HTTP is entry's listener, which serves the forwarder only and drops any other peer.
	HTTP Kind = "http"
)

// Rule is how a callee decides who may call.
type Rule string

const (
	// CallGraph means the caller is allowed when registry.MayCall(caller, Who).
	CallGraph Rule = "call-graph"
	// Only is: the caller is allowed when its name is Who (the owner of a driver, the exact caller of a key@ socket, the
	// forwarder of entry, the writer of the spool's receive socket).
	Only Rule = "only"
)

// Target is a socket of the installation.
type Target struct {
	ID        string // a short unique name, for the table
	Service   string // the Compose service that serves it (for its log)
	Socket    string // the absolute path in a container
	Kind      Kind
	Procedure string // the Connect procedure of the probe; empty for HTTP
	Rule      Rule
	Who       string // the callee name for CallGraph, the only caller for Only
	Note      string
	// SocketOnly says that a denied caller must be refused at the socket itself, by the modes and groups of the socket
	// and its directories (REQ-DATA-066: a driver's socket only its owner can open; REQ-KEYS-044: a key@ socket in a
	// directory only its caller can open); a refusal by the guard is not enough. Server, the process that serves the
	// socket, opens its own socket, so its guard refusal stands.
	SocketOnly bool
	Server     string
}

// Allowed says whether the registry lets the caller (a registry name) call the target.
func (t Target) Allowed(caller string) bool {
	switch t.Rule {
	case CallGraph:
		return registry.MayCall(caller, t.Who)
	case Only:
		return caller == t.Who
	}
	return false
}

// Targets are the sockets of the local installation for the boundary, in a fixed order.
func Targets(boundary string) []Target {
	b := boundary
	owner := func(driver string) string {
		o, ok := registry.DriverOwner(driver)
		if !ok {
			panic("spec: not a driver of the registry: " + driver)
		}
		return o
	}
	ts := []Target{
		{ID: "store", Service: "store", Socket: fmt.Sprintf("/run/sluis/store/%s.sock", b), Kind: Connect,
			Procedure: storev2alpha1connect.StoreServiceGetProcedure, Rule: CallGraph, Who: "store"},
		{ID: "signer", Service: "signer", Socket: fmt.Sprintf("/run/sluis/signer/%s.sock", b), Kind: Connect,
			Procedure: signerv2alpha1connect.SignerServiceKeySetProcedure, Rule: CallGraph, Who: "signer"},
		{ID: "policy", Service: "policy", Socket: fmt.Sprintf("/run/sluis/policy/%s.sock", b), Kind: Connect,
			Procedure: policyv2alpha1connect.PolicyServiceDecideProcedure, Rule: CallGraph, Who: "policy"},
		{ID: "adapter", Service: "adapter-upstream-oidc", Socket: fmt.Sprintf("/run/sluis/adapter-upstream-oidc/%s.sock", b), Kind: Connect,
			Procedure: integrationv2alpha1connect.UpstreamServiceBeginProcedure, Rule: CallGraph, Who: "adapter-upstream-oidc"},
		{ID: "entry", Service: "entry", Socket: fmt.Sprintf("/run/sluis/entry/%s.sock", b), Kind: HTTP,
			Rule: Only, Who: "harness-forwarder", Note: "only the forwarder; any other peer is dropped and audited"},
		{ID: "spool-emit", Service: "drv-writer-spool", Socket: fmt.Sprintf("/run/sluis/audit/%s/emit.sock", b), Kind: Connect,
			Procedure: transportv2alpha1connect.TransportServiceEmitProcedure, Rule: CallGraph, Who: "transport",
			Note: "every emitter of the call graph"},
		{ID: "spool-receive", Service: "drv-writer-spool", Socket: fmt.Sprintf("/run/sluis/audit/%s/receive.sock", b), Kind: Connect,
			Procedure: transportv2alpha1connect.TransportServiceAckProcedure, Rule: Only, Who: "writer",
			Note: "only the writer; the shared group opens the socket, so the guard refuses the others"},
	}
	for _, c := range registry.CallersOf("key") {
		ts = append(ts, Target{ID: "key/" + c, Service: "key", Socket: fmt.Sprintf("/run/sluis/key/%s/%s/key.sock", b, c), Kind: Connect,
			Procedure: keyv2alpha1connect.KeyServicePublicKeyProcedure, Rule: Only, Who: c,
			Note: "a caller opens only its own key@ directory", SocketOnly: true, Server: "key"})
	}
	drv := func(id, service, socket, procedure, driver string) Target {
		return Target{ID: id, Service: service, Socket: socket, Kind: Connect, Procedure: procedure, Rule: Only, Who: owner(driver),
			SocketOnly: true, Server: driver}
	}
	ts = append(ts,
		drv("drv-key", "drv-key-software", fmt.Sprintf("/run/sluis/key/%s/driver/key-store.sock", b),
			keystorev2alpha1connect.KeyStoreServiceCapabilitiesProcedure, "driver-key-software"),
		drv("drv-durable", "drv-store-rqlite-durable", fmt.Sprintf("/run/sluis/store/%s/durable.sock", b),
			itemv2alpha1connect.ItemServiceGetProcedure, "driver-store-rqlite"),
		drv("drv-temp", "drv-store-rqlite-temp", fmt.Sprintf("/run/sluis/store/%s/temp.sock", b),
			itemv2alpha1connect.ItemServiceGetProcedure, "driver-store-rqlite"),
		drv("drv-config", "drv-store-file", fmt.Sprintf("/run/sluis/store/%s/config-source.sock", b),
			sourcev2alpha1connect.SourceServiceCapabilitiesProcedure, "driver-store-file"),
		drv("drv-secret", "drv-store-credential", fmt.Sprintf("/run/sluis/store/%s/secret-source.sock", b),
			sourcev2alpha1connect.SourceServiceCapabilitiesProcedure, "driver-store-credential"),
		drv("drv-blob", "drv-writer-fs", fmt.Sprintf("/run/sluis/writer/%s/blob.sock", b),
			blobv2alpha1connect.BlobServiceGetProcedure, "driver-writer-fs"),
	)
	return ts
}

// CallerName maps a uid of the installation to its registry name.
func CallerName(uid uint32) (string, bool) {
	n, _, ok := registry.NameForUID(uid)
	return n, ok
}

// Outcome is where a probe call ended.
type Outcome string

const (
	// Socket is: the socket could not be opened (EACCES).
	Socket Outcome = "socket"
	// Guard is: the socket opened and the callee refused the peer (permission_denied with call_graph, or for entry a
	// connection dropped with no answer).
	Guard Outcome = "guard"
	// Reached is: the call got past the guard (any other answer, success or error).
	Reached Outcome = "reached"
	// Broken is: the probe could not tell (the socket is missing, refused the connection, or the call failed in another way).
	Broken Outcome = "broken"
)

// Result is what the probe reports for one target.
type Result struct {
	ID      string  `json:"id"`
	Outcome Outcome `json:"outcome"`
	Detail  string  `json:"detail"` // EACCES, call_graph, dropped, the Connect code, ...
}

// Verdict is the judgment of one pair.
type Verdict struct {
	Caller   string
	Target   Target
	Allowed  bool // what the registry says
	Result   Result
	Violated bool
	Why      string
}

// Judge compares what the registry says with what the probe saw. An allowed pair must reach the callee past the guard.
// A denied pair must be refused at the socket or at the guard, and the guard's reason must be call_graph (a reason
// "caller" would mean the probe's uid is not known, which is a fault of the setup, not a refusal of the pair).
func Judge(caller string, t Target, r Result) Verdict {
	v := Verdict{Caller: caller, Target: t, Allowed: t.Allowed(caller), Result: r}
	switch {
	case r.Outcome == Broken:
		v.Violated, v.Why = true, "the probe could not tell: "+r.Detail
	case v.Allowed && r.Outcome != Reached:
		v.Violated, v.Why = true, fmt.Sprintf("allowed by the registry but refused at the %s (%s)", r.Outcome, r.Detail)
	case !v.Allowed && r.Outcome == Reached:
		v.Violated, v.Why = true, fmt.Sprintf("denied by the registry but reached the callee (%s)", r.Detail)
	case !v.Allowed && r.Outcome == Guard && t.SocketOnly && caller != t.Server:
		v.Violated, v.Why = true, "denied, but the socket opened: only its one caller may open it, and the guard alone refused"
	case !v.Allowed && r.Outcome == Guard && r.Detail != "call_graph" && r.Detail != "dropped":
		v.Violated, v.Why = true, "refused at the guard for the wrong reason: "+r.Detail
	}
	return v
}

// notCallers are the uids of the local installation that are no actor, driver or harness of the registry, each with its
// reason. A running container with any other uid that maps to no registry name fails the sweep.
var notCallers = map[uint32]string{
	60999: "rqlite, the engine's own process, which serves no socket of sluis and calls none",
}

// ExpectedCallers are the callers the matrix must probe: the registry name of every uid that a service of the Compose
// project runs as (deploy/local/compose.yaml, which tools/gen/compose generates from the registries), sorted, once
// each. A service with no user (the one-shot init) is not a caller; a uid that maps to no name and is not one of
// notCallers is an error, so a new service cannot drop out of the sweep unseen.
func ExpectedCallers(compose []byte) ([]string, error) {
	var doc struct {
		Services map[string]struct {
			User string `yaml:"user"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("the Compose project: %w", err)
	}
	if len(doc.Services) == 0 {
		return nil, errors.New("the Compose project has no service")
	}
	var names []string
	for svc, s := range doc.Services {
		if s.User == "" {
			continue
		}
		uid, err := strconv.ParseUint(strings.SplitN(s.User, ":", 2)[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("service %s: user %q is not a uid", svc, s.User)
		}
		if _, skip := notCallers[uint32(uid)]; skip {
			continue
		}
		n, ok := CallerName(uint32(uid))
		if !ok {
			return nil, fmt.Errorf("service %s runs as uid %d, which maps to no registry name", svc, uid)
		}
		names = append(names, n)
	}
	return Callers(names), nil
}

// NotCaller says whether a running uid is a known process that is not a caller.
func NotCaller(uid uint32) bool {
	_, ok := notCallers[uid]
	return ok
}

// Pair is one (caller, socket) pair, as the golden file of the allowed pairs writes it.
func Pair(caller, target string) string { return caller + " -> " + target }

// AllowedPairs are the pairs the registry allows among the callers and the targets, sorted.
func AllowedPairs(callers []string, ts []Target) []string {
	var out []string
	for _, c := range callers {
		for _, t := range ts {
			if t.Allowed(c) {
				out = append(out, Pair(c, t.ID))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ParseGolden reads the golden file of the allowed pairs: one pair a line, comments after "#", sorted.
func ParseGolden(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// Callers returns the names of the callers sorted, without duplicates.
func Callers(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
