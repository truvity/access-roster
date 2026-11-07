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
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/blob/v2alpha1/blobv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/destination/v2alpha1/destinationv2alpha1connect"
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
		// The directory destination of exporter@: List of an empty prefix answers harmlessly to its one caller.
		drv("drv-exporter", "drv-exporter-dir", fmt.Sprintf("/run/sluis/exporter/%s/directory.sock", b),
			destinationv2alpha1connect.DestinationServiceListProcedure, "driver-exporter-dir"),
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
	Caller   string // the label of the row (Row.Label)
	Name     string // the registry name the callee's guard sees (Row.Caller)
	Target   Target
	Allowed  bool // what the registry says
	Result   Result
	Violated bool
	Why      string
}

// Judge compares what the registry says with what the probe saw. An allowed pair must reach the callee past the guard.
// A denied pair must be refused at the socket or at the guard, and the guard's reason must be call_graph (a reason
// "caller" would mean the probe's uid is not known, which is a fault of the setup, not a refusal of the pair).
func Judge(row Row, t Target, r Result) Verdict {
	caller := row.Caller
	v := Verdict{Caller: row.Label, Name: caller, Target: t, Allowed: row.Allowed(t), Result: r}
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

// ExpectedRows are the rows the matrix must probe: every distinct (uid, groups) of the services of the Compose project
// (deploy/local/compose.yaml, which tools/gen/compose generates from the registries), as Rows makes them. A service
// with no user (the one-shot init) is no row; a uid that maps to no name and is not one of notCallers is an error, so a
// new service cannot drop out of the sweep unseen.
func ExpectedRows(compose []byte) ([]Row, error) {
	var doc struct {
		Services map[string]struct {
			User     string   `yaml:"user"`
			GroupAdd []string `yaml:"group_add"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("the Compose project: %w", err)
	}
	if len(doc.Services) == 0 {
		return nil, errors.New("the Compose project has no service")
	}
	var us []Unit
	for svc, s := range doc.Services {
		if s.User == "" {
			continue
		}
		uid, err := ParseUser(s.User)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", svc, err)
		}
		us = append(us, Unit{Service: svc, UID: uid, Groups: s.GroupAdd})
	}
	return Rows(us)
}

// ParseUser reads the uid of a Compose or Docker user "uid:gid".
func ParseUser(user string) (uint32, error) {
	uid, err := strconv.ParseUint(strings.SplitN(user, ":", 2)[0], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("user %q is not a uid", user)
	}
	return uint32(uid), nil
}

// Unit is a service of the installation as the matrix sees it: its uid and the supplementary groups of its container.
type Unit struct {
	Service string
	UID     uint32
	Groups  []string
}

// Row is one identity the matrix probes: a uid with the groups of one unit. Label names it in the report and in the
// golden file: the registry name of the uid, or, for a unit that borrows a caller's uid (borrowers), its service.
// Caller is the registry name that the callee's guard sees.
type Row struct {
	Label, Caller string
	Service       string   // the first service, by name, that the row stands for
	Groups        []string // sorted
	borrowed      bool
	reaches       []string // for a borrower, the targets it must reach
}

// Allowed says whether the row must reach the target: what the registry lets its caller call, and, for a borrower,
// only the targets the borrower is listed with.
func (r Row) Allowed(t Target) bool {
	if r.borrowed && !slices.Contains(r.reaches, t.ID) {
		return false
	}
	return t.Allowed(r.Caller)
}

// A borrower is a unit that runs as the uid of a caller with fewer groups than the caller's own unit. The callees'
// guards see the caller, so the registry alone would let it make every call of the caller: the modes and groups of the
// sockets are all that hold it to less, and the matrix probes it as a row of its own, held to the targets listed here.
// Every other target must refuse it.
type borrower struct {
	of      string   // the registry name whose uid it runs as
	reaches []string // the ids of the targets it must reach
}

var borrowers = map[string]borrower{
	// The audit front (ADR 0028, "The audit front"): entry's executable with entry's uid, which holds no key and calls
	// the reader alone (not a target here); it emits its audit records into the spool. key/entry must refuse it.
	"entry-audit": {of: "entry", reaches: []string{"spool-emit"}},
	// The loopback of the upstream (tools/gen/compose): socat in the adapter's network, with the adapter's uid and none
	// of its groups. It is no sluis process and must reach nothing.
	"idp-loopback": {of: "adapter-upstream-oidc"},
}

// Rows are the identities to probe among the units, sorted by label. Units of one uid with the same groups are one row
// (two ports of a driver); a unit of a caller's uid with other groups must be a borrower, or Rows fails: a second unit
// that the matrix does not hold to its own groups is a gap, not a duplicate.
func Rows(us []Unit) ([]Row, error) {
	us = slices.Clone(us)
	slices.SortFunc(us, func(a, b Unit) int { return strings.Compare(a.Service, b.Service) })
	by := map[string]Row{}
	for _, u := range us {
		if _, skip := notCallers[u.UID]; skip {
			continue
		}
		name, ok := CallerName(u.UID)
		if !ok {
			return nil, fmt.Errorf("service %s runs as uid %d, which maps to no registry name", u.Service, u.UID)
		}
		groups := slices.Clone(u.Groups)
		slices.Sort(groups)
		r := Row{Label: name, Caller: name, Service: u.Service, Groups: groups}
		if b, ok := borrowers[u.Service]; ok {
			if b.of != name {
				return nil, fmt.Errorf("service %s runs as %s, not as %s, whose uid it is listed to borrow", u.Service, name, b.of)
			}
			r.Label, r.borrowed, r.reaches = u.Service, true, b.reaches
		}
		if prev, dup := by[r.Label]; dup {
			if !slices.Equal(prev.Groups, groups) {
				return nil, fmt.Errorf("services %s and %s run as %s with other groups: list the second in the borrowers of tests/deny/internal/spec", prev.Service, u.Service, name)
			}
			continue
		}
		by[r.Label] = r
	}
	out := make([]Row, 0, len(by))
	for _, r := range by {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Row) int { return strings.Compare(a.Label, b.Label) })
	return out, nil
}

// Labels are the labels of the rows, in order.
func Labels(rows []Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Label
	}
	return out
}

// Pair is one (caller, socket) pair, as the golden file of the allowed pairs writes it.
func Pair(caller, target string) string { return caller + " -> " + target }

// AllowedPairs are the pairs the rows must reach among the targets, sorted.
func AllowedPairs(rows []Row, ts []Target) []string {
	var out []string
	for _, r := range rows {
		for _, t := range ts {
			if r.Allowed(t) {
				out = append(out, Pair(r.Label, t.ID))
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
