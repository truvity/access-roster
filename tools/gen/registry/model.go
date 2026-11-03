package main

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The verbs of a store rule, as bit positions (the index in this list). The generated tables and the
// hand-written lookups of both kits use the same positions: kits/go/registry/registry.go and kits/rust/sluis-registry/src/lib.rs.
var verbNames = []string{"get", "list", "create", "update", "delete", "apply", "watch"}

// selfShift: bit (selfShift + verb position) says that the rule for that verb holds only for ids that start
// with "<actor>/".
const selfShift = 7

var opNames = []string{"seal", "open", "sign", "mac", "public-key", "wrap", "unwrap"}

// The uid of an actor instance: uidBase + ordinal + uidBlockStride * uid block (REQ-ISO-072).
const (
	uidBase        = 61000
	uidBlockStride = 1000
	maxOrdinals    = 128
)

// transportCallee is the pseudo-callee of the audit transport (the spool).
const transportCallee = "transport"

type kind struct {
	Name, Segment, Class, Scope, Treatment, Writer string
	SelfScoped, Personal, Exportable, BackedUp     bool
	Watched                                        bool
	TTLDefault, TTLMax                             time.Duration
	Indexes                                        []string
}

type actor struct {
	Name, Family, Language string
	Holder                 bool
	Ports, Calls, Egress   []string
}

type ruleKey struct{ Actor, Segment string }

type model struct {
	kinds    []kind
	actors   []actor
	store    map[ruleKey]uint16
	keys     map[[2]string]uint8
	callees  map[string][]string // caller -> sorted callees
	callers  map[string][]string // callee -> sorted callers
	uidNames []string
	drivers  map[string]string // driver user -> owner actor
	ttlNotes []string          // kinds whose TTL was taken from prose, for the generated comment
}

var (
	segmentRe  = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	durationRe = regexp.MustCompile(`\b(\d+)(s|m|h|d)\b`)
	ownIDRe    = regexp.MustCompile(`own id`)
)

// segmentOf: the kebab-case of a PascalCase name, by "Address encoding" in docs/reference/store-api.md: a
// hyphen before each capital that follows a lower-case letter or a digit, then lower-cased.
func segmentOf(name string) string {
	var b strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			p := name[i-1]
			if (p >= 'a' && p <= 'z') || (p >= '0' && p <= '9') {
				b.WriteByte('-')
			}
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// ttlInherit: temp kinds whose registry row gives no duration for the maximum because the lifetime is another
// object's. The bound is that kind's maximum. Listed here so a reviewer sees each one.
var ttlInherit = map[string]string{
	// kinds.yaml: ttl {default: "the session's", max: "the session's"}; the upstream session lives as long as the
	// browser session, which a session chain bounds.
	"UpstreamSession": "SessionChain",
}

func parseDuration(s string) (time.Duration, bool, bool) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false, false
	}
	unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	whole := strings.TrimSpace(s) == m[0]
	return time.Duration(n) * unit, true, whole
}

// shortDur writes a duration the way the registry does: 90d, 24h, 10m, 30s.
func shortDur(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

type expansion struct {
	actors  []string
	self    bool
	outside bool // IaC or pipeline: no actor
}

var contractOf = map[string]string{ //nolint:gosec // contract names, no credentials
	"credential minter": "CredentialMinter",
	"provisioner":       "Provisioner",
	"facts source":      "FactsSource",
	"upstream":          "Upstream",
	"notifier":          "Notifier",
}

type builder struct {
	in        *inputs
	names     []string // the actors of actors.yaml (not the platform pieces)
	nameSet   map[string]bool
	adapters  []string
	contracts map[string][]string
	errs      []error
}

func (b *builder) errorf(format string, a ...any) {
	b.errs = append(b.errs, fmt.Errorf(format, a...))
}

// expand turns one token of `writer`, `readers` or `watched_by` into the actors it names. The macros are the
// ones of docs/architecture/kinds.yaml; tools/checks/rules-page.mjs reads them the same way.
func (b *builder) expand(kindName, tok string) expansion {
	base, qual := tok, ""
	if i := strings.Index(tok, "("); i >= 0 && strings.HasSuffix(strings.TrimSpace(tok), ")") {
		base = strings.TrimSpace(tok[:i])
		qual = strings.TrimSuffix(strings.TrimSpace(tok[i+1:]), ")")
	}
	base = strings.TrimSpace(base)
	plain := strings.TrimSuffix(base, "@")
	switch {
	case b.nameSet[plain]:
		return expansion{actors: []string{plain}}
	case base == "IaC" || base == "pipeline" || strings.HasPrefix(base, "none yet"):
		return expansion{outside: true}
	case base == "every actor":
		return expansion{actors: b.names, self: ownIDRe.MatchString(qual)}
	case base == "self":
		return expansion{actors: b.names, self: true}
	case base == "the actor named in the id":
		if strings.Contains(qual, "adapter") {
			return expansion{actors: b.adapters, self: true}
		}
		return expansion{actors: b.names, self: true}
	case base == "adapter-<vendor>":
		if c, ok := strings.CutPrefix(qual, "as "); ok {
			contract, known := contractOf[c]
			if !known {
				b.errorf("%s: %s: (as %s) names no contract", kindName, tok, c)
				return expansion{outside: true}
			}
			var out []string
			for _, a := range b.adapters {
				if slices.Contains(b.contracts[a], contract) {
					out = append(out, a)
				}
			}
			return expansion{actors: out}
		}
		// an adapter writes and reads ids under its own name only
		return expansion{actors: b.adapters, self: true}
	}
	b.errorf("%s: %q is neither an actor nor a known macro", kindName, tok)
	return expansion{outside: true}
}

func bit(verb string) uint16 {
	return 1 << slices.Index(verbNames, verb)
}

func build(in *inputs) (*model, error) {
	b := &builder{in: in, nameSet: map[string]bool{}, contracts: map[string][]string{}}
	m := &model{store: map[ruleKey]uint16{}, keys: map[[2]string]uint8{}}

	// the actors; the platform pieces follow
	for _, a := range in.actors.Actors {
		b.names = append(b.names, a.Name)
		b.nameSet[a.Name] = true
		b.contracts[a.Name] = a.Contracts
		if strings.HasPrefix(a.Name, "adapter-") {
			b.adapters = append(b.adapters, a.Name)
		}
		m.actors = append(m.actors, actor{a.Name, a.Family, a.Language, a.Holder, a.Ports, a.Calls, a.Egress})
	}
	for _, a := range in.actors.Platform {
		m.actors = append(m.actors, actor{a.Name, "platform", a.Language, a.Holder, a.Ports, a.Calls, a.Egress})
	}
	known := map[string]bool{}
	for _, a := range m.actors {
		if known[a.Name] {
			b.errorf("actor %s is listed twice", a.Name)
		}
		known[a.Name] = true
	}

	b.kinds(m)
	b.keyRules(m)
	b.callGraph(m, known)
	b.uids(m, known)

	if len(b.errs) > 0 {
		return nil, errors.Join(b.errs...)
	}
	return m, nil
}

var (
	classes    = []string{"config", "secret", "durable", "temp"}
	scopes     = []string{"boundary", "boundary+tenant"}
	treatments = []string{"hashed", "sealed", "plain"}
)

func (b *builder) kinds(m *model) {
	segments := map[string]string{}
	type acc struct{ verbs, unscoped uint16 }
	rules := map[ruleKey]*acc{}
	add := func(actorName, segment string, verbs uint16, self bool) {
		k := ruleKey{actorName, segment}
		if rules[k] == nil {
			rules[k] = &acc{}
		}
		r := rules[k]
		r.verbs |= verbs
		if !self {
			r.unscoped |= verbs
		}
	}
	notes := map[string]string{}

	for _, k := range b.in.kinds.Kinds {
		seg := segmentOf(k.Name)
		if !segmentRe.MatchString(seg) {
			b.errorf("%s: segment %q is not a valid address part", k.Name, seg)
		}
		if other, dup := segments[seg]; dup {
			b.errorf("%s and %s share the segment %s", k.Name, other, seg)
		}
		segments[seg] = k.Name
		if !slices.Contains(classes, k.Class) {
			b.errorf("%s: class %q", k.Name, k.Class)
		}
		if !slices.Contains(scopes, k.Scope) {
			b.errorf("%s: scope %q", k.Name, k.Scope)
		}
		if !slices.Contains(treatments, k.Treatment) {
			b.errorf("%s: treatment %q", k.Name, k.Treatment)
		}
		row := kind{
			Name: k.Name, Segment: seg, Class: k.Class, Scope: k.Scope, Treatment: k.Treatment,
			Writer:     strings.TrimSpace(strings.TrimSuffix(strings.SplitN(k.Writer, "(", 2)[0], "@")),
			SelfScoped: k.SelfScoped, Personal: k.Personal,
			Exportable: k.Exportable == "yes", BackedUp: k.BackedUp == "yes",
			Indexes: slices.Clone(k.Indexes),
		}

		// lifetime
		if k.TTL != nil {
			d, dok, dwhole := parseDuration(k.TTL.Default)
			x, xok, xwhole := parseDuration(k.TTL.Max)
			row.TTLDefault, row.TTLMax = d, x
			if dok && !dwhole {
				notes[k.Name] += fmt.Sprintf("default %s taken from %q; ", shortDur(d), k.TTL.Default)
			}
			if xok && !xwhole {
				notes[k.Name] += fmt.Sprintf("max %s taken from %q; ", shortDur(x), k.TTL.Max)
			}
			if k.TTL.Default != "" && !dok {
				notes[k.Name] += fmt.Sprintf("default 0 (the writer must give a TTL): %q; ", k.TTL.Default)
			}
			if k.Class == "temp" && !xok {
				if src, ok := ttlInherit[k.Name]; ok {
					notes[k.Name] += fmt.Sprintf("max taken from the max of %s: %q; ", src, k.TTL.Max)
				} else {
					b.errorf("%s: a temp kind needs a parseable ttl.max, got %q", k.Name, k.TTL.Max)
				}
			}
			if dok && xok && d > x {
				b.errorf("%s: ttl default %s is above its max %s", k.Name, d, x)
			}
		} else if k.Class == "temp" {
			b.errorf("%s: a temp kind needs a ttl", k.Name)
		}

		// the rules
		w := b.expand(k.Name, k.Writer)
		if w.outside && k.Class != "config" && k.Class != "secret" && !strings.HasPrefix(k.Writer, "none yet") {
			b.errorf("%s: writer %s is outside sluis but the kind is %s", k.Name, k.Writer, k.Class)
		}
		for _, a := range w.actors {
			add(a, seg, bit("create")|bit("update")|bit("delete")|bit("apply")|bit("get")|bit("list"), w.self)
		}
		for _, t := range k.Readers {
			r := b.expand(k.Name, t)
			for _, a := range r.actors {
				add(a, seg, bit("get")|bit("list"), r.self)
			}
		}
		watchers := k.WatchedBy
		if k.Class == "config" {
			watchers = k.Readers
		}
		if k.Exportable == "yes" {
			watchers = append(slices.Clone(watchers), "exporter@")
		}
		for _, t := range watchers {
			r := b.expand(k.Name, t)
			for _, a := range r.actors {
				add(a, seg, bit("watch"), r.self)
				row.Watched = true
			}
		}
		// The backup job reads every backed-up kind as ciphertext, whatever `readers` lists, and in full: it is
		// added whether or not exporter is a reader already, because a reader macro may bind exporter to its own
		// ids only (Switch), which would leave the backup unable to read the kind.
		if k.BackedUp == "yes" {
			add("exporter", seg, bit("get")|bit("list"), false)
		}

		m.kinds = append(m.kinds, row)
	}

	for name, src := range ttlInherit {
		var from, to *kind
		for i := range m.kinds {
			switch m.kinds[i].Name {
			case src:
				from = &m.kinds[i]
			case name:
				to = &m.kinds[i]
			}
		}
		if to == nil {
			continue // the kind is gone from the registry; the entry is stale and harmless
		}
		if from == nil || from.TTLMax == 0 {
			b.errorf("ttlInherit: %s cannot take the max of %s", name, src)
			continue
		}
		to.TTLMax = from.TTLMax
	}

	for k, r := range rules {
		bits := r.verbs
		for i := range verbNames {
			if r.verbs&(1<<i) != 0 && r.unscoped&(1<<i) == 0 {
				bits |= 1 << (selfShift + i)
			}
		}
		m.store[k] = bits
	}
	for n, s := range notes {
		m.ttlNotes = append(m.ttlNotes, fmt.Sprintf("%s: %s", n, strings.TrimSuffix(s, "; ")))
	}
	sort.Strings(m.ttlNotes)
}

func (b *builder) keyRules(m *model) {
	allowed := map[string]map[string]bool{}
	note := func(purpose string, ops []string) {
		if allowed[purpose] == nil {
			allowed[purpose] = map[string]bool{}
		}
		for _, o := range ops {
			allowed[purpose][o] = true
		}
	}
	for _, p := range b.in.keys.Purposes {
		note(p.Name, p.Ops)
	}
	for n, d := range b.in.keys.DataKeys.Tenant {
		note(n, d.Ops)
	}
	for n, d := range b.in.keys.DataKeys.Boundary {
		note(n, d.Ops)
	}
	users := slices.Concat(b.in.actors.Actors, b.in.actors.Platform, b.in.actors.Externals)
	for _, a := range users {
		for _, kp := range a.KeyPurposes {
			ops, ok := allowed[kp.Purpose]
			if !ok {
				b.errorf("%s: key purpose %q is not in %s", a.Name, kp.Purpose, keysFile)
				continue
			}
			var bits uint8
			for _, o := range kp.Ops {
				i := slices.Index(opNames, o)
				switch {
				case i < 0:
					b.errorf("%s: key purpose %s: op %q is unknown", a.Name, kp.Purpose, o)
				case !ops[o]:
					b.errorf("%s: key purpose %s: op %q is not an op of the purpose in %s", a.Name, kp.Purpose, o, keysFile)
				default:
					bits |= 1 << i
				}
			}
			m.keys[[2]string{a.Name, kp.Purpose}] |= bits
		}
	}
}

func (b *builder) callGraph(m *model, known map[string]bool) {
	edges := map[[2]string]bool{}
	for _, a := range m.actors {
		for _, c := range a.Calls {
			if c == "adapter-<vendor>" {
				for _, ad := range b.adapters {
					edges[[2]string{a.Name, ad}] = true
				}
				continue
			}
			if !known[c] {
				b.errorf("%s calls %q, which is no actor", a.Name, c)
				continue
			}
			edges[[2]string{a.Name, c}] = true
		}
		// the ports reach store, key and the audit transport
		if slices.Contains(a.Ports, "data") {
			edges[[2]string{a.Name, "store"}] = true
		}
		if slices.Contains(a.Ports, "keys") {
			edges[[2]string{a.Name, "key"}] = true
		}
		if slices.Contains(a.Ports, "audit-emit") || a.Name == "writer" {
			edges[[2]string{a.Name, transportCallee}] = true
		}
	}
	m.callees = map[string][]string{}
	m.callers = map[string][]string{}
	for e := range edges {
		m.callees[e[0]] = append(m.callees[e[0]], e[1])
		m.callers[e[1]] = append(m.callers[e[1]], e[0])
	}
	for _, s := range m.callees {
		sort.Strings(s)
	}
	for _, s := range m.callers {
		sort.Strings(s)
	}
}

func (b *builder) uids(m *model, known map[string]bool) {
	names := b.in.uids.Names
	if len(names) > maxOrdinals {
		b.errorf("%s: %d names, at most %d", uidsFile, len(names), maxOrdinals)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			b.errorf("%s: %s is listed twice", uidsFile, n)
		}
		seen[n] = true
	}
	for n := range known {
		if !seen[n] {
			b.errorf("%s: the actor %s has no ordinal; append it to the list", uidsFile, n)
		}
	}
	m.uidNames = slices.Clone(names)

	m.drivers = map[string]string{}
	for _, n := range names {
		rest, ok := strings.CutPrefix(n, "driver-")
		if !ok {
			continue
		}
		owner := ""
		for a := range known {
			if strings.HasPrefix(rest, a+"-") && len(a) > len(owner) {
				owner = a
			}
		}
		if owner == "" {
			b.errorf("%s: %s names no owning actor", uidsFile, n)
			continue
		}
		m.drivers[n] = owner
	}
}
