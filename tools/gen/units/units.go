package main

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The board layout the units assume. The binaries sit under BinDir exactly where `just build-arm64` puts them
// under dist/arm64 (actors/<name>, drivers/<owner>/<driver>); PLAN.md "Board deployment" and D-12.
const (
	// BinDir is the infrastructure convention on the boards (D-12); the packages use /usr/libexec/sluis.
	BinDir = "/opt/sluis/bin"
	// StateRoot holds the state of the units. It is not /var/lib/sluis, which is the rqlite user's.
	StateRoot = "/var/lib/sluis-state"
	// LoadRoot is where the deploy puts the files that LoadCredential= reads (systemd credentials).
	LoadRoot = "/etc/sluis/credentials"

	// maxName is the longest user name that systemd-sysusers accepts (31 characters).
	maxName = 31
)

// Options say what to generate.
type Options struct {
	Boundary string // the boundary whose users and directories are generated; instances are sluis-<actor>@<boundary>
	UIDBlock uint32 // the uid block of the boundary (REQ-ISO-072)
}

// Unit is one generated service, with the facts the deploy needs to place it.
type Unit struct {
	Name     string // the template: sluis-session@.service; sluis-drv-store-rqlite-durable@.service for a port of a driver
	Instance string // the instance of the boundary: sluis-session@dev.service
	Kind     string // actor | driver
	Binary   string // below BinDir and dist/arm64: actors/session, drivers/key/software
	Registry string // the registry name: session, driver-key-software
	Port     string // a driver with more than one unit: the port that this unit serves (durable); otherwise empty
	User     string // the user of the instance: sluis-session-dev
	UID      uint32
	Order    int // the start order: drivers, data, keys, audit, work
	// Needs are the registry names whose user and directory must exist before this unit can start: the
	// groups it joins. The deploy installs them even when their own binary is not built yet.
	Needs []string
	// Joins are the registry names whose groups the unit joins (SupplementaryGroups=); a subset of Needs.
	Joins []string
}

// A driver the generator knows how to run. A driver of the registry that has no row here is "pending" until
// the package that builds it adds one: nothing is guessed about a command line that does not exist yet.
type driverSpec struct {
	Language string // Go or Rust, for the memory ceiling of the Go ones
	Network  bool   // the driver reaches the network (an engine); every other unit has AF_UNIX only
	// Units are the processes of the driver. Most drivers are one process; the rqlite driver serves one port per process
	// (--namespace), so it is two units of one binary and one user.
	Units []driverProc
}

// driverProc is one process of a driver.
type driverProc struct {
	Port   string // "" for the only unit of a driver; otherwise the unit is named for the port (sluis-drv-store-rqlite-durable)
	Socket string // the port's socket, below Dir (PLAN.md "Socket layout")
	// Dir is where the socket is made, with %i for the boundary; empty is /run/sluis/<owner>/%i. The spool makes both of
	// its sockets in /run/sluis/audit/%i, where every emitter looks for emit.sock.
	Dir string
	// DirMode is the mode of Dir when the owner's tmpfiles entry makes it: 1770, closed to every user but the owner and
	// the owner's drivers, unless the callers of the socket have to pass through it.
	DirMode string
	// SocketFlag is the flag that names the socket: --socket, or --socket-dir for the spool, which makes two sockets.
	SocketFlag string
	Args       []string // the driver's own flags; %STATE% is its state directory
	State      bool     // the driver has a state directory, below StateRoot, given to --state-dir or --root
	// NoSocketGID is set for a binary that has no --socket-gid yet; its socket then stays 0600 for its own user, which the
	// owner cannot open. The row says so until the driver takes the flag.
	NoSocketGID bool
	// Environment and EnvironmentFile are for a value that differs per board and that no flag may carry in the repository.
	Environment     []string
	EnvironmentFile string
	After           []string // units outside the generator that this one starts after
	// Credentials are systemd credentials the unit loads: name -> source file below LoadRoot/<boundary>/<stem>/.
	Credentials []string
}

var drivers = map[string]driverSpec{
	// drivers/key/software: serve --socket --state-dir --environment. The floor of the environment is in the driver.
	"driver-key-software": {
		Language: "Go",
		Units: []driverProc{{
			Socket: keyDriverSocket, State: true,
			Args: []string{"--state-dir", "%STATE%", "--environment", "development"},
		}},
	},
	// drivers/writer/fs: serve --socket --root [--socket-gid].
	"driver-writer-fs": {
		Language: "Rust",
		Units:    []driverProc{{Socket: "blob.sock", State: true, Args: []string{"--root", "%STATE%"}}},
	},
	// drivers/writer/spool: serve --socket-dir --root [--socket-gid]. It makes emit.sock (every emitting actor) and
	// receive.sock (the writer) in one directory, 0660 for the spool's group, which the emitters and the writer join.
	"driver-writer-spool": {
		Language: "Rust",
		Units: []driverProc{{
			Socket: "emit.sock", Dir: "/run/sluis/audit/%i", DirMode: "1771", SocketFlag: "--socket-dir", State: true,
			Args: []string{"--root", "%STATE%"},
		}},
	},
	// drivers/store/rqlite: serve --socket --rqlite-url --namespace durable|temp. One process per port. The engine's URL is
	// the board's own and differs per board, so the repository carries the loopback default of bare-metal.md ("Engines")
	// and the deploy may override it in /etc/sluis/rqlite-<boundary>.env. The driver has no --socket-gid yet.
	"driver-store-rqlite": {
		Language: "Rust", Network: true,
		Units: []driverProc{
			rqliteUnit("durable"),
			rqliteUnit("temp"),
		},
	},
	// drivers/store/file: serve --socket --dir [--socket-gid]. The signed config documents the harness put on the board.
	"driver-store-file": {
		Language: "Rust",
		Units:    []driverProc{{Socket: "config-source.sock", Args: []string{"--dir", "/etc/sluis/config/%i"}}},
	},
	// drivers/store/credential: serve --socket [--dir] [--socket-gid]. The directory is $CREDENTIALS_DIRECTORY, which
	// systemd makes for the LoadCredential= lines. The names are those of tests/installations/local/install.yaml, the
	// credentials that the skeleton's config documents refer to.
	"driver-store-credential": {
		Language: "Rust",
		Units: []driverProc{{
			Socket: "secret-source.sock", Credentials: []string{"client-dev", "client-example-app", "upstream-workforce"},
		}},
	},
}

func rqliteUnit(port string) driverProc {
	return driverProc{
		Port: port, Socket: port + ".sock", NoSocketGID: true,
		Args:            []string{"--rqlite-url", "${SLUIS_RQLITE_URL}", "--namespace", port},
		Environment:     []string{"SLUIS_RQLITE_URL=http://127.0.0.1:4001"},
		EnvironmentFile: "-/etc/sluis/rqlite-%i.env",
		After:           []string{"sluis-rqlite.service"},
	}
}

// pendingDrivers are the drivers of the registry that no package has built yet. A driver that is in neither
// this list nor `drivers` fails the generator, so a new driver cannot be forgotten.
var pendingDrivers = []string{"driver-indexer-sqlite"}

// actorSpec is what an actor's command line has beyond `serve --boundary B --socket S`. An actor that is not here
// takes only those; the package that builds an actor adds its row when it needs more.
type actorSpec struct {
	NoSocket bool // the actor has no --socket (key@ serves one socket per caller below --run-dir)
	// Args are the actor's own flags; %i is the boundary, %H the host's name.
	Args []string
	// ArgsFor are flags that depend on the uid block: a group number is the uid of a registry name.
	ArgsFor func(Options) ([]string, error)
	// Credentials are systemd credentials the unit loads: the source file is LoadRoot/<boundary>/<stem>/<name>.
	Credentials []string
	// Joins are registry names whose group the unit joins although the call graph does not say so.
	Joins []string
}

// forwarder is the registry name of the edge's reverse proxy, the only caller of entry's listener. It is a harness piece,
// not an actor: it has a uid and a group (the generator makes them) and no unit here.
const forwarder = "harness-forwarder"

var actorSpecs = map[string]actorSpec{
	// actors/key: the flags of actors/key/main.go. The run directory and the per-caller directories below it are made by
	// the platform (tmpfiles); the driver's socket is <run-dir>/driver/key-store.sock; --node is the board's short name.
	"key": {NoSocket: true, Args: []string{
		"--run-dir", "/run/sluis/key/%i",
		"--store-socket", "/run/sluis/store/%i.sock",
		"--driver-socket", "/run/sluis/key/%i/" + keyDriverSocket,
		"--transport-socket", "/run/sluis/audit/%i/emit.sock",
		"--node", "%H",
	}},
	// actors/store: the bootstrap file is required; the sockets of key@ and of the audit transport have the defaults, which
	// are those of PLAN.md "Socket layout", and the destinations are in the bootstrap file.
	"store": {Args: []string{"--bootstrap", "/etc/sluis/bootstrap.d/%i.yaml"}},
	// actors/signer: the sockets of store@, key@ and the audit transport have the defaults of the plan; --node is the board's
	// short name, which keeps each board's token-signing key its own. The listener is the default group, signer's own,
	// which session and exchange join.
	"signer": {Args: []string{"--node", "%H"}},
	// actors/entry: the listener is /run/sluis/entry/<boundary>.sock (the default of --socket here), 0660 for the
	// forwarder's group, which entry joins to be allowed to give the socket to it; --run-dir has the default /run/sluis.
	"entry": {
		ArgsFor: func(o Options) ([]string, error) {
			uid, ok := registry.UID(forwarder, o.UIDBlock)
			if !ok {
				return nil, fmt.Errorf("%s has no uid in block %d", forwarder, o.UIDBlock)
			}
			return []string{"--socket-gid", strconv.FormatUint(uint64(uid), 10)}, nil
		},
		Joins: []string{forwarder},
	},
	// actors/adapter-upstream-oidc: the sockets of store@, the transport and key@ have the defaults of the plan. The client
	// secret of the Upstream `workforce` is the credential upstream.workforce.client-secret (upstreamd.CredentialDir).
	"adapter-upstream-oidc": {Credentials: []string{"upstream.workforce.client-secret"}},
}

// keyDriverSocket is the key-store driver's socket below key@'s run directory (actors/key/main.go).
const keyDriverSocket = "driver/key-store.sock"

// A file of the output, by name below the output directory.
type File struct {
	Name string
	Body string
}

const header = "# Generated by tools/gen/units from the registries (docs/architecture/*.yaml, tools/gen/registry/uids.yaml).\n" +
	"# Do not edit: run `just units-gen`.\n"

// Generate returns every file for the boundary: per unit a template, the user and the directories; the shared
// base directories; and the index the deploy reads.
func Generate(o Options) ([]File, error) {
	if o.Boundary != "dev" {
		// The software key driver is started with --environment development; no other boundary is generated.
		return nil, fmt.Errorf("boundary %q: only the dev boundary is generated", o.Boundary)
	}
	units, err := plan(o)
	if err != nil {
		return nil, err
	}
	var files []File
	made := map[string]bool{} // the users made: one user can run more than one unit (the two ports of the rqlite driver)
	for _, u := range units {
		svc, sys, tmp, err := render(o, u)
		if err != nil {
			return nil, err
		}
		stem := unitStem(u.Registry)
		files = append(files, File{u.Name, svc})
		if !made[stem] {
			made[stem] = true
			files = append(files, File{stem + ".sysusers", sys})
			if tmp != "" {
				files = append(files, File{stem + ".tmpfiles", tmp})
			}
		}
	}
	// The node agent has no unit yet, but key@ has a directory for it as one of its callers: its user must exist. The
	// forwarder is the harness's: entry's socket belongs to its group.
	for _, name := range []string{"sluis-node", forwarder} {
		uid, ok := registry.UID(name, o.UIDBlock)
		if !ok {
			return nil, fmt.Errorf("%s has no uid in block %d", name, o.UIDBlock)
		}
		if name == "sluis-node" {
			if a, ok := registry.ActorByName(name); !ok || a.Family != "platform" {
				continue
			}
		}
		piece := Unit{Registry: name, User: userOf(name, o.Boundary), UID: uid}
		files = append(files, File{unitStem(name) + ".sysusers", sysusersFor(o, piece)})
	}
	files = append(files, File{"base.tmpfiles", baseTmpfiles(o)}, File{"index.tsv", index(units)})
	return files, nil
}

// plan lists the units: the drivers that have a row, then the actors by family.
func plan(o Options) ([]Unit, error) {
	var out []Unit
	known := map[string]bool{}
	for _, n := range pendingDrivers {
		known[n] = true
	}
	for n := range drivers {
		known[n] = true
	}
	for _, a := range registry.Actors() {
		if a.Family == "platform" {
			continue // the node agent is per node, not per boundary, and has no consumer yet
		}
		u, err := unit(o, a.Name, "actor", "actors/"+a.Name, orderOf(a.Family))
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	// The drivers come from the uid list through the owner table; the registry has no other list of them.
	for _, d := range knownDriverNames() {
		if !known[d] {
			return nil, fmt.Errorf("the registry has the driver %s but the generator knows neither a row for it nor a pending entry", d)
		}
		if _, ok := drivers[d]; !ok {
			continue
		}
		owner, drv, err := splitDriver(d)
		if err != nil {
			return nil, err
		}
		for _, du := range drivers[d].Units {
			u, err := unit(o, d, "driver", "drivers/"+owner+"/"+drv, 0)
			if err != nil {
				return nil, err
			}
			u.Port = du.Port
			u.Name = driverTemplate(d, du.Port)
			u.Instance = strings.TrimSuffix(u.Name, "@.service") + "@" + o.Boundary + ".service"
			out = append(out, u)
		}
	}
	for n := range known {
		if !slices.Contains(knownDriverNames(), n) {
			return nil, fmt.Errorf("the generator names the driver %s, which the registry does not have", n)
		}
	}
	slices.SortStableFunc(out, func(a, b Unit) int {
		if a.Order != b.Order {
			return a.Order - b.Order
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// orderOf is the start order of PLAN.md: drivers (0), then store@ and the other data actors, key@, the audit pieces and
// last the work actors.
func orderOf(family string) int {
	switch family {
	case "data":
		return 1
	case "keys":
		return 2
	case "audit":
		return 3
	}
	return 4
}

func unit(o Options, regName, kind, binary string, order int) (Unit, error) {
	uid, ok := registry.UID(regName, o.UIDBlock)
	if !ok {
		return Unit{}, fmt.Errorf("%s has no uid in block %d", regName, o.UIDBlock)
	}
	stem := unitStem(regName)
	u := Unit{
		Name: stem + "@.service", Instance: stem + "@" + o.Boundary + ".service", Kind: kind, Binary: binary,
		Registry: regName, User: userOf(regName, o.Boundary), UID: uid, Order: order,
	}
	u.Joins = groupsOf(regName, kind)
	if kind == "actor" {
		u.Joins = append(u.Joins, actorSpecs[regName].Joins...)
		slices.Sort(u.Joins)
	}
	u.Needs = append(slices.Clone(u.Joins), extraNeeds(regName, kind)...)
	slices.Sort(u.Needs)
	u.Needs = slices.Compact(u.Needs)
	if len(u.User) > maxName {
		return Unit{}, fmt.Errorf("the user %s has %d characters, systemd-sysusers takes at most %d", u.User, len(u.User), maxName)
	}
	return u, nil
}

// unitStem: actor "session" is sluis-session; driver "driver-key-software" is sluis-drv-key-software. The driver
// users carry "drv", not "driver", so that the longest name still fits the 31 characters of a user name.
func unitStem(regName string) string {
	if strings.HasPrefix(regName, "sluis-") {
		return regName // the platform piece sluis-node is already named for sluis
	}
	if d, ok := strings.CutPrefix(regName, "driver-"); ok {
		return "sluis-drv-" + d
	}
	return "sluis-" + regName
}

// driverTemplate is the template of one unit of a driver: the stem of its user, then the port when the driver has more
// than one unit.
func driverTemplate(regName, port string) string {
	if port == "" {
		return unitStem(regName) + "@.service"
	}
	return unitStem(regName) + "-" + port + "@.service"
}

// driverInstances are the instances (at %i) of the units of the drivers an actor owns.
func driverInstances(owner string) []string {
	var out []string
	for _, d := range knownDriverNames() {
		if ow, _ := registry.DriverOwner(d); ow != owner {
			continue
		}
		for _, du := range drivers[d].Units {
			out = append(out, strings.TrimSuffix(driverTemplate(d, du.Port), "@.service")+"@%i.service")
		}
	}
	return out
}

func userOf(regName, boundary string) string { return unitStem(regName) + "-" + boundary }

// knownDriverNames are the drivers of the uid list, in its order.
func knownDriverNames() []string {
	var out []string
	for i := uint32(0); ; i++ {
		n, _, ok := registry.NameForUID(61000 + i)
		if !ok {
			return out
		}
		if strings.HasPrefix(n, "driver-") {
			out = append(out, n)
		}
	}
}

func splitDriver(regName string) (owner, drv string, err error) {
	owner, ok := registry.DriverOwner(regName)
	if !ok {
		return "", "", fmt.Errorf("%s has no owner in the registry", regName)
	}
	drv, ok = strings.CutPrefix(regName, "driver-"+owner+"-")
	if !ok || drv == "" {
		return "", "", fmt.Errorf("%s does not start with driver-%s-", regName, owner)
	}
	return owner, drv, nil
}

// groupsOf are the registry names whose groups a unit joins, sorted. An actor joins the group of every actor it may
// call (the callee's socket is 0660 for the callee's group), of the drivers it owns (their sockets are open to
// their owner alone) and, when it emits audit records, of the spool driver, the callee "transport". A driver joins
// its owner's group, to create its socket in the owner's directory.
func groupsOf(regName, kind string) []string {
	if kind == "driver" {
		owner, _ := registry.DriverOwner(regName)
		return []string{owner}
	}
	out := callees(regName)
	for _, d := range knownDriverNames() {
		if ow, _ := registry.DriverOwner(d); ow == regName {
			if _, ok := drivers[d]; ok {
				out = append(out, d)
			}
		}
	}
	if a, ok := registry.ActorByName(regName); ok && slices.Contains(a.Ports, "audit-emit") {
		if _, ok := drivers["driver-writer-spool"]; ok {
			out = append(out, "driver-writer-spool")
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// extraNeeds are the registry names whose users must exist for the unit's directories, without the unit joining their
// groups: key@'s per-caller directories belong to the callers' groups.
func extraNeeds(regName, kind string) []string {
	if kind == "actor" && regName == "key" {
		return registry.CallersOf("key")
	}
	return nil
}

// callees are the actors an actor may call: one for every actor it may call (the call graph of the registry).
func callees(caller string) []string {
	var out []string
	for _, a := range registry.Actors() {
		if a.Family != "platform" && a.Name != caller && registry.MayCall(caller, a.Name) {
			out = append(out, a.Name)
		}
	}
	slices.Sort(out)
	return out
}

func render(o Options, u Unit) (svc, sysusers, tmpfiles string, err error) {
	if u.Kind == "driver" {
		return driverUnit(o, u)
	}
	return actorUnit(o, u)
}

func actorUnit(o Options, u Unit) (svc, sysusers, tmpfiles string, err error) {
	a, ok := registry.ActorByName(u.Registry)
	if !ok {
		return "", "", "", fmt.Errorf("%s is not an actor", u.Registry)
	}
	b := &unitText{}
	b.line("[Unit]")
	b.line("Description=sluis %s (%%i)", a.Name)
	b.line("Documentation=https://sluis.id/runtimes/bare-metal/")
	owned := driverInstances(a.Name) // the drivers this actor owns, which start first
	if len(owned) > 0 {
		b.line("Requires=%s", strings.Join(owned, " "))
		b.line("After=%s", strings.Join(owned, " "))
	}
	b.blank()
	b.line("[Service]")
	b.line("Type=simple")
	b.line("User=sluis-%s-%%i", a.Name)
	b.line("Group=sluis-%s-%%i", a.Name)
	var groups []string
	for _, n := range u.Joins {
		groups = append(groups, unitStem(n)+"-%i")
	}
	if len(groups) > 0 {
		b.line("SupplementaryGroups=%s", strings.Join(groups, " "))
	}
	spec := actorSpecs[a.Name]
	exec := fmt.Sprintf("%s/%s serve --boundary %%i", BinDir, u.Binary)
	if !spec.NoSocket {
		exec += fmt.Sprintf(" --socket /run/sluis/%s/%%i.sock", a.Name)
	}
	args := slices.Clone(spec.Args)
	if spec.ArgsFor != nil {
		more, err := spec.ArgsFor(o)
		if err != nil {
			return "", "", "", err
		}
		args = append(args, more...)
	}
	if len(args) > 0 {
		exec += " " + strings.Join(args, " ")
	}
	b.line("ExecStart=%s", exec)
	b.line("Restart=on-failure")
	b.line("RestartSec=2s")
	if a.Language == "Go" {
		b.line("Environment=GOMEMLIMIT=24MiB")
	}
	for _, c := range spec.Credentials {
		b.line("LoadCredential=%s:%s/%%i/%s/%s", c, LoadRoot, unitStem(a.Name), c)
	}
	b.blank()
	b.harden(len(a.Egress) == 0)
	b.line("ReadWritePaths=/run/sluis/%s", a.Name)
	b.blank()
	b.line("[Install]")
	b.line("WantedBy=multi-user.target")

	// The actor's directory is its own. Its socket is 0660 for its group, which its callers join; every user may pass
	// through the directory (x for others), and only the socket's bits decide who connects. A holder with drivers also
	// has the directory of the boundary, open to the group of its drivers alone (the sticky bit keeps one driver from
	// removing another's socket).
	sysusers = sysusersFor(o, u)
	tmp := header + fmt.Sprintf("d /run/sluis/%s 0751 %s %s -\n", a.Name, u.User, u.User)
	if dirs := driverDirs(a.Name, o.Boundary); len(dirs) > 0 {
		g := driversGroup(a.Name, o.Boundary)
		if len(g) > maxName {
			return "", "", "", fmt.Errorf("the group %s has %d characters, at most %d", g, len(g), maxName)
		}
		sysusers += fmt.Sprintf("g %s -\n", g) // a system group with a number of the host's choosing
		made := map[string]bool{"/run/sluis": true, "/run/sluis/" + a.Name: true}
		for _, d := range dirs {
			// The parents first: key@'s run directory holds the driver's directory and one directory per caller (below),
			// and key@ refuses a run directory that group or world can write to; the audit directory is the writer's too.
			if parent := path.Dir(d.Path); !made[parent] {
				made[parent] = true
				tmp += fmt.Sprintf("d %s 0751 %s %s -\n", parent, u.User, u.User)
			}
			made[d.Path] = true
			tmp += fmt.Sprintf("d %s %s %s %s -\n", d.Path, d.Mode, u.User, g)
		}
	}
	if a.Name == "key" {
		// One directory per caller of key@ (ADR 0006, "Exclusive card access"): the caller's group, not writable by
		// group or world, setgid so that the caller's socket gets the caller's group and only the caller connects.
		for _, c := range registry.CallersOf("key") {
			tmp += fmt.Sprintf("d /run/sluis/key/%s/%s 2750 %s %s -\n", o.Boundary, c, u.User, userOf(c, o.Boundary))
		}
	}
	return header + b.String(), sysusers, tmp, nil
}

// driversGroup is the group that holds the drivers of an owner: the group of its directory of the boundary.
func driversGroup(owner, boundary string) string { return "sluis-" + owner + "-drv-" + boundary }

// dir is a directory below /run/sluis that the owner's tmpfiles entry makes for the sockets of its drivers.
type dir struct{ Path, Mode string }

// driverDirs are the directories of the boundary in which the drivers of an owner create their sockets, in the order of
// the drivers, each once; empty when the owner has no driver with a row.
func driverDirs(owner, boundary string) []dir {
	var out []dir
	for _, d := range knownDriverNames() {
		if ow, _ := registry.DriverOwner(d); ow != owner {
			continue
		}
		for _, du := range drivers[d].Units {
			p, mode := du.socketDir(owner, boundary), du.dirMode()
			if !slices.ContainsFunc(out, func(x dir) bool { return x.Path == p }) {
				out = append(out, dir{p, mode})
			}
		}
	}
	return out
}

// socketPath is the socket of the unit, with the boundary in place of %i's value: below Dir, or below the owner's
// directory of the boundary.
func (du driverProc) socketPath(owner, boundary string) string {
	base := "/run/sluis/" + owner + "/" + boundary
	if du.Dir != "" {
		base = strings.ReplaceAll(du.Dir, "%i", boundary)
	}
	return base + "/" + du.Socket
}

// socketDir is the directory that holds the socket, which the owner's tmpfiles entry makes.
func (du driverProc) socketDir(owner, boundary string) string {
	return path.Dir(du.socketPath(owner, boundary))
}

func (du driverProc) dirMode() string {
	if du.DirMode != "" {
		return du.DirMode
	}
	return "1770"
}

func driverUnit(o Options, u Unit) (svc, sysusers, tmpfiles string, err error) {
	spec := drivers[u.Registry]
	i := slices.IndexFunc(spec.Units, func(x driverProc) bool { return x.Port == u.Port })
	if i < 0 {
		return "", "", "", fmt.Errorf("%s has no unit for the port %q", u.Registry, u.Port)
	}
	du := spec.Units[i]
	owner, _, err := splitDriver(u.Registry)
	if err != nil {
		return "", "", "", err
	}
	if _, ok := registry.ActorByName(owner); !ok {
		return "", "", "", fmt.Errorf("the owner %s of %s is not an actor", owner, u.Registry)
	}
	stem := unitStem(u.Registry)
	socketDir := du.socketDir(owner, "%i")
	socket := du.socketPath(owner, "%i")
	if du.SocketFlag == "--socket-dir" {
		socket = socketDir
	}
	socketFlag := "--socket"
	if du.SocketFlag != "" {
		socketFlag = du.SocketFlag
	}
	desc := strings.TrimPrefix(u.Registry, "driver-")
	if du.Port != "" {
		desc += " " + du.Port
	}
	b := &unitText{}
	b.line("[Unit]")
	b.line("Description=sluis driver %s (%%i)", desc)
	b.line("Documentation=https://sluis.id/runtimes/bare-metal/")
	if len(du.After) > 0 {
		b.line("After=%s", strings.Join(du.After, " "))
	}
	b.blank()
	b.line("[Service]")
	b.line("Type=simple")
	b.line("User=%s-%%i", stem)
	b.line("Group=%s-%%i", stem)
	// The directory of the boundary below the owner's directory is open to the owner and to the group of the owner's
	// drivers alone: the driver creates its socket there. The socket's own group is the driver's (--socket-gid).
	b.line("SupplementaryGroups=%s", driversGroup(owner, "%i"))
	state := ""
	if du.State {
		state = fmt.Sprintf("%s/%%i/%s", StateRoot, strings.TrimPrefix(stem, "sluis-"))
		b.line("StateDirectory=%s", strings.TrimPrefix(state, "/var/lib/"))
		b.line("StateDirectoryMode=0700")
	}
	args := make([]string, 0, len(du.Args)+2)
	for _, a := range du.Args {
		args = append(args, strings.ReplaceAll(a, "%STATE%", state))
	}
	// The driver's socket is 0600 for its own user by default; --socket-gid opens it (0660) to the driver's own group,
	// whose number is its uid (sysusers.d makes the group of a user with the same number), and only the owner joins
	// that group. The driver still answers the owner's uid alone (the OwnerOnly check of the kit).
	if !du.NoSocketGID {
		args = append(args, "--socket-gid", strconv.FormatUint(uint64(u.UID), 10))
	}
	b.line("ExecStart=%s/%s serve --boundary %%i %s %s %s", BinDir, u.Binary, socketFlag, socket, strings.Join(args, " "))
	b.line("Restart=on-failure")
	b.line("RestartSec=2s")
	if spec.Language == "Go" {
		b.line("Environment=GOMEMLIMIT=24MiB")
	}
	for _, e := range du.Environment {
		b.line("Environment=%s", e)
	}
	if du.EnvironmentFile != "" {
		b.line("EnvironmentFile=%s", du.EnvironmentFile)
	}
	for _, c := range du.Credentials {
		b.line("LoadCredential=%s:%s/%%i/%s/%s", c, LoadRoot, stem, c)
	}
	b.blank()
	b.harden(!spec.Network)
	b.line("ReadWritePaths=%s", socketDir)
	b.blank()
	b.line("[Install]")
	b.line("WantedBy=multi-user.target")
	// The driver's directory is made by its owner's tmpfiles entry.
	return header + b.String(), sysusersFor(o, u), "", nil
}

// harden is the hardening of PLAN.md section 6 and ADR 0003. Without egress a unit has no network at all.
func (b *unitText) harden(noNetwork bool) {
	b.line("# Hardening (ADR 0003)")
	b.line("NoNewPrivileges=yes")
	b.line("CapabilityBoundingSet=")
	b.line("AmbientCapabilities=")
	b.line("ProtectSystem=strict")
	b.line("ProtectHome=yes")
	b.line("PrivateTmp=yes")
	b.line("PrivateDevices=yes")
	b.line("ProtectKernelTunables=yes")
	b.line("ProtectKernelModules=yes")
	b.line("ProtectKernelLogs=yes")
	b.line("ProtectControlGroups=yes")
	b.line("ProtectClock=yes")
	b.line("ProtectHostname=yes")
	b.line("ProtectProc=invisible")
	b.line("ProcSubset=pid")
	b.line("RestrictSUIDSGID=yes")
	b.line("RestrictRealtime=yes")
	b.line("RestrictNamespaces=yes")
	b.line("LockPersonality=yes")
	b.line("MemoryDenyWriteExecute=yes")
	b.line("SystemCallArchitectures=native")
	b.line("SystemCallFilter=@system-service")
	b.line("SystemCallErrorNumber=EPERM")
	b.line("UMask=0077")
	if noNetwork {
		b.line("PrivateNetwork=yes")
		b.line("RestrictAddressFamilies=AF_UNIX")
	} else {
		b.line("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
	}
}

func sysusersFor(o Options, u Unit) string {
	// "u name uid" also makes the group of the same name and number. The user has no home and no shell.
	return header + fmt.Sprintf("u %s %s \"sluis %s (%s)\" - /usr/sbin/nologin\n", u.User, strconv.FormatUint(uint64(u.UID), 10), strings.TrimPrefix(u.Registry, "driver-"), o.Boundary)
}

func baseTmpfiles(o Options) string {
	return header + "d /run/sluis 0755 root root -\n" +
		fmt.Sprintf("d %s 0755 root root -\n", StateRoot) +
		fmt.Sprintf("d %s/%s 0755 root root -\n", StateRoot, o.Boundary)
}

// index is the table the deploy reads, in start order: instance, template, kind, binary, user, uid and the stems of
// the units whose users and directories it needs (an owner of a driver, a callee).
func index(units []Unit) string {
	var b strings.Builder
	b.WriteString("# instance\ttemplate\tkind\tbinary\tuser\tuid\tneeds\n")
	for _, u := range units {
		needs := "-"
		if len(u.Needs) > 0 {
			stems := make([]string, len(u.Needs))
			for i, n := range u.Needs {
				stems[i] = unitStem(n)
			}
			needs = strings.Join(stems, ",")
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", u.Instance, u.Name, u.Kind, u.Binary, u.User, u.UID, needs)
	}
	return b.String()
}

type unitText struct{ strings.Builder }

func (b *unitText) line(format string, args ...any) { _, _ = fmt.Fprintf(b, format+"\n", args...) }
func (b *unitText) blank()                          { _, _ = b.WriteString("\n") }
