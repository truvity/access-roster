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
	// Front is "audit" for the second instance of entry, the audit front (ADR 0028); empty for every other unit.
	Front string
	// Driver is, for an actor, the alternative driver it starts instead of the default one of its owner's drivers (the
	// card driver for key@ on a board with a card); empty for the default.
	Driver string
}

// A driver the generator knows how to run. A driver of the registry that has no row here is "pending" until
// the package that builds it adds one: nothing is guessed about a command line that does not exist yet.
type driverSpec struct {
	Language string // Go or Rust, for the memory ceiling of the Go ones
	Network  bool   // the driver reaches the network (an engine); every other unit has AF_UNIX only
	// Instead names the driver of the same owner that this one replaces on a board that has the hardware: the owner's unit
	// starts the first by default, and a whole key@ unit (cardFiles) switches it to this one. The two serve the same socket, so
	// a board runs one of them. An alternative is not in the owner's Requires= or groups.
	Instead string
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
	// Environment and EnvironmentFile are for a value that differs per board and that no flag may carry in the repository.
	Environment     []string
	EnvironmentFile string
	After           []string // units outside the generator that this one starts after
	Requires        []string // units outside the generator that this one needs (and starts after: list them in After too)
	// RuntimeDirectory is a directory below /run that systemd makes for the unit's user, mode 0700, and removes with it:
	// the card driver's admin socket. %i is the boundary.
	RuntimeDirectory string
	// ExtraGroups are groups of the unit's own that no registry name stands for (%i is the boundary): the card driver joins
	// the one that opens the card service to it alone.
	ExtraGroups []string
	// Credentials are systemd credentials the unit loads: name -> source file below LoadRoot/<boundary>/<stem>/.
	Credentials []string
	// StateMode is the mode of the state directory when it is not 0700: the blob directory of the writer's driver is 0750,
	// because the read-only driver of the indexer and the reader reads it through the group.
	StateMode string
	// Socket2 is a second socket for another caller, below the same directory: its file name, the flag that names it, the
	// flag that gives it its group, and the registry name of the caller, whose group (its uid) the socket is given to. The
	// driver joins that group to give the socket away.
	Socket2, Flag2, GidFlag2, Caller2 string
	// Joins are registry names whose groups the unit joins besides its owner's: the writer's driver, whose files the
	// read-only driver reads, and the caller of the second socket.
	Joins []string
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
	// drivers/key/yubikey-piv: serve --socket --admin-socket --state-dir --node --environment --serial [--socket-gid]. The card driver of
	// a board (ADR 0006), the alternative to the software driver: same socket, same owner. It needs the card service; its
	// admin socket, the only way the PIN reaches it, is in a directory of its own that only it and root enter. The unit
	// passes --serial from a file the deploy writes (EnvironmentFile below): the driver is bound to the board's card.
	"driver-key-yubikey-piv": {
		Language: "Go", Instead: "driver-key-software",
		Units: []driverProc{{
			Socket: keyDriverSocket, State: true,
			Args: []string{
				"--state-dir", "%STATE%", // when the driver generated each key: a card does not store it (ADR 0041)
				"--environment", "development", "--node", "%H",
				"--admin-socket", "/run/sluis-drv-key-yubikey-piv-%i/admin.sock",
				"--serial", "${SLUIS_CARD_SERIAL}",
			},
			// The serial of the board's card binds the driver to it; the deploy writes it from the environment of the run
			// (SLUIS_BOARD_CARD_SERIALS) and no serial is in the repository. A unit without the file does not start.
			EnvironmentFile: "/etc/sluis/yubikey-piv-%i.env",
			ExtraGroups:     []string{pcscGroup},
			Requires:        []string{"pcscd.socket"}, After: []string{"pcscd.socket"},
			RuntimeDirectory: "sluis-drv-key-yubikey-piv-%i",
		}},
	},
	// drivers/writer/fs: serve --socket --root [--socket-gid].
	"driver-writer-fs": {
		Language: "Rust",
		Units:    []driverProc{{Socket: "blob.sock", State: true, StateMode: "0750", Args: []string{"--root", "%STATE%"}}},
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
	// drivers/indexer/fs: serve --socket --reader-socket --root [--socket-gid --reader-socket-gid]. The read-only driver of the
	// indexer (blob.sock) and the reader (blob-ro.sock): the directory of driver-writer-fs, read through that driver's group.
	"driver-indexer-fs": {
		Language: "Rust",
		Units: []driverProc{{
			Socket:  "blob.sock",
			Args:    []string{"--root", "%WRITERSTATE%"},
			Socket2: "blob-ro.sock", Flag2: "--reader-socket", GidFlag2: "--reader-socket-gid", Caller2: "reader",
			Joins:   []string{"driver-writer-fs", "reader"},
			DirMode: "1771",
		}},
	},
	// drivers/indexer/sqlite: serve --socket --ro-socket --state-dir [--socket-gid --ro-socket-gid]. The index: index.sock for
	// the indexer, index-ro.sock for the reader, which passes through the directory (1771) to it.
	"driver-indexer-sqlite": {
		Language: "Rust",
		Units: []driverProc{{
			Socket: "index.sock", State: true,
			Args:    []string{"--state-dir", "%STATE%"},
			Socket2: "index-ro.sock", Flag2: "--ro-socket", GidFlag2: "--ro-socket-gid", Caller2: "reader",
			Joins:   []string{"reader"},
			DirMode: "1771",
		}},
	},
	// drivers/store/rqlite: serve --socket --rqlite-url --namespace durable|temp. One process per port. The engine's URL is
	// the board's own and differs per board, so the repository carries the loopback default of bare-metal.md ("Engines")
	// and the deploy may override it in /etc/sluis/rqlite-<boundary>.env.
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
		Port: port, Socket: port + ".sock",
		Args:            []string{"--rqlite-url", "${SLUIS_RQLITE_URL}", "--namespace", port},
		Environment:     []string{"SLUIS_RQLITE_URL=http://127.0.0.1:4001"},
		EnvironmentFile: "-/etc/sluis/rqlite-%i.env",
		After:           []string{"sluis-rqlite.service"},
	}
}

// pendingDrivers are the drivers of the registry that no package has built yet. A driver that is in neither
// this list nor `drivers` fails the generator, so a new driver cannot be forgotten.
var pendingDrivers = []string{}

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
	// State gives the actor a state directory of its own below StateRoot, 0700, named by the --state-dir in Args. It
	// is for what the actor must remember across a restart (key@'s highest KeyPlan seq) and is no other unit's.
	State bool
}

// forwarder is the registry name of the edge's reverse proxy, the only caller of entry's listener. It is a harness piece,
// not an actor: it has a uid and a group (the generator makes them) and no unit here.
const forwarder = "harness-forwarder"

var actorSpecs = map[string]actorSpec{
	// actors/key: the flags of actors/key/main.go. The run directory and the per-caller directories below it are made by
	// the platform (tmpfiles); the driver's socket is <run-dir>/driver/key-store.sock; --node is the board's short name.
	// --bootstrap is the root's public file store@ reads too; key@ reads its publishers block to verify the KeyPlan itself
	// (REQ-KEYS-075). ProtectSystem=strict keeps /etc read-only for the unit, so the file is read-only to it.
	"key": {NoSocket: true, State: true, Args: []string{
		"--bootstrap", "/etc/sluis/bootstrap.d/%i.yaml",
		"--state-dir", StateRoot + "/%i/key",
		"--run-dir", "/run/sluis/key/%i",
		"--store-socket", "/run/sluis/store/%i.sock",
		"--driver-socket", "/run/sluis/key/%i/" + keyDriverSocket,
		"--transport-socket", "/run/sluis/audit/%i/emit.sock",
		"--node", "%H",
	}},
	// actors/store: the bootstrap file is required; the sockets of key@ and of the audit transport have the defaults, which
	// are those of PLAN.md "Socket layout", and the destinations are in the bootstrap file.
	"store": {Args: []string{"--bootstrap", "/etc/sluis/bootstrap.d/%i.yaml"}},
	// actors/policy: the sockets of store@, key@ and the audit transport have the defaults of the plan, and the listener is
	// /run/sluis/policy/<boundary>.sock in policy's own group, which its callers join. It has no network.
	"policy": {},
	// actors/writer: a client only (the audit transport's receive.sock, the blob driver, store@, key@, policy), so it serves
	// no socket; every socket has the default of the plan. --instance is the node's name in the entries it stamps.
	"writer": {NoSocket: true, Args: []string{"--instance", "%H"}},
	// actors/indexer: a client only (the blob and the index drivers, store@, key@, policy), so it serves no socket. The verifier
	// key of each log it follows is a file <log id>.vkey in /etc/sluis/vkeys/<boundary>, which the deploy writes from the key
	// the writer logs at its start (a public key; the directory is root's, 0755).
	"indexer": {NoSocket: true, Args: []string{"--verifier-key-dir", "/etc/sluis/vkeys/%i"}},
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

// writerDriver is the driver whose directory the read-only blob driver reads.
const writerDriver = "driver-writer-fs"

// pcscGroup is the group of the card service's socket (%i is the boundary). Only the card driver joins it; the key-store
// socket has the driver's own group, which key@ joins, so key@ cannot reach the card service through it.
const pcscGroup = "sluis-pcsc-%i"

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
	card, err := cardFiles(o, units)
	if err != nil {
		return nil, err
	}
	files = append(files, card...)
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
			u.Needs = append(u.Needs, du.Joins...)
			slices.Sort(u.Needs)
			u.Needs = slices.Compact(u.Needs)
			out = append(out, u)
		}
	}
	for n := range known {
		if !slices.Contains(knownDriverNames(), n) {
			return nil, fmt.Errorf("the generator names the driver %s, which the registry does not have", n)
		}
	}
	front, err := auditFront(o)
	if err != nil {
		return nil, err
	}
	out = append(out, front)
	slices.SortStableFunc(out, func(a, b Unit) int {
		if a.Order != b.Order {
			return a.Order - b.Order
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// auditFront is the second instance of entry, the audit front of ADR 0028: the same executable with `--front audit`, in
// the same user, with a listener beside entry's (<boundary>-audit.sock) and the reader as the one actor it calls. The
// registry gives entry no edge to the reader, so its groups are listed here and not derived from the call graph.
func auditFront(o Options) (Unit, error) {
	u, err := unit(o, "entry", "actor", "actors/entry", orderOf("work"))
	if err != nil {
		return Unit{}, err
	}
	u.Name = "sluis-entry-audit@.service"
	u.Instance = "sluis-entry-audit@" + o.Boundary + ".service"
	u.Front = "audit"
	u.Joins = []string{"driver-writer-spool", "reader", forwarder}
	slices.Sort(u.Joins)
	u.Needs = slices.Clone(u.Joins)
	return u, nil
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

// driverInstances are the instances (at %i) of the units of the drivers an actor owns. An alternative driver (Instead)
// is left out, unless chosen, and then it takes the place of the driver it replaces.
func driverInstances(owner, chosen string) []string {
	var out []string
	for _, d := range knownDriverNames() {
		if ow, _ := registry.DriverOwner(d); ow != owner {
			continue
		}
		if instead := drivers[d].Instead; (instead != "" && d != chosen) || (chosen != "" && d == drivers[chosen].Instead) {
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
			if spec, ok := drivers[d]; ok && spec.Instead == "" {
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
	if u.Front == "audit" {
		b.line("Description=sluis %s audit front (%%i)", a.Name)
	} else {
		b.line("Description=sluis %s (%%i)", a.Name)
	}
	b.line("Documentation=https://sluis.id/runtimes/bare-metal/")
	owned := driverInstances(a.Name, u.Driver) // the drivers this actor owns, which start first
	if u.Front == "audit" {
		owned = nil // the identity front's unit starts them
	}
	if len(owned) > 0 {
		b.line("Requires=%s", strings.Join(owned, " "))
		b.line("After=%s", strings.Join(owned, " "))
	}
	// An actor dials the sockets of the actors it calls when it starts, and systemd does not order the actors among
	// themselves, so it may fail a few times while a peer comes up. The default limit (5 starts in 10 s, with
	// RestartSec=2s) would put it out for good after 10 s; this one gives a board two minutes to settle.
	b.line("StartLimitIntervalSec=120")
	b.line("StartLimitBurst=40")
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
	if u.Front == "audit" {
		exec += fmt.Sprintf(" --front audit --socket /run/sluis/%s/%%i-audit.sock", a.Name)
	} else if !spec.NoSocket {
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
	if spec.State {
		b.line("StateDirectory=%s", strings.TrimPrefix(fmt.Sprintf("%s/%%i/%s", StateRoot, a.Name), "/var/lib/"))
		b.line("StateDirectoryMode=0700")
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
	if len(du.Requires) > 0 {
		b.line("Requires=%s", strings.Join(du.Requires, " "))
	}
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
	groups := []string{driversGroup(owner, "%i")}
	for _, n := range du.Joins {
		groups = append(groups, unitStem(n)+"-%i")
	}
	groups = append(groups, du.ExtraGroups...)
	b.line("SupplementaryGroups=%s", strings.Join(groups, " "))
	state := ""
	if du.State {
		state = fmt.Sprintf("%s/%%i/%s", StateRoot, strings.TrimPrefix(stem, "sluis-"))
		b.line("StateDirectory=%s", strings.TrimPrefix(state, "/var/lib/"))
		mode := "0700"
		if du.StateMode != "" {
			mode = du.StateMode
		}
		b.line("StateDirectoryMode=%s", mode)
	}
	if du.RuntimeDirectory != "" {
		b.line("RuntimeDirectory=%s", du.RuntimeDirectory)
		b.line("RuntimeDirectoryMode=0700")
	}
	// The read-only blob driver reads the directory of the writer's driver.
	writerState := fmt.Sprintf("%s/%%i/%s", StateRoot, strings.TrimPrefix(unitStem(writerDriver), "sluis-"))
	args := make([]string, 0, len(du.Args)+4)
	for _, a := range du.Args {
		args = append(args, strings.ReplaceAll(strings.ReplaceAll(a, "%STATE%", state), "%WRITERSTATE%", writerState))
	}
	if du.Socket2 != "" {
		caller, ok := registry.UID(du.Caller2, o.UIDBlock)
		if !ok {
			return "", "", "", fmt.Errorf("%s has no uid in block %d", du.Caller2, o.UIDBlock)
		}
		args = append(args, du.Flag2, socketDir+"/"+du.Socket2, du.GidFlag2, strconv.FormatUint(uint64(caller), 10))
	}
	// The driver's socket is 0600 for its own user by default; --socket-gid opens it (0660) to the driver's own group,
	// whose number is its uid (sysusers.d makes the group of a user with the same number), and only the owner joins
	// that group. The driver still answers the owner's uid alone (the OwnerOnly check of the kit).
	args = append(args, "--socket-gid", strconv.FormatUint(uint64(u.UID), 10))
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

// The files of a board that runs the card driver instead of the software one. The deploy installs them only then
// (boards.sh, SLUIS_BOARDS_KEY_DRIVER=yubikey-piv):
//
//	CardKeyUnitFile  /etc/systemd/system/sluis-key@.service (in place of the template of the default key@ unit)
//	PcscdSocketFile  /etc/systemd/system/pcscd.socket.d/10-sluis.conf
//	PolkitRulesFile  /etc/polkit-1/rules.d/49-sluis-pcsc.rules
const (
	CardKeyUnitFile = "sluis-key@.service.card"
	PcscdSocketFile = "pcscd-socket.dropin"
	PolkitRulesFile = "pcsc-polkit.rules"
	PcscGroupFile   = "sluis-pcsc.sysusers" // /etc/sysusers.d/sluis-pcsc-<boundary>.conf
)

// cardFiles makes the files of the card driver's board: the key@ unit that starts after the card driver and joins its
// group in place of the software driver's (a drop-in cannot take a Requires= away in systemd 249, so the whole unit
// is the variant), and the two files that let nobody but the card driver (and root) reach the card service
// (ADR 0006, "Exclusive card access").
func cardFiles(o Options, units []Unit) ([]File, error) {
	const reg = "driver-key-yubikey-piv"
	spec, ok := drivers[reg]
	if !ok || spec.Instead == "" {
		return nil, nil
	}
	owner, _, err := splitDriver(reg)
	if err != nil {
		return nil, err
	}
	ownerIdx := slices.IndexFunc(units, func(u Unit) bool { return u.Registry == owner && u.Kind == "actor" })
	if ownerIdx < 0 {
		return nil, fmt.Errorf("the owner %s of %s has no unit", owner, reg)
	}
	// key@ joins the groups its unit has, with the software driver's replaced by the card driver's.
	ku := units[ownerIdx]
	ku.Driver = reg
	ku.Joins = slices.Clone(ku.Joins)
	for i, n := range ku.Joins {
		if n == spec.Instead {
			ku.Joins[i] = reg
		}
	}
	slices.Sort(ku.Joins)
	svc, _, _, err := actorUnit(o, ku)
	if err != nil {
		return nil, err
	}

	user := userOf(reg, o.Boundary)
	sock := "# Generated by tools/gen/units. Installed by `just boards-deploy` with SLUIS_BOARDS_KEY_DRIVER=yubikey-piv.\n" +
		"# The card service takes connections from the card driver's group and from root, and from nobody else.\n" +
		"# The stock socket is mode 0666 and the Ubuntu 22.04 build of pcscd has no polkit, so this is the control there.\n" +
		"# The group is the card driver's alone: key@ joins the driver's own group for the key-store socket, not this one.\n" +
		"[Socket]\nSocketMode=0660\nSocketUser=root\nSocketGroup=" + strings.ReplaceAll(pcscGroup, "%i", o.Boundary) + "\n"
	rules := "// Generated by tools/gen/units. Installed by `just boards-deploy` with SLUIS_BOARDS_KEY_DRIVER=yubikey-piv,\n" +
		"// and only on a board whose pcscd is built with polkit (it ships org.debian.pcsc-lite.policy).\n" +
		"// Only the card driver's user and root reach the card service and the cards (ADR 0006, \"Exclusive card access\").\n" +
		"polkit.addRule(function(action, subject) {\n" +
		"    if (action.id == \"org.debian.pcsc-lite.access_pcsc\" || action.id == \"org.debian.pcsc-lite.access_card\") {\n" +
		"        return (subject.user == \"root\" || subject.user == \"" + user + "\") ? polkit.Result.YES : polkit.Result.NO;\n" +
		"    }\n" +
		"});\n"
	sysusers := header + "g " + strings.ReplaceAll(pcscGroup, "%i", o.Boundary) + " -\n" // a system group with no member: the unit names it
	return []File{{CardKeyUnitFile, svc}, {PcscdSocketFile, sock}, {PolkitRulesFile, rules}, {PcscGroupFile, sysusers}}, nil
}
