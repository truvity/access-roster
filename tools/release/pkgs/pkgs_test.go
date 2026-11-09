package pkgs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestThePlanFollowsTheTree(t *testing.T) {
	specs := realSpecs(t)
	got := map[string]Spec{}
	for _, s := range specs {
		got[s.Name] = s
	}
	images, err := LoadImages("../../../deploy/release/images.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Every executable of the list of images is in exactly one package, at the path of its image.
	placed := map[string]string{}
	for _, s := range specs {
		for _, e := range s.Execs {
			if other, dup := placed[e.Dest]; dup {
				t.Errorf("%s is in %s and %s", e.Dest, other, s.Name)
			}
			placed[e.Dest] = s.Name
		}
	}
	for _, im := range images {
		if _, ok := placed[im.Files[0]]; !ok {
			t.Errorf("the image %s (%s) is in no package", im.Name, im.Files[0])
		}
	}
	if len(placed) != len(images)+1 { // the images, and the command-line tool
		t.Errorf("%d executables are placed, want %d (the images and sluis)", len(placed), len(images)+1)
	}
	for name, role := range map[string]Role{"sluis-cli": RoleCLI, "sluis": RoleBase, "sluis-store": RoleFoundation, "sluis-key": RoleFoundation, "sluis-exporter": RoleFoundation,
		"sluis-identity": RoleModule, "sluis-audit-writer": RoleModule, "sluis-audit-search": RoleModule, "sluis-driver-store-rqlite": RoleDriver, "sluis-driver-writer-spool": RoleDriver} {
		if got[name].Role != role {
			t.Errorf("%s: role %q, want %q", name, got[name].Role, role)
		}
	}
	// Decision 11: policy and entry (and with it the audit front) are in the base package, with the CLI.
	base := map[string]bool{}
	for _, e := range got["sluis"].Execs {
		base[e.Dest] = true
	}
	for _, d := range []string{"/usr/libexec/sluis/actors/policy", "/usr/libexec/sluis/actors/entry"} {
		if !base[d] {
			t.Errorf("the package sluis lacks %s: %v", d, got["sluis"].Execs)
		}
	}
	if base["/usr/bin/sluis"] {
		t.Error("the CLI is in the package sluis: it is the package sluis-cli (decision 17)")
	}
	if ex := got["sluis-cli"].Execs; len(ex) != 1 || ex[0].Dest != "/usr/bin/sluis" {
		t.Errorf("sluis-cli holds %v, want /usr/bin/sluis alone", ex)
	}
	if n := got["sluis"].Needs; len(n) != 1 || n[0] != "sluis-cli" {
		t.Errorf("sluis needs %v, want sluis-cli", n)
	}
	if n := got["sluis-cli"].Needs; len(n) != 0 {
		t.Errorf("sluis-cli needs %v, want nothing of the release", n)
	}
	if w := got["sluis-driver-indexer-fs"].Weak; len(w) != 1 || w[0] != "sluis-driver-writer-fs" {
		t.Errorf("the indexer's file driver recommends %v, want the writer's (decision 16)", w)
	}
	for name, s := range got {
		if name != "sluis-driver-indexer-fs" && len(s.Weak) > 0 {
			t.Errorf("%s recommends %v: the one weak edge is the indexer's file driver", name, s.Weak)
		}
	}
	for _, e := range got["sluis-identity"].Execs {
		if strings.HasSuffix(e.Dest, "/policy") || strings.HasSuffix(e.Dest, "/entry") {
			t.Errorf("sluis-identity holds %s, which is in the foundation", e.Dest)
		}
	}
	if o := got["sluis-driver-writer-spool"].Owner; o != "sluis-audit-writer" {
		t.Errorf("the spool driver's owner is %q, want sluis-audit-writer", o)
	}
	if d := got["sluis-driver-key-software"].Needs; len(d) != 1 || d[0] != "sluis-key" {
		t.Errorf("the software key driver needs %v, want its owner sluis-key", d)
	}
}

func TestThePlanRefusesWhatItCannotPlace(t *testing.T) {
	img := func(name, file string) []ImageEntry {
		return []ImageEntry{{Name: name, Package: "sluis-" + name, Source: "archive", Bin: "x", Files: []string{file}}}
	}
	actors, err := LoadActors("../../../docs/architecture/actors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		images []ImageEntry
		want   string
	}{
		"an actor the registry does not know":      {img("actor-nope", "/usr/libexec/sluis/actors/nope"), "no actor of the registry"},
		"a driver whose owner the registry lacks":  {img("driver-nope-x", "/usr/libexec/sluis/drivers/nope/x"), "no actor of the registry"},
		"a path outside the install directory":     {img("actor-store", "/opt/sluis/store"), "not below /usr/libexec/sluis"},
		"a path that is neither actor nor driver":  {img("actor-store", "/usr/libexec/sluis/node/store"), "neither actors"},
		"a module with no foundation to depend on": {img("actor-session", "/usr/libexec/sluis/actors/session"), "foundation package"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Plan(tc.images, actors)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Plan: %v, want an error with %q", err, tc.want)
			}
		})
	}
}

func TestThePackageVersion(t *testing.T) {
	for in, want := range map[string]string{"2.0.0-alpha.1": "2.0.0~alpha.1", "2.0.0": "2.0.0", "2.1.3-rc.12": "2.1.3~rc.12", "10.20.30-beta": "10.20.30~beta"} {
		got, err := PackageVersion(in)
		if err != nil || got != want {
			t.Errorf("PackageVersion(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "2.0", "v2.0.0", "2.0.0-", "2.0.0-alpha-1", "2.0.0-alpha.1+build", "2.0.0+build", "02.0.0", "2.0.0-al_pha"} {
		if got, err := PackageVersion(in); err == nil {
			t.Errorf("PackageVersion(%q) = %q, want an error", in, got)
		}
	}
	// The reason for the tilde, from the package manager itself where there is one: 2.0.0~alpha.1 sorts before 2.0.0, and the dash
	// form sorts after it.
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("no dpkg to ask")
	}
	lt := func(a, b string) bool {
		return exec.Command( //nolint:gosec // dpkg, with versions written in this test
			"dpkg", "--compare-versions", a, "lt", b).Run() == nil
	}
	if !lt("2.0.0~alpha.1", "2.0.0") || !lt("2.0.0~alpha.1", "2.0.0~alpha.2") || !lt("2.0.0~alpha.2", "2.0.0~beta.1") {
		t.Error("dpkg does not order the mapped versions as alpha.1 < alpha.2 < beta.1 < release")
	}
	if lt("2.0.0-alpha.1", "2.0.0") {
		t.Error("dpkg orders 2.0.0-alpha.1 before 2.0.0: the reason for the tilde is gone")
	}
}

func TestEveryExternalDependencyIsOnTheAllowList(t *testing.T) {
	for _, s := range realSpecs(t) {
		for _, f := range Formats {
			dep, rec, sug := Externals(s)
			for _, e := range append(append(dep, rec...), sug...) {
				if a, ok := allowedExternal[e.Name]; !ok || a != e {
					t.Errorf("%s (%s): %+v is not on the allow list", s.Name, f, e)
				}
			}
		}
	}
}

// The systemd floor of the packages is the floor of the boards deploy and of the matrix (docs/distribution/dependencies.md).
func TestTheSystemdFloorIsTheBoardsFloor(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/boards/remote-lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^credential_floor=(\d+)$`).FindSubmatch(raw)
	if m == nil || string(m[1]) != SystemdFloor {
		t.Fatalf("credential_floor in remote-lib.sh is %q, the packages say %s", m, SystemdFloor)
	}
	page, err := os.ReadFile("../../../docs/distribution/dependencies.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("Depends `systemd (>= "+SystemdFloor+")` / `systemd >= "+SystemdFloor+"`")) {
		t.Error("the matrix does not state the systemd dependency of the packages")
	}
}

func TestTheScriptLint(t *testing.T) {
	good := map[string]string{
		"the shape of the spike's postinst": `#!/bin/sh
set -e
systemd-sysusers /usr/lib/sysusers.d/sluis-store.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/sluis-store.conf
systemctl daemon-reload
case "$1" in
2) systemctl try-restart 'sluis-store@*.service' || true ;;
configure) [ -z "${2:-}" ] || systemctl try-restart 'sluis-store@*.service' || true ;;
esac
exit 0`,
		"stop on removal only":           "case \"$1\" in\nremove | 0) systemctl stop 'sluis-*@*.service' 2>/dev/null || true ;;\nesac",
		"a comment that says start":      "# systemctl enable --now is what we do not do\nexit 0",
		"is-enabled":                     "systemctl is-enabled sluis-key@dev.service || true",
		"a flag before the verb":         "systemctl --no-block try-restart x.service",
		"a file of /run/sluis":           "rm -f /run/sluis/store/dev/sock && touch /run/sluis/up && mkdir -p /run/sluis",
		"the directory /run/sluis":       "rm -rf /run/sluis/key",
		"a redirect into /run/sluis":     "echo ready > /run/sluis/ready",
		"a variable with a default":      "echo ${HOME:-/root} ${2:-} ${3:-a}",
		"env with a variable":            "env LANG=C systemctl daemon-reload",
		"a redirect to the null device":  "systemctl daemon-reload >/dev/null 2>&1 || true",
		"a stream joined to another":     "systemd-tmpfiles --create /usr/lib/tmpfiles.d/sluis-store.conf 2>&1",
		"awk with a program on the line": "awk '{print $1}' /proc/uptime",
	}
	for name, text := range good {
		if p := lintScript("postinst", text); len(p) > 0 {
			t.Errorf("%s: refused: %v", name, p)
		}
	}
	bad := map[string]struct{ text, want string }{
		"enable":                           {"systemctl enable sluis-key@dev.service", "systemctl enable"},
		"enable --now":                     {"systemctl enable --now sluis-key@dev.service", "systemctl enable"},
		"start":                            {"systemctl start sluis-key@dev.service", "systemctl start"},
		"restart":                          {"systemctl restart sluis-key@dev.service", "systemctl restart"},
		"a flag first":                     {"systemctl --no-block start x.service", "systemctl start"},
		"a full path":                      {"/usr/bin/systemctl enable x.service", "systemctl enable"},
		"after a semicolon":                {"systemctl daemon-reload; systemctl start x.service", "systemctl start"},
		"after an and":                     {"true && systemctl reload-or-restart x.service", "systemctl reload-or-restart"},
		"in an if":                         {"if [ -d /run/systemd/system ]; then systemctl start x.service; fi", "systemctl start"},
		"with an assignment":               {"SYSTEMD_OFFLINE=0 systemctl preset x.service", "systemctl preset"},
		"under sudo":                       {"sudo systemctl enable x.service", "systemctl enable"},
		"a continued line":                 {"systemctl \\\n  start x.service", "systemctl start"},
		"deb-systemd-helper":               {"deb-systemd-helper enable x.service", "deb-systemd-helper"},
		"deb-systemd-invoke":               {"deb-systemd-invoke start x.service", "deb-systemd-invoke"},
		"invoke-rc.d":                      {"invoke-rc.d x start", "invoke-rc.d"},
		"service":                          {"service x start", "service"},
		"systemd-run":                      {"systemd-run --unit=x /bin/true", "systemd-run"},
		"a link into wants":                {"ln -s /usr/lib/systemd/system/x@.service /etc/systemd/system/multi-user.target.wants/x@dev.service", "enables a unit by hand"},
		"a command in a variable":          {"$SYSTEMCTL start x.service", "taken from a variable"},
		"eval":                             {"eval \"systemctl start x\"", "eval"},
		"sh -c":                            {"sh -c 'systemctl start x'", "uses sh"},
		"xargs":                            {"echo x | xargs systemctl start", "xargs"},
		"userdel":                          {"userdel sluis-key-dev", "userdel"},
		"deluser":                          {"deluser --system sluis-key-dev", "deluser"},
		"groupdel":                         {"groupdel sluis-key-dev", "groupdel"},
		"the purge of the spike":           {"case \"$1\" in\npurge) rm -rf /var/lib/sluis-state ;;\nesac", "never deletes state"},
		"the configuration":                {"rm -rf /etc/sluis", "never deletes state"},
		"find -delete":                     {"find /var/lib/sluis-state -delete", "never deletes state"},
		"a quoted verb":                    {"systemctl \"start\" x.service", "systemctl start"},
		"a single-quoted verb":             {"systemctl 'enable' x.service", "systemctl enable"},
		"a verb in a variable":             {"systemctl $VERB x.service", "from a variable"},
		"an option with a value":           {"systemctl -t service start x.service", "systemctl start"},
		"under timeout":                    {"timeout 5 systemctl start x.service", "systemctl start"},
		"under setsid":                     {"setsid systemctl enable x.service", "systemctl enable"},
		"under flock":                      {"flock /run/l systemctl start x.service", "systemctl start"},
		"under su -c":                      {"su -c 'systemctl start x.service' root", "systemctl start"},
		"under runuser":                    {"runuser -u root -- systemctl enable x.service", "systemctl enable"},
		"a script run by sh":               {"sh /tmp/x", "uses sh"},
		"a pipe into sh":                   {"echo 'systemctl start x' | sh", "uses sh"},
		"a pipe into bash":                 {"cat /tmp/x | bash -s", "uses bash"},
		"python":                           {"python3 /tmp/x.py", "uses python3"},
		"busctl":                           {"busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss x.service replace", "busctl"},
		"dbus-send":                        {"dbus-send --system --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.StartUnit", "dbus-send"},
		"machinectl":                       {"machinectl start x", "machinectl"},
		"a state path in a variable":       {"rm -rf \"$STATE\"", "never deletes state"},
		"a state path with //":             {"rm -rf //var/lib/sluis-state", "never deletes state"},
		"a state path with a dot":          {"rm -rf /var/lib/./sluis-state", "never deletes state"},
		"a relative state path":            {"cd /var/lib && rm -rf sluis-state", "never deletes state"},
		"find -delete in a variable":       {"find $DIR -name x -delete", "never deletes state"},
		"find -exec":                       {"find /var/lib -name sluis-state -exec true {} +", "never deletes state"},
		"mv of the state":                  {"mv /var/lib/sluis-state /var/lib/old", "never deletes state"},
		"under timeout rm":                 {"timeout 5 rm -rf /etc/sluis", "never deletes state"},
		"chown -R":                         {"chown -R root:root /var/lib/sluis-state", "recursively"},
		"chmod -R":                         {"chmod -R 0700 /etc/sluis", "recursively"},
		"chown -hR":                        {"chown -hR root /var/lib/sluis-state", "recursively"},
		"a glob in rm":                     {"rm -rf /var/lib/sluis*", "never deletes state"},
		"a glob that spells state":         {"rm -rf /var/lib/s?uis-state", "glob"},
		"a glob in a bracket":              {"mv /etc/sl[u]is /tmp/old", "glob"},
		"a glob in find":                   {"find /var/lib -maxdepth 1 -name 'sl*'", "glob"},
		"a redirect to state":              {"echo x > /var/lib/sluis-state/f", "redirects to"},
		"an append to the config":          {"echo x >> /etc/sluis/uids.env", "redirects to"},
		"a redirect to a variable":         {": > \"$F\"", "redirects to"},
		"a redirect with a dot":            {"echo > /var/lib/./sluis-state/x", "redirects to"},
		"a redirect without a space":       {"cat x >$STATE/y", "redirects to"},
		"cp from the null device":          {"cp /dev/null /etc/sluis/x", "writes no file"},
		"tee":                              {"echo x | tee -a /etc/sluis/y", "writes no file"},
		"tee to a variable":                {"echo x | tee \"$OUT\"", "writes no file"},
		"dd":                               {"dd if=/dev/zero of=/var/lib/sluis-state/x", "writes no file"},
		"install":                          {"install -m 0644 a /etc/sluis/b", "writes no file"},
		"sed in place":                     {"sed -i s/a/b/ /etc/sluis/x", "writes no file"},
		"sed in place with a suffix":       {"sed -i.bak s/a/b/ /etc/sluis/x", "writes no file"},
		"cp -s":                            {"cp -s /usr/libexec/sluis/actors/store /usr/bin/x", "cp -s"},
		"ln into a variable":               {"ln -s /usr/lib/systemd/system/x@.service \"$DIR/x@dev.service\"", "ln into a path from a variable"},
		"ln onto state":                    {"ln -s /tmp/x /var/lib/sluis-state/y", "ln on a path"},
		"php":                              {"php /tmp/x.php", "uses php"},
		"tclsh":                            {"tclsh /tmp/x.tcl", "uses tclsh"},
		"awk -f":                           {"awk -f /tmp/x.awk /proc/uptime", "awk -f"},
		"cd":                               {"cd /var/lib && echo x", "uses cd"},
		"pushd":                            {"pushd /etc/sluis", "uses pushd"},
		"a clobbering redirect":            {"echo x >| /var/lib/sluis-state/f", "redirects to"},
		"a redirect of both streams":       {"echo x &> /etc/sluis/y", "redirects to"},
		"an append of both streams":        {"echo x &>> /etc/sluis/y", "redirects to"},
		"a redirect with >&":               {"echo x >& /etc/sluis/y", "redirects to"},
		"a redirect with >&file":           {"echo x >&/etc/sluis/y", "redirects to"},
		"a brace expansion of state":       {"rm -rf /etc/{sluis,x}", "never deletes state"},
		"a brace expansion in the middle":  {"rm -rf /var/lib/{a,sluis-state}", "never deletes state"},
		"a brace expansion of a directory": {"rm -rf /var/{lib/sluis-state,x}", "never deletes state"},
		"a brace expansion with mv":        {"mv /etc/{sluis,old}", "never deletes state"},
		"a brace expansion of a write":     {"echo x | tee /etc/{sluis/a,b}", "writes no file"},
		"a backslash in a name":            {"rm -rf /etc/s\\luis", "never deletes state"},
		"a backslash in the state name":    {"rm -rf /var/lib/sluis\\-state", "never deletes state"},
		"quotes in a name":                 {"rm -rf /var/lib/sl\"ui\"s-state", "never deletes state"},
		"a quoted prefix":                  {"rm -rf '/etc/'sluis", "never deletes state"},
		"a backslash in a verb":            {"s\\ystemctl start x.service", "systemctl start"},
		"quotes in a command":              {"sy\"stemctl\" start x.service", "systemctl start"},
		"state beside /run/sluis":          {"rm -rf /run/sluis-state", "never deletes state"},
		"state reached from /run/sluis":    {"rm -rf /run/sluis/../../var/lib/sluis-state", "never deletes state"},
		"sed -e e":                         {"echo x | sed -e e", "sed with the e command"},
		"sed --expression":                 {"sed --expression=e /etc/hostname", "sed with the e command"},
		"sed e flag":                       {"sed 's/a/b/e' /etc/hostname", "sed with the e command"},
		"sed e command with a command":     {"sed 'e echo hi' /etc/hostname", "sed with the e command"},
		"env -S":                           {"env -S 'systemctl start x.service'", "env -S"},
		"env -S glued":                     {"env -S'x y' true", "env -S"},
		"env --split-string":               {"env --split-string='x y' true", "env -S"},
		"env with -iS":                     {"env -iS 'x y' true", "env -S"},
		"tmpfiles remove":                  {"systemd-tmpfiles --remove /usr/lib/tmpfiles.d/sluis-key.conf", "never deletes state"},
	}
	for name, tc := range bad {
		p := lintScript("postinst", tc.text)
		found := false
		for _, x := range p {
			found = found || strings.Contains(x, tc.want)
		}
		if !found {
			t.Errorf("%s: want a problem with %q, got %v", name, tc.want, p)
		}
	}
}

func TestAnRPMThatAsksForMoreThanRPM416Provides(t *testing.T) {
	pk := &Pkg{Format: RPM, Name: "sluis", Version: "2.0.0~alpha.1", Release: "1", Arch: "x86_64", Payload: "gzip", DigestAlgo: 8,
		RPMLib: []string{"rpmlib(CompressedFileNames)", "rpmlib(PayloadIsZstd)", "rpmlib(SomethingFromRPM419)"}}
	s := Spec{Name: "sluis", Role: RoleBase}
	p := checkOne(pk, s, RPM, "amd64", "2.0.0~alpha.1", CheckInput{Version: testVersion}, map[string]bool{"sluis": true})
	mustFind(t, p, "rpmlib(SomethingFromRPM419)", "rpm 4.16")
	for _, x := range p {
		if strings.Contains(x, "CompressedFileNames") || strings.Contains(x, "PayloadIsZstd") {
			t.Errorf("a feature rpm 4.16 provides is refused: %s", x)
		}
	}
}

func TestADistWithABadVersionIsRefused(t *testing.T) {
	for _, v := range []string{"", "latest", "2.0.0-alpha.1; rm", "../x", "v2.0.0"} {
		dist := t.TempDir()
		if err := os.WriteFile(filepath.Join(dist, "metadata.json"), []byte(fmt.Sprintf(`{"version":%q}`, v)), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := DistVersion(dist); err == nil {
			t.Errorf("DistVersion accepted %q as %q", v, got)
		}
	}
}

// cpio builds the newc archive an rpm carries, gzipped.
func cpio(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	pad := func() {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	entry := func(name string, data []byte) {
		fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", 1, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
		b.WriteString(name)
		b.WriteByte(0)
		pad()
		b.Write(data)
		pad()
	}
	for _, n := range names {
		entry(n, files[n])
	}
	entry("TRAILER!!!", nil)
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write(b.Bytes())
	_ = zw.Close()
	return z.Bytes()
}

// The payload of an .rpm is read, not trusted: its digest is the header's, and each file is the one the header lists.
func TestTheRPMPayloadIsHeldToTheHeader(t *testing.T) {
	data := []byte("the executable")
	sum := sha256.Sum256(data)
	listed := []PFile{{Path: "/usr/bin/x", Kind: 'f', Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}}
	header := func(payload []byte) rpmHeader {
		d := sha256.Sum256(payload)
		return rpmHeader{tagPayloadDig: rpmEntry{typ: 8, count: 1, data: append([]byte(hex.EncodeToString(d[:])), 0)}}
	}
	good := cpio(t, map[string][]byte{"./usr/bin/x": data})
	if err := checkPayload(header(good), good, listed); err != nil {
		t.Fatalf("a good payload is refused: %v", err)
	}
	flipped := append([]byte(nil), good...)
	flipped[len(flipped)/2] ^= 0xff
	if err := checkPayload(header(good), flipped, listed); err == nil || !strings.Contains(err.Error(), "the header says") {
		t.Errorf("a flipped byte of the payload: %v", err)
	}
	other := cpio(t, map[string][]byte{"./usr/bin/x": []byte("another executable")})
	if err := checkPayload(header(other), other, listed); err == nil || !strings.Contains(err.Error(), "differs from what the header lists") {
		t.Errorf("a payload whose file is not the listed one, with a digest that matches it: %v", err)
	}
	missing := cpio(t, map[string][]byte{"./usr/bin/y": data})
	if err := checkPayload(header(missing), missing, listed); err == nil || !strings.Contains(err.Error(), "lacks") {
		t.Errorf("a payload without the listed file: %v", err)
	}
	if err := checkPayload(rpmHeader{}, good, listed); err == nil || !strings.Contains(err.Error(), "no payload digest") {
		t.Errorf("a header without a payload digest: %v", err)
	}
}

// A .deb whose ar archive holds a member the check does not read (a second data archive, a signature) is refused.
func TestADebWithAnotherArMemberIsRefused(t *testing.T) {
	pk := &Pkg{Format: Deb, Name: "sluis", Version: "2.0.0~alpha.1", Arch: "amd64", Members: []string{"debian-binary", "control.tar.gz", "data.tar.gz", "_gpgorigin"}}
	p := checkOne(pk, Spec{Name: "sluis", Role: RoleBase}, Deb, "amd64", "2.0.0~alpha.1", CheckInput{Version: testVersion}, map[string]bool{"sluis": true})
	mustFind(t, p, "has the ar members")
}

// gzipOf compresses data.
func gzipOf(t *testing.T, data []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// tarGzOf is a tar.gz of one regular file of size bytes of zeros.
func tarGzOf(t *testing.T, name string, size int64) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return gzipOf(t, tb.Bytes())
}

// setCaps lowers the caps for a test.
func setCaps(t *testing.T, payload, control int64) {
	t.Helper()
	p, c := maxPayload, maxControl
	maxPayload, maxControl = payload, control
	t.Cleanup(func() { maxPayload, maxControl = p, c })
}

// A gzip of a few kilobytes inflates to as much as its maker likes. Every stream the reader inflates is capped, and a stream over
// its cap is an error that names it. The caps are 1 GiB for a data archive or a payload and 8 MiB for a control archive; the test
// lowers them and feeds streams that are far over them, and checks that the default caps are the documented ones.
func TestAGzipBombIsRefusedNotInflated(t *testing.T) {
	if maxPayload != 1<<30 || maxControl != 8<<20 {
		t.Fatalf("the caps are %d and %d, want 1 GiB and 8 MiB", maxPayload, maxControl)
	}
	setCaps(t, 1<<20, 64<<10)

	// The control archive of a .deb.
	big := tarGzOf(t, "./control", 1<<20)
	if len(big) > 8<<10 {
		t.Fatalf("a megabyte of zeros is %d bytes of gzip: the test is not a bomb", len(big))
	}
	if _, err := readTarGz(big); err == nil || !strings.Contains(err.Error(), "the control archive inflates to more than 65536 bytes") {
		t.Errorf("an oversized control archive: %v", err)
	}
	if _, err := readTarGz(tarGzOf(t, "./control", 1<<10)); err != nil {
		t.Errorf("a small control archive is refused: %v", err)
	}

	// The data archive of a .deb: one file over the cap, and many files that add up to more.
	pk := &Pkg{}
	if err := readDebData(pk, tarGzOf(t, "./usr/bin/x", 8<<20)); err == nil || !strings.Contains(err.Error(), "the data archive inflates to more than 1048576 bytes") {
		t.Errorf("an oversized data archive: %v", err)
	}
	if err := readDebData(&Pkg{}, tarGzOf(t, "./usr/bin/x", 512<<10)); err != nil {
		t.Errorf("a data archive under the cap is refused: %v", err)
	}
	// A unit file over 64 KiB is hashed and its body is not kept.
	setCaps(t, 8<<20, 64<<10)
	pk = &Pkg{}
	if err := readDebData(pk, tarGzOf(t, "./usr/lib/systemd/system/x@.service", 100<<10)); err != nil {
		t.Fatal(err)
	}
	if len(pk.Files) != 1 || pk.Files[0].Body != nil || pk.Files[0].Size != 100<<10 {
		t.Errorf("a large file below /usr/lib: %+v", pk.Files)
	}
	pk = &Pkg{}
	if err := readDebData(pk, tarGzOf(t, "./usr/lib/systemd/system/x@.service", 1<<10)); err != nil || len(pk.Files[0].Body) != 1<<10 {
		t.Errorf("a small file below /usr/lib: %v %+v", err, pk.Files)
	}

	// The payload of an .rpm, whose digest is right: the cap is checked while it inflates.
	setCaps(t, 1<<20, 64<<10)
	payload := gzipOf(t, make([]byte, 8<<20))
	sum := sha256.Sum256(payload)
	h := rpmHeader{tagPayloadDig: rpmEntry{typ: 8, count: 1, data: append([]byte(hex.EncodeToString(sum[:])), 0)}}
	if err := checkPayload(h, payload, nil); err == nil || !strings.Contains(err.Error(), "the payload inflates to more than 1048576 bytes") {
		t.Errorf("an oversized payload: %v", err)
	}
}
