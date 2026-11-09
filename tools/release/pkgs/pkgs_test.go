package pkgs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
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
configure) [ -z "$2" ] || systemctl try-restart 'sluis-store@*.service' || true ;;
esac
exit 0`,
		"stop on removal only":          "case \"$1\" in\nremove | 0) systemctl stop 'sluis-*@*.service' 2>/dev/null || true ;;\nesac",
		"a comment that says start":     "# systemctl enable --now is what we do not do\nexit 0",
		"a flag before the verb":        "systemctl --no-block try-restart sluis-key@dev.service",
		"a variable in braces":          "echo ${HOME} $2 ${x_1}",
		"a redirect to the null device": "systemctl daemon-reload >/dev/null 2>&1 || true",
		"a stream joined to another":    "systemd-tmpfiles --create /usr/lib/tmpfiles.d/sluis-store.conf 2>&1",
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
		"a continued line":                 {"systemctl \\\n  start x.service", "ends with a backslash"},
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
	if _, err := readTarGz(big); err == nil || !strings.Contains(err.Error(), "the control archive holds the entry ./control of 1048576 bytes, over the cap of 65536") {
		t.Errorf("an oversized control archive: %v", err)
	}
	if _, err := readTarGz(tarGzOf(t, "./control", 1<<10)); err != nil {
		t.Errorf("a small control archive is refused: %v", err)
	}

	// The data archive of a .deb: one file over the cap, and many files that add up to more.
	pk := &Pkg{}
	if err := readDebData(pk, tarGzOf(t, "./usr/bin/x", 8<<20)); err == nil || !strings.Contains(err.Error(), "the data archive holds the entry ./usr/bin/x of 8388608 bytes, over the cap of 1048576") {
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

	// Entries that are small and many: their sizes add up to nothing and their headers (512 bytes each) inflate past the cap, so it is
	// the cap of the stream that stops them, and the one of the sum of the sizes stops many that are each under it.
	setCaps(t, 1<<20, 64<<10)
	var many bytes.Buffer
	mtw := tar.NewWriter(&many)
	for i := 0; i < 4000; i++ {
		if err := mtw.WriteHeader(&tar.Header{Name: fmt.Sprintf("./usr/share/doc/x/%d", i), Mode: 0o644, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
	}
	if err := mtw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readDebData(&Pkg{}, gzipOf(t, many.Bytes())); err == nil || !strings.Contains(err.Error(), "the data archive inflates to more than 1048576 bytes") {
		t.Errorf("many small entries: %v", err)
	}
	var sized bytes.Buffer
	stw := tar.NewWriter(&sized)
	for i := 0; i < 3; i++ {
		if err := stw.WriteHeader(&tar.Header{Name: fmt.Sprintf("./usr/share/doc/x/%d", i), Mode: 0o644, Size: 400 << 10, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := stw.Write(make([]byte, 400<<10)); err != nil {
			t.Fatal(err)
		}
	}
	if err := stw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readDebData(&Pkg{}, gzipOf(t, sized.Bytes())); err == nil {
		t.Error("three entries of 400 KiB against a cap of 1 MiB: not refused")
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

// rpmHeaderOf makes the bytes of an rpm header: the magic, the entries (tag, type, offset, count) and the store.
func rpmHeaderOf(entries [][4]uint32, store []byte) []byte {
	b := []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}
	b = binary.BigEndian.AppendUint32(b, uint32(len(entries))) //nolint:gosec // a test header
	b = binary.BigEndian.AppendUint32(b, uint32(len(store)))   //nolint:gosec // a test header
	for _, e := range entries {
		for _, v := range e {
			b = binary.BigEndian.AppendUint32(b, v)
		}
	}
	return append(b, store...)
}

// A count in an rpm header is read from the file. A string array of 0x7fffffff strings over a few bytes made the reader loop and
// allocate until the memory was gone (MEASURED: about two seconds); the counts are held to the data they point to, and a header
// whose count does not fit is an error before anything reads it.
func TestACountThatDoesNotFitTheDataIsRefused(t *testing.T) {
	store := []byte("abc\x00de\x00\x00\x00\x00\x00\x00\x00\x00\x00zzz")
	for name, tc := range map[string]struct {
		entry [4]uint32
		want  string
	}{
		"a string array of two billion strings":            {[4]uint32{1049, 8, 0, 0x7fffffff}, "claim 2147483647 strings"},
		"a string array with more strings than NULs":       {[4]uint32{1049, 8, 0, 20}, "is more than"},
		"three strings and two NULs before the store ends": {[4]uint32{1049, 8, 0, 3}, ""},
		"32-bit numbers, a billion of them":                {[4]uint32{1048, 4, 0, 0x40000000}, "bytes of numbers"},
		"64-bit numbers, a billion of them":                {[4]uint32{5008, 5, 0, 0x40000000}, "bytes of numbers"},
		"16-bit numbers, the whole range":                  {[4]uint32{1030, 3, 0, 0xffffffff}, "bytes of numbers"},
		"bytes, more than the store":                       {[4]uint32{1004, 7, 0, 1 << 20}, "bytes of numbers"},
		"a string with no NUL":                             {[4]uint32{1000, 6, 15, 1}, "is not one string"},
		"two strings in a STRING":                          {[4]uint32{1000, 6, 0, 2}, "is not one string"},
		"a type the reader does not know":                  {[4]uint32{1000, 42, 0, 1}, "does not know"},
		"more strings than NULs, under the data length":    {[4]uint32{1049, 8, 0, 12}, "is more strings than there are NULs in"},
		"32-bit numbers, more than the store left":         {[4]uint32{1048, 4, 0, 1000}, "takes more than"},
		"a string array with more strings than bytes":      {[4]uint32{1049, 8, 0, 40}, "is more than"},
		"a good array of two strings":                      {[4]uint32{1049, 8, 0, 2}, "-"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := readRPMHeader(rpmHeaderOf([][4]uint32{tc.entry}, store), false)
			switch tc.want {
			case "-":
				if err != nil {
					t.Fatalf("a good header is refused: %v", err)
				}
			case "":
				// three strings: the third is the NUL-terminated empty string after "de", so it fits; the store has the NULs for it.
				if err != nil {
					t.Logf("refused: %v", err)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("readRPMHeader: %v, want an error with %q", err, tc.want)
				}
			}
		})
	}
	// The accessors guard themselves too, for a header that did not come through readRPMHeader.
	h := rpmHeader{1049: rpmEntry{typ: 8, count: 0x7fffffff, data: []byte("a\x00")}, 1048: rpmEntry{typ: 4, count: 0x40000000, data: []byte{0, 0, 0, 1}},
		5008: rpmEntry{typ: 5, count: 0x40000000, data: make([]byte, 8)}}
	if h.strs(1049) != nil || h.u32s(1048) != nil || h.u64s(5008) != nil {
		t.Error("an accessor read a count that does not fit")
	}
}

// tarBlock makes the 512-byte header of a tar entry.
func tarBlock(name string, typeflag byte, size int64) []byte {
	b := make([]byte, 512)
	copy(b[0:], name)
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	copy(b[136:], "00000000000\x00")
	copy(b[148:], "        ")
	b[156] = typeflag
	copy(b[257:], "ustar\x0000")
	if typeflag == 'S' {
		copy(b[257:], "ustar  \x00")     // the GNU magic, which the old sparse type needs
		copy(b[483:], "00000010000\x00") // the real size, 4096
	}
	var sum int
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

// A sparse entry is read by Go's tar reader as its real size of zeros, which no cap of the stream sees: a PAX record
// GNU.sparse.realsize of 8 GiB hashed 8 GiB in 3.5 s (MEASURED), and 1 TiB would take minutes. Any sparse entry, an entry over the
// cap and entries that add up to more than it are refused, whatever the stream says.
func TestASparseEntryIsRefusedWhateverItsRealSize(t *testing.T) {
	setCaps(t, 1<<20, 64<<10)
	pax := func(recs map[string]string) []byte {
		var data string
		for k, v := range recs {
			// A record is "<len> <key>=<value>\n", and len counts its own digits.
			body := " " + k + "=" + v + "\n"
			l := len(body) + 1
			for len(fmt.Sprint(l))+len(body) != l {
				l++
			}
			data += fmt.Sprintf("%d%s", l, body)
		}
		out := tarBlock("PaxHeaders/x", 'x', int64(len(data)))
		blk := make([]byte, (len(data)+511)/512*512)
		copy(blk, data)
		return append(out, blk...)
	}
	// A PAX 1.0 sparse file: the data is the map ("0\n", no segments) padded to a block; the real size is the record's.
	sparse := func(realsize string) []byte {
		b := pax(map[string]string{"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": "usr/bin/x", "GNU.sparse.realsize": realsize})
		b = append(b, tarBlock("GNUSparseFile.0/x", '0', 512)...)
		mapBlock := make([]byte, 512)
		copy(mapBlock, "0\n")
		b = append(b, mapBlock...)
		return append(b, make([]byte, 1024)...)
	}
	start := time.Now()
	for _, size := range []string{"8589934592", "1099511627776", "1048577"} {
		err := readDebData(&Pkg{}, gzipOf(t, sparse(size)))
		if err == nil || !strings.Contains(err.Error(), "sparse") {
			t.Errorf("a PAX sparse entry of %s bytes: %v", size, err)
		}
	}
	// The old GNU sparse type.
	old := append(tarBlock("usr/bin/x", 'S', 0), make([]byte, 1024)...)
	if err := readDebData(&Pkg{}, gzipOf(t, old)); err == nil || !strings.Contains(err.Error(), "sparse") {
		t.Errorf("a GNU sparse entry: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the sparse entries took %s: something read their holes", d)
	}
	// The control archive too.
	if _, err := readTarGz(gzipOf(t, sparse("8589934592"))); err == nil || !strings.Contains(err.Error(), "sparse") {
		t.Errorf("a sparse entry in the control archive: %v", err)
	}
	// A plain file is fine, and a size in the header over the cap is refused before a byte of it is read.
	plain := append(tarBlock("usr/bin/x", '0', 5), append([]byte("hello"), make([]byte, 507+1024)...)...)
	if err := readDebData(&Pkg{}, gzipOf(t, plain)); err != nil {
		t.Errorf("a plain file: %v", err)
	}
	huge := append(tarBlock("usr/bin/x", '0', 8<<30), make([]byte, 1024)...)
	if err := readDebData(&Pkg{}, gzipOf(t, huge)); err == nil || !strings.Contains(err.Error(), "over the cap") {
		t.Errorf("a header of 8 GiB: %v", err)
	}
}

// A planned script may run what is on the list and nothing else: a word the lint has never heard of is a refusal, which is the
// point of a list of what is allowed over a list of what is not.
func TestAPlannedScriptMayRunOnlyWhatIsOnTheList(t *testing.T) {
	ok := []string{
		"#!/bin/sh\nset -e\nexit 0\n",
		"#!/bin/sh\nset -eu\nsystemd-sysusers /usr/lib/sysusers.d/sluis-store.conf\nsystemd-tmpfiles --create /usr/lib/tmpfiles.d/sluis-store.conf\nsystemctl daemon-reload\nexit 0\n",
		"#!/bin/sh\nif [ -d /run/systemd/system ]; then\n  systemctl daemon-reload >/dev/null 2>&1 || true\nfi\n",
		"#!/bin/sh\ncase \"$1\" in\nremove | 0)\n  systemctl stop 'sluis-*@*.service' 2>/dev/null || true\n  ;;\n*) ;;\nesac\n",
		"#!/bin/sh\ncase \"$1\" in\n2) systemctl try-restart 'sluis-store@*.service' || true ;;\nconfigure) [ -z \"$2\" ] || systemctl try-restart sluis-store@dev.service || true ;;\nesac\necho done >&2\ntrue\n",
		"#!/bin/sh\ntest -x /usr/bin/sluis && echo present\nsystemctl --no-block try-restart sluis-key@dev.service sluis-store@dev.service\n",
	}
	for i, text := range ok {
		if p := lintScript("postinst", text); len(p) > 0 {
			t.Errorf("good script %d refused: %v", i, p)
		}
	}
	for name, tc := range map[string]struct{ text, want string }{
		"ls":                                {"ls /etc", "which is not on the list"},
		"cat":                               {"cat /etc/passwd", "which is not on the list"},
		"printf":                            {"printf x", "which is not on the list"},
		"date":                              {"date", "which is not on the list"},
		"id":                                {"id root", "which is not on the list"},
		"getent":                            {"getent passwd root", "which is not on the list"},
		"command -v":                        {"command -v systemctl", "which is not on the list"},
		"a variable assignment":             {"FOO=1 true", "which is not on the list"},
		"systemctl is-active":               {"systemctl is-active sluis-key@dev.service", "not daemon-reload, nor stop or try-restart"},
		"systemctl status":                  {"systemctl status sluis-key@dev.service", "not daemon-reload, nor stop or try-restart"},
		"systemctl daemon-reload and more":  {"systemctl daemon-reload sluis-key@dev.service", "not daemon-reload, nor stop or try-restart"},
		"systemctl stop of a foreign unit":  {"systemctl stop ssh.service", "not the name of a sluis unit"},
		"systemctl stop with no unit":       {"systemctl stop", "not daemon-reload, nor stop or try-restart"},
		"systemctl stop of a path":          {"systemctl stop /etc/systemd/system/x.service", "not the name of a sluis unit"},
		"sysusers on another file":          {"systemd-sysusers /etc/sysusers.d/x.conf", "not a file of /usr/lib/sysusers.d"},
		"sysusers on no file":               {"systemd-sysusers", "on no file"},
		"sysusers with a flag":              {"systemd-sysusers --root=/x /usr/lib/sysusers.d/a.conf", "not a file of /usr/lib/sysusers.d"},
		"tmpfiles on another file":          {"systemd-tmpfiles --create /tmp/x.conf", "not a file of /usr/lib/tmpfiles.d"},
		"tmpfiles --clean":                  {"systemd-tmpfiles --clean /usr/lib/tmpfiles.d/a.conf", "only --create"},
		"tmpfiles with no file":             {"systemd-tmpfiles --create", "only --create"},
		"exit with a word":                  {"exit foo", "not a status"},
		"set with arguments":                {"set -- a b", "only flags"},
		"a command substitution":            {"echo $(id)", "command substitution"},
		"a backtick":                        {"echo `id`", "command substitution"},
		"a heredoc":                         {"cat <<EOF\nx\nEOF", "command substitution or a heredoc"},
		"an input redirect":                 {"true < /etc/passwd", "redirects to or from"},
		"an output redirect":                {"echo x > /tmp/f", "redirects to or from"},
		"an error redirect":                 {"echo x 2>/etc/f", "redirects to or from"},
		"a function":                        {"f() { systemctl daemon-reload; }", "which is not on the list"},
		"a loop":                            {"for u in a b; do systemctl daemon-reload; done", "which is not on the list"},
		"a case pattern is not a free pass": {"case \"$1\" in\nx) ls ;;\nesac", "runs \"ls\""},
	} {
		t.Run(name, func(t *testing.T) {
			p := allowedProblems("postinst", tc.text)
			found := false
			for _, x := range p {
				found = found || strings.Contains(x, tc.want)
			}
			if !found {
				t.Errorf("want a problem with %q, got %v", tc.want, p)
			}
		})
	}
}

// /run/sluis is the runtime directory of the units and is no state; the paths that look like it, or that lead out of it, are.
func TestRunSluisIsNotStateAndNothingNearItIsNot(t *testing.T) {
	for p, want := range map[string]bool{
		"/run/sluis": false, "/run/sluis/store/dev/store.sock": false, "//run//sluis/x": false, "/run/sluis/./x": false,
		"/run/sluis-state": true, "/run/sluis/../../var/lib/sluis-state": true, "/run/sluisx": true, "/var/lib/sluis-state": true,
		"/etc/sluis": true, "/etc/sluis/bootstrap.d": true, "/usr/libexec/sluis/actors/store": false, "$DIR": true,
	} {
		if got := stateish(p); got != want {
			t.Errorf("stateish(%q) = %v, want %v", p, got, want)
		}
	}
}

// Entries may all point at one long run of bytes. A walk of each is quadratic: 2000 entries over an 8 MiB store took 71 s, and the
// 65536 entries a header may have would stall the job for about forty minutes. The walks of a header share a budget.
func TestEntriesOverOneLongStoreAreRefusedFast(t *testing.T) {
	store := bytes.Repeat([]byte("a"), 8<<20)
	store[len(store)-1] = 0
	for name, typ := range map[string]uint32{"string arrays": 8, "strings": 6} {
		t.Run(name, func(t *testing.T) {
			entries := make([][4]uint32, 65536)
			for i := range entries {
				entries[i] = [4]uint32{uint32(1000 + i), typ, 0, 1}
			}
			start := time.Now()
			_, _, err := readRPMHeader(rpmHeaderOf(entries, store), false)
			if err == nil || !strings.Contains(err.Error(), "ran out of its budget") {
				t.Fatalf("65536 entries over one store: %v", err)
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("the refusal took %s", d)
			}
		})
	}
	// Strings that do not overlap are what an rpm has, and are read: a thousand entries of a thousand strings each.
	var good [][4]uint32
	var gs []byte
	for i := 0; i < 1000; i++ {
		good = append(good, [4]uint32{uint32(1000 + i), 8, uint32(len(gs)), 50}) //nolint:gosec // a test header
		for j := 0; j < 50; j++ {
			gs = append(gs, fmt.Sprintf("name-%d-%d", i, j)...)
			gs = append(gs, 0)
		}
	}
	if _, _, err := readRPMHeader(rpmHeaderOf(good, gs), false); err != nil {
		t.Errorf("a header of distinct strings is refused: %v", err)
	}
}

// A quote still open at the end of a line makes the following lines a string, and a line that looks like a comment in it is shell
// code (echo "a, a line of # and ;echo EXECUTED, and a closing quote ran the middle command and passed the lint).
func TestAQuoteOpenAtTheEndOfALineIsRefused(t *testing.T) {
	for name, text := range map[string]string{
		"double quotes":                 "#!/bin/sh\necho \"a\n# \";echo EXECUTED;echo \"\ntrue\"\n",
		"single quotes":                 "#!/bin/sh\necho 'a\n# ';echo EXECUTED;echo '\ntrue'\n",
		"a plain string over two lines": "#!/bin/sh\necho \"one\ntwo\"\n",
		"an unterminated quote":         "#!/bin/sh\necho 'one\n",
	} {
		p := lintScript("postinst", text)
		found := false
		for _, x := range p {
			found = found || strings.Contains(x, "a quote still open at the end of the line")
		}
		if !found {
			t.Errorf("%s: not refused for the open quote: %v", name, p)
		}
	}
	for name, text := range map[string]string{
		"a comment with an apostrophe": "#!/bin/sh\n# it's the postinst\nexit 0\n",
		"an apostrophe in a string":    "#!/bin/sh\necho \"it's\"\nexit 0\n",
		"a double quote in a string":   "#!/bin/sh\necho 'say \"hi\"'\nexit 0\n",
		"an escaped quote":             "#!/bin/sh\necho \"a \\\" b\"\nexit 0\n",
		"an escaped space":             "#!/bin/sh\necho a\\ b\nexit 0\n",
	} {
		if p := lintScript("postinst", text); len(p) > 0 {
			t.Errorf("%s: refused: %v", name, p)
		}
	}
}

// On Linux the rest of the first line reaches the interpreter as its arguments: #!/usr/bin/perl -e system(...) is a program. The
// first line is #!/bin/sh with at most -e or -eu, or the script has none.
func TestOnlyTheShellShebangIsAllowed(t *testing.T) {
	for _, first := range []string{"#!/bin/sh", "#!/bin/sh -e", "#!/bin/sh -eu"} {
		if p := lintScript("postinst", first+"\nexit 0\n"); len(p) > 0 {
			t.Errorf("%q refused: %v", first, p)
		}
	}
	if p := lintScript("postinst", "exit 0\n"); len(p) > 0 {
		t.Errorf("a script with no shebang refused: %v", p)
	}
	for _, first := range []string{
		"#!/usr/bin/perl -e system(\"systemctl start x\")", "#!/usr/bin/perl", "#!/bin/sh -c systemctl", "#!/bin/sh -x", "#!/bin/sh -ex",
		"#!/bin/bash", "#!/usr/bin/env sh", "#!/bin/sh ", "#!/bin/sh\r", "#! /bin/sh", "#!/bin/dash", "#!", "#!/bin/sh -e -u", "#!/bin/sh\t-e",
	} {
		p := lintScript("postinst", first+"\nexit 0\n")
		found := false
		for _, x := range p {
			found = found || strings.Contains(x, "the first line is #!/bin/sh") || strings.Contains(x, "has the byte")
		}
		if !found {
			t.Errorf("%q: not refused as a shebang: %v", first, p)
		}
	}
	// A #! line that is not the first is a comment.
	if p := lintScript("postinst", "#!/bin/sh\n#!/usr/bin/perl\nexit 0\n"); len(p) > 0 {
		t.Errorf("a later #! line is refused: %v", p)
	}
}

// The shape of a planned script is held to the part of the shell where the lint's way of reading is true: a # only at the start of a
// line, no $' or $", a ${ only as ${NAME}, no backslash at the end of a line, no quote open across one.
func TestTheShapeOfAPlannedScriptIsStrict(t *testing.T) {
	for name, text := range map[string]string{
		"a hash in a parameter expansion":      "#!/bin/sh\necho ${a:- #} '\n# x ';echo EXECUTED;echo '\ntrue\n",
		"a hash after a command":               "#!/bin/sh\necho hi # c\n",
		"a hash in a word":                     "#!/bin/sh\necho a#b\n",
		"a hash in a string":                   "#!/bin/sh\necho \"a # b\"\n",
		"the argument count":                   "#!/bin/sh\n[ $# -gt 0 ]\n",
		"the length of a variable":             "#!/bin/sh\necho ${#a}\n",
		"ANSI-C quoting":                       "#!/bin/sh\necho $'a\\'b'\n# x ';echo EXECUTED;echo '\ntrue\n",
		"ANSI-C quoting, plain":                "#!/bin/sh\necho $'a'\n",
		"translation":                          "#!/bin/sh\necho $\"a\"\n",
		"a parameter with an operator":         "#!/bin/sh\necho ${a:-b}\n",
		"a parameter with a pattern":           "#!/bin/sh\necho ${a%x}\n",
		"a positional parameter in braces":     "#!/bin/sh\necho ${2}\n",
		"an unclosed parameter":                "#!/bin/sh\necho ${a\n",
		"a comment that ends with a backslash": "#!/bin/sh\n# a \\\nsystemctl start x.service\n",
		"a command that ends with one":         "#!/bin/sh\necho a \\\nb\n",
		"a string over two lines":              "#!/bin/sh\necho \"a\nb\"\n",
	} {
		if p := shapeProblems("postinst", text); len(p) == 0 {
			t.Errorf("%s: not refused: %q", name, text)
		}
		if p := lintScript("postinst", text); len(p) == 0 {
			t.Errorf("%s: the lint accepts %q", name, text)
		}
	}
	for name, text := range map[string]string{
		"a comment line":            "#!/bin/sh\n# it's a comment with \"quotes\", $', ${a:-b} and a #\nexit 0\n",
		"an indented comment":       "#!/bin/sh\n   # a comment\nexit 0\n",
		"a variable":                "#!/bin/sh\necho $1 ${HOME} $x_1 $?\nexit 0\n",
		"quotes closed on the line": "#!/bin/sh\necho \"it's\" 'say \"hi\"' \"a \\\" b\"\nexit 0\n",
		"a dollar at the end":       "#!/bin/sh\necho a$\nexit 0\n",
	} {
		if p := shapeProblems("postinst", text); len(p) > 0 {
			t.Errorf("%s: refused: %v", name, p)
		}
	}
}

// The lint reads a script a line at a time and the shell reads it as a language. This test closes the gap by experiment: it
// generates short last lines from the pieces that bend the reading of the lines after them (quotes, a backslash, a semicolon, a hash,
// a dollar and braces, with echo and a word), puts after each a line that the lint takes for a comment or a string and that a shell
// would run if the line before it bent the reading, and for every script the lint accepts it runs the script under the shells
// of the host in a temporary directory and asserts that the marker command did not run.
func TestWhatTheLintAcceptsRunsNoMarkerCommand(t *testing.T) {
	var shells []string
	for _, sh := range []string{"dash", "sh", "bash"} {
		if p, err := exec.LookPath(sh); err == nil {
			dup := false
			for _, q := range shells {
				if rp, _ := filepath.EvalSymlinks(q); rp != "" {
					if rp2, _ := filepath.EvalSymlinks(p); rp == rp2 {
						dup = true
					}
				}
			}
			if !dup {
				shells = append(shells, p)
			}
		}
	}
	if len(shells) == 0 {
		t.Skip("no shell (dash, sh or bash) on this host to run the accepted scripts")
	}
	// The odd blanks too: \v, \f, U+00A0 and \r are not blanks to a shell, and are to strings.TrimSpace.
	pieces := []string{"echo", "x", "'", "\"", "\\", ";", "#", "$", "{", "}", " ", "\v", "\f", "\u00a0", "\r"}
	// The lines that follow: comments and strings to the lint, and the marker command to a shell that was bent.
	markers := [][2]string{
		{"# ';touch MARK;'", ""},
		{"# \";touch MARK;\"", ""},
		{"#;touch MARK", ""},
		{"touch MARK #'", ""},
		// The shape of the exploit that passed the first lint: the line before opens a string, a line that looks like a comment closes
		// it and runs the marker and opens another, and a last line closes that one.
		{"# \";touch MARK;echo \"", "true\""},
		{"# ';touch MARK;echo '", "true'"},
		{"# ';touch MARK;echo \"", "true'\""},
		{"#};touch MARK;{", "}"},
		// The last line is a comment to the lint too, and to the shell the end of the string the line before opened.
		{"# ';touch MARK;echo '", "#'"},
		{"# \";touch MARK;echo \"", "#\""},
	}
	// Four pieces cover the shapes that bend the next line (an open quote, a quote and a ;, a hash and a brace, $' ...); five take
	// about ten times as long (SLUIS_LINT_LONG=1).
	maxLen := 4
	if os.Getenv("SLUIS_LINT_LONG") != "" {
		maxLen = 5
	}
	dir := t.TempDir()
	// The generated scripts are code nobody wrote, and they run on the host of whoever runs the tests. They run with recording stubs
	// first on the PATH for everything that could reach the system (systemd, the buses, privilege escalation), with no bus to reach,
	// in a directory of their own; a stub that ran fails the test. The pieces cannot spell any of these names or a path, so the
	// stubs are the second guard, not the first.
	stubs := filepath.Join(dir, "stubs")
	if err := os.Mkdir(stubs, 0o700); err != nil {
		t.Fatal(err)
	}
	stubLog := filepath.Join(dir, "stub.log")
	for _, name := range []string{"systemctl", "systemd-sysusers", "systemd-tmpfiles", "systemd-run", "sudo", "pkexec", "busctl", "dbus-send", "gdbus", "machinectl", "loginctl", "su", "doas"} {
		body := "#!/bin/sh\necho \"" + name + " $*\" >> \"$STUBLOG\"\nexit 0\n"
		if err := os.WriteFile(filepath.Join(stubs, name), []byte(body), 0o700); err != nil { //nolint:gosec // a stub, run by the test
			t.Fatal(err)
		}
	}
	env := []string{"PATH=" + stubs + string(os.PathListSeparator) + os.Getenv("PATH"), "STUBLOG=" + stubLog, "HOME=" + dir,
		"DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent/sluis-lint-test/bus", "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/sluis-lint-test/bus"}
	accepted, ran := 0, 0
	var gen func(prefix string, n int)
	check := func(line string) {
		for _, mm := range markers {
			text := "#!/bin/sh\n" + line + "\n" + mm[0] + "\n"
			if mm[1] != "" {
				text += mm[1] + "\n"
			}
			if len(lintScript("postinst", text)) > 0 {
				continue
			}
			accepted++
			if !strings.ContainsAny(line, "'\"\\#${}") {
				continue // nothing in it can bend the reading of the next line: no quote, backslash, hash, dollar or brace
			}
			// Accepted. Run it where it cannot do harm: the only commands in it are the pieces, and the marker is touch MARK.
			script := filepath.Join(dir, "s.sh")
			if err := os.WriteFile(script, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, sh := range shells {
				_ = os.Remove(filepath.Join(dir, "MARK"))
				cmd := exec.Command(sh, script) //nolint:gosec // a shell, run on a script made of the pieces above
				cmd.Dir = dir
				cmd.Env = env
				_ = cmd.Run()
				ran++
				if b, err := os.ReadFile(stubLog); err == nil { //nolint:gosec // a file of the test's own temporary directory
					t.Fatalf("a stub ran under %s for %q: %s", sh, text, b)
				}
				if _, err := os.Stat(filepath.Join(dir, "MARK")); err == nil {
					t.Errorf("the lint accepts %q, and %s ran the marker command", text, sh)
				}
			}
		}
	}
	gen = func(prefix string, n int) {
		if prefix != "" {
			check(prefix)
		}
		if n == 0 {
			return
		}
		for _, p := range pieces {
			gen(prefix+p, n-1)
		}
	}
	gen("", maxLen)
	t.Logf("%d scripts accepted by the lint and run under %v (%d runs)", accepted, shells, ran)
	if accepted == 0 {
		t.Error("the lint accepts none of the generated scripts: the test proves nothing")
	}
}

// rpmFileOf makes an .rpm file with the given main header: the lead, an empty signature header and the main header.
func rpmFileOf(t *testing.T, entries [][4]uint32, store []byte) string {
	t.Helper()
	b := append([]byte{0xed, 0xab, 0xee, 0xdb, 3, 0}, make([]byte, 90)...)
	b = append(b, rpmHeaderOf(nil, nil)...) // the signature header: no entries, no store (16 bytes, so no padding)
	b = append(b, rpmHeaderOf(entries, store)...)
	p := filepath.Join(t.TempDir(), "x.rpm")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// allocated is the bytes allocated while f runs (TotalAlloc counts every allocation, whether or not it is freed, which is the
// peak a loop that builds slices would reach if nothing were collected).
func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// A crafted package of 64 MiB, whose seven string arrays (tags 1116, 1117, 1118, 1039, 1040, 1049, 1050) claimed strings out of the
// same store, peaked at 5.9 GB: 16 bytes for each string the readers built. The store is capped at 64 MiB, the strings of a header
// at a quarter of its store and 4096, and the sums are checked before a slice is allocated; the test measures what the reader
// allocates on such a file (8 MiB here) and on a file at the very limit of what it allows.
func TestSevenStringArraysOverOneStoreAllocateLittle(t *testing.T) {
	const size = 8 << 20
	store := make([]byte, size) // all NULs: every string is empty and takes one byte
	store[0] = 'x'              // the name, the version and the architecture of the package: "x"
	tags := []uint32{1116, 1117, 1118, 1039, 1040, 1049, 1050}
	entries := func(each uint32) [][4]uint32 {
		// With a name, a version and an architecture the reader goes on to build the slices of the arrays.
		e := [][4]uint32{{1000, 6, 0, 1}, {1001, 6, 0, 1}, {1022, 6, 0, 1}}
		for _, tag := range tags {
			e = append(e, [4]uint32{tag, 8, 0, each})
		}
		return e
	}
	// Over the limit: seven arrays of 400000 strings in a store of 8 MiB, 2.8 million strings against a quarter and 4096 of 2.1.
	over := rpmFileOf(t, entries(400000), store)
	var err error
	a := allocated(func() { _, err = ReadPackage(over) })
	if err == nil || !strings.Contains(err.Error(), "claim 2800003 strings") {
		t.Fatalf("the crafted package: %v", err)
	}
	if a > 3*size {
		t.Errorf("the refusal allocated %d bytes for a file of %d: more than three times it", a, size)
	}
	// At the limit: 7 arrays that add up to a quarter of the store and 4096. The reader takes them; what it allocates is held to a
	// small multiple of the file (a string slice is 16 bytes a string, and a quarter of the store is one string per four bytes).
	each := uint32((maxStrings - 3) / 7)
	at := rpmFileOf(t, entries(each), store)
	a = allocated(func() { _, err = ReadPackage(at) })
	t.Logf("at the limit the reader allocated %d bytes for a file of %d", a, size)
	if a > 8*size || a > 100<<20 {
		t.Errorf("the reader allocated %d bytes for a file of %d at the limit: more than eight times it, or 100 MiB", a, size)
	}
	// The absolute caps, under the quarter of a big store: a million strings in a store that has room for them are still refused.
	if _, _, err := readRPMHeader(rpmHeaderOf(entries(150000), store), false); err == nil || !strings.Contains(err.Error(), "or than 262144") {
		t.Errorf("a million strings in a store of 8 MiB: %v", err)
	}
	big20 := make([]byte, 20<<20)
	var nums [][4]uint32
	for _, tag := range tags {
		nums = append(nums, [4]uint32{tag, 4, 0, 600000}) // 7 x 2.4 MB = 16.8 MB of numbers, in a store of 20 MiB
	}
	if _, _, err := readRPMHeader(rpmHeaderOf(nums, big20), false); err == nil || !strings.Contains(err.Error(), "or than 16777216") {
		t.Errorf("16.8 MB of numbers in a store of 20 MiB: %v", err)
	}
	// The cap on the store: a header that says its store is 64 MiB and a byte is refused whatever the file holds.
	big := rpmHeaderOf(nil, nil)
	binary.BigEndian.PutUint32(big[12:], maxRPMStore+1)
	if _, _, err := readRPMHeader(big, false); err == nil || !strings.Contains(err.Error(), "over the 67108864 the reader takes") {
		t.Errorf("a store of 64 MiB and a byte: %v", err)
	}
	// And a store of exactly 64 MiB is not refused for its size (the file is short, so it is refused as larger than the file).
	binary.BigEndian.PutUint32(big[12:], maxRPMStore)
	if _, _, err := readRPMHeader(big, false); err == nil || strings.Contains(err.Error(), "over the") {
		t.Errorf("a store of 64 MiB: %v", err)
	}
	// Numbers and bytes are summed too: 7 arrays of 32-bit numbers over one store.
	var num [][4]uint32
	for _, tag := range tags {
		num = append(num, [4]uint32{tag, 4, 0, 1 << 20})
	}
	if _, _, err := readRPMHeader(rpmHeaderOf(num, store), false); err == nil || !strings.Contains(err.Error(), "bytes of numbers") {
		t.Errorf("seven arrays of numbers over one store: %v", err)
	}
}

// A shell's blanks are the space and the tab. TrimSpace and Fields also take \v, \f, U+0085, U+00A0, U+2028 and U+3000, so a line
// "<blank># '" was a comment to the lint and, to a shell, a word and an open quote, and the line after it ran. The 5 escapes that a
// mutation fuzzer found were of that shape.
func TestOnlyTheSpaceAndTheTabAreBlanks(t *testing.T) {
	leads := map[string]string{"\\v": "\v", "\\f": "\f", "U+0085": "\u0085", "U+00A0": "\u00a0", "U+2028": "\u2028", "U+3000": "\u3000", "\\r": "\r", "NUL": "\x00", "U+FEFF": "\ufeff", "DEL": "\x7f", "ESC": "\x1b"}
	for name, lead := range leads {
		text := "#!/bin/sh\n" + lead + "# '\n# ';touch MARK;echo '\ntrue'\n"
		if p := charsetProblems("postinst", text); len(p) == 0 {
			t.Errorf("%s: charsetProblems accepts %q", name, text)
		}
		if p := lintScript("postinst", text); len(p) == 0 {
			t.Errorf("%s: the lint accepts %q", name, text)
		}
		// Whatever the charset rule does, the readers of lines do not take the character for a blank: the line is no comment, so the
		// shape check sees a # that does not start its line (or the byte it cannot read).
		if lead != "\x00" && lead != "\r" && lead != "\x7f" && lead != "\x1b" && lead != "\ufeff" {
			if p := shapeProblems("postinst", text); len(p) == 0 {
				t.Errorf("%s: shapeProblems takes %q for a comment", name, lead+"# '")
			}
		}
		if trimBlank(lead+"x") != lead+"x" {
			t.Errorf("%s: trimBlank trims %q", name, lead)
		}
		if got := fieldsBlank("a" + lead + "b"); len(got) != 1 {
			t.Errorf("%s: fieldsBlank splits at %q: %q", name, lead, got)
		}
	}
	if got := fieldsBlank(" a\t b  "); len(got) != 2 || trimBlank(" \t x \t") != "x" {
		t.Errorf("the space and the tab are the blanks: %q", got)
	}
	// A character that no other rule reads as dangerous is refused too: only the charset rule stops these.
	for name, text := range map[string]string{
		"a no-break space in an echo": "#!/bin/sh\necho a\u00a0b\nexit 0\n", "a CR in an echo": "#!/bin/sh\necho a\r\nexit 0\n",
		"a form feed in an echo": "#!/bin/sh\necho a\fb\nexit 0\n", "a NUL in an echo": "#!/bin/sh\necho a\x00b\nexit 0\n",
		"an accented letter": "#!/bin/sh\necho caf\u00e9\nexit 0\n", "a CRLF script": "#!/bin/sh -e\r\nexit 0\r\n",
	} {
		if p := lintScript("postinst", text); len(p) == 0 || !strings.Contains(p[0], "has the byte") {
			t.Errorf("%s: %v", name, p)
		}
	}
	// Printable ASCII, newlines and tabs are fine, and the shapes of the good scripts stay good.
	if p := charsetProblems("postinst", "#!/bin/sh\n\texit 0\n~ } ! |\n"); len(p) > 0 {
		t.Errorf("printable ASCII refused: %v", p)
	}
}
