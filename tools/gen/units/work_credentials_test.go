package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// A work unit holds no storage, key or audit credential at rest: nothing in its unit hands it a credential file, an
// environment file (but the uid plan of the boundary, numbers alone) or a variable, or gives it a directory of state, cache, configuration or logs, or binds a path from the
// host into it. The one directory it may write is its own run directory, where it makes its socket (and which the unit
// makes noexec). The sweep covers every work actor that has a unit and the audit front of entry. A scan of the memory of
// a running unit needs a board; this holds every way the unit's text could put a credential there.
//
// verifies: REQ-ISO-085
func TestWorkUnitsHoldNoCredentialAtRest(t *testing.T) {
	files := generate(t)
	var names []string
	for _, a := range registry.Actors() {
		if a.Family == "work" {
			if _, ok := files["sluis-"+a.Name+"@.service"]; ok {
				names = append(names, "sluis-"+a.Name+"@.service")
			}
		}
	}
	names = append(names, "sluis-entry-audit@.service")
	if len(names) < 6 {
		t.Fatalf("only %d work units found: %v", len(names), names)
	}

	forbidden := []string{
		"LoadCredential", "LoadCredentialEncrypted", "SetCredential", "SetCredentialEncrypted", "ImportCredential",
		"PassEnvironment", "StateDirectory", "CacheDirectory", "ConfigurationDirectory",
		"LogsDirectory", "RuntimeDirectory", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem",
	}
	for _, name := range names {
		d := directives(files[name])
		for _, k := range forbidden {
			if _, ok := d[k]; ok {
				t.Errorf("%s sets %s", name, k)
			}
		}
		for _, v := range d["EnvironmentFile"] {
			// The one file a work unit reads is the boundary's uid plan: the numbers of the uid block, which entry needs for the
			// group of its socket (checked below to hold nothing else). Any other file could hold a credential.
			if v != UIDsFile {
				t.Errorf("%s reads the environment file %s, not the uid plan %s", name, v, UIDsFile)
			}
		}
		for _, v := range d["Environment"] {
			// Only a memory limit of the Go runtime; a credential, a path or an address would be another variable.
			if !strings.HasPrefix(v, "GOMEMLIMIT=") {
				t.Errorf("%s sets the variable %s", name, v)
			}
		}
		rw := d["ReadWritePaths"]
		if len(rw) != 1 || !strings.HasPrefix(rw[0], "/run/sluis/") || strings.Count(rw[0], "/") != 3 {
			t.Errorf("%s may write %v, not its run directory alone", name, rw)
		}
		for _, bad := range []string{LoadRoot, StateRoot, "/etc/sluis/bootstrap.d", "/etc/sluis/config", "/var/lib/"} {
			if strings.Contains(files[name], bad) {
				t.Errorf("%s names %s", name, bad)
			}
		}
	}

	// The uid plan holds numbers and no credential: a comment, or one variable of the plan for each name of the uid list, with a
	// uid of the block as its value, and nothing else. The deploy refuses any other line (check_uids_file in remote-lib.sh)
	// with the same pattern, which this test reads from the script.
	const pattern = `^SLUIS_UID_[A-Z0-9_]+=61[0-9]{3}$`
	if !strings.Contains(readRepoFile(t, "deploy/boards/remote-lib.sh"), "=~ "+pattern) {
		t.Errorf("check_uids_file in remote-lib.sh does not use the pattern %s", pattern)
	}
	line := regexp.MustCompile(pattern)
	want := map[string]bool{}
	for i := uint32(0); ; i++ {
		n, _, ok := registry.NameForUID(61000 + i)
		if !ok {
			break
		}
		want["SLUIS_UID_"+uidVar(n)] = true
	}
	got := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSuffix(files[UIDsFileName], "\n"), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		if !line.MatchString(l) {
			t.Errorf("%s holds %q, which is not a uid of the block", UIDsFileName, l)
		}
		k, _, _ := strings.Cut(l, "=")
		if got[k] {
			t.Errorf("%s names %s twice", UIDsFileName, k)
		}
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("%s lacks %s", UIDsFileName, k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s has %s, which is no name of the uid list", UIDsFileName, k)
		}
	}
	if len(want) < 25 {
		t.Errorf("only %d names in the uid list", len(want))
	}

	// The controls: the same directives exist in the units of the holders, so the sweep is looking for something real.
	holds := map[string]bool{}
	for _, name := range []string{"sluis-key@.service", "sluis-drv-store-credential@.service", "sluis-store@.service"} {
		d := directives(files[name])
		for _, k := range forbidden {
			if _, ok := d[k]; ok {
				holds[k] = true
			}
		}
	}
	for _, k := range []string{"StateDirectory", "LoadCredentialEncrypted"} {
		if !holds[k] {
			t.Errorf("no unit of a holder sets %s: the control is gone", k)
		}
	}
}
