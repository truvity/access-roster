package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assetFiles(t *testing.T) (dir string, paths []string, digests map[string]string) {
	t.Helper()
	dir = t.TempDir()
	digests = map[string]string{}
	for n, b := range map[string]string{"a.tar.gz": "aaaa", "b.deb": "bbbbbb", "SHA256SUMS": "sums"} {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		digests[n] = "sha256:" + hexOf([]byte(b))
	}
	return dir, paths, digests
}

func remoteJSON(t *testing.T, digests map[string]string, mutate func(name string, m map[string]any) bool) []byte {
	t.Helper()
	var items []string
	id := 100
	for _, n := range []string{"a.tar.gz", "b.deb", "SHA256SUMS"} {
		id++
		sizes := map[string]int{"a.tar.gz": 4, "b.deb": 6, "SHA256SUMS": 4}
		m := map[string]any{"id": id, "name": n, "size": sizes[n], "state": "uploaded", "digest": digests[n]}
		if mutate != nil && !mutate(n, m) {
			continue
		}
		items = append(items, string(j(t, m)))
	}
	return []byte("[" + strings.Join(items, ",") + "]")
}

func kinds(plan []AssetAction) string {
	var s []string
	for _, a := range plan {
		s = append(s, a.Kind+" "+a.Name)
	}
	return strings.Join(s, "; ")
}

// verifies: REQ-SUPPLY-037
// A re-run uploads what is missing and nothing else: assets that are there complete, with the size and the digest of the file, are
// kept, and a draft that holds exactly the files has an empty plan (which is the check that the release is complete).
func TestARerunUploadsOnlyTheAssetsThatAreMissing(t *testing.T) {
	_, files, d := assetFiles(t)
	plan, _, err := PlanAssets(files, remoteJSON(t, d, nil), nil)
	if err != nil || len(plan) != 0 {
		t.Fatalf("a complete draft has a plan: %v %v", kinds(plan), err)
	}
	plan, _, err = PlanAssets(files, []byte("[]"), nil)
	if err != nil || len(plan) != 3 || strings.Contains(kinds(plan), "delete") {
		t.Errorf("an empty draft: %v %v", kinds(plan), err)
	}
	plan, _, err = PlanAssets(files, remoteJSON(t, d, func(n string, _ map[string]any) bool { return n != "b.deb" }), nil)
	if err != nil || kinds(plan) != "upload b.deb" {
		t.Errorf("one missing: %v %v", kinds(plan), err)
	}
}

// verifies: REQ-SUPPLY-037
// What is there and is not the file, or not finished, or not the release's, is deleted by its id and made again; the plan deletes
// before it uploads.
func TestAnAssetThatIsNotTheFileIsReplacedAndAStrayIsDeleted(t *testing.T) {
	_, files, d := assetFiles(t)
	for name, c := range map[string]struct {
		mutate func(n string, m map[string]any) bool
		want   string
	}{
		"another digest": {func(n string, m map[string]any) bool {
			if n == "a.tar.gz" {
				m["digest"] = "sha256:" + hexOf([]byte("other"))
			}
			return true
		}, "delete a.tar.gz; upload a.tar.gz"},
		"another size": {func(n string, m map[string]any) bool {
			if n == "b.deb" {
				m["size"] = 5
			}
			return true
		}, "delete b.deb; upload b.deb"},
		"an unfinished upload": {func(n string, m map[string]any) bool {
			if n == "SHA256SUMS" {
				m["state"] = "starter"
				m["size"] = 0
			}
			return true
		}, "delete SHA256SUMS; upload SHA256SUMS"},
	} {
		t.Run(name, func(t *testing.T) {
			plan, _, err := PlanAssets(files, remoteJSON(t, d, c.mutate), nil)
			if err != nil || kinds(plan) != c.want {
				t.Errorf("plan = %v (%v), want %s", kinds(plan), err, c.want)
			}
			if len(plan) == 2 && (plan[0].Kind != "delete" || plan[0].ID == 0) {
				t.Errorf("the delete is not first, or has no id: %v", plan)
			}
		})
	}
	// An asset that is no file of the release, and an asset twice.
	raw := string(remoteJSON(t, d, nil))
	raw = strings.TrimSuffix(raw, "]") + `,{"id":900,"name":"stray.txt","size":1,"state":"uploaded","digest":""},{"id":901,"name":"b.deb","size":6,"state":"uploaded","digest":"` + d["b.deb"] + `"}]`
	plan, _, err := PlanAssets(files, []byte(raw), nil)
	if err != nil || kinds(plan) != "delete stray.txt; delete b.deb" {
		t.Errorf("plan = %v (%v)", kinds(plan), err)
	}
	// An API that gives no digest does not tell the file from another of its size: the asset is deleted and uploaded again, unless this
	// job uploaded it itself, and then the size is what is compared, and said.
	noDigest := remoteJSON(t, d, func(_ string, m map[string]any) bool { m["digest"] = ""; return true })
	plan, notes, err := PlanAssets(files, noDigest, nil)
	if err != nil || len(plan) != 6 || len(notes) != 0 || !strings.Contains(kinds(plan), "delete a.tar.gz") || !strings.Contains(kinds(plan), "upload SHA256SUMS") {
		t.Errorf("no digests, nothing uploaded by this job: %v %v %v", kinds(plan), notes, err)
	}
	plan, notes, err = PlanAssets(files, noDigest, map[string]bool{"a.tar.gz": true, "b.deb": true, "SHA256SUMS": true})
	if err != nil || len(plan) != 0 || len(notes) != 3 {
		t.Errorf("no digests, uploaded by this job: %v %v %v", kinds(plan), notes, err)
	}
	plan, _, err = PlanAssets(files, noDigest, map[string]bool{"b.deb": true})
	if err != nil || len(plan) != 4 || !strings.HasPrefix(kinds(plan), "delete ") || strings.Count(kinds(plan), "a.tar.gz") != 2 || strings.Count(kinds(plan), "SHA256SUMS") != 2 || strings.Contains(kinds(plan), "b.deb") {
		t.Errorf("no digests, one of three uploaded by this job: %v %v", kinds(plan), err)
	}
}

func TestTwoFilesOfOneNameOrNoFileAreRefused(t *testing.T) {
	dir, files, _ := assetFiles(t)
	other := filepath.Join(dir, "sub")
	_ = os.Mkdir(other, 0o750)
	_ = os.WriteFile(filepath.Join(other, "b.deb"), []byte("x"), 0o600)
	if _, _, err := PlanAssets(append(files, filepath.Join(other, "b.deb")), []byte("[]"), nil); err == nil {
		t.Error("two files of one name")
	}
	if _, _, err := PlanAssets([]string{filepath.Join(dir, "missing")}, []byte("[]"), nil); err == nil {
		t.Error("a missing file")
	}
	if _, _, err := PlanAssets([]string{other}, []byte("[]"), nil); err == nil {
		t.Error("a directory")
	}
	if _, _, err := PlanAssets(files, []byte("{"), nil); err == nil {
		t.Error("broken JSON")
	}
}

// The flags of assets-plan are read by main(): -verify turns a plan that is not empty into a failure, and an empty one passes.
func TestTheFlagsOfAssetsPlanAreWired(t *testing.T) {
	bin := buildTool(t)
	_, files, d := assetFiles(t)
	tmp := t.TempDir()
	list := filepath.Join(tmp, "files")
	if err := os.WriteFile(list, []byte(strings.Join(files, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(tmp, "remote.json")
	if err := os.WriteFile(remote, remoteJSON(t, d, func(n string, _ map[string]any) bool { return n != "b.deb" }), 0o600); err != nil {
		t.Fatal(err)
	}
	out, ok := run(t, bin, "assets-plan", "-remote", remote, "-files", list)
	if !ok || !strings.Contains(out, "upload\t") || !strings.Contains(out, "b.deb") || strings.Contains(out, "a.tar.gz") {
		t.Errorf("plan = %v %s", ok, out)
	}
	if out, ok := run(t, bin, "assets-plan", "-verify", "-remote", remote, "-files", list); ok {
		t.Errorf("-verify passed a draft that lacks a file: %s", out)
	}
	if err := os.WriteFile(remote, remoteJSON(t, d, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, ok := run(t, bin, "assets-plan", "-verify", "-remote", remote, "-files", list); !ok {
		t.Errorf("-verify refused a complete draft: %s", out)
	}
	// -uploaded is read: without it an asset with no digest is replaced, with it the size is enough.
	if err := os.WriteFile(remote, remoteJSON(t, d, func(_ string, m map[string]any) bool { m["digest"] = ""; return true }), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, ok := run(t, bin, "assets-plan", "-verify", "-remote", remote, "-files", list); ok {
		t.Errorf("-verify trusted the size of assets that have no digest: %s", out)
	}
	up := filepath.Join(tmp, "uploaded")
	if err := os.WriteFile(up, []byte("a.tar.gz\nb.deb\nSHA256SUMS\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, ok := run(t, bin, "assets-plan", "-verify", "-uploaded", up, "-remote", remote, "-files", list); !ok {
		t.Errorf("-verify refused assets this job uploaded: %s", out)
	}
	_ = fmt.Sprint()
}
