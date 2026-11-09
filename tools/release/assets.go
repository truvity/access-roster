package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/truvity/sluis/v2/tools/verify/evidence"
)

// remoteAsset is an asset of a draft release as the API lists it (`gh api repos/<repo>/releases/<id> --jq .assets`).
type remoteAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	State  string `json:"state"`
	Digest string `json:"digest"` // "sha256:<hex>", when the API gives one
}

// AssetAction is one step of the plan that makes the assets of a draft the files of the release.
type AssetAction struct {
	Kind string // upload or delete
	Path string // upload: the local file
	ID   int64  // delete: the asset
	Name string
	Why  string
}

// PlanAssets compares the files of the release with the assets a draft already holds and returns what makes the draft hold exactly
// those files: an asset that is there complete, with the size and, when the API gives a digest, the digest of the local file, is
// kept (a re-run uploads what is missing and nothing else, REQ-SUPPLY-037); an asset that is missing is uploaded; one that is there
// but unfinished, of another size or digest, is deleted and uploaded again; one that is no file of the release is deleted. Two local
// files of one name are an error: an asset has one. The plan being empty is the check that a draft holds the release and nothing more.
func PlanAssets(files []string, remoteJSON []byte) ([]AssetAction, []string, error) {
	var remote []remoteAsset
	if err := json.Unmarshal(remoteJSON, &remote); err != nil {
		return nil, nil, fmt.Errorf("the assets of the draft: %w", err)
	}
	type local struct {
		path   string
		size   int64
		digest string
	}
	byName := map[string]*local{}
	var order []string
	for _, p := range files {
		n := filepath.Base(p)
		if _, dup := byName[n]; dup {
			return nil, nil, fmt.Errorf("two files of the release are named %s: an asset has one name", n)
		}
		st, err := os.Stat(p) //nolint:gosec // a path of the list this tool's recipe wrote
		if err != nil {
			return nil, nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("%s is not a regular file", p)
		}
		byName[n] = &local{path: p, size: st.Size()}
		order = append(order, n)
	}
	var plan []AssetAction
	var notes []string
	kept := map[string]bool{}
	for _, r := range remote {
		l, isFile := byName[r.Name]
		switch {
		case !isFile:
			plan = append(plan, AssetAction{Kind: "delete", ID: r.ID, Name: r.Name, Why: "it is no file of this release"})
		case kept[r.Name]:
			plan = append(plan, AssetAction{Kind: "delete", ID: r.ID, Name: r.Name, Why: "the draft holds it twice"})
		case r.State != "uploaded":
			plan = append(plan, AssetAction{Kind: "delete", ID: r.ID, Name: r.Name, Why: "its upload did not finish (" + r.State + ")"})
		case r.Size != l.size:
			plan = append(plan, AssetAction{Kind: "delete", ID: r.ID, Name: r.Name, Why: fmt.Sprintf("it has %d bytes, the file has %d", r.Size, l.size)})
		case r.Digest == "":
			notes = append(notes, r.Name+": the API gives no digest, so it is compared by size alone")
			kept[r.Name] = true
		default:
			if l.digest == "" {
				d, err := evidence.FileDigest(l.path)
				if err != nil {
					return nil, nil, err
				}
				l.digest = "sha256:" + d
			}
			if r.Digest != l.digest {
				plan = append(plan, AssetAction{Kind: "delete", ID: r.ID, Name: r.Name, Why: "its digest is " + r.Digest + ", the file's is " + l.digest})
			} else {
				kept[r.Name] = true
			}
		}
	}
	for _, n := range order {
		if !kept[n] {
			plan = append(plan, AssetAction{Kind: "upload", Path: byName[n].path, Name: n, Why: "the draft does not hold it"})
		}
	}
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].Kind == "delete" && plan[j].Kind != "delete" })
	return plan, notes, nil
}

// readLines reads a file of one path on each line.
func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the list this tool's recipe wrote
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}
