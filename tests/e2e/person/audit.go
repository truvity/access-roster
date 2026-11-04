package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// The audit part of the smoke follows the M1 smoke (tests/e2e/spine): the writer's log is copied out of its volume, the
// records are opened under the evidence key by a client that has the indexer's uid (policy gives the indexer a grant to
// open evidence by a built-in permit), and `sluis audit verify` checks the checkpoint and the tree.

// batchWait is the writer's batch interval (5 s) with margin.
const batchWait = 25 * time.Second

// image is any image of the project: the step's executable is mounted into it.
func (c *config) image() string { return "sluis-local/signer:" + c.tag }

func uidOf(name string) (string, error) {
	u, ok := registry.UID(name, 0)
	if !ok {
		return "", fmt.Errorf("%s has no uid in the registry", name)
	}
	return strconv.FormatUint(uint64(u), 10), nil
}

// copyLog copies the log of the writer's blob into dst, as the uid that owns the blob, by way of a tar stream. Only
// directories and regular files are taken.
func (c *config) copyLog(dst string) error {
	compose, err := os.ReadFile(filepath.Join(c.root, "deploy", "local", "compose.yaml"))
	if err != nil {
		return err
	}
	alpine := regexp.MustCompile(`alpine@sha256:[0-9a-f]{64}`).FindString(string(compose))
	if alpine == "" {
		return errors.New("deploy/local/compose.yaml names no alpine image")
	}
	u, err := uidOf("driver-writer-fs")
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--user", u+":"+u, //nolint:gosec // the image is pinned in the Compose file of this repository
		"-v", c.project+"_state-blob:/blob:ro", alpine, "tar", "-C", "/blob/audit/main", "-cf", "-", ".")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("copy the log: %s", strings.TrimSpace(stderr.String()))
	}
	tr := tar.NewReader(&stdout)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("copy the log: %w", err)
		}
		name := filepath.Clean(h.Name)
		if !filepath.IsLocal(name) {
			return errors.New("copy the log: a path leaves the log")
		}
		p := filepath.Join(dst, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil { //nolint:gosec // a temporary copy the indexer's uid must enter
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // as above
				return err
			}
			f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // readable by the indexer's uid
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, 1<<25)); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}

var verifierRE = regexp.MustCompile(`"verifier_key":"([^"]+)"`)

// verifierKey is the public key of the log, which the writer logs when it starts.
func (c *config) verifierKey() (string, error) {
	out, err := exec.Command("docker", "ps", "-q", "--filter", "label=com.docker.compose.project="+c.project, //nolint:gosec // G204: the project name is the recipe's own
		"--filter", "label=com.docker.compose.service=writer").Output()
	id := strings.TrimSpace(string(out))
	if err != nil || id == "" {
		return "", errors.New("the writer container is not running")
	}
	logs, err := exec.Command("docker", "logs", id).CombinedOutput() //nolint:gosec // id is a container id that docker printed
	if err != nil {
		return "", errors.New("the writer's log cannot be read")
	}
	all := verifierRE.FindAllSubmatch(logs, -1)
	if len(all) == 0 {
		return "", errors.New("the writer's log does not carry the log's verifier key")
	}
	return string(all[len(all)-1][1]), nil
}

// verify runs the CLI's `audit verify` on a copy of the log.
func (c *config) verify(key, dir string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(c.cli, "audit", "verify", "--key", key, dir) //nolint:gosec // the CLI of this build
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(stderr.String()+stdout.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// events runs the step `audit-events` in a container that has the indexer's uid and the sockets it may reach, on a copy
// of the log, and returns what it found among the entries from `from` on.
func (c *config) events(logDir string, from int64) (*eventsOut, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	u, err := uidOf("indexer")
	if err != nil {
		return nil, err
	}
	pg, err := uidOf("policy")
	if err != nil {
		return nil, err
	}
	a := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", u + ":" + u, "--group-add", pg,
		"-v", c.project + "_run-policy:/run/sluis/policy:ro", "-v", c.project + "_key-indexer:/run/sluis/key/" + boundary + ":ro",
		"-v", logDir + ":/log:ro", "-v", self + ":/person:ro", "--entrypoint", "/person", c.image(),
		"step", "audit-events", "--blob", "/log", "--from", strconv.FormatInt(from, 10)}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", a...) //nolint:gosec // G204: the arguments are built here from the registry and constants
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.New(strings.TrimSpace(stderr.String()))
	}
	var out eventsOut
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, errors.New("the step's answer is not JSON")
	}
	return &out, nil
}

// eventsOut is what the step reports: the size of the log, and the records from the first new entry on.
type eventsOut struct {
	Size    int64      `json:"size"`
	Records []eventOut `json:"records"`
}

type eventOut struct {
	Event  string `json:"event"`
	Actor  string `json:"actor"`
	Status string `json:"status,omitempty"`
	// Reason is the closed reason of a failed step (status_code): a rule's name, never a value.
	Reason string `json:"reason,omitempty"`
}

// logSize is the size in the checkpoint of a copy of the log, 0 for a log with no checkpoint yet.
func logSize(dir string) (int64, error) {
	head, err := os.ReadFile(filepath.Join(dir, "checkpoint")) //nolint:gosec // the copy of this run
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(head), "\n")
	var n int64
	if len(lines) < 3 {
		return 0, errors.New("the checkpoint is not a checkpoint")
	}
	if _, err := fmt.Sscanf(lines[1], "%d", &n); err != nil {
		return 0, errors.New("the checkpoint has no size")
	}
	return n, nil
}

// ---- the step, in the container --------------------------------------------------------------------------------------

func runStep(args []string) error {
	if len(args) == 0 || args[0] != "audit-events" {
		return errors.New("step: audit-events is the one step")
	}
	fs := flag.NewFlagSet("audit-events", flag.ContinueOnError)
	blob := fs.String("blob", "", "the directory of the log")
	from := fs.Int64("from", 0, "the first entry to open")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := auditEvents(ctx, *blob, *from)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func describe(what string, err error) error {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return fmt.Errorf("%s: %w", what, err)
	}
	reason, _ := refusal.Reason(err)
	path, _ := refusal.FieldPath(err)
	return fmt.Errorf("%s: %s, reason %q, field %q", what, cerr.Code(), reason, path)
}

// auditEvents opens the records of the log from entry `from` on, as the indexer does, and reports each one's event code
// and actor, never its content.
func auditEvents(ctx context.Context, blob string, from int64) (*eventsOut, error) {
	hc, url := rpc.Dial("/run/sluis/policy/" + boundary + ".sock")
	pol := policyv2alpha1connect.NewPolicyServiceClient(hc, url, rpc.ClientOptions()...)
	res, err := pol.Decide(ctx, connect.NewRequest(&policyv2alpha1.DecideRequest{
		Action: "audit.index", Principal: &policyv2alpha1.EntityRef{Type: "Actor", Id: "indexer"},
		Resource: &policyv2alpha1.EntityRef{Type: "Boundary", Id: boundary}, Tenant: "*",
		Actor: &policyv2alpha1.ActorFacts{Name: "indexer"}, GrantKeyOps: []string{"open"},
	}))
	if err != nil {
		return nil, describe("policy Decide audit.index", err)
	}
	if res.Msg.GetDecision() != policyv2alpha1.Decision_ALLOW || len(res.Msg.GetSealedGrant()) == 0 {
		return nil, errors.New("policy gave the indexer no grant to open audit records")
	}
	grant := res.Msg.GetSealedGrant()
	kh, kurl := rpc.Dial("/run/sluis/key/" + boundary + "/key.sock")
	kc := keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...)

	head, err := os.ReadFile(filepath.Join(blob, "checkpoint")) //nolint:gosec // the copy of the run
	if err != nil {
		return nil, fmt.Errorf("the log has no checkpoint yet: %w", err)
	}
	out := &eventsOut{}
	if _, err := fmt.Sscanf(strings.Split(string(head), "\n")[1], "%d", &out.Size); err != nil {
		return nil, errors.New("the checkpoint has no size")
	}
	entries, err := readEntries(blob, out.Size)
	if err != nil {
		return nil, err
	}
	for i, raw := range entries {
		if int64(i) < from {
			continue
		}
		var e struct {
			Entry    string `json:"entry"`
			Sealed   string `json:"sealed"`
			Metadata struct {
				UID    string `json:"uid"`
				Tenant string `json:"tenant_uid"`
			} `json:"metadata"`
		}
		if json.Unmarshal(raw, &e) != nil || e.Entry != "record" {
			continue
		}
		env, err := base64.StdEncoding.DecodeString(e.Sealed)
		if err != nil {
			return nil, errors.New("an entry's sealed record is not base64")
		}
		// The address is the one the writer sealed at: <project>/audit/main/<record id>.
		r, err := kc.Open(ctx, connect.NewRequest(&keyv2alpha1.OpenRequest{
			Items: []*keyv2alpha1.OpenItem{{
				Purpose: "evidence", Envelope: env,
				Address: &typev2alpha1.Address{Kind: "audit-entry", Tenant: e.Metadata.Tenant, Id: "sluis/audit/main/" + e.Metadata.UID},
			}},
			Grant: grant,
		}))
		if err != nil {
			return nil, describe("key Open", err)
		}
		var rec struct {
			Metadata struct {
				EventCode string `json:"event_code"`
			} `json:"metadata"`
			Actor struct {
				User struct {
					UID string `json:"uid"`
				} `json:"user"`
			} `json:"actor"`
			Status     string `json:"status"`
			StatusCode string `json:"status_code"`
		}
		if json.Unmarshal(r.Msg.GetPlaintexts()[0], &rec) != nil {
			return nil, errors.New("an opened record is not JSON")
		}
		out.Records = append(out.Records, eventOut{Event: rec.Metadata.EventCode, Actor: rec.Actor.User.UID, Status: rec.Status, Reason: rec.StatusCode})
	}
	return out, nil
}

// ---- the entries of a tiled log ---------------------------------------------------------------------------------------

// The entries of a tiled log (C2SP tlog-tiles, "Log entries"): entry bundles of up to 256 entries, each entry a
// big-endian uint16 length and its bytes. `sluis audit verify` authenticates every tile; this reader only lists the
// entries so that the records can be opened.
const bundleWidth = 256

// bundlePath is the path of entry bundle n: tile/entries/<N>, with N as groups of three digits led by x, and a partial
// bundle as <N>.p/<W>.
func bundlePath(n int64, width int) string {
	nStr := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		nStr = fmt.Sprintf("x%03d/%s", n%1000, nStr)
	}
	p := "tile/entries/" + nStr
	if width < bundleWidth {
		p += ".p/" + strconv.Itoa(width)
	}
	return filepath.FromSlash(p)
}

func readEntries(dir string, size int64) ([][]byte, error) {
	var all [][]byte
	for b := int64(0); int64(len(all)) < size; b++ {
		width := bundleWidth
		if want := size - int64(len(all)); want < bundleWidth {
			width = int(want)
		}
		data, err := os.ReadFile(filepath.Join(dir, bundlePath(b, width))) //nolint:gosec // the copy of the run
		if errors.Is(err, os.ErrNotExist) && width < bundleWidth {
			// A partial bundle may have been completed since the checkpoint was written (tlog-tiles).
			data, err = os.ReadFile(filepath.Join(dir, bundlePath(b, bundleWidth))) //nolint:gosec // as above
		}
		if err != nil {
			return nil, fmt.Errorf("entry bundle %d: %w", b, err)
		}
		for n := 0; n < width; n++ {
			if len(data) < 2 {
				return nil, fmt.Errorf("entry bundle %d: short bundle", b)
			}
			l := int(binary.BigEndian.Uint16(data))
			if len(data) < 2+l {
				return nil, fmt.Errorf("entry bundle %d: short entry", b)
			}
			all = append(all, data[2:2+l])
			data = data[2+l:]
		}
	}
	return all, nil
}
