// Command deny runs the deny matrix of the local installation (WP-29; ADR 0002, "Enforcement is tested").
//
// For every identity that runs in the installation (a uid with the groups of one unit) and every socket it serves, it asks: does the registry allow this
// call, and what happens when the caller tries? A probe container runs as the caller's uid with the groups of the
// caller's own unit and with every socket directory mounted, so that the modes and groups of the directories and sockets
// are what is tested, not the choice of what the caller was given to mount. An allowed pair must get past the guard of
// the callee. A denied pair must be refused at the socket (EACCES) or by the guard (permission_denied, reason
// call_graph; for entry, a dropped connection). Anything else is a violation, and the exit status is 1.
//
//	go run ./tests/deny -project sluis-deny -probe-bin dist/deny/probe
//
// The project must be running (tests/deny/run.sh starts its own and removes it). The command only reads the project:
// it never stops or removes a container or a volume, and it removes only its own probe containers.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/tests/deny/internal/spec"
)

func main() {
	project := flag.String("project", "", "the Compose project that runs the installation")
	boundary := flag.String("boundary", "dev", "the boundary")
	image := flag.String("probe-image", "", "the image of the probe (a built tests/deny/probe on the distroless base)")
	report := flag.String("report", "", "also write the report to this file")
	compose := flag.String("compose", "deploy/local/compose.yaml", "the Compose project file the installation runs, for the callers it must probe")
	golden := flag.String("golden", "tests/deny/testdata/allowed-pairs.txt", "the golden file of the allowed pairs")
	flag.Parse()
	if *project == "" || *image == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "deny: -project and -probe-image are required")
		os.Exit(2)
	}
	ok, err := run(context.Background(), sweep{project: *project, boundary: *boundary, image: *image, report: *report, compose: *compose, golden: *golden})
	if err != nil {
		fmt.Fprintln(os.Stderr, "deny:", err)
		os.Exit(1)
	}
	if !ok {
		os.Exit(1)
	}
}

// unit is a running container of the project.
type unit struct {
	ID, Service string
	User        string
	Groups      []string
	Mounts      []mount
}

type mount struct{ Volume, Dest string }

func docker(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204/G702: a test harness; the arguments are built from inspect output and the harness's own flags and environment
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func discover(ctx context.Context, project string) ([]unit, error) {
	ids, err := docker(ctx, "ps", "--filter", "label=com.docker.compose.project="+project, "--filter", "status=running", "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(ids))
	if len(fields) == 0 {
		return nil, fmt.Errorf("project %q has no running container", project)
	}
	raw, err := docker(ctx, append([]string{"inspect"}, fields...)...)
	if err != nil {
		return nil, err
	}
	var ins []struct {
		ID     string
		Config struct {
			User   string
			Labels map[string]string
		}
		HostConfig struct{ GroupAdd []string }
		Mounts     []struct{ Type, Name, Destination string }
	}
	if err := json.Unmarshal(raw, &ins); err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	var us []unit
	for _, in := range ins {
		u := unit{ID: in.ID, Service: in.Config.Labels["com.docker.compose.service"], User: in.Config.User, Groups: in.HostConfig.GroupAdd}
		for _, m := range in.Mounts {
			if m.Type == "volume" && strings.HasPrefix(m.Destination, "/run/sluis/") {
				u.Mounts = append(u.Mounts, mount{m.Name, m.Destination})
			}
		}
		us = append(us, u)
	}
	sort.Slice(us, func(i, j int) bool { return us[i].Service < us[j].Service })
	return us, nil
}

// rows are the identities that run, each with the unit that stands for it: every distinct (uid, groups) of the running
// containers (spec.Rows), so that a second unit of a uid with other groups (entry's audit front) is probed with its own.
func rows(us []unit) ([]spec.Row, map[string]unit, error) {
	var sus []spec.Unit
	byService := map[string]unit{}
	for _, u := range us {
		uid, err := spec.ParseUser(u.User)
		if err != nil {
			return nil, nil, fmt.Errorf("the container of %s: %w", u.Service, err)
		}
		// A running process whose uid the registry does not name would drop out of the sweep unseen: Rows refuses it.
		sus = append(sus, spec.Unit{Service: u.Service, UID: uid, Groups: u.Groups})
		byService[u.Service] = u
	}
	rs, err := spec.Rows(sus)
	if err != nil {
		return nil, nil, err
	}
	by := map[string]unit{}
	for _, r := range rs {
		by[r.Label] = byService[r.Service]
	}
	return rs, by, nil
}

// mounts are every socket directory of the project, once by path, for the probe to mount read-only.
func mounts(us []unit) ([]mount, error) {
	seen := map[string]string{}
	var out []mount
	for _, u := range us {
		for _, m := range u.Mounts {
			if v, ok := seen[m.Dest]; ok {
				if v != m.Volume {
					return nil, fmt.Errorf("%s is two volumes, %s and %s", m.Dest, v, m.Volume)
				}
				continue
			}
			seen[m.Dest] = m.Volume
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dest < out[j].Dest })
	return out, nil
}

func runProbe(ctx context.Context, image string, project string, u unit, ms []mount, ts []spec.Target) ([]spec.Result, error) {
	in, err := json.Marshal(ts)
	if err != nil {
		return nil, err
	}
	args := []string{"run", "--rm", "--label", "sluis.deny.probe=" + project, "--user", u.User, "--network", "none",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp"}
	for _, g := range u.Groups {
		args = append(args, "--group-add", g)
	}
	for _, m := range ms {
		args = append(args, "-v", m.Volume+":"+m.Dest+":ro")
	}
	args = append(args, image, string(in))
	raw, err := docker(ctx, args...)
	if err != nil {
		return nil, err
	}
	var rs []spec.Result
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, fmt.Errorf("probe output: %w", err)
	}
	return rs, nil
}

// sweep is one run of the matrix: the project, the probe, and the two files the run is checked against.
type sweep struct {
	project, boundary, image, report string
	compose                          string // the Compose project file: the callers that must be probed
	golden                           string // the golden file of the allowed pairs
}

func run(ctx context.Context, sw sweep) (bool, error) {
	project, boundary, image, reportPath := sw.project, sw.boundary, sw.image, sw.report
	cb, err := os.ReadFile(sw.compose)
	if err != nil {
		return false, err
	}
	expectedRows, err := spec.ExpectedRows(cb)
	if err != nil {
		return false, err
	}
	gb, err := os.ReadFile(sw.golden)
	if err != nil {
		return false, err
	}
	golden := spec.ParseGolden(gb)
	us, err := discover(ctx, project)
	if err != nil {
		return false, err
	}
	ms, err := mounts(us)
	if err != nil {
		return false, err
	}
	rs, by, err := rows(us)
	if err != nil {
		return false, err
	}
	names, expected := spec.Labels(rs), spec.Labels(expectedRows)
	// An empty or a partial sweep is no evidence: every identity the project file runs must be probed.
	if !slices.Equal(names, expected) {
		return false, fmt.Errorf("the running rows %v are not the %d the project file runs, %v", names, len(expected), expected)
	}
	ts := spec.Targets(boundary)
	serving := map[string]unit{}
	for _, u := range us {
		serving[u.Service] = u
	}
	for _, t := range ts {
		if _, ok := serving[t.Service]; !ok {
			return false, fmt.Errorf("the target %s needs the service %s, which does not run in project %s", t.ID, t.Service, project)
		}
	}
	since := time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339Nano)
	var vs []spec.Verdict
	for _, row := range rs {
		c := row.Label
		res, err := runProbe(ctx, image, project, by[c], ms, ts)
		if err != nil {
			return false, fmt.Errorf("probe as %s: %w", c, err)
		}
		if len(res) != len(ts) {
			return false, fmt.Errorf("probe as %s answered %d of %d targets", c, len(res), len(ts))
		}
		for i, t := range ts {
			if res[i].ID != t.ID {
				return false, fmt.Errorf("probe as %s answered %q where %q was asked", c, res[i].ID, t.ID)
			}
			vs = append(vs, spec.Judge(row, t, res[i]))
		}
	}
	if want := len(expected) * len(ts); len(vs) != want || want == 0 {
		return false, fmt.Errorf("the sweep judged %d pairs, not %d (%d rows x %d sockets)", len(vs), want, len(expected), len(ts))
	}
	// The oracle that is not the guard's own function: the pairs that reached their callee are the golden ones, and the
	// registry's allowed set is the golden one too.
	var reached []string
	for _, v := range vs {
		if v.Result.Outcome == spec.Reached {
			reached = append(reached, spec.Pair(v.Caller, v.Target.ID))
		}
	}
	sort.Strings(reached)
	if !slices.Equal(reached, golden) {
		return false, fmt.Errorf("the pairs that reached their callee differ from %s: reached %d, golden %d", sw.golden, len(reached), len(golden))
	}
	if allowed := spec.AllowedPairs(rs, ts); !slices.Equal(allowed, golden) {
		return false, fmt.Errorf("the registry allows %d pairs and %s lists %d: update the golden file on purpose", len(allowed), sw.golden, len(golden))
	}
	logs, err := checkLogs(ctx, vs, serving, since)
	if err != nil {
		return false, err
	}
	out := render(project, names, ts, vs, logs)
	if _, err := io.WriteString(os.Stdout, out); err != nil {
		return false, err
	}
	if reportPath != "" {
		if err := os.WriteFile(reportPath, []byte(out), 0o600); err != nil {
			return false, err
		}
	}
	for _, v := range vs {
		if v.Violated {
			return false, nil
		}
	}
	return len(logs.Missing) == 0, nil
}

// logCheck is the second half of "the refusal is logged where the kit logs it": a pair refused by the guard leaves a line
// in the callee's log that names the caller. The kit logs a refusal (Go: "call refused"; Rust: "refused: call graph"); it
// does not yet emit an audit record for it, which is a gap of the kit and not of this matrix.
type logCheck struct {
	Checked int
	Missing []string
	Skipped []string // refused by a listener that audits the refusal and logs nothing (entry)
}

func checkLogs(ctx context.Context, vs []spec.Verdict, serving map[string]unit, since string) (logCheck, error) {
	var lc logCheck
	text := map[string]string{}
	for _, v := range vs {
		if v.Result.Outcome != spec.Guard || v.Violated {
			continue
		}
		svc := v.Target.Service
		if v.Target.Kind == spec.HTTP {
			// entry drops the peer and emits an audit record (reason "peer"); it writes no log line. The record is not read here.
			lc.Skipped = append(lc.Skipped, v.Caller+" -> "+v.Target.ID)
			continue
		}
		if _, ok := text[svc]; !ok {
			// The log of a container is its stdout and its stderr: docker prints the second on its own stderr.
			b, err := exec.CommandContext(ctx, "docker", "logs", "--since", since, serving[svc].ID).CombinedOutput() // #nosec G204 -- an id from inspect
			if err != nil {
				return lc, fmt.Errorf("docker logs %s: %w", svc, err)
			}
			text[svc] = string(b)
		}
		lc.Checked++
		// The guard logs the registry name of the peer's uid: a borrower's refusal is logged as its caller's, and the
		// line cannot tell the two apart.
		re := regexp.MustCompile(`(?i)refus\w*.*\b` + regexp.QuoteMeta(v.Name) + `\b|\b` + regexp.QuoteMeta(v.Name) + `\b.*refus\w*`)
		if !re.MatchString(text[svc]) {
			lc.Missing = append(lc.Missing, v.Caller+" -> "+v.Target.ID)
		}
	}
	return lc, nil
}

var cell = map[spec.Outcome]string{spec.Reached: "A", spec.Socket: "s", spec.Guard: "g", spec.Broken: "?"}

func render(project string, names []string, ts []spec.Target, vs []spec.Verdict, lc logCheck) string {
	var b strings.Builder
	idx := map[string]spec.Verdict{}
	for _, v := range vs {
		idx[v.Caller+"|"+v.Target.ID] = v
	}
	fmt.Fprintf(&b, "Deny matrix of project %s: %d rows x %d sockets = %d pairs\n\n", project, len(names), len(ts), len(vs))
	b.WriteString("Cell: A allowed and past the guard | s denied at the socket (EACCES) | g denied by the guard | ! violation | ? could not tell\n")
	b.WriteString("Rows are the identities (a caller's registry name, or the service of a unit that borrows a caller's uid); columns are the sockets, numbered below.\n\n")
	w := 0
	for _, n := range names {
		w = max(w, len(n))
	}
	fmt.Fprintf(&b, "%-*s ", w, "")
	for i := range ts {
		fmt.Fprintf(&b, "%2d ", i+1)
	}
	b.WriteString("\n")
	for _, c := range names {
		fmt.Fprintf(&b, "%-*s ", w, c)
		for _, t := range ts {
			v := idx[c+"|"+t.ID]
			s := cell[v.Result.Outcome]
			if v.Violated {
				s = "!"
			}
			fmt.Fprintf(&b, "%2s ", s)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nSockets:\n")
	for i, t := range ts {
		fmt.Fprintf(&b, "%3d  %-16s %s", i+1, t.ID, t.Socket)
		if t.Note != "" {
			fmt.Fprintf(&b, "  (%s)", t.Note)
		}
		b.WriteString("\n")
	}
	var allowed, sock, guard, viol int
	for _, v := range vs {
		switch {
		case v.Violated:
			viol++
		case v.Allowed:
			allowed++
		case v.Result.Outcome == spec.Socket:
			sock++
		default:
			guard++
		}
	}
	fmt.Fprintf(&b, "\nSummary: %d pairs: %d allowed and reached, %d denied (%d at the socket, %d by the guard), %d violations\n",
		len(vs), allowed, sock+guard, sock, guard, viol)
	fmt.Fprintf(&b, "Guard refusals found in the callee's log: %d of %d\n", lc.Checked-len(lc.Missing), lc.Checked)
	b.WriteString("\nAllowed pairs (caller -> socket: answer):\n")
	for _, v := range vs {
		if v.Allowed {
			fmt.Fprintf(&b, "  %s -> %s: %s\n", v.Caller, v.Target.ID, v.Result.Detail)
		}
	}
	b.WriteString("\nDenied by the guard, not the socket (the socket opened for the caller):\n")
	for _, v := range vs {
		if !v.Allowed && v.Result.Outcome == spec.Guard {
			fmt.Fprintf(&b, "  %s -> %s: %s\n", v.Caller, v.Target.ID, v.Result.Detail)
		}
	}
	if viol > 0 {
		b.WriteString("\nVIOLATIONS:\n")
		for _, v := range vs {
			if v.Violated {
				fmt.Fprintf(&b, "  %s -> %s [%s]: %s\n", v.Caller, v.Target.ID, v.Result.Outcome, v.Why)
			}
		}
	}
	if len(lc.Skipped) > 0 {
		b.WriteString("\nGuard refusals not checked in a log (entry audits a refused peer and logs nothing; the record is not read):\n")
		for _, m := range lc.Skipped {
			fmt.Fprintf(&b, "  %s\n", m)
		}
	}
	if len(lc.Missing) > 0 {
		b.WriteString("\nGuard refusals with no line in the callee's log:\n")
		for _, m := range lc.Missing {
			fmt.Fprintf(&b, "  %s\n", m)
		}
	}
	return b.String()
}
