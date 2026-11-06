// Command r2-temp-credential-spike measures how long Cloudflare R2 takes to accept a credential that was just
// created, and whether it refuses one again after it has accepted it. It is a spike harness (docs/contributing/
// decisions.md, "Spikes and research"), never part of a product binary. The question, the method and the decision
// rule are on docs/research/r2-temporary-credential-propagation.md.
//
// Every credential is handed out by Cloudflare, then probed at once: PutObject, GetObject and HeadObject of its
// own key, each repeated every 500 ms until it is accepted or 120 s pass, then HeadObject until -soak has passed
// since the first accept, then DeleteObject. The tool records the time to the first accept, every refusal after an
// accept ("accept then refuse"), the HTTP status (401 or 403) and the S3 error code of every request.
//
//	SLUIS_SPIKE_R2_ACCOUNT_ID=... SLUIS_SPIKE_R2_PARENT_TOKEN=... SLUIS_SPIKE_R2_BUCKET=... \
//	  go run ./tools/harness/r2-temp-credential-spike -n 30 -spacing 10s
//
// The account id, the parent token and the bucket come from the environment only. Nothing is printed or written
// that holds them or any credential: the files hold the arm, the credential's number, times, statuses and S3
// error codes. It calls only the Cloudflare API and the bucket's S3 endpoint of the account.
//
// With -arm token (or both) it also creates an API token that can read and write the bucket's objects, derives
// its S3 credential as R2 documents it (access key id = token id, secret = SHA-256 of the token value), probes it
// the same way and deletes the token: this is the mechanism that the v1 measurement concerned. The tokens are
// created with SLUIS_SPIKE_R2_TOKEN_CREATOR, a separate token.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// The environment variables. Their values are never printed.
const (
	envAccount     = "SLUIS_SPIKE_R2_ACCOUNT_ID"
	envParentToken = "SLUIS_SPIKE_R2_PARENT_TOKEN"  //nolint:gosec // the name of a variable, not a credential
	envParentKeyID = "SLUIS_SPIKE_R2_PARENT_KEY_ID" // optional: the parent token's id, found by the tool when unset
	envBucket      = "SLUIS_SPIKE_R2_BUCKET"
	envPrefix      = "SLUIS_SPIKE_R2_PREFIX"        // optional, default sluis-spike/
	envCreator     = "SLUIS_SPIKE_R2_TOKEN_CREATOR" // only for -arm token or both
)

const (
	defaultAPIBase = "https://api.cloudflare.com/client/v4"
	defaultPrefix  = "sluis-spike/"
	// region is the one R2 documents for the S3 API.
	region = "auto"
)

var (
	accountShape = regexp.MustCompile(`^[0-9a-f]{32}$`)
	bucketShape  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
)

type config struct {
	account     string
	parent      secret
	parentKeyID secret
	creator     secret
	bucket      string
	prefix      string

	n        int
	spacing  time.Duration
	ttl      time.Duration
	interval time.Duration
	deadline time.Duration
	soak     time.Duration
	arms     []string
	group    string
	outDir   string

	apiBase  string
	endpoint *url.URL
}

func main() {
	n := flag.Int("n", 30, "how many credentials to mint and probe, for each arm")
	spacing := flag.Duration("spacing", 10*time.Second, "time between the starts of two credentials")
	ttl := flag.Duration("ttl", 15*time.Minute, "time to live of a temporary credential and of a token; must outlast one credential's probe")
	interval := flag.Duration("interval", 500*time.Millisecond, "between the starts of two attempts of one operation")
	deadline := flag.Duration("deadline", 120*time.Second, "for one operation, from its first attempt")
	soak := flag.Duration("soak", 40*time.Second, "how long after its first accept a credential keeps being tried (v1 saw refusals up to about 34 s); 0 to skip")
	arm := flag.String("arm", "temp", "which credentials: temp (R2 temporary credentials), token (a new API token, the v1 mechanism) or both")
	group := flag.String("token-permission-group", "Workers R2 Storage Bucket Item Write", "the permission group of the tokens of the token arm")
	out := flag.String("out", "", "the directory for the CSV files and the summary; default .cache/r2-spike/<UTC time>")
	dry := flag.Bool("dry-run", false, "check the settings and print the plan; no request is sent")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "r2-temp-credential-spike: there are no arguments")
		os.Exit(2)
	}
	cfg, err := newConfig(os.Getenv, *n, *spacing, *ttl, *interval, *deadline, *soak, *arm, *group, *out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "r2-temp-credential-spike: %v\n", err)
		os.Exit(2)
	}
	if *dry {
		printPlan(os.Stdout, cfg)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, cfg, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "r2-temp-credential-spike: %v\n", err)
		os.Exit(1)
	}
}

// newConfig reads the settings. An error names a variable, never a value.
func newConfig(getenv func(string) string, n int, spacing, ttl, interval, deadline, soak time.Duration, arm, group, out string) (config, error) {
	cfg := config{
		account: getenv(envAccount), parent: secret(getenv(envParentToken)), parentKeyID: secret(getenv(envParentKeyID)),
		creator: secret(getenv(envCreator)), bucket: getenv(envBucket), prefix: getenv(envPrefix),
		n: n, spacing: spacing, ttl: ttl, interval: interval, deadline: deadline, soak: soak, group: group, outDir: out,
		apiBase: defaultAPIBase,
	}
	switch arm {
	case "temp":
		cfg.arms = []string{"temp"}
	case "token":
		cfg.arms = []string{"token"}
	case "both":
		cfg.arms = []string{"temp", "token"}
	default:
		return cfg, errors.New("-arm is temp, token or both")
	}
	var missing []string
	for _, v := range []struct{ name, value string }{{envAccount, cfg.account}, {envParentToken, string(cfg.parent)}, {envBucket, cfg.bucket}} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if slices.Contains(cfg.arms, "token") && cfg.creator == "" {
		missing = append(missing, envCreator)
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("set %s", strings.Join(missing, ", "))
	}
	if !accountShape.MatchString(cfg.account) {
		return cfg, fmt.Errorf("%s is not a 32-character hexadecimal account id", envAccount)
	}
	if !bucketShape.MatchString(cfg.bucket) {
		return cfg, fmt.Errorf("%s is not a bucket name", envBucket)
	}
	if cfg.prefix == "" {
		cfg.prefix = defaultPrefix
	}
	if !strings.HasSuffix(cfg.prefix, "/") {
		cfg.prefix += "/"
	}
	if !cleanKey(cfg.prefix) {
		return cfg, fmt.Errorf("%s may hold only letters, digits, . _ - and /, and no .. ", envPrefix)
	}
	if n < 1 || interval <= 0 || deadline < interval || spacing < 0 || soak < 0 {
		return cfg, errors.New("-n must be at least 1, -interval positive, -deadline at least -interval, -spacing and -soak not negative")
	}
	if need := 4*deadline + soak + time.Minute; ttl < need {
		return cfg, fmt.Errorf("-ttl %s is shorter than one credential's longest probe plus a minute (%s): a credential that expires mid-probe would look like a refusal", ttl, need)
	}
	u, err := url.Parse("https://" + cfg.account + ".r2.cloudflarestorage.com")
	if err != nil {
		return cfg, err
	}
	cfg.endpoint = u
	return cfg, nil
}

func printPlan(w io.Writer, cfg config) {
	set := func(v string) string {
		if v == "" {
			return "not set"
		}
		return "set"
	}
	say(w, "r2-temp-credential-spike: dry run, no request sent\n")
	say(w, "  %s  %s\n  %s  %s\n  %s  %s\n  %s  %s\n", envAccount, set(cfg.account), envParentToken, set(string(cfg.parent)),
		envBucket, set(cfg.bucket), envParentKeyID, set(string(cfg.parentKeyID))+" (optional)")
	say(w, "  arms %s, %d credentials each, one every %s, ttl %s\n", strings.Join(cfg.arms, "+"), cfg.n, cfg.spacing, cfg.ttl)
	say(w, "  each operation every %s for up to %s; head for %s after the first accept\n", cfg.interval, cfg.deadline, cfg.soak)
	say(w, "  about %s of minting and a probe of up to %s after the last one\n",
		time.Duration(cfg.n)*cfg.spacing, 4*cfg.deadline+cfg.soak)
}

// run mints and probes the credentials, cleans up and writes the files.
func run(ctx context.Context, cfg config, stdout, stderr io.Writer) error {
	started := time.Now().UTC()
	if cfg.outDir == "" {
		cfg.outDir = filepath.Join(".cache", "r2-spike", started.Format("20060102T150405Z"))
	}
	if err := os.MkdirAll(cfg.outDir, 0o700); err != nil {
		return fmt.Errorf("creating the output directory: %w", err)
	}
	idBytes := make([]byte, 4)
	if _, err := rand.Read(idBytes); err != nil {
		return err
	}
	runID := hex.EncodeToString(idBytes)

	red := newRedactor()
	red.add(cfg.account, "<account>")
	red.add(cfg.bucket, "<bucket>")
	red.add(string(cfg.parent), "<parent-token>")
	red.add(string(cfg.parentKeyID), "<parent-key-id>")
	red.add(string(cfg.creator), "<creator-token>")
	hc := &http.Client{Timeout: 20 * time.Second}
	api := &cfAPI{hc: hc, base: cfg.apiBase, account: cfg.account, red: red}
	p := &probe{
		s3:  &s3{hc: hc, endpoint: cfg.endpoint, bucket: cfg.bucket, region: region},
		rec: newRecorder(), interval: cfg.interval, deadline: cfg.deadline, soak: cfg.soak,
	}

	if cfg.parentKeyID == "" {
		id, err := api.verifyTokenID(ctx, cfg.parent)
		if err != nil {
			return err
		}
		cfg.parentKeyID = id
		red.add(string(id), "<parent-key-id>")
	}
	groupID := ""
	if slices.Contains(cfg.arms, "token") {
		var err error
		if groupID, err = api.permissionGroupID(ctx, cfg.creator, cfg.group); err != nil {
			return err
		}
	}

	var (
		mu      sync.Mutex
		results []credResult
		wg      sync.WaitGroup
		lostTok []string
	)
	book := func(r credResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
		say(stderr, "arm=%s credential=%d accepted=%t first_accept=%s attempts=%d refused_before=%d refused_after=%d deleted=%t\n",
			r.Arm, r.Index, r.Accepted, ms(r.FirstAcceptMS), r.AttemptsToFirstAccept, r.RefusalsBefore, r.RefusalsAfter, r.Deleted)
	}
	var runErr error
mint:
	for idx := 1; idx <= cfg.n; idx++ {
		next := time.Now().Add(cfg.spacing)
		for _, arm := range cfg.arms {
			if ctx.Err() != nil {
				break mint
			}
			key := fmt.Sprintf("%s%s/%s-%03d.txt", cfg.prefix, runID, arm, idx)
			t0 := time.Now()
			var (
				cred  credentials
				token apiToken
				err   error
			)
			if arm == "temp" {
				cred, err = api.mintTemp(ctx, cfg.parent, cfg.parentKeyID, cfg.bucket, cfg.prefix, cfg.ttl)
			} else {
				token, err = api.createToken(ctx, cfg.creator, fmt.Sprintf("sluis-spike-%s-%03d", runID, idx), groupID, cfg.bucket, cfg.ttl)
				cred = token.creds
			}
			if err != nil {
				if idx == 1 {
					runErr = err
					break mint
				}
				mu.Lock()
				say(stderr, "arm=%s credential=%d: %v\n", arm, idx, err)
				mu.Unlock()
				book(credResult{Arm: arm, Index: idx, MintedAt: t0, FailedOp: "mint", OpAcceptMS: map[string]int64{}})
				continue
			}
			minted := time.Now()
			mintMS := minted.Sub(t0).Milliseconds()
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := p.run(ctx, arm, idx, cred, key, minted, mintMS)
				if arm == "token" {
					dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
					defer cancel()
					if err := api.deleteToken(dctx, cfg.creator, token.ID); err != nil {
						mu.Lock()
						lostTok = append(lostTok, fmt.Sprintf("sluis-spike-%s-%03d", runID, idx))
						mu.Unlock()
					}
				}
				book(r)
			}()
		}
		if idx < cfg.n && !sleepUntil(ctx, next) {
			break
		}
	}
	wg.Wait()

	left := cleanup(context.WithoutCancel(ctx), cfg, api, p, stderr)
	if len(lostTok) > 0 {
		say(stderr, "warning: %d API tokens could not be deleted; delete the tokens named sluis-spike-%s-* in the dashboard\n", len(lostTok), runID)
	}
	if len(results) == 0 {
		if runErr != nil {
			return runErr
		}
		return errors.New("no credential was probed")
	}

	var sums []armSummary
	for _, arm := range cfg.arms {
		sums = append(sums, summarizeArm(arm, results))
	}
	meta := map[string]string{
		"started (UTC)":      started.Format(time.RFC3339),
		"finished (UTC)":     time.Now().UTC().Format(time.RFC3339),
		"run id":             runID,
		"go":                 runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH,
		"credentials/arm":    fmt.Sprint(cfg.n),
		"spacing":            cfg.spacing.String(),
		"ttl":                cfg.ttl.String(),
		"attempt interval":   cfg.interval.String(),
		"operation deadline": cfg.deadline.String(),
		"soak after accept":  cfg.soak.String(),
		"s3 region":          region,
		"api tokens left":    fmt.Sprint(len(lostTok)),
	}
	if err := writeFiles(cfg.outDir, results, p.rec.attempts, meta, sums, left); err != nil {
		return err
	}
	writeSummary(stdout, meta, sums, left)
	say(stdout, "\nfiles: %s/{credentials.csv,attempts.csv,summary.txt}\n", cfg.outDir)
	return runErr
}

// cleanup deletes the objects whose delete was not accepted (a stopped run, a failed delete), with one more
// temporary credential. It returns how many objects are still there.
func cleanup(ctx context.Context, cfg config, api *cfAPI, p *probe, stderr io.Writer) int {
	keys := p.rec.pendingKeys()
	if len(keys) == 0 {
		return 0
	}
	mctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cred, err := api.mintTemp(mctx, cfg.parent, cfg.parentKeyID, cfg.bucket, cfg.prefix, cfg.ttl)
	if err != nil {
		say(stderr, "cleanup: %v\n", err)
		return len(keys)
	}
	left := 0
	for _, key := range keys {
		limit := time.Now().Add(cfg.deadline)
		for {
			at := time.Now()
			status, _, _ := p.s3.do(ctx, cred, http.MethodDelete, key, nil)
			if classify(status) == classAccept {
				p.rec.setPending(key, false)
				break
			}
			if at.Add(cfg.interval).After(limit) || !sleepUntil(ctx, at.Add(cfg.interval)) {
				left++
				say(stderr, "cleanup: the object %s is still there\n", key)
				break
			}
		}
	}
	return left
}

func writeFiles(dir string, results []credResult, attempts []attempt, meta map[string]string, sums []armSummary, left int) error {
	create := func(name string, fn func(io.Writer) error) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // a fixed name in the output directory the operator chose
		if err != nil {
			return err
		}
		if err := fn(f); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	if err := create("credentials.csv", func(w io.Writer) error { return writeCredentialsCSV(w, results) }); err != nil {
		return err
	}
	if err := create("attempts.csv", func(w io.Writer) error { return writeAttemptsCSV(w, attempts) }); err != nil {
		return err
	}
	return create("summary.txt", func(w io.Writer) error { writeSummary(w, meta, sums, left); return nil })
}
