package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// `sluis key status` (cli.md, "The key commands"; ADR 0024, "Lifetimes and the warning") lists each key key@ holds for the
// KeyPlan, with its store, slot, fingerprint and the expiry of its certificate chain, and warns before an expiry: a notice
// 60 days before (exit 10), an alert 30 days before (11) and a critical alert 14 days before (12). It asks key@ on this node
// over the admin socket, which only root reaches, and it only reads: key@'s status call writes nothing and makes no audit
// fact, and the command prints no secret (a key is never in the answer, only its public half and the public chain).

// The lead times of the warning (ADR 0024, "Lifetimes and the warning"; REQ-PKI-031).
const (
	noticeLead   = 60 * 24 * time.Hour
	alertLead    = 30 * 24 * time.Hour
	criticalLead = 14 * 24 * time.Hour
)

// The levels of the warning, as the `level` member of the JSON object names them.
const (
	levelNone     = "none"
	levelNotice   = "notice"
	levelAlert    = "alert"
	levelCritical = "critical"
)

// expiryLevel is the warning level of a certificate that ends in remaining, and the exit code of that level. A chain that
// has ended is critical: it is not a warning any more, and the exit code is the highest one.
func expiryLevel(remaining time.Duration) (level string, exit int) {
	switch {
	case remaining <= criticalLead:
		return levelCritical, exitCritical
	case remaining <= alertLead:
		return levelAlert, exitAlert
	case remaining <= noticeLead:
		return levelNotice, exitNotice
	}
	return levelNone, 0
}

// daysLeft is the whole days in d, rounded down, so that a chain that ended an hour ago is -1.
func daysLeft(d time.Duration) int {
	day := 24 * time.Hour
	n := int(d / day)
	if d%day < 0 {
		n--
	}
	return n
}

// chainValidity is the earliest end of validity and the latest start of validity among the certificates of a chain, DER: the
// chain is valid from the moment its last certificate begins to the moment its first one ends.
func chainValidity(chain [][]byte) (notAfter, notBefore time.Time, err error) {
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("certificate %d of the chain does not parse", i)
		}
		if notAfter.IsZero() || c.NotAfter.Before(notAfter) {
			notAfter = c.NotAfter
		}
		if notBefore.IsZero() || c.NotBefore.After(notBefore) {
			notBefore = c.NotBefore
		}
	}
	return notAfter.UTC(), notBefore.UTC(), nil
}

// statusClockFloorYear is the year before which sluis did not exist: a clock that shows an earlier one has lost its time,
// as the backup clock of a board does in a power cut (cli.md, `sluis doctor`).
const statusClockFloorYear = 2026

// errClockUnset is the error of a host whose clock cannot be trusted to judge an expiry: it shows a date before sluis
// existed, or before a certificate of an installed chain began. Judged on that date, a chain that ended long ago would
// have thousands of days left.
var errClockUnset = errors.New("the clock of this host is not set")

// keyStatus is what `key status` and `doctor` read of key@.
type keyStatus struct {
	store, environment string
	keys               []keyOut
	// exit is the highest level among the keys: 0, 10, 11 or 12.
	exit int
	// invalid lists the purposes with a certificate that cannot be used, with the way it fails.
	invalid []string
	// noCert lists the purposes that need a certificate and have none installed.
	noCert []string
}

// The values of the `certificate` member.
const (
	certNone      = "none"
	certInstalled = "installed"
	// certInvalid: key@ holds a certificate meant for the key that cannot be used (it does not parse, or its leaf holds
	// another key). It is not "none": the intermediate has one, and it is wrong.
	certInvalid = "invalid"
)

// needsCertificate is true for a purpose whose key is certified by root custody: the intermediate (cli.md, "The key
// commands"; the first version hands off x509-intermediate only).
func needsCertificate(purpose string) bool { return purpose == handoffPurpose }

// keyStatusSocket is key@'s admin socket on this node.
func (a *app) keyStatusSocket(socket string) (string, error) {
	if socket != "" {
		return socket, nil
	}
	if a.boundary == "" || !validBoundary(a.boundary) {
		return "", cli.Usage(errors.New("name the boundary with --boundary"))
	}
	return filepath.Join(keyAdminSocketPrefix, a.boundary, "admin.sock"), nil
}

// askKeyStatus asks key@ for its keys and reads each key's chain. A key@ that cannot be asked is an error, never an empty
// list: a caller that cannot ask does not know.
func (a *app) askKeyStatus(ctx context.Context, socket string) (*keyStatus, error) {
	hc, url := rpc.Dial(socket)
	c := keyv2alpha1connect.NewKeyStatusServiceClient(hc, url, rpc.ClientOptions()...)
	res, err := c.Status(ctx, connect.NewRequest(&keyv2alpha1.StatusRequest{}))
	if err != nil {
		return nil, keyStatusError(err, socket)
	}
	if len(res.Msg.GetKeys()) == 0 {
		// key@ always holds a wrapping key, so an empty list is an answer that cannot be right, not a host with nothing to say.
		return nil, errors.New("key@ reported no keys, and it always holds at least its wrapping key")
	}
	now := a.now()
	st := &keyStatus{store: res.Msg.GetStore(), environment: res.Msg.GetEnvironment()}
	chains := map[string]struct{ after, before time.Time }{}
	clockSet := true
	for _, k := range res.Msg.GetKeys() {
		out := keyOut{Purpose: k.GetPurpose(), Boundary: a.boundary, Store: st.store, Slot: k.GetSlot(), Fingerprint: fingerprint(k.GetSpkiDer()), Level: levelNone, Certificate: certNone}
		if len(k.GetChain()) > 0 {
			after, before, err := chainValidity(k.GetChain())
			if err != nil {
				return nil, fmt.Errorf("the chain of %s: %w", k.GetPurpose(), err)
			}
			out.Certificate, out.NotAfter = certInstalled, after.Format(time.RFC3339)
			chains[k.GetPurpose()] = struct{ after, before time.Time }{after, before}
			// A chain needs a clock that is set: one that shows a date before sluis existed, or before a certificate of the
			// chain began, is not one to judge an expiry by.
			if now.UTC().Year() < statusClockFloorYear || now.Before(before) {
				clockSet = false
			}
		} else if k.GetChainProblem() != "" {
			out.Certificate = certInvalid
			st.invalid = append(st.invalid, k.GetPurpose()+" ("+k.GetChainProblem()+")")
		} else if needsCertificate(k.GetPurpose()) {
			st.noCert = append(st.noCert, k.GetPurpose())
		}
		st.keys = append(st.keys, out)
	}
	if !clockSet {
		// The expiry is not judged: no days left and no level, which would be read as "fine" (or as thousands of days).
		for i := range st.keys {
			st.keys[i].Level = ""
		}
		return st, fmt.Errorf("%w: it shows %s, which is before sluis existed or before a certificate of an installed chain began, "+
			"so no expiry can be judged; a board sets its clock about 35 seconds after boot: run it again in a minute, and if it stays so, "+
			"the host has no working time source", errClockUnset, now.UTC().Format("2006-01-02"))
	}
	for i := range st.keys {
		c, ok := chains[st.keys[i].Purpose]
		if !ok {
			continue
		}
		remaining := c.after.Sub(now)
		level, code := expiryLevel(remaining)
		n := daysLeft(remaining)
		st.keys[i].DaysLeft, st.keys[i].Level, st.keys[i].code = &n, level, code
		st.exit = max(st.exit, code)
	}
	if len(st.invalid) > 0 {
		// Not "no certificate": a certificate is installed for the key and it cannot be used. The keys are listed.
		return st, fmt.Errorf("key@ holds a certificate that cannot be used for %s: it does not parse, or its leaf holds another key", strings.Join(st.invalid, ", "))
	}
	return st, nil
}

// errNoKeySocket is the error of a key@ that has no admin socket on this host: it is not running here, or this is not the
// node. `doctor` reads it as "key@ is not here" and not as a failure; `key status` fails on it, as on any other.
var errNoKeySocket = errors.New("key@ has no admin socket on this host")

// keyStatusError turns the error of the status call into a failure that says what to do. Neither is a refusal by a check:
// `key status` has no exit code 3 or 4 (cli.md, "Exit codes").
func keyStatusError(err error, socket string) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w (%s): is key@ running on this node?", errNoKeySocket, socket)
	}
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied:
		return errors.New("key@ did not take the call: its admin socket serves root only, so run it as root")
	case connect.CodeUnavailable:
		return errors.New("key@ could not be asked: its admin socket cannot be reached, or key@ cannot reach its store or driver (is key@ running, and are you root?)")
	}
	return fmt.Errorf("key@ answered %s", connect.CodeOf(err))
}

// keyStatusCommand is `sluis key status`.
func (a *app) keyStatusCommand() command {
	var socket string
	return command{
		name: "key status",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&socket, "socket", "", "key@'s admin socket; by default "+keyAdminSocketPrefix+"/<boundary>/admin.sock")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 0 {
				return cli.Usage(errors.New("key status takes no argument"))
			}
			sock, err := a.keyStatusSocket(socket)
			if err != nil {
				return err
			}
			st, err := a.askKeyStatus(ctx, sock)
			if st != nil {
				res.Keys = st.keys // with a clock that cannot judge, the keys still show, with no level
			}
			if err != nil {
				return fmt.Errorf("key status: %w", err)
			}
			res.Keys = st.keys
			res.Text = keyTable(st.keys)
			a.warnExpiry(st)
			if st.exit != 0 {
				return findingExit(st.exit)
			}
			return nil
		},
	}
}

// keyTable is the table `key status` prints: a line for each key, with the fingerprint cut to its first 16 digits (the
// JSON object has all of it).
func keyTable(keys []keyOut) string {
	rows := [][]string{{"purpose", "store", "slot", "fingerprint", "expires", "warning"}}
	for _, k := range keys {
		fp := k.Fingerprint
		if len(fp) > 16 {
			fp = fp[:16] + "..."
		}
		slot, expires, level := "-", "no certificate", k.Level
		if k.Certificate == certInvalid {
			expires = "invalid certificate"
		}
		if k.Slot != "" {
			slot = k.Slot
		}
		if k.NotAfter != "" {
			expires = k.NotAfter[:10]
		}
		if level == "" {
			level = "unknown"
		}
		rows = append(rows, []string{k.Purpose, k.Store, slot, fp, expires, level})
	}
	width := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			width[i] = max(width[i], len(c))
		}
	}
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = fmt.Sprintf("%-*s", width[i], c)
		}
		lines = append(lines, strings.TrimRight(strings.Join(cells, "  "), " "))
	}
	return strings.Join(lines, "\n")
}

// warnExpiry says on standard error what a person should act on: each key with a level, and each purpose that needs a
// certificate and has none.
func (a *app) warnExpiry(st *keyStatus) {
	for _, k := range st.keys {
		if k.Level == levelNone || k.Level == "" || k.DaysLeft == nil {
			continue
		}
		_, _ = fmt.Fprintf(a.stderr, "sluis: %s: %s\n", k.Level, expiryPhrase(k))
	}
	for _, p := range st.noCert {
		_, _ = fmt.Fprintf(a.stderr, "sluis: %s has no certificate installed; run sluis key request and sluis key install\n", p)
	}
}

// expiryPhrase says when the certificate of a key ends.
func expiryPhrase(k keyOut) string {
	d := *k.DaysLeft
	switch {
	case d < 0:
		return fmt.Sprintf("the certificate of %s ended on %s and has expired; renewal is overdue", k.Purpose, k.NotAfter[:10])
	case d == 0:
		return fmt.Sprintf("the certificate of %s ends on %s, in less than a day", k.Purpose, k.NotAfter[:10])
	}
	return fmt.Sprintf("the certificate of %s ends on %s, in %d days; a card renewal needs a person at root custody", k.Purpose, k.NotAfter[:10], d)
}
