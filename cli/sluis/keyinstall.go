package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/handoff"
)

// installedOut is one entry of the `installed` member of the JSON object of `sluis key install`.
type installedOut struct {
	Stem    string   `json:"stem"`
	Outcome string   `json:"outcome"` // installed, already-installed, refused or no-answer
	Reasons []string `json:"reasons,omitempty"`
	// NotRun names the checks of the contract that could not run for this answer, such as the trust sequence when no
	// root list is held. A check that cannot run is never reported as passed.
	NotRun []string `json:"not_run,omitempty"`
}

// maxAnswerFile bounds a file of an answer that is read whole.
const maxAnswerFile = 1 << 20

// installCommand is `sluis key install DIR`: for each request this node made, it reads the answer in DIR, runs the
// requester's checks of the hand-off contract and only then hands the certificate to key@. Anything that fails a check
// installs nothing and exits 3 with the contract's code.
func (a *app) installCommand() command {
	var requests, bundle, rootList, socket string
	var pins repeated
	var acceptUnanchored, replace bool
	return command{
		name: "key install",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&requests, "requests", defaultRequestDir, "the directory `key request` wrote to: the requests the answers are checked against")
			fs.StringVar(&bundle, "ca-bundle", "", "the CA bundle: the certificates that anchor the answers (the file of trust.ca_bundle)")
			fs.StringVar(&rootList, "root-list", "", "the signed root list (root-list.json, with root-list.jws beside it), when sluis holds one")
			fs.Var(&pins, "root-pin", "an initial pin: the x509_spki_sha256 of a root this host was installed to trust; repeat for each")
			fs.BoolVar(&acceptUnanchored, "accept-unanchored-list", false, "read --root-list with no --root-pin: nothing then weighs who signed it, and the output says so")
			fs.BoolVar(&replace, "replace", false, "let the certificate replace an installed one that ends no later or has a higher trust sequence")
			fs.StringVar(&socket, "socket", "", "key@'s admin socket; by default "+keyAdminSocketPrefix+"/<boundary>/admin.sock")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 1 {
				return cli.Usage(errors.New("key install takes the directory of the answers"))
			}
			if a.boundary == "" || !validBoundary(a.boundary) {
				return cli.Usage(errors.New("name the boundary with --boundary"))
			}
			if bundle == "" {
				return cli.Usage(errors.New("--ca-bundle: name the CA bundle that anchors the answers"))
			}
			if rootList != "" && len(pins) == 0 && !acceptUnanchored {
				return cli.Usage(errors.New("--root-list needs --root-pin, the x509_spki_sha256 of a root this host was installed to trust: without one, nothing weighs who signed the list (--accept-unanchored-list reads it anyway)"))
			}
			if rootList == "" && (len(pins) > 0 || acceptUnanchored) {
				return cli.Usage(errors.New("--root-pin and --accept-unanchored-list are for --root-list"))
			}
			if len(pins) > 0 && acceptUnanchored {
				return cli.Usage(errors.New("--accept-unanchored-list is for a list read with no --root-pin"))
			}
			return a.install(ctx, installOptions{answers: positional[0], requests: requests, bundle: bundle, rootList: rootList, pins: pins, socket: socket, replace: replace}, res)
		},
	}
}

// readSmall reads a regular file of at most maxAnswerFile bytes. The path is opened without following a symbolic link, so
// that a name in a directory that others write to cannot lead to another file, and the file is read through a limit
// of one byte more than the cap, so that a file that grows after the check is refused too.
func readSmall(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAnswerFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxAnswerFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), maxAnswerFile)
	}
	return b, nil
}

// installOptions are the inputs of `key install`.
type installOptions struct {
	answers, requests, bundle, rootList string
	pins                                []string
	socket                              string
	replace                             bool
}

func (a *app) install(ctx context.Context, o installOptions, res *result) error {
	answers, requests := o.answers, o.requests
	bundleBytes, err := readSmall(o.bundle)
	if err != nil {
		return fmt.Errorf("key install: the CA bundle cannot be read: %w", err)
	}
	anchors, bundleSeq, err := handoff.ParseBundle(bundleBytes)
	if err != nil {
		return refused(reasonOf(err), "ca-bundle")
	}
	var held *handoff.RootList
	var listNotAnchored bool
	if o.rootList != "" {
		list, err := readSmall(o.rootList)
		if err != nil {
			return fmt.Errorf("key install: the root list cannot be read: %w", err)
		}
		jws, err := readSmall(strings.TrimSuffix(o.rootList, filepath.Ext(o.rootList)) + ".jws")
		if err != nil {
			return fmt.Errorf("key install: the signatures of the root list cannot be read: %w", err)
		}
		var checks handoff.RootListChecks
		if held, checks, err = handoff.ReadRootList(list, jws, nil, o.pins, a.now()); err != nil {
			return refused(reasonOf(err), "root-list")
		}
		listNotAnchored = !checks.Anchored
	}

	stems, err := requestStems(requests, a.boundary)
	if err != nil {
		return fmt.Errorf("key install: %w", err)
	}
	if len(stems) == 0 {
		return fmt.Errorf("key install: no request of boundary %s in %s (run key request first)", a.boundary, requests)
	}
	c := a.handoffClient(o.socket)
	var lines, refusals []string
	installedAny, answeredAny := false, false
	for _, stem := range stems {
		out := installedOut{Stem: stem}
		ans, found, rerr := readAnswer(answers, stem)
		if rerr != nil {
			return rerr
		}
		if !found {
			out.Outcome = "no-answer"
			res.Installed = append(res.Installed, out)
			lines = append(lines, stem+": no answer in "+answers)
			continue
		}
		answeredAny = true
		chain, seq, notRun, err := a.checkAnswer(stem, requests, ans, anchors, bundleSeq, held, listNotAnchored)
		out.NotRun = notRun
		if listNotAnchored {
			out.NotRun = append(out.NotRun, "root_list_signers")
		}
		var cr *handoff.CertifierRefused
		switch {
		case errors.As(err, &cr):
			out.Outcome, out.Reasons = "refused", cr.Reasons
		case err != nil:
			out.Outcome, out.Reasons = "refused", []string{reasonOf(err)}
		default:
			ir, err := c.Install(ctx, connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: handoffPurpose, Chain: chain, TrustSequence: seq, Replace: o.replace}))
			if err != nil {
				res.Installed = append(res.Installed, out)
				return keyCallError("key install", err)
			}
			out.Outcome = "installed"
			if ir.Msg.GetAlready() {
				out.Outcome = "already-installed"
			}
			installedAny = true
		}
		res.Installed = append(res.Installed, out)
		line := stem + ": " + out.Outcome
		if len(out.Reasons) > 0 {
			line += " (" + strings.Join(out.Reasons, ", ") + ")"
			refusals = append(refusals, out.Reasons...)
		}
		if len(out.NotRun) > 0 {
			line += "; not run: " + strings.Join(out.NotRun, ", ")
		}
		lines = append(lines, line)
	}
	res.Text = strings.Join(lines, "\n")
	if len(refusals) > 0 {
		return refused(refusals...)
	}
	if !installedAny && !answeredAny {
		return errors.New("key install: no answer in " + answers)
	}
	return nil
}

// answerFiles are the files of an answer as read.
type answerFiles struct {
	certName   string
	certFile   []byte
	resultFile []byte
}

// readAnswer reads the files of the answer to a stem: the certificate, and the result file when there is one.
func readAnswer(dir, stem string) (*answerFiles, bool, error) {
	a := &answerFiles{certName: stem + ".cert.pem"}
	cf, cerr := readSmall(filepath.Join(dir, a.certName))
	rf, rerr := readSmall(filepath.Join(dir, stem+".result.json"))
	// A file that is not there is not part of the answer; a file that cannot be read is a failure, not an absence: a
	// result file that is unreadable must not turn an answer into one on the floor, which has no result file to check.
	if errors.Is(cerr, fs.ErrNotExist) && errors.Is(rerr, fs.ErrNotExist) {
		return nil, false, nil
	}
	if cerr != nil && !errors.Is(cerr, fs.ErrNotExist) {
		return nil, true, fmt.Errorf("key install: %s.cert.pem cannot be read: %w", stem, cerr)
	}
	if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return nil, true, fmt.Errorf("key install: %s.result.json cannot be read: %w", stem, rerr)
	}
	a.certFile, a.resultFile = cf, rf
	return a, true, nil
}

// checkAnswer reads the request this node made and runs the requester's checks on the answer. It returns the chain to
// install and the trust sequence the answer named, or the refusal.
func (a *app) checkAnswer(stem, requests string, ans *answerFiles, anchors []*x509.Certificate, bundleSeq int64, held *handoff.RootList, unanchored bool) ([][]byte, int64, []string, error) {
	csrPEM, err := readSmall(filepath.Join(requests, stem+".csr.pem"))
	if err != nil {
		return nil, 0, nil, &handoff.Refusal{Code: handoff.CodeMalformed, At: "request"}
	}
	proofJSON, err := readSmall(filepath.Join(requests, stem+".proof.json"))
	if err != nil {
		return nil, 0, nil, &handoff.Refusal{Code: handoff.CodeMalformed, At: "proof"}
	}
	_, proof, err := handoff.CheckRequest(csrPEM, proofJSON)
	if err != nil {
		return nil, 0, nil, err
	}
	if ans.certFile == nil {
		// A refused answer has a result file and no certificate: its reasons are the certifier's.
		if ans.resultFile != nil {
			if r, perr := handoff.ParseResult(ans.resultFile); perr == nil && !r.Issued {
				return nil, 0, nil, &handoff.CertifierRefused{Reasons: r.Reasons}
			}
		}
		return nil, 0, nil, &handoff.Refusal{Code: handoff.CodeMalformed, At: "certificate"}
	}
	blk, _ := pem.Decode(csrPEM)
	v, err := handoff.CheckX509(handoff.X509Answer{
		Request: blk.Bytes, Proof: proof, CertName: ans.certName, CertFile: ans.certFile, ResultFile: ans.resultFile,
		Anchors: anchors, BundleSequence: bundleSeq, RootList: held, ListUnanchored: unanchored, Now: a.now(),
	})
	if err != nil {
		return nil, 0, nil, err
	}
	// The chain ends at the root that issued it, so that the key set's x5c does (REQ-PKI-034).
	return [][]byte{v.CertDER, v.RootDER}, v.TrustSequence, v.NotRun, nil
}

// requestStems lists the stems of the requests this node made for the boundary: <boundary>-<purpose>.csr.pem.
func requestStems(dir, boundary string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		stem, ok := strings.CutSuffix(name, ".csr.pem")
		if !ok || e.IsDir() || !handoff.ValidStem(stem) || stem != boundary+"-"+handoffPurpose {
			continue
		}
		out = append(out, stem)
	}
	sort.Strings(out)
	return out, nil
}

// reasonOf is the contract's code of a refusal of the kit, or malformed.
func reasonOf(err error) string {
	var r *handoff.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return handoff.CodeMalformed
}
