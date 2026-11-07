package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	return command{
		name: "key install",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&requests, "requests", defaultRequestDir, "the directory `key request` wrote to: the requests the answers are checked against")
			fs.StringVar(&bundle, "ca-bundle", "", "the CA bundle: the certificates that anchor the answers (the file of trust.ca_bundle)")
			fs.StringVar(&rootList, "root-list", "", "the signed root list (root-list.json, with root-list.jws beside it), when sluis holds one")
			fs.Var(&pins, "root-pin", "an initial pin: the x509_spki_sha256 of a root this host was installed to trust; repeat for each")
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
			return a.install(ctx, positional[0], requests, bundle, rootList, pins, socket, res)
		},
	}
}

func readSmall(path string) ([]byte, error) {
	fi, err := os.Stat(path) //nolint:gosec // G703: the operator names the file
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxAnswerFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), maxAnswerFile)
	}
	return os.ReadFile(path) //nolint:gosec // the operator names the directory
}

func (a *app) install(ctx context.Context, answers, requests, bundlePath, rootListPath string, pins []string, socket string, res *result) error {
	bundleBytes, err := readSmall(bundlePath)
	if err != nil {
		return fmt.Errorf("key install: the CA bundle cannot be read: %w", err)
	}
	anchors, bundleSeq, err := handoff.ParseBundle(bundleBytes)
	if err != nil {
		return refused(reasonOf(err), "ca-bundle")
	}
	var held *handoff.RootList
	var listNotAnchored bool
	if rootListPath != "" {
		list, err := readSmall(rootListPath)
		if err != nil {
			return fmt.Errorf("key install: the root list cannot be read: %w", err)
		}
		jws, err := readSmall(strings.TrimSuffix(rootListPath, filepath.Ext(rootListPath)) + ".jws")
		if err != nil {
			return fmt.Errorf("key install: the signatures of the root list cannot be read: %w", err)
		}
		var checks handoff.RootListChecks
		if held, checks, err = handoff.ReadRootList(list, jws, nil, pins, a.now()); err != nil {
			return refused(reasonOf(err), "root-list")
		}
		listNotAnchored = !checks.Anchored
	} else if len(pins) > 0 {
		return cli.Usage(errors.New("--root-pin is for --root-list"))
	}

	stems, err := requestStems(requests, a.boundary)
	if err != nil {
		return fmt.Errorf("key install: %w", err)
	}
	if len(stems) == 0 {
		return fmt.Errorf("key install: no request of boundary %s in %s (run key request first)", a.boundary, requests)
	}
	c := a.handoffClient(socket)
	var lines, refusals []string
	installedAny, answeredAny := false, false
	for _, stem := range stems {
		out := installedOut{Stem: stem}
		ans, found := readAnswer(answers, stem)
		if !found {
			out.Outcome = "no-answer"
			res.Installed = append(res.Installed, out)
			lines = append(lines, stem+": no answer in "+answers)
			continue
		}
		answeredAny = true
		chain, seq, notRun, err := a.checkAnswer(stem, requests, ans, anchors, bundleSeq, held)
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
			ir, err := c.Install(ctx, connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: handoffPurpose, Chain: chain, TrustSequence: seq}))
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
func readAnswer(dir, stem string) (*answerFiles, bool) {
	a := &answerFiles{certName: stem + ".cert.pem"}
	cf, cerr := readSmall(filepath.Join(dir, a.certName))
	rf, rerr := readSmall(filepath.Join(dir, stem+".result.json"))
	if cerr != nil && rerr != nil {
		return nil, false
	}
	if cerr == nil {
		a.certFile = cf
	}
	if rerr == nil {
		a.resultFile = rf
	}
	return a, true
}

// checkAnswer reads the request this node made and runs the requester's checks on the answer. It returns the chain to
// install and the trust sequence the answer named, or the refusal.
func (a *app) checkAnswer(stem, requests string, ans *answerFiles, anchors []*x509.Certificate, bundleSeq int64, held *handoff.RootList) ([][]byte, int64, []string, error) {
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
		Anchors: anchors, BundleSequence: bundleSeq, RootList: held, Now: a.now(),
	})
	if err != nil {
		return nil, 0, nil, err
	}
	return [][]byte{v.CertDER}, v.TrustSequence, v.NotRun, nil
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
