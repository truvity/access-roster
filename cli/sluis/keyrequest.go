package main

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/handoff"
)

// requestOut is one request of the `requests` member of the JSON object of `sluis key request`.
type requestOut struct {
	Stem  string    `json:"stem"`
	Kind  string    `json:"kind"`
	Files []fileOut `json:"files"`
}

// fileOut is a file the command wrote.
type fileOut struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// keyOut is one entry of the `keys` member of `key request` and `key status` (cli.md, "JSON output"). `key status` fills
// all of it; the members after Fingerprint are the ones a request has no value for.
type keyOut struct {
	Purpose     string `json:"purpose"`
	Boundary    string `json:"boundary"`
	Store       string `json:"store"`
	Slot        string `json:"slot,omitempty"`
	Fingerprint string `json:"fingerprint"`
	// NotAfter is the earliest end of validity in the installed chain, RFC 3339 in UTC; absent when no certificate is
	// installed. DaysLeft is the whole days until then, negative once it has ended.
	NotAfter string `json:"not_after,omitempty"`
	DaysLeft *int   `json:"days_left,omitempty"`
	Level    string `json:"level,omitempty"`
}

// requestCommand is `sluis key request`: it asks key@ on this node for the key of the boundary's X.509 intermediate,
// has key@ sign a PKCS#10 request for it, and writes the request and the proof of where the key lives, for the person
// who takes them to root custody. It prints the key's fingerprint, which the person compares with the one the certifier
// shows before anything is signed.
func (a *app) requestCommand() command {
	var (
		out, purpose, socket, cn string
		replace                  bool
		trustDomains, zones      repeated
		ranges                   repeated
	)
	return command{
		name: "key request",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&out, "out", defaultRequestDir, "the directory the request and the proof are written to")
			fs.StringVar(&purpose, "purpose", handoffPurpose, "the key purpose to request; the first working version requests "+handoffPurpose)
			fs.StringVar(&socket, "socket", "", "key@'s admin socket; by default "+keyAdminSocketPrefix+"/<boundary>/admin.sock")
			fs.StringVar(&cn, "common-name", "", "the common name of the intermediate; by default \"sluis <boundary> intermediate\"")
			fs.Var(&trustDomains, "trust-domain", "a permitted URI host of the intermediate: the boundary's SPIFFE trust domain; repeat for each")
			fs.Var(&zones, "dns-zone", "a permitted DNS name of the intermediate: a public host or a zone of the boundary; repeat for each")
			fs.Var(&ranges, "ip-range", "a permitted IP range of the intermediate; with none, every address is excluded")
			fs.BoolVar(&replace, "replace", false, "replace a request of the same stem; an answer to the old request is then refused")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 0 {
				return cli.Usage(errors.New("key request takes no argument"))
			}
			if a.boundary == "" || !validBoundary(a.boundary) {
				return cli.Usage(errors.New("name the boundary with --boundary"))
			}
			if purpose != handoffPurpose {
				return cli.Usage(fmt.Errorf("--purpose: the first working version requests %s only", handoffPurpose))
			}
			stem := a.boundary + "-" + purpose
			if !handoff.ValidStem(stem) {
				return cli.Usage(errors.New("the boundary name makes no stem of the hand-off contract"))
			}
			if cn == "" {
				cn = "sluis " + a.boundary + " intermediate"
			}
			cons := handoff.Constraints{URIHosts: trustDomains, DNS: zones}
			for _, r := range ranges {
				p, err := netip.ParsePrefix(r)
				if err != nil {
					return cli.Usage(errors.New("--ip-range: not a prefix"))
				}
				cons.IPRanges = append(cons.IPRanges, p)
			}
			if err := cons.Validate(); err != nil {
				return cli.Usage(fmt.Errorf("name the boundary's names with --trust-domain and --dns-zone: %w", err))
			}
			return a.makeRequest(ctx, stem, socket, out, replace, handoff.RequestSpec{Subject: pkix.Name{CommonName: cn}, Constraints: cons}, res)
		},
	}
}

func (a *app) makeRequest(ctx context.Context, stem, socket, outDir string, replace bool, spec handoff.RequestSpec, res *result) error {
	c := a.handoffClient(socket)
	prep, err := c.Prepare(ctx, connect.NewRequest(&keyv2alpha1.PrepareRequest{Purpose: handoffPurpose}))
	if err != nil {
		return keyCallError("key request", err)
	}
	spki := prep.Msg.GetSpkiDer()
	info, err := handoff.CertificationRequestInfo(spki, spec)
	if err != nil {
		return cli.Usage(err)
	}
	signed, err := c.SignRequest(ctx, connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: handoffPurpose, Info: info}))
	if err != nil {
		return keyCallError("key request", err)
	}
	der, err := handoff.AssembleCSR(info, signed.Msg.GetSignatureDer())
	if err != nil {
		return fmt.Errorf("key request: %w", err)
	}
	csrPEM := handoff.CSRPEM(der)
	proof := &handoff.Proof{RequestSHA256: handoff.RequestDigest(der), Store: prep.Msg.GetStore(), Attestation: prep.Msg.GetAttestation()}
	if proof.Store == handoff.StorePIV {
		if err := proof.CheckAttestationShape(); err != nil {
			return refused("malformed", "attestation")
		}
	}
	proofJSON, err := proof.Marshal()
	if err != nil {
		return fmt.Errorf("key request: %w", err)
	}
	// Never write a request that the certifier would refuse as unreadable: the files are read back by its checks 1 to 5.
	csr, _, err := handoff.CheckRequest(csrPEM, proofJSON)
	if err != nil {
		return fmt.Errorf("key request: key@ made a request that fails the contract's checks: %w", err)
	}
	if fingerprint(csr.RawSubjectPublicKeyInfo) != fingerprint(spki) {
		return errors.New("key request: the request holds another key than key@ named")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // public material, read by the person at the ceremony
		return fmt.Errorf("key request: %w", err)
	}
	csrPath := filepath.Join(outDir, stem+".csr.pem")
	proofPath := filepath.Join(outDir, stem+".proof.json")
	if err := writeNew(csrPath, csrPEM, replace); err != nil {
		return fmt.Errorf("key request: %w", err)
	}
	if err := writeNew(proofPath, proofJSON, replace); err != nil {
		_ = os.Remove(csrPath)
		return fmt.Errorf("key request: %w", err)
	}
	fp := fingerprint(spki)
	res.Keys = append(res.Keys, keyOut{Purpose: handoffPurpose, Boundary: a.boundary, Store: proof.Store, Fingerprint: fp})
	res.Requests = append(res.Requests, requestOut{Stem: stem, Kind: handoff.TypeX509, Files: []fileOut{
		{Path: csrPath, SHA256: fileDigest(csrPEM)}, {Path: proofPath, SHA256: fileDigest(proofJSON)},
	}})
	var b strings.Builder
	fmt.Fprintf(&b, "%s: store %s, key fingerprint %s\n", stem, proof.Store, fp)
	fmt.Fprintf(&b, "  %s\n  %s\n", csrPath, proofPath)
	b.WriteString("Take both files to the ceremony and compare the fingerprint with the one the certifier shows.")
	res.Text = b.String()
	return nil
}
