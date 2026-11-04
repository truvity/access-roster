package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
	krefusal "github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// `sluis key revoke` is the operator's side of a revocation (ADR 0041, "A person declares, and a suspicion counts";
// cli.md, "sluis key revoke"). It has two steps with the publisher's signature between them, because the publisher key
// lives where the config is signed and never on a node:
//
//  1. With --kid and --reason it writes the declaration: the payload of a KeyRevocationDeclaration, checked here, to
//     --out or to standard output. The publisher signs it as it signs the KeyPlan.
//  2. With --declaration it delivers the signed declaration to key@'s admin socket on the node it runs on, as root.
//     key@ verifies it and writes the revocations; the command prints what key@ did with each key.

// keyAdminSocketPrefix is the run directory of key@: <prefix>/<boundary>/admin.sock.
const keyAdminSocketPrefix = "/run/sluis/key"

// revokeReasons is the closed list of the reasons of a revocation.
var revokeReasons = []string{"compromise", "suspicion", "lost-board", "drill"}

// thumbprintPattern is an RFC 7638 thumbprint of SHA-256: 43 characters of base64url without padding.
var thumbprintPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// maxRevokeKids is key@'s bound on the keys of one declaration.
const maxRevokeKids = 64

// revokeOut is the `revoke` member of the JSON object of `sluis key revoke`.
type revokeOut struct {
	// Written is the file the declaration was written to, in the first step; empty for standard output.
	Written string `json:"written,omitempty"`
	// Seq and Keys are what key@ did, in the second step.
	Seq     uint64          `json:"seq,omitempty"`
	Keys    []revokedKeyOut `json:"keys,omitempty"`
	Audited *bool           `json:"audited,omitempty"`
}

type revokedKeyOut struct {
	Kid     string `json:"kid"`
	Already bool   `json:"already"`
}

// kidList is a repeated --kid.
type kidList []string

func (k *kidList) String() string     { return strings.Join(*k, ",") }
func (k *kidList) Set(v string) error { *k = append(*k, v); return nil }

func (a *app) revokeCommand() command {
	var (
		kids        kidList
		reason, out string
		declaration string
		socket      string
	)
	return command{
		name: "key revoke",
		flags: func(fs *flag.FlagSet) {
			fs.Var(&kids, "kid", "the RFC 7638 thumbprint of a key to revoke; repeat it for each key")
			fs.StringVar(&reason, "reason", "", "compromise, suspicion, lost-board or drill")
			fs.StringVar(&out, "out", "", "write the declaration to this file, not to standard output")
			fs.StringVar(&declaration, "declaration", "", "deliver this signed declaration to key@ on this node")
			fs.StringVar(&socket, "socket", "", "key@'s admin socket; by default "+keyAdminSocketPrefix+"/<boundary>/admin.sock")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 0 {
				return cli.Usage(errors.New("key revoke takes no argument"))
			}
			if a.boundary == "" || !validBoundary(a.boundary) {
				return cli.Usage(errors.New("name the boundary with --boundary"))
			}
			if declaration != "" {
				if len(kids) > 0 || reason != "" || out != "" {
					return cli.Usage(errors.New("--declaration delivers a signed declaration: it takes no --kid, --reason or --out"))
				}
				return a.deliverDeclaration(ctx, declaration, socket, res)
			}
			if socket != "" {
				return cli.Usage(errors.New("--socket is for --declaration"))
			}
			return a.writeDeclaration(kids, reason, out, res)
		},
	}
}

// validBoundary is an address part, as a boundary name is.
func validBoundary(b string) bool {
	if len(b) > 128 || b == "." || b == ".." {
		return false
	}
	for _, c := range b {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return b != ""
}

// writeDeclaration checks the keys and the reason and writes the payload of the declaration. It names keys and never a
// purpose (ADR 0041, "The declaration").
func (a *app) writeDeclaration(kids []string, reason, out string, res *result) error {
	if len(kids) == 0 || len(kids) > maxRevokeKids {
		return cli.Usage(fmt.Errorf("name 1 to %d keys with --kid", maxRevokeKids))
	}
	for i, k := range kids {
		if !thumbprintPattern.MatchString(k) {
			return cli.Usage(fmt.Errorf("--kid %d: not an RFC 7638 thumbprint", i+1))
		}
		if slices.Contains(kids[:i], k) {
			return cli.Usage(fmt.Errorf("--kid %d: listed twice", i+1))
		}
	}
	if !slices.Contains(revokeReasons, reason) {
		return cli.Usage(errors.New("--reason must be compromise, suspicion, lost-board or drill"))
	}
	var b strings.Builder
	b.WriteString("# A key revocation declaration (ADR 0041). Sign it with the publisher key as a KeyRevocationDeclaration,\n")
	b.WriteString("# then deliver it on a node: sluis key revoke --boundary " + a.boundary + " --declaration FILE\n")
	fmt.Fprintf(&b, "boundary: %s\nkids:\n", a.boundary)
	for _, k := range kids {
		fmt.Fprintf(&b, "  - %s\n", k)
	}
	fmt.Fprintf(&b, "reason: %s\n", reason)
	if out == "" {
		res.Text = strings.TrimSuffix(b.String(), "\n")
		res.Revoke = &revokeOut{}
		return nil
	}
	// A declaration is not secret: it names public key ids. It is written whole or not at all.
	tmp, err := os.CreateTemp(filepath.Dir(out), ".declaration-*")
	if err != nil {
		return fmt.Errorf("key revoke: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("key revoke: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("key revoke: %w", err)
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return fmt.Errorf("key revoke: %w", err)
	}
	res.Revoke = &revokeOut{Written: out}
	res.Text = fmt.Sprintf("the declaration for %d keys is in %s: sign it with the publisher key, then deliver it with --declaration", len(kids), out)
	return nil
}

// deliverDeclaration sends the signed declaration to key@'s admin socket. key@ decides; the command reports. A
// revocation is confirmed only when the published key set lacks the key, which this command does not check yet
// (REQ-KEYS-088), so it says so.
func (a *app) deliverDeclaration(ctx context.Context, path, socket string, res *result) error {
	doc, err := os.ReadFile(path) //nolint:gosec // the operator names the file
	if err != nil {
		return fmt.Errorf("key revoke: the declaration cannot be read: %w", err)
	}
	if len(doc) > signedconfig.MaxDocument {
		return refused("declaration")
	}
	if socket == "" {
		socket = filepath.Join(keyAdminSocketPrefix, a.boundary, "admin.sock")
	}
	hc, url := rpc.Dial(socket)
	c := keyv2alpha1connect.NewKeyAdminServiceClient(hc, url, rpc.ClientOptions()...)
	r, err := c.Revoke(ctx, connect.NewRequest(&keyv2alpha1.RevokeRequest{Declaration: doc}))
	if err != nil {
		if reason, ok := krefusal.Reason(err); ok {
			if p, _ := krefusal.FieldPath(err); p != "" && p != reason {
				return refused(reason, p)
			}
			return refused(reason)
		}
		switch connect.CodeOf(err) {
		case connect.CodePermissionDenied:
			return refused("caller")
		case connect.CodeUnavailable:
			return errors.New("key revoke: key@'s admin socket cannot be reached (is key@ running, and are you root?)")
		}
		return fmt.Errorf("key revoke: %s", connect.CodeOf(err))
	}
	audited := r.Msg.GetAudited()
	o := &revokeOut{Seq: r.Msg.GetSeq(), Audited: &audited}
	var lines []string
	for _, k := range r.Msg.GetKeys() {
		o.Keys = append(o.Keys, revokedKeyOut{Kid: k.GetKid(), Already: k.GetAlready()})
		state := "revoked"
		if k.GetAlready() {
			state = "already revoked"
		}
		lines = append(lines, fmt.Sprintf("%s %s", k.GetKid(), state))
	}
	res.Revoke = o
	res.Text = strings.Join(lines, "\n")
	_, _ = fmt.Fprintln(a.stderr, "not confirmed: this build does not yet fetch the published key set to check that the keys left it")
	if !audited {
		return errors.New("key revoke: the keys are revoked, but key@ could not make the audit fact durable")
	}
	return nil
}
