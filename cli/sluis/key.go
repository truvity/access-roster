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
//     key@ verifies it and writes the revocations; the command prints what key@ did with each key, then confirms that
//     the keys left the key sets a verifier can be given (keyconfirm.go) and exits 5 when it cannot.

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
	// Confirmation is what the check of the key sets found, after the delivery.
	Confirmation *confirmationOut `json:"confirmation,omitempty"`
}

type revokedKeyOut struct {
	Kid     string `json:"kid"`
	Already bool   `json:"already"`
	Unknown bool   `json:"unknown,omitempty"`
	Pending bool   `json:"pending,omitempty"`
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
		allowUnk    bool
		confirm     confirmOptions
		set         *flag.FlagSet
	)
	return command{
		name: "key revoke",
		flags: func(fs *flag.FlagSet) {
			set = fs
			fs.Var(&kids, "kid", "the RFC 7638 thumbprint of a key to revoke; repeat it for each key")
			fs.StringVar(&reason, "reason", "", "compromise, suspicion, lost-board or drill")
			fs.StringVar(&out, "out", "", "write the declaration to this file, not to standard output")
			fs.BoolVar(&allowUnk, "allow-unknown", false, "let key@ revoke keys that it does not know (a lost board's own keys); without it such a key refuses the declaration")
			fs.StringVar(&declaration, "declaration", "", "deliver this signed declaration to key@ on this node")
			fs.StringVar(&socket, "socket", "", "key@'s admin socket; by default "+keyAdminSocketPrefix+"/<boundary>/admin.sock")
			fs.StringVar(&confirm.issuer, "issuer", "", "the issuer whose key set is checked after the delivery; by default the one entry reports on its socket")
			fs.StringVar(&confirm.entrySocket, "entry-socket", "", "entry's socket, where its live key set is read; by default "+entrySocketPrefix+"/<boundary>.sock")
			fs.DurationVar(&confirm.wait, "wait", defaultConfirmWait, "how long to check that the keys left the key sets; 0 checks once")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 0 {
				return cli.Usage(errors.New("key revoke takes no argument"))
			}
			if a.boundary == "" || !validBoundary(a.boundary) {
				return cli.Usage(errors.New("name the boundary with --boundary"))
			}
			if declaration != "" {
				if len(kids) > 0 || reason != "" || out != "" || allowUnk {
					return cli.Usage(errors.New("--declaration delivers a signed declaration: it takes no --kid, --reason, --out or --allow-unknown"))
				}
				if err := validateConfirmFlags(confirm); err != nil {
					return cli.Usage(err)
				}
				return a.deliverDeclaration(ctx, declaration, socket, confirm, res)
			}
			if socket != "" {
				return cli.Usage(errors.New("--socket is for --declaration"))
			}
			confirmFlag := false
			set.Visit(func(f *flag.Flag) {
				if f.Name == "issuer" || f.Name == "entry-socket" || f.Name == "wait" {
					confirmFlag = true
				}
			})
			if confirmFlag {
				return cli.Usage(errors.New("--issuer, --entry-socket and --wait are for --declaration"))
			}
			return a.writeDeclaration(kids, reason, out, allowUnk, res)
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
func (a *app) writeDeclaration(kids []string, reason, out string, allowUnknown bool, res *result) error {
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
	if allowUnknown {
		b.WriteString("allow_unknown: true\n")
	}
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
// revocation is confirmed only when both key sets lack the keys (REQ-KEYS-088), which the command then checks.
func (a *app) deliverDeclaration(ctx context.Context, path, socket string, confirm confirmOptions, res *result) error {
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
	var msg *keyv2alpha1.RevokeResponse
	partial := false
	if err != nil {
		reason, ok := krefusal.Reason(err)
		if ok && reason == "partial" {
			msg, partial = partialOf(err), true
		}
		if msg == nil {
			if ok {
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
	} else {
		msg = r.Msg
	}
	audited := msg.GetAudited()
	o := &revokeOut{Seq: msg.GetSeq(), Audited: &audited}
	var lines, kids []string
	for _, k := range msg.GetKeys() {
		kids = append(kids, k.GetKid())
		o.Keys = append(o.Keys, revokedKeyOut{Kid: k.GetKid(), Already: k.GetAlready(), Unknown: k.GetUnknown(), Pending: k.GetPending()})
		state := "revoked"
		switch {
		case k.GetPending():
			state = "not yet revoked"
		case k.GetAlready():
			state = "already revoked"
		}
		if k.GetUnknown() {
			state += " (a key key@ does not know)"
		}
		lines = append(lines, fmt.Sprintf("%s %s", k.GetKid(), state))
	}
	res.Revoke = o
	res.Text = strings.Join(lines, "\n")
	if partial {
		// The text is printed only on success; a person reads the keys on standard error here.
		_, _ = fmt.Fprintln(a.stderr, res.Text)
		return errors.New("key revoke: key@ took the declaration in part (store@ failed); deliver the same declaration again to complete it")
	}
	conf := a.confirmRevoked(ctx, kids, confirm, a.stderr)
	o.Confirmation = conf
	lines = append(lines, confirmationLines(conf)...)
	res.Text = strings.Join(lines, "\n")
	if !audited {
		// A failure of the audit comes first; what the check found is still read, on standard error.
		_, _ = fmt.Fprintln(a.stderr, res.Text)
		return errors.New("key revoke: the keys are revoked, but key@ could not make the audit fact durable")
	}
	if !conf.Confirmed {
		return notConfirmedError{}
	}
	return nil
}

// partialOf reads what key@ did from the detail of a "partial" refusal; nil when there is none.
func partialOf(err error) *keyv2alpha1.RevokeResponse {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return nil
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if derr != nil {
			continue
		}
		if m, ok := v.(*keyv2alpha1.RevokeResponse); ok {
			return m
		}
	}
	return nil
}
