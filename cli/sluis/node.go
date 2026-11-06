package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"

	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
	krefusal "github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// nodeOut is the `node` member of the JSON object of `sluis node unlock` and `sluis node status`. It holds no PIN.
type nodeOut struct {
	Node   string `json:"node"`
	Locked bool   `json:"locked"`
}

// adminSocketPrefix is where the card driver of a board opens its admin socket: <prefix>-<boundary>/admin.sock, the
// RuntimeDirectory of its unit. Only root reaches it.
const adminSocketPrefix = "/run/sluis-drv-key-yubikey-piv"

// pinMax bounds what is read for a PIN; a PIV PIN has 6 to 8 octets and the driver checks the length.
const pinMax = 64

// unlockCommand is `sluis node unlock <node>` (ADR 0006, "Touch and PIN"): it delivers the PIN of the card to the
// locked card driver of the node it runs on, over the driver's local admin socket. The node is reached by a shell on
// it (SSH, then sudo), which is the authenticated channel of this milestone; the PIN reaches the driver only through
// the socket and is never a flag, an environment variable or a file.
func (a *app) unlockCommand() command {
	var socket string
	var secretFd int
	return command{
		name: "node unlock",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&socket, "socket", "", "the admin socket of the card driver; by default "+adminSocketPrefix+"-<boundary>/admin.sock")
			fs.IntVar(&secretFd, "secret-fd", -1, "read the PIN from this descriptor; by default from standard input")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 1 {
				return cli.Usage(errors.New("node unlock takes one argument, the node"))
			}
			return a.unlock(ctx, positional[0], socket, secretFd, res)
		},
	}
}

// statusCommand is `sluis node status <node>`: whether the card driver of the node it runs on holds the PIN. It is the
// read-only half of `node unlock`, for the deploy and for a person who wants to know before asking for a PIN. It asks the
// driver's admin socket for the same Status call that unlock makes first, reads no PIN, sends none and prints none; the
// answer is the node's name and one word, "locked" or "unlocked". A driver that cannot be reached is a failure (exit 1),
// never "locked" or "unlocked": a caller that cannot ask does not know.
func (a *app) statusCommand() command {
	var socket string
	return command{
		name: "node status",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&socket, "socket", "", "the admin socket of the card driver; by default "+adminSocketPrefix+"-<boundary>/admin.sock")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 1 {
				return cli.Usage(errors.New("node status takes one argument, the node"))
			}
			return a.status(ctx, positional[0], socket, res)
		},
	}
}

// adminSocket is the admin socket the flags name: --socket, or the one of the boundary.
func (a *app) adminSocket(socket string) (string, error) {
	if socket != "" {
		return socket, nil
	}
	if a.boundary == "" || strings.ContainsAny(a.boundary, "/.") {
		return "", cli.Usage(errors.New("name the admin socket with --socket, or the boundary with --boundary"))
	}
	return filepath.Join(adminSocketPrefix+"-"+a.boundary, "admin.sock"), nil
}

func (a *app) status(ctx context.Context, node, socket string, res *result) error {
	socket, err := a.adminSocket(socket)
	if err != nil {
		return err
	}
	hc, url := rpc.Dial(socket)
	c := keystorev2alpha1connect.NewUnlockServiceClient(hc, url, rpc.ClientOptions()...)
	st, err := c.Status(ctx, connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if err != nil {
		return dialError("status", err)
	}
	// The socket is the node's own; a name that is not this node's means the command was sent to the wrong place.
	if st.Msg.GetNode() != node {
		return refused("node")
	}
	locked := st.Msg.GetLocked()
	res.Node = &nodeOut{Node: node, Locked: locked}
	if locked {
		res.Text = fmt.Sprintf("node %s is locked", node)
	} else {
		res.Text = fmt.Sprintf("node %s is unlocked", node)
	}
	return nil
}

func (a *app) unlock(ctx context.Context, node, socket string, secretFd int, res *result) error {
	socket, err := a.adminSocket(socket)
	if err != nil {
		return err
	}
	pin, err := a.readPIN(secretFd)
	if err != nil {
		return err
	}
	defer clear(pin)

	hc, url := rpc.Dial(socket)
	c := keystorev2alpha1connect.NewUnlockServiceClient(hc, url, rpc.ClientOptions()...)
	st, err := c.Status(ctx, connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if err != nil {
		return dialError("status", err)
	}
	// The socket is the node's own; a name that is not this node's means the command was sent to the wrong place.
	if st.Msg.GetNode() != node {
		return refused("node")
	}
	if !st.Msg.GetLocked() {
		res.Node = &nodeOut{Node: node}
		res.Text = fmt.Sprintf("node %s is already unlocked", node)
		return nil
	}
	// With one attempt left, a wrong PIN would block the card and need the PUK, which is the owners' procedure (ADR 0006:
	// a bad unlock cannot lock the card). The PIN is not sent. The driver refuses the same, whatever this says.
	if n := st.Msg.GetPinRetries(); n == 1 {
		_, _ = fmt.Fprintln(a.stderr, "the card has one PIN attempt left: it is not tried; the PUK procedure is the owners'")
		return refused("pin_retries")
	}
	if _, err := c.Unlock(ctx, connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: pin})); err != nil {
		// The driver tried the PIN once. Say how many attempts the card has left, so that nobody guesses.
		if reason, _ := krefusal.Reason(err); reason == "pin_retries" {
			_, _ = fmt.Fprintln(a.stderr, "the card has one PIN attempt left: it is not tried; the PUK procedure is the owners'")
		} else if reason == "pin" {
			if st2, serr := c.Status(ctx, connect.NewRequest(&keystorev2alpha1.StatusRequest{})); serr == nil {
				_, _ = fmt.Fprintf(a.stderr, "the card did not accept the PIN; it allows %d more attempts\n", st2.Msg.GetPinRetries())
			}
		}
		return dialError("unlock", err)
	}
	res.Node = &nodeOut{Node: node}
	res.Text = fmt.Sprintf("node %s is unlocked", node)
	return nil
}

// dialError maps an error of the admin socket to the end of the command. A refusal of the driver is a refused
// result with its reason; anything else (no socket, no permission) is a failure. No message holds the PIN.
func dialError(step string, err error) error {
	if reason, ok := krefusal.Reason(err); ok {
		return refused(reason)
	}
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied:
		return refused("caller")
	case connect.CodeUnavailable:
		return fmt.Errorf("node unlock: %s: the admin socket cannot be reached (is the driver running, and are you root?)", step)
	}
	return fmt.Errorf("node unlock: %s: %s", step, connect.CodeOf(err))
}

// readPIN reads one line from the descriptor, or from standard input, into a buffer that the caller wipes. A terminal is
// refused: this build cannot turn the echo off, and a PIN that shows on a screen is not delivered. It reads a byte at a
// time into one array, so that no buffered copy of the line, and no string, is left behind.
func (a *app) readPIN(fd int) ([]byte, error) {
	var r io.Reader
	switch {
	case fd >= 0:
		r = a.secretFd(fd)
		if r == nil {
			return nil, cli.Usage(errors.New("--secret-fd: not an open descriptor"))
		}
	default:
		r = a.stdin
	}
	if f, ok := r.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return nil, cli.Usage(errors.New("the PIN is read from a pipe or --secret-fd, not from a terminal that would show it"))
		}
	}
	var buf [pinMax + 1]byte
	defer clear(buf[:])
	n := 0
	var one [1]byte
	for {
		m, err := r.Read(one[:])
		if m == 1 {
			if one[0] == '\n' {
				break
			}
			if n == len(buf) {
				return nil, cli.Usage(errors.New("the PIN is longer than a PIV PIN can be"))
			}
			buf[n] = one[0]
			n++
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("reading the PIN: %w", err)
		}
	}
	for n > 0 && buf[n-1] == '\r' {
		n--
	}
	if n == 0 {
		return nil, cli.Usage(errors.New("no PIN on standard input (or --secret-fd)"))
	}
	if n > pinMax {
		return nil, cli.Usage(errors.New("the PIN is longer than a PIV PIN can be"))
	}
	return bytes.Clone(buf[:n]), nil
}
