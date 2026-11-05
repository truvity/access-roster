// Command yubikey-piv is the card key driver of key@: the key-store port over the keys of a board's YubiKey, through
// piv-go and pcsc-lite (ADR 0006, 0012, 0013). It holds the card exclusively and starts locked: it has no PIN until
// an administrator delivers it on the local admin socket with `sluis node unlock`.
//
//	yubikey-piv serve --socket PATH --admin-socket PATH --node NAME --environment development|staging|production
//	              --bootstrap PATH --state-dir PATH [--serial N] [--socket-gid GID]
//	yubikey-piv check [--serial N]
//	yubikey-piv conformance --socket PATH
//	yubikey-piv version
//
// The executable that talks to a card is built natively with the tag sluis_card and CGO_ENABLED=1 (`just
// build-arm64-native`). A build without the tag has the same commands and refuses to open a card.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

func main() {
	cli.Main("yubikey-piv", cli.Commands{Serve: serve, Check: check, Conformance: conformance}, flags)
}

func flags(fs *flag.FlagSet) {
	fs.String("environment", "", "development, staging or production (required); only development makes a key with the factory management key")
	fs.String("node", "", "the node whose card this is (required for serve)")
	fs.String("admin-socket", "", "the absolute path of the local admin socket that takes the PIN (required for serve); root only")
	fs.Uint("serial", 0, "the serial number of the card the driver is bound to; required outside development (in development, none means the only card, and two cards are refused)")
	fs.String("bootstrap", "", "the bootstrap file of the boundary (required for serve): its publisher keys verify the KeyPlan of a PIN release, as key@'s do")
	fs.String("state-dir", "", "the driver's own state directory, mode 0700 (required for serve): it holds the highest KeyPlan seq verified")
	fs.Uint("socket-gid", 0, "open the socket (mode 0660) to this group, which the owner joins; 0 keeps mode 0600 for the driver's user alone")
}

func value(f cli.Flags, name string) string {
	if fl := f.Extra.Lookup(name); fl != nil {
		return fl.Value.String()
	}
	return ""
}

func serial(f cli.Flags) (uint32, error) {
	s := value(f, "serial")
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, cli.Usage(errors.New("--serial is not a serial number"))
	}
	return uint32(n), nil
}

func serve(ctx context.Context, f cli.Flags) error {
	env := value(f, "environment")
	if env == "" {
		return cli.Usage(errors.New("--environment is required"))
	}
	// The environment is checked before anything is opened: no socket, no card.
	if err := driver.Floor(env); err != nil {
		return err
	}
	if f.Socket == "" {
		return cli.Usage(errors.New("--socket is required"))
	}
	adminSocket, node := value(f, "admin-socket"), value(f, "node")
	if adminSocket == "" {
		return cli.Usage(errors.New("--admin-socket is required"))
	}
	if node == "" {
		return cli.Usage(errors.New("--node is required"))
	}
	// The PIN release is verified by the driver itself against the publisher keys key@ pins (ADR 0006, "Touch and PIN"),
	// with a mark of the highest KeyPlan seq in a state directory of its own.
	bootstrap, stateDir := value(f, "bootstrap"), value(f, "state-dir")
	if bootstrap == "" || stateDir == "" {
		return cli.Usage(errors.New("--bootstrap and --state-dir are required"))
	}
	raw, err := os.ReadFile(bootstrap) //nolint:gosec // the operator names the boundary's bootstrap file
	if err != nil {
		return errors.New("the bootstrap file cannot be read")
	}
	publishers, err := signedconfig.ParsePublishers(raw)
	if err != nil {
		return fmt.Errorf("the bootstrap file: %w", err)
	}
	sn, err := serial(f)
	if err != nil {
		return err
	}
	// The driver is bound to one card outside development, so that a genuine YubiKey that is not the board's cannot be
	// adopted because its attestations match the slot map.
	if env != driver.Development && sn == 0 {
		return cli.Usage(errors.New("--serial is required outside development"))
	}
	cfg := rpc.ServerConfig{
		Actor:    driver.Name,
		Boundary: f.Boundary,
		Socket:   f.Socket,
		Mode:     0o600,
		Allow:    rpc.OwnerOnly(driver.Owner()),
	}
	// The owner is another uid: a group that only the owner joins may connect. OwnerOnly still decides who may call.
	if gid := value(f, "socket-gid"); gid != "0" && gid != "" {
		n, err := strconv.ParseUint(gid, 10, 32)
		if err != nil {
			return cli.Usage(errors.New("--socket-gid is not a group number"))
		}
		cfg.Mode, cfg.GID = 0o660, uint32(n)
	}
	// The administrator of a node is root, reached through sudo: the socket is mode 0600 and the driver checks the
	// peer's uid again before it reads the PIN.
	admin := driver.AdminConfig{Socket: adminSocket, Allow: func(uid uint32) bool { return uid == 0 }}
	return driver.Run(ctx, driver.Options{Environment: env, Node: node, Serial: sn, Publishers: publishers, StateDir: stateDir}, cfg, admin)
}

// check opens the card, applies the firmware floor and verifies the attestation of every key it holds. It
// writes nothing. The card is exclusive, so it cannot run beside a driver that serves.
func check(_ context.Context, f cli.Flags) error {
	env := value(f, "environment")
	if env == "" {
		env = driver.Staging // check never makes a key; the environment only has to be a real one
	}
	sn, err := serial(f)
	if err != nil {
		return err
	}
	if env != driver.Development && sn == 0 {
		return cli.Usage(errors.New("--serial is required outside development"))
	}
	return driver.Check(driver.Options{Environment: env, Serial: sn})
}

func conformance(ctx context.Context, f cli.Flags) error {
	if f.Socket == "" {
		return cli.Usage(errors.New("--socket is required"))
	}
	return driver.Conformance(ctx, f.Socket, os.Stdout)
}
