//go:build !sluis_test

package main

import "github.com/truvity/sluis/v2/kits/go/rpc"

// withTestCaller is the identity in a normal build: the callers of the driver are named by the uid registry alone.
func withTestCaller(cfg rpc.ServerConfig) rpc.ServerConfig { return cfg }
