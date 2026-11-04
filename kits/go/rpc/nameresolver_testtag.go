//go:build sluis_test

package rpc

// WithNameResolver returns cfg with another uid-to-name resolver.
//
// It exists for tests, which run under their own uid, and only in a build with the tag sluis_test: a normal
// build does not contain it, so product code cannot rename its callers. Go tests, `just go-test` and the echo
// conformance binary are built with the tag. It is the counterpart of the test-identities feature of the Rust kit.
func WithNameResolver(cfg ServerConfig, resolve NameResolver) ServerConfig {
	cfg.resolve = resolve
	return cfg
}
