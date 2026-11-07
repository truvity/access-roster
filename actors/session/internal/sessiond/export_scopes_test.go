//go:build sluis_test

package sessiond

// KnownScopes is the set of scopes session grants, for the tests of package sessiond_test.
func KnownScopes() []string {
	var out []string
	for s := range knownScopes {
		out = append(out, s)
	}
	return out
}
