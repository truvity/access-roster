package verify

// FromIssuer points a GitHub verifier at a test issuer. Production has no
// such lever: the issuer is a constant, because one that could be moved
// would make every CI matcher in the policy meaningless.
func (g *GitHub) FromIssuer(url string) *GitHub {
	g.issuer = url
	return g
}
