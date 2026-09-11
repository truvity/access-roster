package tokens

import (
	"context"
	"net/http"
	"strings"
)

// AssumeAt is AssumeRoleWithWebIdentity against a stand-in for STS. The
// endpoint is a constant in the production path on purpose — an
// installation that could point it elsewhere is one values file away
// from sending every token to somebody else — so a test reaches it
// through here rather than through configuration.
func AssumeAt(
	ctx context.Context, endpoint string, client *http.Client, roleARN, sessionName, token string,
) (Credentials, error) {
	previous := stsEndpoint
	stsEndpoint = strings.TrimSuffix(endpoint, "/") + "/"
	defer func() { stsEndpoint = previous }()
	return AssumeRoleWithWebIdentity(ctx, client, roleARN, sessionName, token)
}
