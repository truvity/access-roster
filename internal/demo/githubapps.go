package demo

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
)

// The demonstration's Apps beyond the link App and the organisation's own:
// one of each state the Apps list and an App's page have to show. A runner
// tier installed and one not created; a catalogue App installed as
// declared, one an owner edited on GitHub since, and one not created.

// GitHubRunnerTiers are the runner tiers the demonstration declares.
func GitHubRunnerTiers() []string { return []string{"standard", "large"} }

// GitHubRunnerApps are the runner Apps the demonstration has created: the
// standard tier's, installed. The large tier's is left to create.
func GitHubRunnerApps(now time.Time) []runnerapp.Record {
	return []runnerapp.Record{{
		Version: 1, Tier: "standard", Org: "example-org", AppID: 1000021, AppSlug: "example-org-runners-standard",
		InstallationID: 2000021, HTMLURL: "https://github.com/apps/example-org-runners-standard",
		ConnectedAt: now.Add(-60 * time.Hour), ConnectedBy: "ada@north.example",
	}}
}

// githubCatalogue is the demonstration's catalogue. Its grants name groups
// the demonstration policy declares, as a real catalogue's must.
const githubCatalogue = `
apps:
  - id: release-bot
    org: example-org
    description: Tags releases and publishes their notes
    permissions: {contents: write, pull_requests: read}
    installation: all
    grants:
      - group: rung:platform
        repositories: ["*"]
        permissions: {contents: write, pull_requests: read}
      - group: all:gitops:deployer
        repositories: ["*"]
        permissions: {contents: read}
  - id: docs-bot
    org: example-org
    description: Opens pull requests on the documentation
    permissions: {contents: write, pull_requests: write}
    grants:
      - group: rung:engineering
        repositories: [docs, "site-*"]
        permissions: {contents: write, pull_requests: write}
  - id: labeler
    org: example-org
    description: Labels pull requests by the paths they touch
    permissions: {contents: read, pull_requests: write}
    events: [pull_request]
    grants:
      - group: rung:engineering
        repositories: ["*"]
        permissions: {pull_requests: write}
`

// GitHubCatalogue is the demonstration's catalogue.
func GitHubCatalogue() *catalogue.Catalogue {
	c, err := catalogue.Parse([]byte(githubCatalogue))
	if err != nil {
		// A fixture that does not parse is a bug in this file, caught by its
		// test rather than by somebody opening the page.
		panic(err)
	}
	return c
}

// GitHubCatalogueApps are the catalogue Apps the demonstration has created:
// release-bot and docs-bot, both installed. labeler is left to create.
func GitHubCatalogueApps(now time.Time) []catalogueapp.Record {
	return []catalogueapp.Record{
		{
			Version: 1, ID: "release-bot", Org: "example-org", AppID: 1000011, AppSlug: "example-org-release-bot", InstallationID: 2000011,
			HTMLURL: "https://github.com/apps/example-org-release-bot", ConnectedAt: now.Add(-50 * time.Hour), ConnectedBy: "ada@north.example",
		},
		{
			Version: 1, ID: "docs-bot", Org: "example-org", AppID: 1000012, AppSlug: "example-org-docs-bot", InstallationID: 2000012,
			HTMLURL: "https://github.com/apps/example-org-docs-bot", ConnectedAt: now.Add(-26 * time.Hour), ConnectedBy: "ada@north.example",
		},
	}
}

// GitHubAppKey is a private key for the demonstration's Apps, made at
// start. Nothing outside this process ever accepts it: it exists so the
// console signs its questions to GitHubAPI the way it signs real ones.
func GitHubAppKey() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil
}

// githubAnswer is what the demonstration's GitHub says of one App and its
// installation.
type githubAnswer struct {
	slug, selection string
	app, installed  map[string]string
}

// githubAnswers are keyed by App id: release-bot holds what it declares,
// docs-bot was edited on GitHub and holds pull requests at read only.
var githubAnswers = map[int64]githubAnswer{
	1000011: {
		slug: "example-org-release-bot", selection: "all",
		app:       map[string]string{"contents": "write", "pull_requests": "read", "metadata": "read"},
		installed: map[string]string{"contents": "write", "pull_requests": "read", "metadata": "read"},
	},
	1000012: {
		slug: "example-org-docs-bot", selection: "selected",
		app:       map[string]string{"contents": "write", "pull_requests": "read", "metadata": "read"},
		installed: map[string]string{"contents": "write", "pull_requests": "read", "metadata": "read"},
	},
}

// GitHubAPI answers the two reads the console makes of a catalogue App —
// the App, and its installation — from the fixtures above, by the App id
// its token names. Everything else is a 404: a demonstration creates,
// installs and mints nothing.
func GitHubAPI() http.RoundTripper { return githubAPI{} }

type githubAPI struct{}

func (githubAPI) RoundTrip(req *http.Request) (*http.Response, error) {
	answer, ok := githubAnswers[appOfToken(req.Header.Get("Authorization"))]
	switch {
	case !ok || req.Method != http.MethodGet:
	case req.URL.Path == "/app":
		return jsonResponse(req, map[string]any{
			"slug": answer.slug, "html_url": "https://github.com/apps/" + answer.slug,
			"owner": map[string]string{"login": "example-org"}, "permissions": answer.app, "events": []string{},
		})
	case strings.HasPrefix(req.URL.Path, "/app/installations/"):
		return jsonResponse(req, map[string]any{
			"account": map[string]string{"login": "example-org"}, "permissions": answer.installed,
			"events": []string{}, "repository_selection": answer.selection,
		})
	}
	return &http.Response{
		StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{"message":"Not Found"}`)),
		Header: http.Header{}, Request: req,
	}, nil
}

// appOfToken reads the App id out of an App's JWT, unverified: this GitHub
// only tells Apps apart, it does not check them.
func appOfToken(header string) int64 {
	parts := strings.Split(strings.TrimPrefix(header, "Bearer "), ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return 0
	}
	id, _ := strconv.ParseInt(claims.Issuer, 10, 64)
	return id
}

func jsonResponse(req *http.Request, body any) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(raw)),
		Header: http.Header{"Content-Type": []string{"application/json"}}, Request: req,
	}, nil
}
