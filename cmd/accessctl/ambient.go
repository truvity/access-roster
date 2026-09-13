package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// The two variables GitHub Actions sets in a job granted `id-token: write`.
// Their presence is what makes a run a job rather than a laptop: no
// person's shell has them, and a job without the permission has neither.
const (
	envGitHubTokenURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	envGitHubTokenGrant = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// proof is what a command exchanges for its audience, and the client it
// presents while doing so.
type proof struct {
	// Subject is the token to exchange.
	Subject string
	// Client is presented in Basic. For a person it is the client they
	// signed in as; for a job it is the audience itself, exactly as the
	// root action presents it, because a job never signed in to anything.
	Client string
	// Name is who the token is about, for a session name the cloud shows.
	Name string
}

// proofFor is the one place a command decides whose token it is holding.
//
// In a GitHub Actions job it is the job's own identity token, minted for
// the issuer; anywhere else it is the cached sign-in, refreshed. That is
// what lets ONE committed kubeconfig and ONE aws.ini serve a laptop and a
// job alike: the same `accessctl kube-token` / `accessctl aws` line runs in
// both, and only the proof behind it differs. Before this, a repository
// kept a second copy of each file for CI.
func proofFor(ctx context.Context, cfg Config, audience string) (proof, error) {
	if requestURL, grant := os.Getenv(envGitHubTokenURL), os.Getenv(envGitHubTokenGrant); requestURL != "" && grant != "" {
		subject, err := githubToken(ctx, requestURL, grant, cfg.Issuer)
		if err != nil {
			return proof{}, err
		}
		return proof{Subject: subject, Client: audience, Name: githubSessionName()}, nil
	}

	own, err := refresh(ctx, cfg)
	if err != nil {
		return proof{}, err
	}
	session, _ := loadSession()
	name := session.Email
	if name == "" {
		name = session.Subject
	}
	return proof{Subject: own.AccessToken, Client: cfg.ClientID, Name: name}, nil
}

// githubToken asks the job's token service for an identity token whose
// audience is the issuer — the audience the issuer requires, and the only
// one it accepts, so a token minted for anything else cannot be replayed
// here.
func githubToken(ctx context.Context, requestURL, grant, issuer string) (string, error) {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s is not a URL: %w", errUnreachable, envGitHubTokenURL, err)
	}
	query := parsed.Query()
	query.Set("audience", issuer)
	parsed.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", fmt.Errorf("%w: build the GitHub token request: %w", errUnreachable, err)
	}
	request.Header.Set("Authorization", "bearer "+grant)
	request.Header.Set("Accept", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: ask GitHub for the job's token: %w", errUnreachable, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("%w: read the job's token: %w", errUnreachable, err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: GitHub answered %s for the job's token", errUnreachable, response.Status)
	}

	var answer struct {
		Value string `json:"value"`
	}
	if err = json.Unmarshal(body, &answer); err != nil || strings.TrimSpace(answer.Value) == "" {
		return "", errors.Join(errUnreachable, errors.New("GitHub returned no identity token for this job"))
	}
	return answer.Value, nil
}

// githubSessionName names a job the way its token does: by repository.
func githubSessionName() string {
	if repository := os.Getenv("GITHUB_REPOSITORY"); repository != "" {
		return "github-" + strings.ReplaceAll(repository, "/", "-")
	}
	return "github"
}
