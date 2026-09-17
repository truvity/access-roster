package githubapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// AppInfo is what GitHub says an App is, asked as the App.
type AppInfo struct {
	ID          int64
	Slug        string
	Owner       string
	HTMLURL     string
	Permissions map[string]string
	Events      []string
}

// GetApp reads the App the token belongs to: its permissions and events
// as GitHub holds them now, which an owner may have edited since it was
// created.
func GetApp(ctx context.Context, client *http.Client, appToken string) (AppInfo, error) {
	var body struct {
		ID      int64  `json:"id"`
		Slug    string `json:"slug"`
		HTMLURL string `json:"html_url"`
		Owner   struct {
			Login string `json:"login"`
		} `json:"owner"`
		Permissions map[string]string `json:"permissions"`
		Events      []string          `json:"events"`
	}
	if err := call(ctx, client, http.MethodGet, APIBase+"/app", appToken, http.StatusOK, &body); err != nil {
		return AppInfo{}, fmt.Errorf("github: read the App: %w", err)
	}
	return AppInfo{
		ID: body.ID, Slug: body.Slug, Owner: body.Owner.Login, HTMLURL: body.HTMLURL,
		Permissions: body.Permissions, Events: body.Events,
	}, nil
}

// InstallationInfo is one installation as GitHub holds it: the
// permissions its owner accepted, which lag the App's until they approve
// a change.
type InstallationInfo struct {
	ID                  int64
	Account             string
	Permissions         map[string]string
	Events              []string
	RepositorySelection string
	Suspended           bool
}

// ErrInstallationGone is an installation GitHub no longer has: somebody
// uninstalled the App on GitHub.
var ErrInstallationGone = errors.New("github: the installation no longer exists")

// GetInstallation reads one of the App's installations.
func GetInstallation(ctx context.Context, client *http.Client, appToken string, installation int64) (InstallationInfo, error) {
	var body struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
		Permissions         map[string]string `json:"permissions"`
		Events              []string          `json:"events"`
		RepositorySelection string            `json:"repository_selection"`
		SuspendedAt         *string           `json:"suspended_at"`
	}
	endpoint := APIBase + "/app/installations/" + strconv.FormatInt(installation, 10)
	err := call(ctx, client, http.MethodGet, endpoint, appToken, http.StatusOK, &body)
	if status := (*StatusError)(nil); errors.As(err, &status) && status.Code == http.StatusNotFound {
		return InstallationInfo{}, fmt.Errorf("%w: %d", ErrInstallationGone, installation)
	}
	if err != nil {
		return InstallationInfo{}, fmt.Errorf("github: read the installation: %w", err)
	}
	return InstallationInfo{
		ID: body.ID, Account: body.Account.Login, Permissions: body.Permissions, Events: body.Events,
		RepositorySelection: body.RepositorySelection, Suspended: body.SuspendedAt != nil && *body.SuspendedAt != "",
	}, nil
}
