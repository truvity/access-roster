package verify

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Federation is the set of clusters whose ServiceAccount tokens this
// installation will act on. It is the whole of what makes one issuer
// serve many clusters, and it holds no secret: every row is a name and
// two URLs (INF-692).
type Federation struct {
	Clusters []FederatedCluster `yaml:"clusters"`
}

// FederatedCluster is one cluster's row.
type FederatedCluster struct {
	// Name is the estate's own word for the cluster — `kernel`, `devel`
	// — the same one that scopes a group name. It becomes the cluster in
	// a `workload` matcher and in the subject of the minted token, so a
	// row renamed is every rule about it changed.
	Name string `yaml:"name"`
	// Issuer is the `iss` its ServiceAccount tokens carry: for EKS the
	// cluster's OIDC provider URL, for Talos whatever
	// `--service-account-issuer` says.
	Issuer string `yaml:"issuer"`
	// JWKSURI is where its public keys are. Empty discovers it from the
	// issuer, which works wherever the cluster publishes a discovery
	// document at an address this service can reach.
	JWKSURI string `yaml:"jwksUri,omitempty"`
}

// LoadFederation reads the rows from a file the deployment mounted.
//
// It is a file and not an environment variable because a list of objects
// in one is a format somebody has to invent, and every reader of it
// afterwards has to agree with. An empty path is a deployment that
// federates no cluster, which is a real posture and not a failure.
//
// A malformed file is a START-UP failure, deliberately. A row skipped
// would be a cluster whose workloads stop being able to exchange, with
// nothing to see but a refusal that names the wrong cause.
func LoadFederation(path string) (Federation, error) {
	if strings.TrimSpace(path) == "" {
		return Federation{}, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is deployment configuration
	if err != nil {
		return Federation{}, fmt.Errorf("read the federated clusters from %s: %w", path, err)
	}
	var federation Federation
	if err = yaml.Unmarshal(raw, &federation); err != nil {
		return Federation{}, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]string{}
	for i, row := range federation.Clusters {
		switch {
		case strings.TrimSpace(row.Name) == "":
			return Federation{}, fmt.Errorf("%s: cluster %d names no cluster", path, i+1)
		case strings.TrimSpace(row.Issuer) == "":
			// Without an issuer nothing can decide whether a token is
			// this row's to judge, so the row would silently verify
			// nothing at all.
			return Federation{}, fmt.Errorf("%s: cluster %q names no issuer", path, row.Name)
		}
		// Two rows for one issuer is ambiguous in the one way that
		// matters: the first would answer for every token of it, so the
		// second's name would never reach a matcher, and a rule written
		// against that name would grant nothing with no reason visible.
		if other, clash := seen[row.Issuer]; clash {
			return Federation{}, fmt.Errorf(
				"%s: %q and %q both claim the issuer %s", path, other, row.Name, row.Issuer)
		}
		seen[row.Issuer] = row.Name
	}
	return federation, nil
}

// Verifiers turns the rows into verifiers, one per cluster, each
// answering only for tokens carrying its own issuer.
func (f Federation) Verifiers(audience string, httpClient *http.Client) []*Cluster {
	out := make([]*Cluster, 0, len(f.Clusters))
	for _, row := range f.Clusters {
		out = append(out, &Cluster{
			Name:     strings.TrimSpace(row.Name),
			Issuer:   strings.TrimSpace(row.Issuer),
			JWKSURI:  strings.TrimSpace(row.JWKSURI),
			Audience: audience,
			Client:   httpClient,
		})
	}
	return out
}

// Names lists the clusters, for the line an operator reads at start.
func (f Federation) Names() []string {
	names := make([]string, 0, len(f.Clusters))
	for _, row := range f.Clusters {
		names = append(names, row.Name)
	}
	return names
}
