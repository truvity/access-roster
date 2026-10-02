package verify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/access-roster/policy"
)

// AWSFederation is the set of AWS accounts whose roles may exchange their
// outbound identity federation token for one of this installation's. Like
// [Federation] it holds no secret: an account, a name and a URL per row.
type AWSFederation struct {
	// Audience the role must request from `sts:GetWebIdentityToken`.
	// Required whenever an account is listed; it is the trust boundary.
	Audience string `yaml:"audience"`
	// MaxAge rejects a token whose `iat` is older, whatever its `exp`
	// allows. Default 5m, at most 1h.
	MaxAge time.Duration `yaml:"maxAge,omitempty"`
	// Accounts are the trusted accounts. Empty is an installation with no
	// AWS proof, which is a real posture and not a failure.
	Accounts []AWSAccountRow `yaml:"accounts"`
}

// AWSAccountRow is one account's row.
type AWSAccountRow struct {
	// Account is the 12-digit AWS account id.
	Account string `yaml:"account"`
	// Name is the estate's own word for the account, for logs.
	Name string `yaml:"name"`
	// Issuer is the account's `iss`, from
	// `aws iam get-outbound-web-identity-federation-info`.
	Issuer string `yaml:"issuer"`
	// JWKSURI is where its keys are. Empty means
	// `{issuer}/.well-known/jwks.json`.
	JWKSURI string `yaml:"jwksUri,omitempty"`
	// OrgID, when set, must equal the token's `org_id` claim.
	OrgID string `yaml:"orgId,omitempty"`
	// Algs narrows the accepted algorithms. Default `[ES384, RS256]`.
	Algs []string `yaml:"algs,omitempty"`
}

// LoadAWSFederation reads the rows from a file the deployment mounted. An
// empty path is a deployment that federates no AWS account.
//
// As with [LoadFederation], a malformed file is a start-up failure: a row
// skipped would be an account whose roles stop being able to exchange
// with nothing to see but a refusal that names the wrong cause. Unknown
// keys are refused for the same reason, since a misspelt `orgId` would
// silently drop the check it was written for.
func LoadAWSFederation(path string) (AWSFederation, error) {
	if strings.TrimSpace(path) == "" {
		return AWSFederation{}, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is deployment configuration
	if err != nil {
		return AWSFederation{}, fmt.Errorf("read the AWS accounts from %s: %w", path, err)
	}
	var federation AWSFederation
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err = dec.Decode(&federation); err != nil && !errors.Is(err, io.EOF) {
		return AWSFederation{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err = federation.validate(); err != nil {
		return AWSFederation{}, fmt.Errorf("%s: %w", path, err)
	}
	return federation, nil
}

func (f *AWSFederation) validate() error {
	f.Audience = strings.TrimSpace(f.Audience)
	if len(f.Accounts) == 0 {
		return nil
	}
	if f.Audience == "" {
		return fmt.Errorf("an audience is required: without one every token any AWS account mints would be a proof")
	}
	if f.MaxAge < 0 || f.MaxAge > MaxAWSMaxAge {
		return fmt.Errorf("maxAge %s is outside 0..%s", f.MaxAge, MaxAWSMaxAge)
	}
	accounts, issuers, names := map[string]bool{}, map[string]string{}, map[string]bool{}
	for i := range f.Accounts {
		row := &f.Accounts[i]
		row.Account, row.Name = strings.TrimSpace(row.Account), strings.TrimSpace(row.Name)
		row.Issuer = strings.TrimSuffix(strings.TrimSpace(row.Issuer), "/")
		row.JWKSURI, row.OrgID = strings.TrimSpace(row.JWKSURI), strings.TrimSpace(row.OrgID)
		switch {
		case !policy.ValidAWSAccount(row.Account):
			return fmt.Errorf("account %d: %q is not a 12-digit AWS account id", i+1, row.Account)
		case row.Name == "":
			return fmt.Errorf("account %s names no name", row.Account)
		case accounts[row.Account]:
			return fmt.Errorf("account %s is listed twice", row.Account)
		case names[row.Name]:
			return fmt.Errorf("the name %q is used by two accounts", row.Name)
		}
		if err := requireHTTPS("issuer", row.Issuer); err != nil {
			return fmt.Errorf("account %s: %w", row.Account, err)
		}
		if row.JWKSURI != "" {
			if err := requireHTTPS("jwksUri", row.JWKSURI); err != nil {
				return fmt.Errorf("account %s: %w", row.Account, err)
			}
		}
		// Two rows for one issuer would let the first answer for every
		// token of it, so the second's account would never be reached.
		if other, clash := issuers[row.Issuer]; clash {
			return fmt.Errorf("accounts %s and %s both claim the issuer %s", other, row.Account, row.Issuer)
		}
		for _, alg := range row.Algs {
			if alg != AWSAlgES384 && alg != AWSAlgRS256 {
				return fmt.Errorf("account %s: algorithm %q is not one AWS signs with (%s, %s)",
					row.Account, alg, AWSAlgES384, AWSAlgRS256)
			}
		}
		accounts[row.Account], names[row.Name], issuers[row.Issuer] = true, true, row.Account
	}
	return nil
}

func requireHTTPS(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s %q is not an https URL", field, raw)
	}
	return nil
}

// Verifiers turns the rows into verifiers, one per account, each
// answering only for tokens carrying its own issuer.
func (f AWSFederation) Verifiers(httpClient *http.Client) []*AWSAccount {
	out := make([]*AWSAccount, 0, len(f.Accounts))
	for _, row := range f.Accounts {
		out = append(out, &AWSAccount{
			Account:  row.Account,
			Name:     row.Name,
			Issuer:   row.Issuer,
			JWKSURI:  row.JWKSURI,
			OrgID:    row.OrgID,
			Algs:     slices.Clone(row.Algs),
			Audience: f.Audience,
			MaxAge:   f.MaxAge,
			Client:   httpClient,
		})
	}
	return out
}

// Names lists the accounts, for the line an operator reads at start.
func (f AWSFederation) Names() []string {
	names := make([]string, 0, len(f.Accounts))
	for _, row := range f.Accounts {
		names = append(names, row.Name+" ("+row.Account+")")
	}
	return names
}
