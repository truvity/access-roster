package tokens

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ExecCredentialVersion is what kubectl has asked for since 1.22.
const ExecCredentialVersion = "client.authentication.k8s.io/v1"

// WriteExecCredential writes what `kubectl` reads from an exec plugin.
//
// The apiVersion is the plugin's contract with kubectl and not a detail:
// kubectl sets KUBERNETES_EXEC_INFO with the version it wants, and a
// plugin answering a different one is refused with a message about the
// version rather than about the token. So the caller passes back
// whatever kubectl asked for, and the constant above is the default.
//
// The expiry is what makes kubectl cache the credential instead of
// running the plugin on every API call. Omitting it works, and is slow
// in a way nobody attributes to the plugin.
func WriteExecCredential(w io.Writer, apiVersion string, token Token) error {
	if token.AccessToken == "" {
		return errors.New("tokens: no token to write")
	}
	if apiVersion == "" {
		apiVersion = ExecCredentialVersion
	}

	status := map[string]any{"token": token.AccessToken}
	if !token.Expires.IsZero() {
		status["expirationTimestamp"] = token.Expires.UTC().Format(time.RFC3339)
	}

	return json.NewEncoder(w).Encode(map[string]any{
		"apiVersion": apiVersion,
		"kind":       "ExecCredential",
		"status":     status,
	})
}

// Credentials are what STS hands back, and what the AWS SDKs expect from
// a credential process.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time
}

// WriteCredentialProcess writes what the AWS SDKs read from
// `credential_process`.
//
// `Version` is the NUMBER one and not a string; a document that gets
// that wrong is rejected with a parse error naming neither this tool nor
// the profile. The field names are capitalised exactly as written, for
// the same reason.
//
// It is real STS credentials rather than the issuer's token, because
// that is what a credential process returns. A token goes to AWS through
// [AssumeRoleWithWebIdentity] first — the profile's alternative,
// `web_identity_token_file`, would mean keeping a token on disk and
// refreshing it behind the SDK's back.
func WriteCredentialProcess(w io.Writer, creds Credentials) error {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("tokens: no credentials to write")
	}

	out := map[string]any{
		"Version":         1,
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
	}
	if creds.SessionToken != "" {
		out["SessionToken"] = creds.SessionToken
	}
	if !creds.Expires.IsZero() {
		out["Expiration"] = creds.Expires.UTC().Format(time.RFC3339)
	}

	return json.NewEncoder(w).Encode(out)
}

// STSEndpoint is where AssumeRoleWithWebIdentity is called. Global
// rather than regional because the call is unsigned and the credentials
// it returns work in every region.
//
// It is not configurable. An installation that could point it elsewhere
// is one values file away from sending every token to somebody else.
const STSEndpoint = "https://sts.amazonaws.com/"

// stsEndpoint is the same, as a variable a test can move.
var stsEndpoint = STSEndpoint

// AssumeRoleWithWebIdentity trades an issuer token for AWS credentials.
//
// **It is unsigned**, which is the whole reason this needs no AWS SDK
// and no stored key: the token IS the proof, and the account's trust
// policy decides what it opens by naming this issuer as an OIDC provider
// and matching the token's audience. That is why "no secret anywhere" is
// true of the AWS path and not just of ours.
//
// sessionName appears in CloudTrail against every call the credentials
// make, so it should name the person or the job rather than the tool.
func AssumeRoleWithWebIdentity(
	ctx context.Context, client *http.Client, roleARN, sessionName, token string,
) (Credentials, error) {
	switch {
	case strings.TrimSpace(roleARN) == "":
		return Credentials{}, errors.New("tokens: no role to assume")
	case strings.TrimSpace(token) == "":
		return Credentials{}, errors.New("tokens: no token to present")
	}
	if strings.TrimSpace(sessionName) == "" {
		// STS requires one, and an empty value is refused with a
		// validation error that does not say which field.
		sessionName = "access-roster"
	}

	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {roleARN},
		"RoleSessionName":  {sessionName},
		"WebIdentityToken": {token},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, stsEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Credentials{}, fmt.Errorf("tokens: build the STS call: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/xml")

	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return Credentials{}, fmt.Errorf("tokens: call STS: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Credentials{}, fmt.Errorf("tokens: read the STS answer: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Message string `xml:"Error>Message"`
			Code    string `xml:"Error>Code"`
		}
		_ = xml.Unmarshal(body, &failure)
		// STS says which of the three it was — the trust policy, the
		// audience, or the token — and that sentence is the whole value
		// of the error to whoever is reading it.
		detail := strings.TrimSpace(failure.Message)
		if detail == "" {
			detail = response.Status
		}
		return Credentials{}, fmt.Errorf("tokens: STS refused: %s (%s)", detail, failure.Code)
	}

	var answer struct {
		AccessKeyID     string `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
		SecretAccessKey string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
		SessionToken    string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
		Expiration      string `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
	}
	if err = xml.Unmarshal(body, &answer); err != nil {
		return Credentials{}, fmt.Errorf("tokens: parse the STS answer: %w", err)
	}
	if answer.AccessKeyID == "" {
		return Credentials{}, errors.New("tokens: STS returned no credentials")
	}

	out := Credentials{
		AccessKeyID:     answer.AccessKeyID,
		SecretAccessKey: answer.SecretAccessKey,
		SessionToken:    answer.SessionToken,
	}
	if answer.Expiration != "" {
		if at, parseErr := time.Parse(time.RFC3339, answer.Expiration); parseErr == nil {
			out.Expires = at
		}
	}
	return out, nil
}
