package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// The signing algorithms AWS signs an outbound identity federation token
// with. `GetWebIdentityToken` takes exactly these two, so an account row
// can only ever narrow this set, never widen it.
const (
	AWSAlgES384 = "ES384"
	AWSAlgRS256 = "RS256"
)

// Defaults and bounds for [AWSAccount].
const (
	// DefaultAWSMaxAge is how old a token may be, by its `iat`, whatever
	// its `exp` allows. AWS lets a token live for an hour, and nothing here
	// needs one that long: the exchange happens at once, and the token it
	// is exchanged for is the thing that is kept.
	DefaultAWSMaxAge = 5 * time.Minute
	// MaxAWSMaxAge is the longest age a deployment may configure: AWS's
	// own ceiling on a token's lifetime.
	MaxAWSMaxAge = time.Hour

	defaultKeyRefresh = 10 * time.Second
	keySetTTL         = time.Hour
	clockLeeway       = 30 * time.Second
	maxKeySetBytes    = 1 << 20
)

// AWSAccount verifies the token an AWS IAM role gets from
// `sts:GetWebIdentityToken` (outbound identity federation) for ONE AWS
// account, against the key set that account's own issuer publishes.
//
// It is the third sibling of [Cluster] and [GitHub], and carries the same
// two kinds of trust boundary:
//
// **The account row.** Anybody can open an AWS account, enable outbound
// federation and mint a perfectly valid token for a role of their own
// with any audience they like. Signature and expiry therefore prove only
// that SOME AWS account vouched for the role. What makes it ours is that
// the token's issuer is one this installation was told to trust, and that
// the account the token claims (`aws_account`), the account in the role's
// ARN and the account the row names are all the same. There is no default
// account.
//
// **The audience.** A token for another service is a valid token, so the
// audience must equal the one configured, exactly.
//
// On top of those, a token older than MaxAge by its `iat` is refused even
// though `exp` still allows it, and the algorithm is pinned to the row's
// list rather than read from the token's header.
//
// The identity is the IAM ROLE. Which function, instance or task is
// running as it is the account owner's concern; the function ARN a Lambda
// token carries is passed on for audit and for a matcher that asks for it,
// and is never the subject.
type AWSAccount struct {
	// Account is the 12-digit AWS account id this row trusts.
	Account string
	// Name is the estate's word for the account, for the logs.
	Name string
	// Issuer is the account's `iss`:
	// `https://<id>.tokens.sts.global.api.aws`, from
	// `aws iam get-outbound-web-identity-federation-info`.
	Issuer string
	// JWKSURI is where the issuer publishes its keys. Empty means
	// `{Issuer}/.well-known/jwks.json`, which is where AWS puts them.
	JWKSURI string
	// OrgID, when set, is the AWS Organizations id the token's `org_id`
	// claim must carry.
	OrgID string
	// Algs are the signature algorithms accepted. Empty means both
	// [AWSAlgES384] and [AWSAlgRS256].
	Algs []string
	// Audience the role must have requested from STS. Required: without
	// one nothing is verified.
	Audience string
	// MaxAge rejects a token whose `iat` is older. Zero means
	// [DefaultAWSMaxAge].
	MaxAge time.Duration
	// Client fetches the keys. Nil means [http.DefaultClient].
	Client *http.Client
	// KeyRefresh is the shortest time between two fetches of the key set
	// caused by an unknown `kid`; without it a caller could make this
	// service hammer AWS with tokens naming keys that do not exist. Zero
	// means ten seconds.
	KeyRefresh time.Duration
	// Now is the clock. Nil means [time.Now].
	Now func() time.Time

	mu      sync.Mutex
	keys    map[string]jose.JSONWebKey
	fetched time.Time
}

var _ issuer.Verifier = (*AWSAccount)(nil)

// errAWSRefused marks a token this verifier owned and rejected, so that
// [issuer.Verifiers] stops rather than trying it as something else.
var errAWSRefused = errors.New("aws")

// Verify implements [issuer.Verifier].
//
// A token whose `iss` is not this row's comes back [issuer.ErrUnverified],
// so the next verifier may try it. One that names this row's issuer and
// fails anything after that is a final refusal.
func (a *AWSAccount) Verify(ctx context.Context, token, tokenType string) (issuer.Proof, error) {
	switch {
	case a == nil || a.Issuer == "" || a.Audience == "" || a.Account == "":
		return issuer.Proof{}, issuer.ErrUnverified
	case tokenType != "" && tokenType != TypeAccessToken && tokenType != TypeJWT:
		return issuer.Proof{}, issuer.ErrUnverified
	case unverifiedIssuer(token) != a.Issuer:
		return issuer.Proof{}, issuer.ErrUnverified
	}

	algs, err := a.joseAlgs()
	if err != nil {
		return issuer.Proof{}, fmt.Errorf("verify a token from %s: %w", a.label(), err)
	}
	parsed, err := jwt.ParseSigned(token, algs)
	if err != nil {
		// Wrong algorithm for this row (`none`, HS256, ES256...) and a
		// malformed token land here alike.
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s is not signed with an accepted algorithm: %w",
			errAWSRefused, a.label(), err)
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID == "" {
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s names no signing key", errAWSRefused, a.label())
	}
	header := parsed.Headers[0]

	key, found, err := a.key(ctx, header.KeyID)
	if err != nil {
		// Reaching AWS's keys failed. That is this installation's problem
		// and not the caller's, so it must not read as "your token is
		// bad" — nor fall through to another verifier.
		return issuer.Proof{}, fmt.Errorf("verify a token from %s: %w", a.label(), err)
	}
	if !found {
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s is signed with a key its issuer does not publish",
			errAWSRefused, a.label())
	}
	if key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s uses %s with a key published for %s",
			errAWSRefused, a.label(), header.Algorithm, key.Algorithm)
	}

	var claims awsClaims
	if err = parsed.Claims(key.Key, &claims); err != nil {
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s did not verify: %w", errAWSRefused, a.label(), err)
	}

	if err = a.checkTimes(claims); err != nil {
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s %w", errAWSRefused, a.label(), err)
	}
	if !slices.Contains(claims.Audience, a.Audience) {
		return issuer.Proof{}, fmt.Errorf("%w: that token was minted for another audience", errAWSRefused)
	}

	ns := claims.AWS
	if ns.Account != a.Account {
		// The row, not the token, names the account. A token whose issuer
		// is this row's but whose claim says another account is not
		// something AWS mints; refusing it costs nothing.
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s claims account %q, the row trusts %q",
			errAWSRefused, a.label(), ns.Account, a.Account)
	}
	if a.OrgID != "" && ns.OrgID != a.OrgID {
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s is for organization %q, the row requires %q",
			errAWSRefused, a.label(), ns.OrgID, a.OrgID)
	}

	role, err := ParseAWSRoleARN(claims.Subject)
	if err != nil {
		return issuer.Proof{}, fmt.Errorf("%w: the token from %s: %w", errAWSRefused, a.label(), err)
	}
	if role.Account != a.Account {
		return issuer.Proof{}, fmt.Errorf("%w: the role %s is in account %s, the issuer is account %s's",
			errAWSRefused, claims.Subject, role.Account, a.Account)
	}
	role.OrgID = ns.OrgID
	role.Function = ns.LambdaSourceFunctionARN

	return issuer.Proof{AWS: &role}, nil
}

// awsClaims is the part of the token this verifier reads.
type awsClaims struct {
	Issuer    string           `json:"iss"`
	Subject   string           `json:"sub"`
	Audience  audienceList     `json:"aud"`
	Expiry    *jwt.NumericDate `json:"exp"`
	NotBefore *jwt.NumericDate `json:"nbf"`
	IssuedAt  *jwt.NumericDate `json:"iat"`
	// AWS is everything AWS nests under the `https://sts.amazonaws.com/`
	// claim: what is about AWS rather than about JWTs.
	AWS struct {
		Account                 string `json:"aws_account"`
		OrgID                   string `json:"org_id"`
		LambdaSourceFunctionARN string `json:"lambda_source_function_arn"`
	} `json:"https://sts.amazonaws.com/"`
}

// audienceList reads `aud` as either a string or a list, which RFC 7519
// allows and AWS's documentation shows as a string.
type audienceList []string

// UnmarshalJSON implements [json.Unmarshaler].
func (l *audienceList) UnmarshalJSON(raw []byte) error {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		*l = audienceList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return fmt.Errorf("aud is neither a string nor a list of strings: %w", err)
	}
	*l = many
	return nil
}

func (a *AWSAccount) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *AWSAccount) maxAge() time.Duration {
	if a.MaxAge > 0 {
		return a.MaxAge
	}
	return DefaultAWSMaxAge
}

// checkTimes enforces `exp`, `nbf`, `iat` and the maximum age. All three
// of `exp` and `iat` are required: AWS always sets them, and a token
// without them has no age to measure.
func (a *AWSAccount) checkTimes(c awsClaims) error {
	now := a.now()
	switch {
	case c.Expiry == nil:
		return errors.New("has no expiry")
	case c.IssuedAt == nil:
		return errors.New("has no issue time")
	case !now.Before(c.Expiry.Time().Add(clockLeeway)):
		return errors.New("has expired")
	case c.NotBefore != nil && now.Add(clockLeeway).Before(c.NotBefore.Time()):
		return errors.New("is not valid yet")
	case now.Add(clockLeeway).Before(c.IssuedAt.Time()):
		return errors.New("was issued in the future")
	case now.Sub(c.IssuedAt.Time()) > a.maxAge():
		return fmt.Errorf("is older than the %s this installation accepts", a.maxAge())
	}
	return nil
}

func (a *AWSAccount) label() string {
	if a.Name != "" {
		return a.Name
	}
	return a.Account
}

func (a *AWSAccount) joseAlgs() ([]jose.SignatureAlgorithm, error) {
	names := a.Algs
	if len(names) == 0 {
		names = []string{AWSAlgES384, AWSAlgRS256}
	}
	out := make([]jose.SignatureAlgorithm, 0, len(names))
	for _, name := range names {
		if name != AWSAlgES384 && name != AWSAlgRS256 {
			return nil, fmt.Errorf("algorithm %q is not one AWS signs with", name)
		}
		out = append(out, jose.SignatureAlgorithm(name))
	}
	return out, nil
}

// unverifiedIssuer reads the token's `iss` WITHOUT trusting it, only to
// decide whether this verifier is the one that should answer. Nothing is
// granted on the strength of it: the signature is what makes it true.
func unverifiedIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Issuer
}

// key returns the published key with this id. The set is fetched on first
// use, again when it is older than an hour, and again — at most once per
// KeyRefresh — when a token names a key not in it, which is what makes
// AWS's key rotation a non-event here.
func (a *AWSAccount) key(ctx context.Context, kid string) (jose.JSONWebKey, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	stale := a.keys == nil || now.Sub(a.fetched) > keySetTTL
	if key, ok := a.keys[kid]; ok && !stale {
		return key, true, nil
	}
	interval := a.KeyRefresh
	if interval == 0 {
		interval = defaultKeyRefresh
	}
	if a.keys != nil && now.Sub(a.fetched) < interval {
		// Fetched a moment ago and still no such key: it does not exist.
		key, ok := a.keys[kid]
		return key, ok, nil
	}
	if err := a.fetch(ctx); err != nil {
		if key, ok := a.keys[kid]; ok {
			// Keep serving from what was fetched rather than fail every
			// exchange while AWS's endpoint is unreachable.
			return key, true, nil
		}
		return jose.JSONWebKey{}, false, err
	}
	a.fetched = now
	key, ok := a.keys[kid]
	return key, ok, nil
}

// fetch replaces the cached key set. The caller holds the lock.
func (a *AWSAccount) fetch(ctx context.Context) error {
	uri := a.JWKSURI
	if uri == "" {
		uri = strings.TrimSuffix(a.Issuer, "/") + "/.well-known/jwks.json"
	}
	httpClient := a.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", uri, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: %s", uri, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes))
	if err != nil {
		return fmt.Errorf("read %s: %w", uri, err)
	}
	var set jose.JSONWebKeySet
	if err = json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("parse %s: %w", uri, err)
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for i := range set.Keys {
		key := &set.Keys[i]
		if key.KeyID != "" && key.Valid() && key.IsPublic() {
			keys[key.KeyID] = *key
		}
	}
	a.keys = keys
	return nil
}

// awsNameSegment is what an IAM role name, and each element of its path,
// is made of. IAM allows a path any printable ASCII; this is the subset
// every real one uses, and anything else is refused rather than guessed.
var awsNameSegment = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]+$`)

// ParseAWSRoleARN reads the `sub` of an outbound identity federation token
// as an IAM role: `arn:aws:iam::<account>:role/<path><name>`.
//
// THE DECISION. AWS documents `sub` as "the ARN of the IAM principal that
// requested the token" and every example it gives (the token claims page,
// the getting-started guide, the announcement) is the role ARN of the
// principal, with the account and a role path shown as `role/<name>` — never the
// `arn:aws:sts::<account>:assumed-role/<name>/<session>` form that
// `sts:GetCallerIdentity` returns for the same caller. Nothing in the
// documentation says `sub` can take the assumed-role form, so this parser
// does NOT accept it: it is refused with an error saying so. The session
// name is chosen by whoever assumes the role, so a rule that depended on
// it would be a rule its caller can write; the role is the identity.
// Should AWS ever document the session form, accepting it is a one-line
// change in this function and a new test, not a configuration option.
//
// Users, the account root, federated users and every other ARN are
// refused. So is any partition but `aws`.
func ParseAWSRoleARN(arn string) (policy.AWSRole, error) {
	const iamPrefix = "arn:aws:iam::"
	if strings.HasPrefix(arn, "arn:aws:sts::") && strings.Contains(arn, ":assumed-role/") {
		return policy.AWSRole{}, errors.New(
			"the subject is an assumed-role session, which AWS does not document as a token subject: only a role ARN is accepted")
	}
	rest, ok := strings.CutPrefix(arn, iamPrefix)
	if !ok {
		return policy.AWSRole{}, errors.New("the subject is not an IAM ARN in the aws partition")
	}
	account, resource, ok := strings.Cut(rest, ":")
	if !ok || !policy.ValidAWSAccount(account) {
		return policy.AWSRole{}, errors.New("the subject names no 12-digit account")
	}
	elements, ok := strings.CutPrefix(resource, "role/")
	if !ok {
		return policy.AWSRole{}, errors.New("the subject is not an IAM role")
	}
	segments := strings.Split(elements, "/")
	for _, segment := range segments {
		if !awsNameSegment.MatchString(segment) {
			return policy.AWSRole{}, errors.New("the subject's role name or path is malformed")
		}
	}
	name := segments[len(segments)-1]
	path := "/"
	if len(segments) > 1 {
		path = "/" + strings.Join(segments[:len(segments)-1], "/") + "/"
	}
	if len(name) > 64 || len(path) > 512 {
		return policy.AWSRole{}, errors.New("the subject's role name or path is too long")
	}

	return policy.AWSRole{Account: account, Path: path, Name: name}, nil
}
