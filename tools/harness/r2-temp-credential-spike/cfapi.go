package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The shapes of the Cloudflare API calls below are READ from Cloudflare's public API reference and have not
// been run by this tool's author (UNVERIFIED until the first run of the spike): a run with -n 2 answers it.

// permissionObjectReadWrite is the temp-access-credentials permission that allows reading, writing and
// deleting objects (the values are admin-read-write, admin-read-only, object-read-write, object-read-only).
const permissionObjectReadWrite = "object-read-write"

// cfAPI calls the Cloudflare REST API with a bearer token.
type cfAPI struct {
	hc      *http.Client
	base    string // https://api.cloudflare.com/client/v4
	account string
	red     *redactor
}

type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// call sends one request. label names the call in errors (the path holds the account id). in, when not nil,
// is the JSON body; out, when not nil, receives the result.
func (a *cfAPI) call(ctx context.Context, bearer secret, method, label, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return fmt.Errorf("cloudflare %s: %s", label, a.red.clean(err.Error()))
	}
	req.Header.Set("Authorization", "Bearer "+string(bearer))
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare %s: %s", label, a.red.clean(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("cloudflare %s: reading the answer: %s", label, a.red.clean(err.Error()))
	}
	var env cfEnvelope
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode/100 != 2 || !env.Success {
		var parts []string
		for _, e := range env.Errors {
			parts = append(parts, strconv.Itoa(e.Code)+" "+a.red.clean(e.Message))
		}
		return fmt.Errorf("cloudflare %s: HTTP %d: %s", label, resp.StatusCode, strings.Join(parts, "; "))
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("cloudflare %s: the result has an unexpected shape", label)
		}
	}
	return nil
}

// verifyTokenID returns the id of the token the bearer is. The id is the access key id of an R2 API token,
// which temp-access-credentials asks for as the parent. An account-owned token is verified at the account, a
// user token at /user.
func (a *cfAPI) verifyTokenID(ctx context.Context, token secret) (secret, error) {
	var res struct {
		ID string `json:"id"`
	}
	err := a.call(ctx, token, http.MethodGet, "verify token (account)", "/accounts/"+url.PathEscape(a.account)+"/tokens/verify", nil, &res)
	if err != nil || res.ID == "" {
		err = a.call(ctx, token, http.MethodGet, "verify token (user)", "/user/tokens/verify", nil, &res)
	}
	if err != nil {
		return "", err
	}
	if res.ID == "" {
		return "", errors.New("cloudflare verify token: the answer has no id; set SLUIS_SPIKE_R2_PARENT_KEY_ID")
	}
	return secret(res.ID), nil
}

// mintTemp creates one temporary credential, scoped to the bucket and to the prefix, with a time to live of
// ttl: POST /accounts/{id}/r2/temp-access-credentials.
func (a *cfAPI) mintTemp(ctx context.Context, parent secret, parentKeyID secret, bucket, prefix string, ttl time.Duration) (credentials, error) {
	in := map[string]any{
		"bucket":            bucket,
		"parentAccessKeyId": string(parentKeyID),
		"permission":        permissionObjectReadWrite,
		"ttlSeconds":        int(ttl / time.Second),
		"prefixes":          []string{prefix},
	}
	var out struct {
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
		SessionToken    string `json:"sessionToken"`
	}
	if err := a.call(ctx, parent, http.MethodPost, "mint temp credential", "/accounts/"+url.PathEscape(a.account)+"/r2/temp-access-credentials", in, &out); err != nil {
		return credentials{}, err
	}
	c := credentials{AccessKeyID: secret(out.AccessKeyID), Secret: secret(out.SecretAccessKey), SessionToken: secret(out.SessionToken)}
	if c.AccessKeyID == "" || c.Secret == "" || c.SessionToken == "" {
		return credentials{}, errors.New("cloudflare mint temp credential: the result lacks a field")
	}
	a.red.addCredentials(c)
	return c, nil
}

// permissionGroupID finds the id of a permission group by its name:
// GET /accounts/{id}/tokens/permission_groups.
func (a *cfAPI) permissionGroupID(ctx context.Context, creator secret, name string) (string, error) {
	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := a.call(ctx, creator, http.MethodGet, "list permission groups", "/accounts/"+url.PathEscape(a.account)+"/tokens/permission_groups", nil, &groups); err != nil {
		return "", err
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare list permission groups: no group named %q", name)
}

// apiToken is a token created for the comparison arm.
type apiToken struct {
	ID    string
	creds credentials
}

// createToken creates an API token that can read and write the objects of one bucket (the v1 mechanism) and
// derives its S3 credential as R2 documents it: the access key id is the token's id, the secret access key is
// the SHA-256 of the token's value: POST /accounts/{id}/tokens.
func (a *cfAPI) createToken(ctx context.Context, creator secret, name, groupID, bucket string, ttl time.Duration) (apiToken, error) {
	resource := "com.cloudflare.edge.r2.bucket." + a.account + "_default_" + bucket
	in := map[string]any{
		"name": name,
		"policies": []any{map[string]any{
			"effect":            "allow",
			"resources":         map[string]string{resource: "*"},
			"permission_groups": []any{map[string]string{"id": groupID}},
		}},
		"expires_on": time.Now().UTC().Add(ttl + time.Minute).Format(time.RFC3339),
	}
	var out struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	if err := a.call(ctx, creator, http.MethodPost, "create token", "/accounts/"+url.PathEscape(a.account)+"/tokens", in, &out); err != nil {
		return apiToken{}, err
	}
	if out.ID == "" || out.Value == "" {
		return apiToken{}, errors.New("cloudflare create token: the result lacks a field")
	}
	sum := sha256.Sum256([]byte(out.Value))
	t := apiToken{ID: out.ID, creds: credentials{AccessKeyID: secret(out.ID), Secret: secret(hex.EncodeToString(sum[:]))}}
	a.red.add(out.Value, "<token-value>")
	a.red.addCredentials(t.creds)
	return t, nil
}

// deleteToken revokes a token the tool created: DELETE /accounts/{id}/tokens/{id}.
func (a *cfAPI) deleteToken(ctx context.Context, creator secret, id string) error {
	return a.call(ctx, creator, http.MethodDelete, "delete token", "/accounts/"+url.PathEscape(a.account)+"/tokens/"+url.PathEscape(id), nil, nil)
}
