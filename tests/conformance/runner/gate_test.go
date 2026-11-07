package main

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// The tests below are the proof of the requirements that the OpenID Foundation conformance suite is named for. They read
// results.json of a run (SLUIS_OIDF_RESULTS names the file, which tests/conformance/run.sh makes and the workflow
// Conformance passes on) and say which condition of which module the suite must have judged a success for the requirement to
// hold. Without that file they skip, which is why the Conformance workflow fails when any of them skips: a skipped test proves
// nothing, and the workflow counts passes (tests/conformance/run.sh, "the gate").
//
// The conditions are the suite's own: the Java classes that the module calls, named by their class (the "src" of the log
// line). A condition counts as passed when the suite logged it as a success; a condition that logs "nothing to check" as
// information, such as ValidateIssIfPresentInAuthorizationResponse for a response with no iss, is not a success, so a
// response that lacks iss does not pass.

// results is a run read from SLUIS_OIDF_RESULTS.
type runResults map[string]outcome // by plan/module

func loadRunResults(t *testing.T) runResults {
	t.Helper()
	path := os.Getenv("SLUIS_OIDF_RESULTS")
	if path == "" {
		t.Skip("SLUIS_OIDF_RESULTS is not set: the conformance suite did not run here (the Conformance workflow sets it)")
	}
	b, err := os.ReadFile(path) //nolint:gosec // the run's own file
	if err != nil {
		t.Fatal(err)
	}
	var rf runFile
	if err := json.Unmarshal(b, &rf); err != nil {
		t.Fatal(err)
	}
	return indexOutcomes(rf.Outcomes)
}

// loadProbes is the probes of the same run: the requests of the runner's own.
func loadProbes(t *testing.T) []probeResult {
	t.Helper()
	path := os.Getenv("SLUIS_OIDF_RESULTS")
	if path == "" {
		t.Skip("SLUIS_OIDF_RESULTS is not set: the conformance suite did not run here (the Conformance workflow sets it)")
	}
	b, err := os.ReadFile(path) //nolint:gosec // the run's own file
	if err != nil {
		t.Fatal(err)
	}
	var rf runFile
	if err := json.Unmarshal(b, &rf); err != nil {
		t.Fatal(err)
	}
	return rf.Probes
}

// probed fails the test unless a probe whose name contains each of these words ran and passed.
func probed(t *testing.T, probes []probeResult, words ...string) {
	t.Helper()
	for _, w := range words {
		found := false
		for _, p := range probes {
			if strings.Contains(p.Name, w) {
				found = true
				if !p.Passed {
					t.Errorf("probe %q failed: %s", p.Name, p.Seen)
				}
			}
		}
		if !found {
			t.Errorf("no probe named %q ran", w)
		}
	}
}

func indexOutcomes(os []outcome) runResults {
	r := runResults{}
	for _, o := range os {
		r[o.Plan+"/"+o.Module] = o
	}
	return r
}

// passed fails the test unless the module ran in the plan, ended as a pass the suite can give (PASSED, or WARNING with the
// warnings the table lists) and the suite judged each named condition a success and none of them a failure.
func (r runResults) passed(t *testing.T, plan, module string, conditions ...string) {
	t.Helper()
	if msg := r.why(plan, module, conditions); msg != "" {
		t.Errorf("%s", msg)
	}
}

func (r runResults) why(plan, module string, conditions []string) string {
	o, ok := r[plan+"/"+module]
	if !ok {
		return plan + "/" + module + ": the module did not run"
	}
	if o.Result != "PASSED" && o.Result != "WARNING" {
		return plan + "/" + module + ": the module ended " + o.Result + ", and a requirement is not proved by a module that did not pass"
	}
	var bad []string
	for _, c := range conditions {
		switch {
		case slices.Contains(o.Failures, c):
			bad = append(bad, c+" failed")
		case !slices.Contains(o.Passed, c):
			bad = append(bad, c+" was not judged a success")
		}
	}
	if len(bad) > 0 {
		return plan + "/" + module + ": " + strings.Join(bad, ", ")
	}
	return ""
}

const pkceModule = "oidcc-ensure-request-with-valid-pkce-succeeds"

// The ID token of the full code flow, signed in by a person and redeemed at the token endpoint, has an issuer equal to the
// one in discovery, an audience that is the client, an exp, an iat and a sub, and a signature that verifies against the key
// set the issuer publishes. The suite checks these in ValidateIdToken (iss against the discovered issuer, aud against the
// client id, exp and iat against the clock), CheckForSubjectInIdToken and ValidateIdTokenSignature.
//
// verifies: REQ-TOKEN-013
func TestIDTokenCarriesIssSubAudExpIatThatTheSuiteValidates(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "ValidateIdToken", "CheckForSubjectInIdToken", "ValidateIdTokenSignature", "ValidateIdTokenStandardClaims")
	}
}

// The client sent a nonce (AddNonceToAuthorizationEndpointRequest) and the ID token carries the same one: the suite's
// ValidateIdTokenNonce logs a success for "Nonce values match" only when a nonce was sent and the token has it.
//
// verifies: REQ-TOKEN-030
func TestIDTokenCarriesTheNonceOfTheRequest(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "AddNonceToAuthorizationEndpointRequest", "ValidateIdTokenNonce")
	}
}

// The token endpoint answers the authorization code request with a JSON body that holds the access token and the ID token: the
// suite reads them from the parsed body (CallTokenEndpointAndReturnFullResponse, ExtractAccessTokenFromTokenResponse,
// ExtractIdTokenFromTokenResponse) and checks the status (CheckTokenEndpointHttpStatus200). The suite does not look at the content
// type, and it never sees an error response of the token endpoint; the runner's probes do: a success and each refusal (a wrong
// verifier, no verifier, a verifier that is the challenge) answer with application/json and Cache-Control: no-store.
//
// verifies: REQ-TOKEN-010
func TestTokenEndpointAnswersJSONThatIsNotCached(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "CallTokenEndpointAndReturnFullResponse", "CheckTokenEndpointHttpStatus200",
			"ExtractAccessTokenFromTokenResponse", "ExtractIdTokenFromTokenResponse", "ValidateExpiresIn")
	}
	probed(t, loadProbes(t), "token: a wrong code_verifier", "token: no code_verifier", "token: the verifier that is the challenge itself", "token: the right code_verifier")
}

// The authorization response carries iss, and it is the issuer of discovery, in the cases measured: a code (the suite's
// ValidateIssIfPresentInAuthorizationResponse logs a success only for an iss that is present and equal, in the module whose
// answer is a code and in the one whose answer is an error, a request with no response_type) and four errors of the runner's
// probes (no challenge, the method plain, an unsupported response_type, no response_type), each with the issuer and the
// client's state. Other errors are not sampled; the row says so.
//
// verifies: REQ-AUTHN-005
func TestAuthorizationResponsesCarryTheIssuer(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "ValidateIssIfPresentInAuthorizationResponse")
		r.passed(t, plan, "oidcc-response-type-missing", "ValidateIssIfPresentInAuthorizationResponse", "EnsureErrorFromAuthorizationEndpointResponse")
	}
	probed(t, loadProbes(t), "authorize: no code_challenge is refused", "authorize: code_challenge_method=plain is refused",
		"authorize: an unsupported response_type is refused", "authorize: no response_type is refused")
}

// The issuer of the discovery document is the one in the ID token's iss and in the authorization response's iss, and the
// document is served at the address its issuer names: ValidateIdToken compares the token's iss with the discovered issuer,
// ValidateIssIfPresentInAuthorizationResponse the response's, and CheckDiscEndpointIssuer and CheckDiscEndpointDiscoveryUrl
// the issuer with the address of the document (Config OP, whose other condition, RS256, is in the table as a failure).
//
// verifies: REQ-AUTHN-030
func TestTheIssuerOfDiscoveryIsTheIssuerOfTheTokenAndTheResponse(t *testing.T) {
	r := loadRunResults(t)
	r.passed(t, "basic", pkceModule, "ValidateIdToken", "ValidateIssIfPresentInAuthorizationResponse")
	r.passedConditionsOfAFailedModule(t, "config", "oidcc-discovery-endpoint-verification",
		"CheckDiscEndpointIssuer", "CheckDiscEndpointDiscoveryUrl", "CheckDiscEndpointIssuerIsValidUrl")
}

// passedConditionsOfAFailedModule is for a module the table expects to fail on other conditions: the named conditions are
// judged successes, and the failing ones are exactly those of the table (the run is also held to the table by the runner).
func (r runResults) passedConditionsOfAFailedModule(t *testing.T, plan, module string, conditions ...string) {
	t.Helper()
	o, ok := r[plan+"/"+module]
	if !ok {
		t.Errorf("%s/%s: the module did not run", plan, module)
		return
	}
	if o.Result != "PASSED" && o.Result != "WARNING" && o.Result != "FAILED" {
		t.Errorf("%s/%s: the module ended %s", plan, module, o.Result)
	}
	for _, c := range conditions {
		if slices.Contains(o.Failures, c) || !slices.Contains(o.Passed, c) {
			t.Errorf("%s/%s: %s was not judged a success", plan, module, c)
		}
	}
}

// A request with a valid S256 challenge is served (the module that sends one passes the whole flow, and the runner's probe redeems
// a code with its verifier), and every other request is refused, by the runner's probes with a public client, which always needs
// PKCE and so survives any client that may skip it: no challenge and the method plain are refused at the authorization endpoint with
// the PKCE error, and at the token endpoint a wrong verifier, none, and the challenge used as the verifier are refused.
//
// verifies: REQ-AUTHN-002
func TestPKCEIsRequiredAndAValidChallengeIsServed(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "AddCodeChallengeToAuthorizationEndpointRequest", "CheckTokenEndpointHttpStatus200")
	}
	probed(t, loadProbes(t), "authorize: no code_challenge is refused", "authorize: code_challenge_method=plain is refused",
		"token: a wrong code_verifier", "token: no code_verifier", "token: the verifier that is the challenge itself", "token: the right code_verifier")
}

// With response_mode=form_post the code and the error come to the registered redirect_uri as a POST of an
// application/x-www-form-urlencoded body, with nothing in the URL's query (CheckCallbackHttpMethodIsPost,
// CheckCallbackContentTypeIsFormUrlEncoded, RejectAuthCodeInUrlQuery, RejectErrorInUrlQuery), and the code of the form is
// accepted at the token endpoint (the module goes on to a 200 from it and a validated ID token).
//
// verifies: REQ-AUTHN-058
func TestFormPostAnswersCodeAndErrorAsAFormPost(t *testing.T) {
	r := loadRunResults(t)
	r.passed(t, "formpost", pkceModule, "CheckCallbackHttpMethodIsPost", "CheckCallbackContentTypeIsFormUrlEncoded",
		"RejectAuthCodeInUrlQuery", "RejectErrorInUrlQuery", "CheckTokenEndpointHttpStatus200", "ValidateIdToken")
	r.passed(t, "formpost", "oidcc-response-type-missing", "CheckCallbackHttpMethodIsPost", "CheckCallbackContentTypeIsFormUrlEncoded",
		"RejectErrorInUrlQuery", "RejectAuthCodeInUrlQuery")
}

// The gate's own logic, which runs everywhere: a requirement is not proved by a module that failed, skipped or did not run,
// by a condition that did not succeed, or by a refusal that is not the one named.
func TestTheProofOfARequirementNeedsTheModuleAndTheConditions(t *testing.T) {
	r := indexOutcomes([]outcome{
		{Plan: "p", Module: "ok", Result: "PASSED", Passed: []string{"A", "B"}},
		{Plan: "p", Module: "warns", Result: "WARNING", Passed: []string{"A"}, Warnings: []string{"W"}},
		{Plan: "p", Module: "failed", Result: "FAILED", Passed: []string{"A"}, Failures: []string{"B"}},
		{Plan: "p", Module: "skipped", Result: "SKIPPED"},
		{Plan: "p", Module: "mixed", Result: "PASSED", Passed: []string{"A", "B"}, Failures: []string{"B"}},
	})
	for name, c := range map[string]struct {
		module string
		conds  []string
		ok     bool
	}{
		"a pass with its conditions":   {"ok", []string{"A", "B"}, true},
		"a warning module":             {"warns", []string{"A"}, true},
		"a condition not judged":       {"ok", []string{"A", "C"}, false},
		"a module that failed":         {"failed", []string{"A"}, false},
		"a module that skipped":        {"skipped", nil, false},
		"a module that did not run":    {"absent", nil, false},
		"a condition that also failed": {"mixed", []string{"B"}, false},
	} {
		if got := r.why("p", c.module, c.conds) == ""; got != c.ok {
			t.Errorf("%s: proved = %v, want %v", name, got, c.ok)
		}
	}
}
