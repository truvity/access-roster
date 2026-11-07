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

// refused fails the test unless the module ended FAILED with a failure that carries these words: the suite saw the
// authorization server refuse what the requirement says it must refuse.
func (r runResults) refused(t *testing.T, plan, module, words string) {
	t.Helper()
	o, ok := r[plan+"/"+module]
	switch {
	case !ok:
		t.Errorf("%s/%s: the module did not run", plan, module)
	case o.Result != "FAILED":
		t.Errorf("%s/%s: the module ended %s; the suite was to see the request refused", plan, module, o.Result)
	case !slices.ContainsFunc(o.Details, func(d string) bool { return strings.Contains(d, words) }):
		t.Errorf("%s/%s: no failure carries %q: %v", plan, module, words, o.Details)
	}
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

// The token endpoint answers the authorization code request with a JSON body that holds the access token and the ID token:
// the suite reads them from the parsed body (CallTokenEndpointAndReturnFullResponse, ExtractAccessTokenFromTokenResponse,
// ExtractIdTokenFromTokenResponse) and checks the status (CheckTokenEndpointHttpStatus200).
//
// verifies: REQ-TOKEN-010
func TestTokenEndpointAnswersAJSONBody(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "CallTokenEndpointAndReturnFullResponse", "CheckTokenEndpointHttpStatus200",
			"ExtractAccessTokenFromTokenResponse", "ExtractIdTokenFromTokenResponse", "ValidateExpiresIn")
	}
}

// The authorization response carries iss, for a code and for an error alike, and it is the issuer of discovery: the suite's
// ValidateIssIfPresentInAuthorizationResponse logs a success only for an iss that is present and equal, in the module whose
// answer is a code and in the one whose answer is an error (a request with no response_type).
//
// verifies: REQ-AUTHN-005
func TestAuthorizationResponsesCarryTheIssuer(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "ValidateIssIfPresentInAuthorizationResponse")
		r.passed(t, plan, "oidcc-response-type-missing", "ValidateIssIfPresentInAuthorizationResponse", "EnsureErrorFromAuthorizationEndpointResponse")
	}
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

// A request with a valid S256 challenge is served (the module that sends one passes the whole flow, with the verifier at the
// token endpoint), and a request without one is refused at the authorization endpoint with the PKCE error: the module that
// sends none (oidcc-server) ends FAILED on CheckIfAuthorizationEndpointError, and the error the suite quotes is
// "PKCE with S256 is required".
//
// verifies: REQ-AUTHN-002
func TestPKCEIsRequiredAndAValidChallengeIsServed(t *testing.T) {
	r := loadRunResults(t)
	for _, plan := range []string{"basic", "formpost"} {
		r.passed(t, plan, pkceModule, "AddCodeChallengeToAuthorizationEndpointRequest", "CheckIfAuthorizationEndpointError", "CheckTokenEndpointHttpStatus200")
		r.refused(t, plan, "oidcc-server", "PKCE with S256 is required")
	}
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
		{Plan: "p", Module: "failed", Result: "FAILED", Passed: []string{"A"}, Failures: []string{"B"}, Details: []string{"B: refused [invalid_request: PKCE with S256 is required]"}},
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
