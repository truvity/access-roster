package exchanged

import "encoding/json"

// Workload is the verified identity of a GitHub Actions job: the claims of its token that policy reads as the
// attributes of the Cedar entity Workload (policy.md "Workload attributes are the verified claims of the proof").
// An empty field is a claim the token does not carry; Attributes leaves it out, so that policy sees it as absent and
// not as an empty string.
type Workload struct {
	Repository  string // repository
	Ref         string // ref
	RefType     string // ref_type: "branch" or "tag"
	Event       string // event_name: "push", "pull_request", ...
	Environment string // environment
	// The workflow file of the job comes from job_workflow_ref and arrives with the workload exchange (#961).
}

// Attributes returns the attributes of the Cedar entity Workload (without verifier, which the caller sets), leaving
// out every claim the token does not carry.
func (w *Workload) Attributes() map[string]string {
	out := map[string]string{}
	for name, v := range map[string]string{
		"repository": w.Repository, "ref": w.Ref, "ref_type": w.RefType, "event": w.Event, "environment": w.Environment,
	} {
		if v != "" {
			out[name] = v
		}
	}
	return out
}

// githubWorkload reads the job claims of a verified GitHub Actions token. It returns false for a token that no
// GitHub token can be: a claim that is not a string, or no event_name. GitHub sends event_name in every token, and
// the event is what tells a pull request from a push (REQ-WORKLOAD-007), so a token without it is refused here and
// is never taken to be a push.
func githubWorkload(payload []byte) (*Workload, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(payload, &m) != nil {
		return nil, false
	}
	ok := true
	text := func(name string) string {
		raw, present := m[name]
		if !present {
			return ""
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			ok = false
		}
		return s
	}
	w := &Workload{
		Repository: text("repository"), Ref: text("ref"), RefType: text("ref_type"), Event: text("event_name"),
		Environment: text("environment"),
	}
	if !ok || w.Event == "" {
		return nil, false
	}
	return w, true
}
