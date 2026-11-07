package handoff

import (
	"time"
)

// Result is `<stem>.result.json`, the certifier's answer (contract, "The answer").
type Result struct {
	Type          string
	RequestSHA256 string
	// Issued says whether the outcome is issued; a refused answer carries Reasons.
	Issued  bool
	Reasons []string
	// Artifacts are the files of the answer other than the result file, with their SHA-256.
	Artifacts  []Artifact
	ValidFrom  time.Time
	ValidUntil time.Time
	// Issuer is the SHA-256 of the DER SubjectPublicKeyInfo of the issuing root, in lower-case hexadecimal.
	Issuer string
	// TrustSequence is the sequence of the trust set the answer belongs to.
	TrustSequence int64
}

// Artifact is a file of an answer.
type Artifact struct {
	Name   string
	SHA256 string
}

// The reason codes a certifier writes into a refused answer.
var certifierCodes = map[string]bool{
	"version-unsupported": true, "malformed": true, "request-mismatch": true, "unknown-primary": true,
	"algorithm-unsupported": true, "possession-invalid": true, "store-not-allowed": true, "proof-invalid": true,
	"key-mismatch": true, "policy": true, "declined": true,
}

// ParseResult reads a result file of an X.509 answer. A version it does not know is version-unsupported and nothing
// else in the file is read.
func ParseResult(b []byte) (*Result, error) {
	o, err := parseObject(b, "")
	if err != nil {
		return nil, err
	}
	if err := o.version(); err != nil {
		return nil, err
	}
	r := &Result{}
	if r.Type, _, err = o.str("type", true); err != nil {
		return nil, err
	}
	if r.Type != TypeX509 {
		return nil, refuse(CodeMalformed, "type")
	}
	if r.RequestSHA256, _, err = o.str("request_sha256", true); err != nil {
		return nil, err
	}
	if !isDigest(r.RequestSHA256) {
		return nil, refuse(CodeMalformed, "request_sha256")
	}
	outcome, _, err := o.str("outcome", true)
	if err != nil {
		return nil, err
	}
	reasons, hasReasons, err := o.list("reasons", false)
	if err != nil {
		return nil, err
	}
	for i, raw := range reasons {
		if len(raw) == 0 || raw[0] != '"' {
			return nil, refusef(CodeMalformed, "reasons[%d]", i)
		}
		s := string(raw[1 : len(raw)-1])
		if !certifierCodes[s] {
			return nil, refusef(CodeMalformed, "reasons[%d]", i)
		}
		r.Reasons = append(r.Reasons, s)
	}
	arts, hasArts, err := o.list("artifacts", false)
	if err != nil {
		return nil, err
	}
	for i, raw := range arts {
		ao, err := parseObject(raw, joinAt("artifacts", itoa(i)))
		if err != nil {
			return nil, err
		}
		var a Artifact
		if a.Name, _, err = ao.str("name", true); err != nil {
			return nil, err
		}
		if a.SHA256, _, err = ao.str("sha256", true); err != nil {
			return nil, err
		}
		if err := ao.done(); err != nil {
			return nil, err
		}
		if !isDigest(a.SHA256) {
			return nil, refusef(CodeMalformed, "artifacts.%d.sha256", i)
		}
		r.Artifacts = append(r.Artifacts, a)
	}
	switch outcome {
	case "refused":
		if len(r.Reasons) == 0 || len(r.Artifacts) != 0 {
			return nil, refuse(CodeMalformed, "outcome")
		}
		// A refused answer installs nothing, so no other member of it is read; the reasons are what the operator sees.
		return r, nil
	case "issued":
		r.Issued = true
		if hasReasons || !hasArts {
			return nil, refuse(CodeMalformed, "outcome")
		}
	default:
		return nil, refuse(CodeMalformed, "outcome")
	}
	from, _, err := o.str("valid_from", true)
	if err != nil {
		return nil, err
	}
	until, _, err := o.str("valid_until", true)
	if err != nil {
		return nil, err
	}
	var ok1, ok2 bool
	r.ValidFrom, ok1 = parseTime(from)
	r.ValidUntil, ok2 = parseTime(until)
	if !ok1 {
		return nil, refuse(CodeMalformed, "valid_from")
	}
	if !ok2 {
		return nil, refuse(CodeMalformed, "valid_until")
	}
	if r.Issuer, _, err = o.str("issuer", true); err != nil {
		return nil, err
	}
	if !isDigest(r.Issuer) {
		return nil, refuse(CodeMalformed, "issuer")
	}
	if r.TrustSequence, _, err = o.integer("trust_sequence", true); err != nil {
		return nil, err
	}
	if r.TrustSequence < 1 {
		return nil, refuse(CodeMalformed, "trust_sequence")
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return r, nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for ; i > 0; i /= 10 {
		n--
		b[n] = byte('0' + i%10)
	}
	return string(b[n:])
}
