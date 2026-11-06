package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Classes of one request.
const (
	classAccept = "accept" // 2xx
	classRefuse = "refuse" // 401 or 403: the store refused the credential
	classOther  = "other"  // anything else: a network error, 404, 429, 5xx
)

// attempt is one request, as written to attempts.csv. It holds no credential, no key and no message.
type attempt struct {
	Arm      string
	Index    int
	Op       string
	Seq      int   // the attempt's number within its operation
	OffsetMS int64 // the start of the request, from the moment the credential was handed out
	DurMS    int64
	Status   int // 0 when no answer came
	Code     string
	Class    string
}

// credResult is one credential's row in credentials.csv.
type credResult struct {
	Arm      string
	Index    int
	MintedAt time.Time
	MintMS   int64

	Accepted              bool
	FirstAcceptMS         int64 // the start of the first accepted request, from the mint
	AttemptsToFirstAccept int
	FirstAttemptRefused   bool
	RefusalsBefore        int // 401 or 403 before the first accept
	RefusalsAfter         int // 401 or 403 after the first accept: the "accept then refuse" case
	LastRefusalMS         int64
	Refused401            int
	Refused403            int
	Other                 int
	OpAcceptMS            map[string]int64 // per operation: the start of its first accepted request
	Codes                 []string
	Deleted               bool
	FailedOp              string
}

// s3 is a path-style S3 client for one bucket.
type s3 struct {
	hc       *http.Client
	endpoint *url.URL
	bucket   string
	region   string
}

// s3Code reads the code of an S3 error document. Only the code is kept, and only when it looks like one.
var codeShape = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func s3Code(body []byte) string {
	var e struct {
		Code string `xml:"Code"`
	}
	if xml.Unmarshal(body, &e) != nil || !codeShape.MatchString(e.Code) {
		return ""
	}
	return e.Code
}

// do sends one signed request. The error is never the error of net/http, which holds the URL: a failure to
// get an answer is the code "NoAnswer" and the status 0.
func (c *s3) do(ctx context.Context, cred credentials, method, key string, body []byte) (status int, code string, answer []byte) {
	u := *c.endpoint
	u.Path = "/" + c.bucket + "/" + key
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, "BadRequest", nil
	}
	if len(body) == 0 {
		req.Body = http.NoBody
		req.ContentLength = 0
	}
	signV4(req, cred, hexSHA256(body), c.region, time.Now())
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, "NoAnswer", nil
	}
	defer func() { _ = resp.Body.Close() }()
	answer, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		code = s3Code(answer)
	}
	return resp.StatusCode, code, answer
}

func classify(status int) string {
	switch {
	case status/100 == 2:
		return classAccept
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return classRefuse
	}
	return classOther
}

// recorder collects the attempts of all credentials and the keys still to delete.
type recorder struct {
	mu       sync.Mutex
	attempts []attempt
	pending  map[string]bool
}

func newRecorder() *recorder { return &recorder{pending: map[string]bool{}} }

func (r *recorder) add(a attempt) {
	r.mu.Lock()
	r.attempts = append(r.attempts, a)
	r.mu.Unlock()
}

func (r *recorder) setPending(key string, on bool) {
	r.mu.Lock()
	if on {
		r.pending[key] = true
	} else {
		delete(r.pending, key)
	}
	r.mu.Unlock()
}

func (r *recorder) pendingKeys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := make([]string, 0, len(r.pending))
	for k := range r.pending {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// probe holds the settings of the per-credential probe.
type probe struct {
	s3       *s3
	rec      *recorder
	interval time.Duration // between the starts of two attempts of one operation
	deadline time.Duration // for one operation, from its first attempt
	soak     time.Duration // how long after the first accept the credential keeps being tried
}

// sleepUntil waits until t or until ctx ends. It reports whether t was reached.
func sleepUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// run probes one credential, handed out at minted: PutObject, GetObject and HeadObject of its own key, each
// repeated every interval until it is accepted or the deadline passes; then HeadObject until soak has passed
// since the first accept, to catch a refusal after an accept; then DeleteObject. Every attempt is recorded.
func (p *probe) run(ctx context.Context, arm string, index int, cred credentials, key string, minted time.Time, mintMS int64) credResult {
	res := credResult{Arm: arm, Index: index, MintedAt: minted, MintMS: mintMS, OpAcceptMS: map[string]int64{}}
	payload := []byte("sluis r2 spike " + key)
	codes := map[string]bool{}
	total := 0

	// try sends one request and books its outcome. It reports whether it was accepted.
	try := func(op, method string, seq int, body []byte, verify func([]byte) bool) bool {
		at := time.Now()
		status, code, answer := p.s3.do(ctx, cred, method, key, body)
		done := time.Now()
		class := classify(status)
		if class == classAccept && verify != nil && !verify(answer) {
			class, code = classOther, "BodyMismatch"
		}
		total++
		offset := at.Sub(minted).Milliseconds()
		p.rec.add(attempt{Arm: arm, Index: index, Op: op, Seq: seq, OffsetMS: offset, DurMS: done.Sub(at).Milliseconds(), Status: status, Code: code, Class: class})
		if code != "" {
			codes[code] = true
		}
		switch class {
		case classAccept:
			if !res.Accepted {
				res.Accepted = true
				res.FirstAcceptMS = offset
				res.AttemptsToFirstAccept = total
			}
			if _, ok := res.OpAcceptMS[op]; !ok {
				res.OpAcceptMS[op] = offset
			}
			return true
		case classRefuse:
			if total == 1 {
				res.FirstAttemptRefused = true
			}
			if res.Accepted {
				res.RefusalsAfter++
			} else {
				res.RefusalsBefore++
			}
			res.LastRefusalMS = offset
			if status == http.StatusUnauthorized {
				res.Refused401++
			} else {
				res.Refused403++
			}
		default:
			res.Other++
		}
		return false
	}

	// until repeats try every interval, up to the deadline.
	until := func(op, method string, body []byte, verify func([]byte) bool) bool {
		limit := time.Now().Add(p.deadline)
		for seq := 1; ; seq++ {
			at := time.Now()
			if try(op, method, seq, body, verify) {
				return true
			}
			next := at.Add(p.interval)
			if ctx.Err() != nil || next.After(limit) {
				if res.FailedOp == "" {
					res.FailedOp = op
				}
				return false
			}
			if !sleepUntil(ctx, next) {
				if res.FailedOp == "" {
					res.FailedOp = op
				}
				return false
			}
		}
	}

	p.rec.setPending(key, true)
	if until("put", http.MethodPut, payload, nil) {
		until("get", http.MethodGet, nil, func(b []byte) bool { return bytes.Equal(b, payload) })
		until("head", http.MethodHead, nil, nil)
		if p.soak > 0 && res.Accepted {
			end := minted.Add(time.Duration(res.FirstAcceptMS) * time.Millisecond).Add(p.soak)
			for seq := 1; time.Now().Before(end) && ctx.Err() == nil; seq++ {
				at := time.Now()
				try("soak", http.MethodHead, seq, nil, nil)
				if !sleepUntil(ctx, at.Add(p.interval)) {
					break
				}
			}
		}
		if until("delete", http.MethodDelete, nil, nil) {
			res.Deleted = true
			p.rec.setPending(key, false)
		}
	}
	for c := range codes {
		res.Codes = append(res.Codes, c)
	}
	sort.Strings(res.Codes)
	return res
}

var keyShape = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// cleanKey reports whether a key or prefix is made of characters that need no escaping, which keeps the
// canonical URI the same as the path on the wire.
func cleanKey(s string) bool {
	return !strings.HasPrefix(s, "/") && !strings.Contains(s, "..") && keyShape.MatchString(s)
}
