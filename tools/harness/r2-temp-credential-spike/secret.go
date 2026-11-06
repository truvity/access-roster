package main

import (
	"fmt"
	"strings"
	"sync"
)

// secret is a value that must not reach any output. Every formatting verb prints a placeholder, so a
// stray %v, %s or %+v of a struct that holds one cannot leak it.
type secret string

// Format implements fmt.Formatter.
func (secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("<redacted>")) }

// credentials are what a request is signed with. The access key id counts as a secret: for an API-token
// credential it is the token's id.
type credentials struct {
	AccessKeyID  secret
	Secret       secret
	SessionToken secret
}

// redactor replaces known sensitive values in text that comes from outside (an error of net/http holds the
// request URL, with the account id in the host name). Values are added as they appear.
type redactor struct {
	mu     sync.RWMutex
	values map[string]string
}

func newRedactor() *redactor { return &redactor{values: map[string]string{}} }

// add makes clean replace value with label. A value shorter than 4 bytes is ignored: it would replace
// ordinary text.
func (r *redactor) add(value, label string) {
	if len(value) < 4 {
		return
	}
	r.mu.Lock()
	r.values[value] = label
	r.mu.Unlock()
}

func (r *redactor) clean(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for value, label := range r.values {
		s = strings.ReplaceAll(s, value, label)
	}
	return s
}

func (r *redactor) addCredentials(c credentials) {
	r.add(string(c.AccessKeyID), "<access-key-id>")
	r.add(string(c.Secret), "<secret>")
	r.add(string(c.SessionToken), "<session-token>")
}
