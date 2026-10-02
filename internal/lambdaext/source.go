package lambdaext

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Source hands out the access token for the OTLP endpoint, getting it on
// demand. A Lambda environment is frozen between invocations, so no timer
// can be trusted to have run; every caller checks the clock itself, and a
// refresh happens inside the call that needs it.
type Source struct {
	// Subject mints the STS identity token. Exchange trades it for the
	// access token and says how long that token lives.
	Subject  func(ctx context.Context) (string, error)
	Exchange func(ctx context.Context, subject string) (string, time.Duration, error)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Logf receives one line per failure window and one on recovery.
	Logf func(format string, args ...any)
	// OnToken sees each newly minted token (the optional token file).
	OnToken func(token string)
	// RefreshTimeout bounds one refresh; zero is 10 seconds.
	RefreshTimeout time.Duration
	// Backoff is how long after a failed refresh the next one waits; zero
	// is 5 seconds. Exporters retry fast, and each retry must not be an
	// STS call.
	Backoff time.Duration

	mu        sync.Mutex
	token     string
	refreshAt time.Time
	expires   time.Time
	failedAt  time.Time
	lastErr   error
	failing   bool
	flight    singleflight.Group
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Source) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// ErrNoToken wraps the reason no token could be had.
var ErrNoToken = errors.New("lambdaext: no access token")

// Token returns a token that is valid now. A token inside its refresh
// window is replaced first; if the replacement fails and the old token has
// not expired, the old one is used.
func (s *Source) Token(ctx context.Context) (string, error) {
	backoff := s.Backoff
	if backoff == 0 {
		backoff = 5 * time.Second
	}
	s.mu.Lock()
	now := s.now()
	if s.token != "" && now.Before(s.refreshAt) {
		defer s.mu.Unlock()
		return s.token, nil
	}
	usable := s.token != "" && now.Add(time.Second).Before(s.expires)
	if !s.failedAt.IsZero() && now.Sub(s.failedAt) < backoff {
		token, err := s.token, s.lastErr
		s.mu.Unlock()
		if usable {
			return token, nil
		}
		return "", err
	}
	s.mu.Unlock()

	ch := s.flight.DoChan("refresh", func() (any, error) { return nil, s.refresh() })
	var err error
	select {
	case res := <-ch:
		err = res.Err
	case <-ctx.Done():
		return "", ctx.Err()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		return s.token, nil
	}
	if s.token != "" && s.now().Add(time.Second).Before(s.expires) {
		return s.token, nil
	}
	return "", err
}

// refresh runs once at a time, detached from any caller's context.
func (s *Source) refresh() error {
	timeout := s.RefreshTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	token, ttl, err := s.fetch(ctx)

	s.mu.Lock()
	if err != nil {
		s.failedAt, s.lastErr = s.now(), err
		first := !s.failing
		s.failing = true
		s.mu.Unlock()
		if first {
			s.logf("access-roster-otlp: no access token, exports will be refused until one is obtained: %v", err)
		}
		return err
	}
	now := s.now()
	s.token, s.expires = token, now.Add(ttl)
	s.refreshAt = now.Add(ttl - refreshMargin(ttl))
	s.failedAt, s.lastErr = time.Time{}, nil
	recovered := s.failing
	s.failing = false
	s.mu.Unlock()
	if recovered {
		s.logf("access-roster-otlp: access token obtained again")
	}
	if s.OnToken != nil {
		s.OnToken(token)
	}
	return nil
}

func (s *Source) fetch(ctx context.Context) (string, time.Duration, error) {
	subject, err := s.Subject(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrNoToken, err)
	}
	token, ttl, err := s.Exchange(ctx, subject)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrNoToken, err)
	}
	if token == "" || ttl <= 0 {
		return "", 0, fmt.Errorf("%w: the exchange returned no usable token", ErrNoToken)
	}
	return token, ttl, nil
}

// Invalidate drops the cached token if it is still the one given, because
// the upstream refused it. The next call mints a new one.
func (s *Source) Invalidate(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == token {
		s.refreshAt = time.Time{}
		s.failedAt = time.Time{}
	}
}

// Warm refreshes if the token is inside its window, for the INVOKE event,
// so the common export finds a fresh one already.
func (s *Source) Warm(ctx context.Context) {
	_, _ = s.Token(ctx)
}
