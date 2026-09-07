package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Recovery is the way in when the ordinary one is broken: nobody is in the
// operators group, the group was renamed, the directory will not answer.
//
// It has two shapes because the honest answer depends on where the hub
// runs. In a cluster there is already an authority that says who is
// trusted — the API server — so recovery proves access to it and the hub
// stores no credential at all. Anywhere else there is nothing to prove
// access to, so a generated password is the only thing left.
type Recovery interface {
	// Kind is "token" or "password": what the recovery page asks for.
	Kind() string
	// Prompt is how the sign-in page explains this shape. Each shape
	// carries its own words, because the two are not variations on one
	// sentence: one is a command to run, the other a secret to have kept.
	Prompt() Prompt
	// Verify returns the identity the proof establishes.
	Verify(ctx context.Context, proof string) (string, error)
}

// Prompt is what the sign-in page shows above the recovery field.
type Prompt struct {
	// Label names the field.
	Label string
	// Intro is the sentence before it.
	Intro string
	// Command, when set, is shown as a command to run. It carries this
	// installation's own names rather than placeholders.
	Command string
	// Caution is the sentence after it, and is the reason showing any of
	// this is safe to do on a page anyone may load.
	Caution string
}

// ErrRecoveryRefused is returned for a proof that does not check out. It
// is one error for every reason: the caller is unauthenticated, and
// telling it which would help it guess.
var ErrRecoveryRefused = errors.New("server: recovery refused")

// ErrRecoveryThrottled is returned when too many proofs have been refused
// recently. It is distinct because it is not a statement about the proof.
var ErrRecoveryThrottled = errors.New("server: too many attempts")

// recoveryEnabled reports whether a deployment has a recovery path at all.
func recoveryEnabled(r Recovery) bool { return r != nil }

// recoveryKindOf is Kind for a possibly absent recovery.
func recoveryKindOf(r Recovery) string {
	if r == nil {
		return ""
	}
	return r.Kind()
}

// ------------------------------------------------------------- by token

// TokenRecovery proves access to the cluster the hub runs in.
//
// Nothing is stored: no password, no digest, no Secret to rotate or to
// find in a backup. What may be presented is a ServiceAccount token
// minted for one audience and a few minutes, so the authority is the
// cluster's own RBAC — who may create a token for that account — which is
// where cluster privilege is supposed to be visible, is revocable by
// removing a binding, and lands in the cluster's audit log.
//
// It also names who recovered. A shared password makes every recovery
// look like the same person.
type TokenRecovery struct {
	// Review is [kube.Client.ReviewToken].
	Review func(ctx context.Context, token string, audiences []string) (string, error)
	// Namespace and Account are what the sign-in page tells a person to
	// mint a token for. They are object names, not secrets: they are
	// visible to anyone who may read the namespace, the chart that
	// creates them is public, and none of it helps without the RBAC to
	// create a token — which is itself enough to reach the hub by other
	// means. Printing the real ones beats making somebody guess a release
	// name during an outage.
	Namespace string
	Account   string
	// Audience the token must have been minted for.
	Audience string
	// Subjects that may recover, as the API server spells them.
	Subjects []string
}

var _ Recovery = (*TokenRecovery)(nil)

// Kind implements [Recovery].
func (t *TokenRecovery) Kind() string { return "token" }

// Prompt implements [Recovery]: the command that mints a proof, with this
// installation's own names in it.
func (t *TokenRecovery) Prompt() Prompt {
	return Prompt{
		Label:   "Recovery token",
		Intro:   "Mint a short-lived token proving access to this cluster:",
		Command: t.command(),
		// The command is an instruction to produce a credential that
		// grants operator here, printed on a page anyone may load. The
		// names in it are not secrets and are useless without the RBAC to
		// mint the token — but a person who *has* that RBAC could be
		// talked into running it on somebody else's behalf, so the page
		// says so plainly.
		Caution: "This mints a credential that grants operator on this hub. " +
			"Never run it because someone asked you to.",
	}
}

func (t *TokenRecovery) command() string {
	namespace, account := t.Namespace, t.Account
	if namespace == "" {
		namespace = "<namespace>"
	}
	if account == "" {
		account = "<service-account>"
		if len(t.Subjects) == 1 {
			if _, name, found := strings.Cut(strings.TrimPrefix(t.Subjects[0], "system:serviceaccount:"), ":"); found {
				account = name
			}
		}
	}
	return fmt.Sprintf("kubectl -n %s create token %s \\\n  --audience %s --duration 10m",
		namespace, account, t.Audience)
}

// Verify implements [Recovery].
func (t *TokenRecovery) Verify(ctx context.Context, proof string) (string, error) {
	subject, err := t.Review(ctx, proof, []string{t.Audience})
	if err != nil {
		// A review that could not run is not a refusal, and must not read
		// as one: an unreachable API server is an outage to report, not a
		// wrong token to try again.
		return "", err
	}
	if !slices.Contains(t.Subjects, subject) {
		return "", fmt.Errorf("%w: %s may not recover this hub", ErrRecoveryRefused, subject)
	}
	return subject, nil
}

// ---------------------------------------------------------- by password

// Argon2id parameters for the recovery password.
//
// Deliberately modest. The password this normally holds is machine
// generated, against which no amount of stretching matters; the
// stretching is for the installation that sets a memorable one, where
// reaching the process memory should not hand the password back. Memory
// is the parameter that bounds what an unauthenticated caller can cost
// us, so it is kept where one verification is a few tens of milliseconds
// — and [recoveryAttempts] stops there being many.
const (
	argonTime    = 2
	argonMemory  = 32 * 1024 // KiB
	argonThreads = 2
	argonLength  = 32
)

// recoveryAttempts is how many failures are answered before the password
// stops answering for recoveryWindow.
//
// Not really about guessing — a generated password will not be guessed.
// It is because verifying costs memory on purpose, and an endpoint anyone
// can reach that allocates on every call needs a ceiling, or the
// hardening becomes a way to take the hub down.
const (
	recoveryAttempts = 10
	recoveryWindow   = time.Minute
)

// PasswordRecovery is the shape for a hub outside Kubernetes: a generated
// password, kept only as an Argon2id digest with a random salt.
//
// It carries a lock, so it is created once and used through a pointer;
// the lock serialises verification, which keeps the memory cost of one
// attempt from becoming the cost of as many as anyone cares to send.
type PasswordRecovery struct {
	salt   []byte
	digest []byte

	mu       sync.Mutex
	failures int
	blocked  time.Time
	now      func() time.Time
}

var _ Recovery = (*PasswordRecovery)(nil)

// NewPasswordRecovery returns the password shape.
func NewPasswordRecovery(password string) *PasswordRecovery {
	salt := make([]byte, 16)
	// crypto/rand.Read does not fail; it stops the program if the system
	// source is broken, which is the right outcome for a process about to
	// authenticate people.
	_, _ = rand.Read(salt)
	return &PasswordRecovery{
		salt:   salt,
		digest: argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonLength),
		now:    time.Now,
	}
}

// Kind implements [Recovery].
func (p *PasswordRecovery) Kind() string { return "password" }

// Prompt implements [Recovery].
func (p *PasswordRecovery) Prompt() Prompt {
	return Prompt{
		Label:   "Recovery password",
		Intro:   "Present the password this hub printed when it started.",
		Caution: "This grants operator on this hub. Never give it to anyone who asks for it.",
	}
}

// Verify implements [Recovery].
func (p *PasswordRecovery) Verify(_ context.Context, proof string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	if now.Before(p.blocked) {
		return "", ErrRecoveryThrottled
	}
	got := argon2.IDKey([]byte(proof), p.salt, argonTime, argonMemory, argonThreads, argonLength)
	if subtle.ConstantTimeCompare(got, p.digest) != 1 {
		p.failures++
		if p.failures >= recoveryAttempts {
			p.failures, p.blocked = 0, now.Add(recoveryWindow)
		}
		return "", ErrRecoveryRefused
	}
	p.failures = 0
	return "recovery", nil
}
