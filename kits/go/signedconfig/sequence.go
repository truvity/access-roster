package signedconfig

import (
	"errors"
	"sync"
)

// Sequence is what the sequence number says about a document (signed-config.md, step 5).
type Sequence int

// Newer is a higher seq than the one in force, or nothing in force: it replaces it. Same is the same seq and the same
// payload: nothing changes. Conflict is the same seq with another payload, because two documents must not share a
// number. Older is a lower seq, because an older document must not come back.
const (
	Newer Sequence = iota
	Same
	Conflict
	Older
)

// The refusals of Sequencer.Admit.
var (
	ErrOlder    = errors.New("signed config: step 5: a lower seq than the one in force")
	ErrConflict = errors.New("signed config: step 5: the same seq with another payload")
)

// Sequencer holds the highest document of one kind that this process has seen, and refuses an older one. It protects
// a running process only: a process that starts has nothing to compare with and takes what it is given, as store@
// does (ADR 0005, "Freshness at a cold start"). It remembers nothing across restarts.
type Sequencer struct {
	mu     sync.Mutex
	held   bool
	seq    uint64
	digest [48]byte
}

// Admit applies step 5 to a verified document. A Newer document becomes the one held; a Same one changes nothing; a
// Conflict or an Older one is an error and leaves the held one as it is.
func (s *Sequencer) Admit(v *Verified) (Sequence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := compare(s.held, s.seq, s.digest, v)
	if r == Newer {
		s.held, s.seq, s.digest = true, v.Seq, v.Digest
	}
	switch r {
	case Conflict:
		return r, ErrConflict
	case Older:
		return r, ErrOlder
	case Newer, Same:
	}
	return r, nil
}

// Peek is what Admit would say of v, without admitting it: a caller that must save a mark before it takes a
// document asks first and admits after.
func (s *Sequencer) Peek(v *Verified) Sequence {
	s.mu.Lock()
	defer s.mu.Unlock()
	return compare(s.held, s.seq, s.digest, v)
}

// Restore sets the document held, before any is admitted: the highest one a previous process saw, which the caller kept
// in durable state of its own. A process that restores one refuses an older document after a restart, which a process
// that restores none cannot (ADR 0005, "Freshness at a cold start"). It does nothing once a document is held.
func (s *Sequencer) Restore(seq uint64, digest [48]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.held {
		s.held, s.seq, s.digest = true, seq, digest
	}
}

// Held returns the seq of the highest document seen, and whether there is one.
func (s *Sequencer) Held() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq, s.held
}

// Compare is step 5 for a document against the seq and payload digest in force. inForce false: nothing is in force.
func Compare(inForce bool, seq uint64, digest [48]byte, v *Verified) Sequence {
	return compare(inForce, seq, digest, v)
}

func compare(held bool, seq uint64, digest [48]byte, v *Verified) Sequence {
	switch {
	case !held, v.Seq > seq:
		return Newer
	case v.Seq < seq:
		return Older
	case v.Digest == digest:
		return Same
	}
	return Conflict
}
