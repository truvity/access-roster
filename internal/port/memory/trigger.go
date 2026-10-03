package memory

import (
	"context"
	"sync"
)

// Trigger is an in-process [port.Trigger]: a notification reaches the
// subscribers of this process only, and several for one target while a
// delivery is waiting coalesce into one.
type Trigger struct {
	mu      sync.Mutex
	subs    map[int]func(string)
	next    int
	pending map[string]bool
}

// NewTrigger returns a trigger with no subscribers.
func NewTrigger() *Trigger {
	return &Trigger{subs: map[int]func(string){}, pending: map[string]bool{}}
}

// Notify implements [port.Trigger]. Notifications for a target already
// waiting coalesce into one delivery.
func (s *Trigger) Notify(_ context.Context, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[target] {
		return nil
	}
	s.pending[target] = true
	go func() {
		s.mu.Lock()
		delete(s.pending, target)
		handlers := make([]func(string), 0, len(s.subs))
		for _, h := range s.subs {
			handlers = append(handlers, h)
		}
		s.mu.Unlock()
		for _, h := range handlers {
			h(target)
		}
	}()
	return nil
}

// Subscribe implements [port.Trigger].
func (s *Trigger) Subscribe(handler func(target string)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.next
	s.next++
	s.subs[id] = handler
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.subs, id)
	}
}
