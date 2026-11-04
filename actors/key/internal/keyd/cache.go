package keyd

import (
	"sync"
	"time"
)

// keyRef names a data key: the tenant ("" for a boundary purpose), the purpose and the generation.
type keyRef struct {
	tenant, purpose string
	generation      uint32
}

// entry is an opened data key in the cache. Users hold the read lock while they use the bytes, so the key is
// never zeroed under a running operation.
type entry struct {
	mu      sync.RWMutex
	key     []byte
	expires time.Time
	dead    bool
}

// use runs fn with the key. It returns used == false when the entry was wiped before fn could run.
func (e *entry) use(fn func(key []byte) error) (used bool, err error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.dead {
		return false, nil
	}
	return true, fn(e.key)
}

// wipe zeroes the key. Go gives no guarantee that no copy of the bytes lives elsewhere (the garbage collector
// may have moved the buffer, and the AES key schedule that crypto/aes expanded from it stays in the heap until it
// is collected), so this is best effort (ADR 0012 says the same of Go).
func (e *entry) wipe() {
	e.mu.Lock()
	defer e.mu.Unlock()
	clear(e.key)
	e.key = nil
	e.dead = true
}

// cache holds opened data keys, and data keys only: never a wrapping key or an authority key. Each entry has
// the time to live of the KeyPlan, under the built-in maximum (ADR 0006, "The cache").
type cache struct {
	mu  sync.Mutex
	m   map[keyRef]*entry
	ttl time.Duration
	now func() time.Time
}

func newCache(ttl time.Duration, now func() time.Time) *cache {
	return &cache{m: map[keyRef]*entry{}, ttl: ttl, now: now}
}

// get returns the live entry of ref, or nil. An expired entry is wiped and dropped.
func (c *cache) get(ref keyRef) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[ref]
	if e == nil {
		return nil
	}
	if !c.now().Before(e.expires) {
		delete(c.m, ref)
		go e.wipe()
		return nil
	}
	return e
}

// put stores the key under ref and takes ownership of the slice. A key already there is replaced and wiped.
func (c *cache) put(ref keyRef, key []byte) *entry {
	e := &entry{key: key, expires: c.now().Add(c.ttl)}
	c.mu.Lock()
	old := c.m[ref]
	c.m[ref] = e
	c.mu.Unlock()
	if old != nil {
		go old.wipe()
	}
	return e
}

// sweep drops and wipes the expired entries.
func (c *cache) sweep() {
	c.mu.Lock()
	var dead []*entry
	for ref, e := range c.m {
		if !c.now().Before(e.expires) {
			delete(c.m, ref)
			dead = append(dead, e)
		}
	}
	c.mu.Unlock()
	for _, e := range dead {
		e.wipe()
	}
}

// wipeAll drops and wipes every entry.
func (c *cache) wipeAll() {
	c.mu.Lock()
	all := c.m
	c.m = map[keyRef]*entry{}
	c.mu.Unlock()
	for _, e := range all {
		e.wipe()
	}
}
