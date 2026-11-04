package audit

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
)

// UUIDv7 follows RFC 9562 section 5.7, with the fixed-length dedicated counter of section 6.2 (method 1) so that
// values made in one millisecond increase: 48 bits of Unix milliseconds, the version, a 12-bit counter in rand_a,
// the variant and 62 random bits.
var uuidState struct {
	mu      sync.Mutex
	lastMS  uint64
	counter uint16
}

// counterSeedMask keeps the starting counter below 2048, so at least 2048 values fit in one millisecond before
// the timestamp has to move on (section 6.2: when the counter would overflow, increase the timestamp).
const counterSeedMask = 0x7ff

// NewUUIDv7 returns a UUIDv7 (RFC 9562) for now, as 36 characters in the canonical text form. Values made by one
// process increase, also within one millisecond and also if the clock steps back: the larger of the clock and
// the last value's time is used. The random bits come from the operating system (crypto/rand).
func NewUUIDv7(now time.Time) string {
	ms := uint64(max(now.UnixMilli(), 0))
	var seed [10]byte
	if _, err := rand.Read(seed[:]); err != nil {
		// crypto/rand.Read does not return an error on a supported platform; it crashes the program instead.
		panic("audit: the operating system's random generator failed: " + err.Error())
	}
	uuidState.mu.Lock()
	defer uuidState.mu.Unlock()
	if ms > uuidState.lastMS {
		uuidState.lastMS = ms
		uuidState.counter = binary.BigEndian.Uint16(seed[8:]) & counterSeedMask
	} else {
		ms = uuidState.lastMS
		uuidState.counter++
		if uuidState.counter > 0xfff {
			ms++
			uuidState.lastMS = ms
			uuidState.counter = binary.BigEndian.Uint16(seed[8:]) & counterSeedMask
		}
	}
	var randB [8]byte
	copy(randB[:], seed[:8])
	return uuidV7(ms, uuidState.counter, randB)
}

// uuidV7 lays out the 128 bits: 48 bits ms, 0111, 12 bits counter, 10, 62 bits randB.
func uuidV7(ms uint64, counter uint16, randB [8]byte) string {
	var u [16]byte
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], ms)
	copy(u[:6], t[2:]) // the low 48 bits
	binary.BigEndian.PutUint16(u[6:8], counter&0x0fff)
	u[6] |= 0x70
	copy(u[8:], randB[:])
	u[8] = 0x80 | u[8]&0x3f
	var out [36]byte
	hex.Encode(out[0:8], u[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], u[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], u[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], u[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], u[10:16])
	return string(out[:])
}
