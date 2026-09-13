package audit

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// sequence tells apart the ids one process assigns in the same
// nanosecond. One counter for the whole process rather than one per
// writer, so an id recorded by the log and one assigned by a writer to an
// event that arrived without one can never be the same.
var sequence atomic.Uint64

// NewID returns an event id that orders by time as a string: nineteen
// digits of Unix nanoseconds, the writer, and a sequence. It is the shape
// the S3 trail has always used, so ids from before and after it was
// recorded here sort together.
func NewID(at time.Time, writer string) string {
	return fmt.Sprintf("%019d-%s-%d", at.UTC().UnixNano(), writer, sequence.Add(1))
}

// WriterName names this process in event ids and object keys: the name
// given, or the host's when none is, kept to characters no key needs
// escaped. In a cluster it is the pod's name, so two replicas never
// assign the same id or write the same key.
func WriterName(name string) string {
	if name == "" {
		name, _ = os.Hostname()
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "writer"
	}
	return b.String()
}
