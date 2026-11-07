package keyd

import (
	"bytes"
	"net/http"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// undecodable wraps the handler of KeyService to see the one refusal that no handler makes: a request of an allowed caller
// that Connect cannot decode (bad JSON or bytes). Connect answers it with invalid_argument before any interceptor runs, so
// key@ would leave no trace of it. A refusal of a handler always carries the Refusal detail (refusal.New), and Connect's own
// answer to an undecodable message never does, so a 400 with the code invalid_argument and no details is such a request.
// It is noted through the limiter of the handlers' refusals, under the key (caller, "undecodable"), so a caller that sends
// garbage in a loop leaves a counted, bounded trace like any other refusal. Only the Connect unary protocol is seen; the
// callers of key@ speak it.
func (s *Server) undecodable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status != http.StatusBadRequest || !bytes.Contains(rec.head, []byte(`"invalid_argument"`)) || bytes.Contains(rec.head, []byte(`"details"`)) {
			return
		}
		p, ok := rpc.PeerFromContext(r.Context())
		if !ok || p.Name == "" {
			return
		}
		_ = s.refuse(r.Context(), p.Name, opOf(r.URL.Path), "", "", connect.CodeInvalidArgument, reasonUndecodable, "") // the answer was given
	})
}

// statusRecorder keeps the status and the first bytes of a response, and passes everything on.
type statusRecorder struct {
	http.ResponseWriter
	status int
	head   []byte
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if room := 1024 - len(r.head); room > 0 {
		r.head = append(r.head, b[:min(room, len(b))]...)
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets net/http reach the underlying writer for the interfaces this one does not repeat.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
