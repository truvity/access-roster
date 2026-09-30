package resourceproxy

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/truvity/access-roster/identity"
)

// record is what one audit line is made of. It holds names and numbers
// only: never a token, never a body.
type record struct {
	who     identity.Verified
	have    bool
	method  string
	tool    string
	calls   []rpcCall
	batched bool
}

type recordKey struct{}

func recordOf(ctx context.Context) *record {
	rec, _ := ctx.Value(recordKey{}).(*record)
	return rec
}

// audited writes one structured line per request after it finishes,
// whatever it ended as -- a refused request is the one most worth a line.
func audited(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &record{}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), recordKey{}, rec)))

		attrs := []slog.Attr{
			slog.String("http_method", clean(r.Method)),
			slog.String("path", bounded(r.URL.Path, maxPathLen)),
			slog.Int("status", sw.status),
			slog.Float64("duration_ms", since(start)),
		}
		if rec.have {
			attrs = append(attrs, slog.String("sub", clean(rec.who.Subject)))
			if rec.who.Email != "" {
				attrs = append(attrs, slog.String("email", clean(rec.who.Email)))
			}
			if rec.who.Name != "" {
				attrs = append(attrs, slog.String("name", clean(rec.who.Name)))
			}
			if rec.who.ClientID != "" {
				attrs = append(attrs, slog.String("client", bounded(rec.who.ClientID, maxPathLen)))
			}
		}
		if rec.method != "" {
			attrs = append(attrs, slog.String("method", rec.method))
		}
		if rec.tool != "" {
			attrs = append(attrs, slog.String("tool", rec.tool))
		}
		if rec.batched {
			attrs = append(attrs, slog.Any("calls", rec.calls))
		}
		log.LogAttrs(r.Context(), slog.LevelInfo, "mcp_request", attrs...)
	})
}

// statusWriter records the status and passes everything else through,
// Flush included: a streamed response must not be held back by the thing
// that is watching it.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the real writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func since(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}
