package repo

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Listen opens a listener on addr, which must be a loopback address with a port (127.0.0.1:0 picks a free one). The trees are
// unsigned and for a test: a server that could be reached from another host would be a way to hand them out, so any other address
// is refused, a name too (a name could resolve to a host that is not this one).
func Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("address %q: the unsigned repository is served on a loopback IP address alone (127.0.0.1:PORT)", addr)
	}
	return net.Listen("tcp", addr)
}

// Handler serves the files below dir, read only, with no listing of a directory.
func Handler(dir string) http.Handler {
	files := http.FileServer(noListing{http.Dir(dir)})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
}

// Server is the server of Handler(dir) with timeouts. When log is not nil it writes one line for each request, "<method> <path>
// <status>", which is the record that a client fetched a file from the repository and not from a disk.
func Server(dir string, log io.Writer) *http.Server {
	h := Handler(dir)
	if log != nil {
		h = logged(h, log)
	}
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 5 * time.Minute}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logged writes a line for each request after it is answered. The lines of concurrent requests do not interleave.
func logged(h http.Handler, w io.Writer) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: rw, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprintf(w, "%s %s %d\n", r.Method, r.URL.Path, rec.status)
	})
}

// noListing hides the listing of a directory: a client asks for a file by its name.
type noListing struct{ fs http.FileSystem }

func (n noListing) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		_ = f.Close()
		return nil, os.ErrNotExist
	}
	return f, nil
}
