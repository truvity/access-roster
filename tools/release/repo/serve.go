package repo

import (
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
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

// Handler serves the files below dir, read only, with no listing of a directory. It serves a regular file and nothing else: a
// symbolic link, a device or a socket is a 404, whatever it points at, and the directory is opened with os.OpenRoot, so that no
// name (a ".." or a link) can reach a file outside it. The returned closer ends the hold on the directory.
func Handler(dir string) (http.Handler, io.Closer, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	files := http.FileServer(regularFiles{root})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	}), root, nil
}

// Server is the server of Handler(dir) with timeouts. When log is not nil it writes one line for each request, "<method> <path>
// <status>", which is the record that a client fetched a file from the repository and not from a disk. Close the closer when the
// server is done.
func Server(dir string, log io.Writer) (*http.Server, io.Closer, error) {
	h, c, err := Handler(dir)
	if err != nil {
		return nil, nil, err
	}
	if log != nil {
		h = logged(h, log)
	}
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 5 * time.Minute}, c, nil
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

// regularFiles is the http.FileSystem of a directory held as an os.Root: it opens a regular file and nothing else (no listing of a
// directory, no link followed, no device), so a client asks for a file by its name.
type regularFiles struct{ root *os.Root }

func (r regularFiles) Open(name string) (http.File, error) {
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" {
		return nil, fs.ErrNotExist
	}
	// Every failure is "not there" to the client: a name that climbs out through a link is refused by the root with an error of its own.
	st, err := r.root.Lstat(name)
	if err != nil || !st.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	f, err := r.root.Open(name)
	if err != nil {
		return nil, fs.ErrNotExist
	}
	// The file may have been replaced by a link between the two calls: look at what was opened.
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() {
		_ = f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}
