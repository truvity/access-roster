package nats_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/truvity/access-roster/internal/port"
	natsport "github.com/truvity/access-roster/internal/port/nats"
	"github.com/truvity/access-roster/internal/port/porttest"
)

// server starts an in-process nats-server with JetStream.
func server(t *testing.T, mod func(*natsserver.Options)) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true}
	if mod != nil {
		mod(opts)
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(20 * time.Second) {
		t.Fatal("the test server did not start")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

var buckets atomic.Int64

// store opens a fresh bucket on the server.
func store(t *testing.T, url string, replicas int, opts ...natsport.Option) *natsport.Store {
	t.Helper()
	cfg := natsport.Config{URL: url, Bucket: "ar" + strconv.FormatInt(buckets.Add(1), 10), Replicas: replicas}
	s, err := natsport.Open(context.Background(), cfg, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// A NATS bucket holds State, Index and Trigger; Blob, Sealer and Identity are
// other adapters' ports, so their assertions are skipped here and run there.
var otherPorts = map[string]string{
	"blob/round-trip":       "Blob is not a NATS port: the S3 and legacy adapters hold it",
	"blob/write-if-version": "Blob is not a NATS port: the S3 and legacy adapters hold it",
	"blob/list-delete":      "Blob is not a NATS port: the S3 and legacy adapters hold it",
	"sealing/context":       "Sealer is not a NATS port: the KMS adapter holds it",
	"identity/verify":       "Identity is not a NATS port: the TokenReview adapter holds it",
}

func conformance(t *testing.T, url string, replicas int, opts ...natsport.Option) {
	porttest.Run(t, func(t *testing.T) porttest.Env {
		s := store(t, url, replicas, append([]natsport.Option{natsport.WithSweepEvery(50 * time.Millisecond)}, opts...)...)
		return porttest.Env{Set: s.Set(), Advance: s.Advance, Skips: otherPorts}
	})
}

func TestConformance(t *testing.T) {
	conformance(t, server(t, nil).ClientURL(), 1)
}

// TestConformanceWithoutServerTTL is the same suite on a bucket made as on a
// server without per-message TTL: expiry is judged on read only.
func TestConformanceWithoutServerTTL(t *testing.T) {
	conformance(t, server(t, nil).ClientURL(), 1, natsport.WithoutServerTTL())
}

func TestConformanceOnACluster(t *testing.T) {
	if testing.Short() {
		t.Skip("a three-node cluster takes a few seconds")
	}
	ports := make([]int, 3)
	for i := range ports {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
	}
	var routes []string
	for _, p := range ports {
		routes = append(routes, fmt.Sprintf("nats://127.0.0.1:%d", p))
	}
	var urls string
	for i := range ports {
		srv := server(t, func(o *natsserver.Options) {
			o.ServerName = "n" + strconv.Itoa(i)
			o.Cluster.Name = "ar"
			o.Cluster.Host = "127.0.0.1"
			o.Cluster.Port = ports[i]
			o.Routes = natsserver.RoutesFromStr(joinRoutes(routes))
		})
		if urls != "" {
			urls += ","
		}
		urls += srv.ClientURL()
	}
	waitForMeta(t, urls)
	conformance(t, urls, 3)
}

func joinRoutes(r []string) string {
	out := ""
	for i, s := range r {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// waitForMeta waits until the three servers have formed a JetStream group that
// can place a replicated bucket.
func waitForMeta(t *testing.T, urls string) {
	t.Helper()
	nc, err := nats.Connect(urls)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		s, err := natsport.New(context.Background(), nc, natsport.Config{Bucket: "probe", Replicas: 3})
		if err == nil {
			_ = s
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("the cluster did not form")
}

// TestServerReapsExpiredRecords is the real server TTL, on the real clock:
// the record is gone from the stream and not only filtered.
func TestServerReapsExpiredRecords(t *testing.T) {
	srv := server(t, nil)
	s := store(t, srv.ClientURL(), 1)
	if !s.ServerTTL() {
		t.Fatalf("nats-server %s did not give the bucket per-message TTL", natsserver.VERSION)
	}
	ctx := context.Background()
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := s.Watch(c, "tok.")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Put(ctx, "tok.short", []byte("x"), time.Second); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(15 * time.Second)
	for puts := 0; ; {
		select {
		case ev := <-ch:
			if ev.Err != nil {
				t.Fatal(ev.Err)
			}
			if !ev.Deleted {
				puts++
				continue
			}
			if puts == 0 {
				t.Fatal("a delete before the put")
			}
			if _, err = s.Get(ctx, "tok.short"); !errors.Is(err, port.ErrNotFound) {
				t.Fatalf("Get after the server reaped it: %v", err)
			}
			// The key is free again.
			if _, err = s.Create(ctx, "tok.short", []byte("y"), time.Minute); err != nil {
				t.Fatalf("Create over a reaped record: %v", err)
			}
			return
		case <-deadline:
			t.Fatal("the server did not reap a one-second record")
		}
	}
}

// TestRevisionIsTheStreamSequence pins the claim the package makes: a
// record that went A, B, A is not the record that never moved.
func TestABADetected(t *testing.T) {
	s := store(t, server(t, nil).ClientURL(), 1)
	ctx := context.Background()
	r1, _ := s.Put(ctx, "tok.aba", []byte("a"), time.Minute)
	if _, err := s.Put(ctx, "tok.aba", []byte("b"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "tok.aba", []byte("a"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, "tok.aba", []byte("c"), time.Minute, r1); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("Update with the revision of the first A: %v, want ErrConflict", err)
	}
}

func TestKeysThatAreNotSubjects(t *testing.T) {
	s := store(t, server(t, nil).ClientURL(), 1)
	ctx := context.Background()
	for _, key := range []string{"lease.github-tick:acme", "tok.a b", "tok.=3D", "tok.é*>"} {
		if _, err := s.Put(ctx, key, []byte(key), time.Minute); err != nil {
			t.Fatalf("Put %q: %v", key, err)
		}
		got, err := s.Get(ctx, key)
		if err != nil || string(got.Value) != key {
			t.Fatalf("Get %q: %v %q", key, err, got.Value)
		}
	}
	page, err := s.List(ctx, "tok.", "", 0)
	if err != nil || len(page.Records) != 3 {
		t.Fatalf("List: %v %v", page.Records, err)
	}
}

func TestIndexSetsDoNotLeakIntoEachOther(t *testing.T) {
	s := store(t, server(t, nil).ClientURL(), 1)
	ctx := context.Background()
	_ = s.Add(ctx, "ses:a", "x", time.Minute)
	_ = s.Add(ctx, "ses:a.b", "y.z", time.Minute)
	got, err := s.Members(ctx, "ses:a")
	if err != nil || fmt.Sprint(got) != "[x]" {
		t.Fatalf("Members of ses:a: %v %v", got, err)
	}
	got, _ = s.Members(ctx, "ses:a.b")
	if fmt.Sprint(got) != "[y.z]" {
		t.Fatalf("Members of ses:a.b: %v", got)
	}
}

// TestNotifyCrossesProcesses is the point against the in-process trigger: a
// second connection (another process, as far as the server can tell) receives
// what the first notified.
func TestNotifyCrossesProcesses(t *testing.T) {
	srv := server(t, nil)
	cfg := natsport.Config{URL: srv.ClientURL(), Bucket: "shared", Replicas: 1}
	a, err := natsport.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := natsport.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	got := make(chan string, 4)
	stop := b.Subscribe(func(target string) { got <- target })
	defer stop()
	if err = a.Notify(context.Background(), "slack.T0123"); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-got:
		if target != "slack.T0123" {
			t.Fatalf("delivered %q", target)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a notification did not cross to the other connection")
	}
}

func TestTokenFileIsPresented(t *testing.T) {
	srv := server(t, func(o *natsserver.Options) { o.Authorization = "sa-token" })
	file := t.TempDir() + "/token"
	if err := writeFile(file, "sa-token\n"); err != nil {
		t.Fatal(err)
	}
	cfg := natsport.Config{URL: srv.ClientURL(), Bucket: "auth", Replicas: 1, TokenFile: file}
	s, err := natsport.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("with the token: %v", err)
	}
	s.Close()
	if err = writeFile(file, "wrong\n"); err != nil {
		t.Fatal(err)
	}
	if _, err = natsport.Open(context.Background(), cfg); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("with a wrong token: %v, want ErrUnavailable", err)
	}
}
