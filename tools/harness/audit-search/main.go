// Command audit-search asks the audit front of the local installation to Search the audit log, and prints the records
// that match (`just local-audit-search`). It is a test harness tool, never part of a product binary: it trusts the harness
// CA only, and it dials the loopback port of the forwarder so that no hosts-file line is needed.
//
//	go run ./tools/harness/audit-search [-ca FILE] [-addr HOST:PORT] [-host NAME] [-limit N] [-json] [WORD...]
//
// A word of the form key:value is a filter, any other word is free text over the searchable fields:
//
//	action:signer.sign   only this action           status:ok      only this status code
//	actor:signer@dev     only this actor            trace:ID       only this correlation id
//	record:ID            only this record id        tenant:acme    the tenant(s) to read, comma separated; default acme
//	project:sluis        only this project          since:2m       only records of the last two minutes (Go duration)
//
// The tenant is not a filter of the records but the grant that is asked for: the reader reads no tenant it was not
// granted, and a tenant with no records answers with none.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	searchPath    = "/sluis.reader.v2alpha1.ReaderService/Search"
	defaultTenant = "acme" // boundary.yaml, default_tenant of the local installation
)

// request is the JSON of a SearchRequest (proto names; the front reads either spelling).
type request struct {
	Tenants   []string `json:"tenants"`
	Project   string   `json:"project,omitempty"`
	Q         string   `json:"q,omitempty"`
	Action    string   `json:"action,omitempty"`
	Status    string   `json:"status_code,omitempty"`
	Actor     string   `json:"actor_uid,omitempty"`
	Trace     string   `json:"trace_id,omitempty"`
	Record    string   `json:"record_id,omitempty"`
	FromMs    string   `json:"from_ms,omitempty"`
	PageSize  int      `json:"page_size,omitempty"`
	PageToken string   `json:"page_token,omitempty"`
}

type hit struct {
	Tenant     string `json:"tenant"`
	Seq        string `json:"seq"`
	TimeMs     string `json:"timeMs"`
	Action     string `json:"action"`
	StatusCode string `json:"statusCode"`
	ActorUID   string `json:"actorUid"`
	TraceID    string `json:"traceId"`
	RecordID   string `json:"recordId"`
	Record     string `json:"record"`
}

type response struct {
	Hits          []hit  `json:"hits"`
	NextPageToken string `json:"nextPageToken"`
}

// parse turns the words of the command line into a request.
func parse(words []string, now time.Time) (request, error) {
	r := request{Tenants: []string{defaultTenant}}
	var free []string
	for _, w := range words {
		k, v, ok := strings.Cut(w, ":")
		if !ok || v == "" {
			free = append(free, w)
			continue
		}
		switch k {
		case "action":
			r.Action = v
		case "status":
			r.Status = v
		case "actor":
			r.Actor = v
		case "trace":
			r.Trace = v
		case "record":
			r.Record = v
		case "project":
			r.Project = v
		case "tenant":
			r.Tenants = strings.Split(v, ",")
		case "since":
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return r, fmt.Errorf("since:%s is not a duration such as 2m", v)
			}
			r.FromMs = strconv.FormatInt(now.Add(-d).UnixMilli(), 10)
		default:
			// A word with a colon that is no filter is a word: "10:30" is text.
			free = append(free, w)
		}
	}
	r.Q = strings.Join(free, " ")
	return r, nil
}

func client(caFile, addr, host string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile) //nolint:gosec // the harness CA of the run, named on the command line
	if err != nil {
		return nil, fmt.Errorf("the harness CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the harness CA file holds no certificate")
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}, nil
}

// search runs the call, page by page, until `limit` records or the last page.
func search(c *http.Client, host string, r request, limit int) ([]hit, error) {
	var out []hit
	for {
		if r.PageSize = limit - len(out); r.PageSize > 200 {
			r.PageSize = 200
		}
		body, _ := json.Marshal(r)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+host+searchPath, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
		if resp.StatusCode != http.StatusOK {
			// The edge says nothing of the reason (contracts.md "Uniform refusals"): the status and the correlation id.
			return nil, fmt.Errorf("the audit front answered %d (correlation id %s)", resp.StatusCode, resp.Header.Get("Sluis-Correlation-Id"))
		}
		var page response
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, errors.New("the audit front's answer is not the contract's JSON")
		}
		out = append(out, page.Hits...)
		if page.NextPageToken == "" || len(out) >= limit || len(page.Hits) == 0 {
			return out, nil
		}
		r.PageToken = page.NextPageToken
	}
}

func main() {
	ca := flag.String("ca", ".cache/local/ca/ca.pem", "the harness CA")
	addr := flag.String("addr", "127.0.0.1:"+port(), "where the forwarder listens")
	host := flag.String("host", "sluis-audit.dev.local.test", "the name of the audit front")
	limit := flag.Int("limit", 50, "the most records to print")
	asJSON := flag.Bool("json", false, "print each record as the emitter made it, one per line")
	flag.Parse()
	if *limit < 1 || *limit > 1000 {
		fmt.Fprintln(os.Stderr, "audit-search: -limit is from 1 to 1000")
		os.Exit(2)
	}
	r, err := parse(flag.Args(), time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-search: %v\n", err)
		os.Exit(2)
	}
	c, err := client(*ca, *addr, *host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-search: %v\n", err)
		os.Exit(1)
	}
	hits, err := search(c, *host, r, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-search: %v\n", err)
		os.Exit(1)
	}
	for _, h := range hits {
		if *asJSON {
			fmt.Println(h.Record)
			continue
		}
		ms, _ := strconv.ParseInt(h.TimeMs, 10, 64)
		fmt.Printf("%s  %-8s %-22s %-6s %-26s %s\n", time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z"), h.Tenant, h.Action, h.StatusCode, h.ActorUID, h.RecordID)
	}
	fmt.Fprintf(os.Stderr, "audit-search: %d record(s) for tenant(s) %s\n", len(hits), strings.Join(r.Tenants, ","))
}

// port is the loopback port the forwarder is published on (SLUIS_LOCAL_PORT of local.sh, 8443 by default).
func port() string {
	if p := os.Getenv("SLUIS_LOCAL_PORT"); p != "" {
		return p
	}
	return "8443"
}
