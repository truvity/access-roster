package lambdaext_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// riePort is the emulator's fixed port; the container shares the host
// network so the fakes on 127.0.0.1 are reachable and the https-or-loopback
// rule for the upstream holds unchanged.
const riePort = "8080"

// TestInTheRuntimeInterfaceEmulator runs the extension beside a shell
// "function" inside the real Lambda base image, whose emulator implements the
// Extensions API. It is opt-in (ACCESS_ROSTER_RIE=1): it needs docker, a pull
// of public.ecr.aws/lambda/provided:al2023 and a free port 8080. The emulator
// has no Telemetry API (it answers the subscription 202 Telemetry.NotSupported),
// so this test proves the extension tolerates that, not that logs flow.
func TestInTheRuntimeInterfaceEmulator(t *testing.T) {
	if os.Getenv("ACCESS_ROSTER_RIE") != "1" {
		t.Skip("set ACCESS_ROSTER_RIE=1 to run against aws-lambda-rie in docker")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	if ln, err := net.Listen("tcp", "127.0.0.1:"+riePort); err != nil {
		t.Skip("port 8080 is busy")
	} else {
		_ = ln.Close()
	}
	bin := extensionBinary(t)
	sts, up := newFakeSTS(t), newFakeUpstream(t)
	issuer := newFakeIssuer(t, 900)

	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "opt", "extensions"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "task"), 0o755))
	data, err := os.ReadFile(bin)
	must(err)
	must(os.WriteFile(filepath.Join(root, "opt", "extensions", "access-roster-otlp"), data, 0o755))
	// The function exports through the loopback proxy like an OTel SDK would.
	must(os.WriteFile(filepath.Join(root, "task", "bootstrap"), []byte(`#!/bin/bash
while true; do
  h=$(mktemp)
  curl -sS -D "$h" -o /dev/null "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"
  id=$(grep -i '^lambda-runtime-aws-request-id' "$h" | cut -d' ' -f2 | tr -d '\r')
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d '{"resourceSpans":[]}' http://127.0.0.1:4318/v1/traces)
  curl -s -X POST "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/${id}/response" -d "{\"export\":${code}}"
done
`), 0o755))

	name := fmt.Sprintf("access-roster-rie-%d", time.Now().UnixNano())
	run := exec.Command("docker", "run", "--rm", "--name", name, "--network", "host",
		"-v", filepath.Join(root, "opt", "extensions")+":/opt/extensions:ro",
		"-v", filepath.Join(root, "task")+":/var/task:ro",
		"-e", "AWS_REGION=eu-west-1", "-e", "AWS_ACCESS_KEY_ID=AKIDEXAMPLE", "-e", "AWS_SECRET_ACCESS_KEY=secret",
		"-e", "AWS_SESSION_TOKEN=session", "-e", "AWS_ENDPOINT_URL_STS="+sts.URL, "-e", "AWS_EC2_METADATA_DISABLED=true",
		"-e", "ACCESS_ROSTER_ISSUER="+issuer.URL, "-e", "ACCESS_ROSTER_AUDIENCE="+issuer.URL,
		"-e", "ACCESS_ROSTER_OTLP_ENDPOINT="+up.URL,
		"-e", "ACCESS_ROSTER_FUNCTION_LOGS=true", "-e", "ACCESS_ROSTER_EXTENSION_LOGS=true",
		"public.ecr.aws/lambda/provided:al2023", "handler")
	logs := &syncBuffer{}
	run.Stdout, run.Stderr = logs, logs
	must(run.Start())
	t.Cleanup(func() {
		_ = exec.Command("docker", "stop", "-t", "3", name).Run()
		_ = run.Wait()
		t.Logf("emulator output:\n%s", logs.String())
	})

	var answer string
	eventually(t, "the emulator to answer an invocation", func() bool {
		resp, err := http.Post("http://127.0.0.1:"+riePort+"/2015-03-31/functions/function/invocations", "application/json", strings.NewReader("{}"))
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		answer = string(b)
		return resp.StatusCode == 200
	})
	if !strings.Contains(answer, `"export":200`) {
		t.Fatalf("the function's export was answered %q", answer)
	}
	// The emulator implements the Extensions API only: it answers a Telemetry
	// API subscription 202 "Telemetry.NotSupported" and delivers no events,
	// so the platform-log path is covered by the fake-Telemetry-API tests in
	// telemetry_test.go. Here it must degrade to one log line and nothing else.
	eventually(t, "the unsupported Telemetry API to be reported", func() bool {
		return strings.Contains(logs.String(), "Lambda telemetry logs are off: telemetry subscribe: 202")
	})
	if seen := up.seen(); len(seen) == 0 || seen[0].Auth != "Bearer access-1" {
		t.Fatalf("upstream saw %+v", seen)
	}
}
