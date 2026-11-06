package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPercentileIsNearestRank(t *testing.T) {
	v := make([]int64, 100)
	for k := range v {
		v[k] = int64(k + 1)
	}
	for p, want := range map[float64]int64{50: 50, 95: 95, 100: 100, 1: 1} {
		if got := percentile(v, p); got != want {
			t.Errorf("p%v = %d, want %d", p, got, want)
		}
	}
	if percentile(nil, 50) != 0 {
		t.Error("an empty set must give 0")
	}
}

func results(n int, edit func(k int, r *credResult)) []credResult {
	out := make([]credResult, n)
	for k := range out {
		out[k] = credResult{Arm: "temp", Index: k + 1, Accepted: true, AttemptsToFirstAccept: 1, FirstAcceptMS: 120, Deleted: true,
			OpAcceptMS: map[string]int64{"put": 120, "get": 300}}
		if edit != nil {
			edit(k, &out[k])
		}
	}
	return out
}

func TestTheRuleNeedsThirtyCredentials(t *testing.T) {
	if v := summarizeArm("temp", results(29, nil)).Verdict; !strings.HasPrefix(v, "NO VERDICT") {
		t.Errorf("29 credentials: %q", v)
	}
	if v := summarizeArm("temp", results(30, nil)).Verdict; !strings.HasPrefix(v, "NO DELAY") {
		t.Errorf("30 clean credentials: %q", v)
	}
}

func TestOneRetryIsStillNoDelayButTwoIsADelay(t *testing.T) {
	one := results(30, func(k int, r *credResult) {
		if k == 0 {
			r.AttemptsToFirstAccept, r.FirstAttemptRefused, r.RefusalsBefore, r.Refused401 = 2, true, 1, 1
		}
	})
	if s := summarizeArm("temp", one); !strings.HasPrefix(s.Verdict, "NO DELAY") || s.FirstAttemptRefused != 1 {
		t.Errorf("one retry: %q, first attempt refused %d", s.Verdict, s.FirstAttemptRefused)
	}
	two := results(30, func(k int, r *credResult) {
		if k == 0 {
			r.AttemptsToFirstAccept = 3
		}
	})
	if v := summarizeArm("temp", two).Verdict; !strings.HasPrefix(v, "DELAY") {
		t.Errorf("two retries: %q", v)
	}
}

func TestARefusalAfterAnAcceptOrAMissingAcceptIsADelay(t *testing.T) {
	later := results(30, func(k int, r *credResult) {
		if k == 7 {
			r.RefusalsAfter, r.Refused403 = 1, 1
		}
	})
	s := summarizeArm("temp", later)
	if !strings.HasPrefix(s.Verdict, "DELAY") || s.WithLaterRefusal != 1 || s.Refused403 != 1 {
		t.Errorf("a later refusal: %+v", s)
	}
	never := results(30, func(k int, r *credResult) {
		if k == 0 {
			r.Accepted, r.AttemptsToFirstAccept = false, 0
		}
	})
	if s := summarizeArm("temp", never); !strings.HasPrefix(s.Verdict, "DELAY") || s.NeverAccepted != 1 {
		t.Errorf("never accepted: %+v", s)
	}
}

func TestTheCSVFilesHaveAHeaderAndARowEach(t *testing.T) {
	var cred, att bytes.Buffer
	rs := results(2, nil)
	rs[0].MintedAt = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	if err := writeCredentialsCSV(&cred, rs); err != nil {
		t.Fatal(err)
	}
	if err := writeAttemptsCSV(&att, []attempt{{Arm: "temp", Index: 1, Op: "put", Seq: 1, Status: 401, Code: "InvalidAccessKeyId", Class: classRefuse}}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(cred.String(), "\n"); lines != 3 {
		t.Errorf("credentials.csv has %d lines, want 3:\n%s", lines, cred.String())
	}
	if !strings.Contains(att.String(), "temp,1,put,1,0,0,401,InvalidAccessKeyId,refuse") {
		t.Errorf("attempts.csv:\n%s", att.String())
	}
}
