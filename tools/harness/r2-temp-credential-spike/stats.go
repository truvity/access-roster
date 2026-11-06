package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// minForRule is the number of credentials of an arm below which the decision rule gives no verdict.
const minForRule = 30

// percentile is the nearest-rank percentile of sorted values (p in 1..100). It is 0 for no value.
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[min(max(rank, 1), len(sorted))-1]
}

func sortedCopy(v []int64) []int64 {
	out := append([]int64(nil), v...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func ms(v int64) string { return strconv.FormatFloat(float64(v)/1000, 'f', 3, 64) + " s" }

// armSummary is the figures of one arm.
type armSummary struct {
	Arm                 string
	N                   int
	NeverAccepted       int
	FirstAttemptRefused int
	MaxAttemptsToAccept int
	P50, P95, Max       int64 // time to first accept, ms, over the credentials that were accepted
	WithLaterRefusal    int
	LaterRefusals       int
	Refused401          int
	Refused403          int
	OtherFailures       int
	FailedOps           map[string]int
	Codes               map[string]int
	PerOp               map[string][]int64
	LeftoverUndeleted   int
	Verdict             string
}

func summarizeArm(arm string, results []credResult) armSummary {
	s := armSummary{Arm: arm, FailedOps: map[string]int{}, Codes: map[string]int{}, PerOp: map[string][]int64{}}
	var first []int64
	for _, r := range results {
		if r.Arm != arm {
			continue
		}
		s.N++
		if r.Accepted {
			first = append(first, r.FirstAcceptMS)
			s.MaxAttemptsToAccept = max(s.MaxAttemptsToAccept, r.AttemptsToFirstAccept)
		} else {
			s.NeverAccepted++
		}
		if r.FirstAttemptRefused {
			s.FirstAttemptRefused++
		}
		if r.RefusalsAfter > 0 {
			s.WithLaterRefusal++
		}
		s.LaterRefusals += r.RefusalsAfter
		s.Refused401 += r.Refused401
		s.Refused403 += r.Refused403
		s.OtherFailures += r.Other
		if r.FailedOp != "" {
			s.FailedOps[r.FailedOp]++
		}
		if !r.Deleted {
			s.LeftoverUndeleted++
		}
		for _, c := range r.Codes {
			s.Codes[c]++
		}
		for op, v := range r.OpAcceptMS {
			s.PerOp[op] = append(s.PerOp[op], v)
		}
	}
	sorted := sortedCopy(first)
	s.P50, s.P95 = percentile(sorted, 50), percentile(sorted, 95)
	s.Max = percentile(sorted, 100)
	s.Verdict = verdict(s)
	return s
}

// verdict applies the decision rule of the spike page: with N of at least 30 and every credential accepted
// by its second attempt (at most one retry) and never refused after an accept, retrying once on a 401 is
// enough; anything else needs the v1 shape. Below 30 there is no verdict. The page says the maintainer decides.
func verdict(s armSummary) string {
	switch {
	case s.N < minForRule:
		return fmt.Sprintf("NO VERDICT: N is %d, the rule needs at least %d", s.N, minForRule)
	case s.NeverAccepted == 0 && s.MaxAttemptsToAccept <= 2 && s.WithLaterRefusal == 0:
		return "NO DELAY: retry once on 401 is enough for this arm"
	default:
		return "DELAY OR LATER REFUSAL: the v1 shape is needed for this arm (keep the old credential valid, hold the new one back, bound the attempts)"
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeSummary writes the summary text.
func writeSummary(w io.Writer, meta map[string]string, sums []armSummary, leftovers int) {
	say(w, "R2 credential propagation spike: summary\n")
	for _, k := range sortedKeys(meta) {
		say(w, "  %-22s %s\n", k, meta[k])
	}
	for _, s := range sums {
		say(w, "\narm: %s\n", s.Arm)
		say(w, "  credentials                         %d\n", s.N)
		say(w, "  never accepted within the deadline  %d\n", s.NeverAccepted)
		say(w, "  first attempt refused               %d\n", s.FirstAttemptRefused)
		say(w, "  most attempts to the first accept   %d\n", s.MaxAttemptsToAccept)
		say(w, "  time to first accept  p50           %s\n", ms(s.P50))
		say(w, "  time to first accept  p95           %s\n", ms(s.P95))
		say(w, "  time to first accept  max (p100)    %s\n", ms(s.Max))
		say(w, "  credentials refused after an accept %d\n", s.WithLaterRefusal)
		say(w, "  refusals after an accept (total)    %d\n", s.LaterRefusals)
		say(w, "  refusals by status                  401: %d   403: %d   other failures: %d\n", s.Refused401, s.Refused403, s.OtherFailures)
		say(w, "  operations that failed              %s\n", counts(s.FailedOps))
		say(w, "  error codes (credentials with it)   %s\n", counts(s.Codes))
		for _, op := range sortedKeys(s.PerOp) {
			v := sortedCopy(s.PerOp[op])
			say(w, "  first accept of %-6s p50 %s  p95 %s  max %s\n", op, ms(percentile(v, 50)), ms(percentile(v, 95)), ms(percentile(v, 100)))
		}
		say(w, "  decision rule                       %s\n", s.Verdict)
	}
	say(w, "\nobjects left behind after cleanup: %d\n", leftovers)
}

func counts(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+": "+strconv.Itoa(m[k]))
	}
	return strings.Join(parts, "   ")
}

// say writes formatted text; a failed write of the summary to a terminal is not worth handling.
func say(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

func b(v bool) string { return strconv.FormatBool(v) }

func i(v int64) string { return strconv.FormatInt(v, 10) }

// writeCredentialsCSV writes one row for each credential.
func writeCredentialsCSV(w io.Writer, results []credResult) error {
	cw := csv.NewWriter(w)
	ops := []string{"put", "get", "head", "delete"}
	head := []string{"arm", "credential", "minted_utc", "mint_ms", "accepted", "first_accept_ms", "attempts_to_first_accept",
		"first_attempt_refused", "refusals_before_accept", "refusals_after_accept", "last_refusal_ms", "refused_401", "refused_403", "other_failures"}
	for _, op := range ops {
		head = append(head, op+"_accept_ms")
	}
	head = append(head, "error_codes", "deleted", "failed_op")
	if err := cw.Write(head); err != nil {
		return err
	}
	rows := append([]credResult(nil), results...)
	sort.Slice(rows, func(a, c int) bool {
		if rows[a].Arm != rows[c].Arm {
			return rows[a].Arm < rows[c].Arm
		}
		return rows[a].Index < rows[c].Index
	})
	for _, r := range rows {
		row := []string{r.Arm, strconv.Itoa(r.Index), r.MintedAt.UTC().Format(time.RFC3339), i(r.MintMS), b(r.Accepted), "", strconv.Itoa(r.AttemptsToFirstAccept),
			b(r.FirstAttemptRefused), strconv.Itoa(r.RefusalsBefore), strconv.Itoa(r.RefusalsAfter), i(r.LastRefusalMS),
			strconv.Itoa(r.Refused401), strconv.Itoa(r.Refused403), strconv.Itoa(r.Other)}
		if r.Accepted {
			row[5] = i(r.FirstAcceptMS)
		}
		for _, op := range ops {
			if v, ok := r.OpAcceptMS[op]; ok {
				row = append(row, i(v))
			} else {
				row = append(row, "")
			}
		}
		row = append(row, strings.Join(r.Codes, ";"), b(r.Deleted), r.FailedOp)
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// writeAttemptsCSV writes one row for each request.
func writeAttemptsCSV(w io.Writer, attempts []attempt) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"arm", "credential", "operation", "attempt", "offset_ms", "duration_ms", "status", "error_code", "class"}); err != nil {
		return err
	}
	rows := append([]attempt(nil), attempts...)
	sort.Slice(rows, func(a, c int) bool {
		if rows[a].Arm != rows[c].Arm {
			return rows[a].Arm < rows[c].Arm
		}
		if rows[a].Index != rows[c].Index {
			return rows[a].Index < rows[c].Index
		}
		return rows[a].OffsetMS < rows[c].OffsetMS
	})
	for _, a := range rows {
		if err := cw.Write([]string{a.Arm, strconv.Itoa(a.Index), a.Op, strconv.Itoa(a.Seq), i(a.OffsetMS), i(a.DurMS), strconv.Itoa(a.Status), a.Code, a.Class}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
