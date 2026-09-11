package main

import (
	"errors"
	"strings"
	"testing"
)

// The exit codes are a contract: a wrapper script should be able to tell
// "sign in again" from "the issuer is down" without parsing English, and
// should know not to retry a refusal.
func TestTheExitCodesSayWhatToDoNext(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"a typo":             {badUsage("no such thing"), exitUsage},
		"no cached login":    {errNotSignedIn, exitNotSignedIn},
		"a refusal":          {errNotGranted, exitNotGranted},
		"the issuer is down": {errUnreachable, exitUnreachable},
		"something else":     {errors.New("something else went wrong"), 1},
	} {
		if got := codeFor(tc.err); got != tc.want {
			t.Errorf("%s = %d, want %d", name, got, tc.want)
		}
	}
}

// The audience already names the account and the role, so a profile
// needs nothing a person has to look up. An audience in another shape is
// a usage error rather than a guess: an ARN assembled from the wrong
// pieces fails at STS with a message about the role, not the audience.
func TestTheRoleComesFromTheAudience(t *testing.T) {
	t.Parallel()

	arn, err := roleFromAudience("aws:111122223333:power")
	if err != nil {
		t.Fatalf("roleFromAudience: %v", err)
	}
	if arn != "arn:aws:iam::111122223333:role/power" {
		t.Errorf("arn = %q", arn)
	}

	for _, bad := range []string{"aws:111122223333", "k8s:kernel", "aws::power", "aws:111122223333:", ""} {
		if _, err = roleFromAudience(bad); err == nil {
			t.Errorf("%q was turned into a role anyway", bad)
		} else if codeFor(err) != exitUsage {
			t.Errorf("%q exits %d, want a usage error", bad, codeFor(err))
		}
	}
}

// The session name appears in CloudTrail against every call these
// credentials make, so it names the person. STS refuses characters
// outside a narrow set and truncates at 64 — a name it refuses fails the
// whole call with a validation error naming the field.
func TestTheSessionNameIsSomethingSTSAccepts(t *testing.T) {
	t.Parallel()

	if got := sessionName("ada@north.example"); got != "ada@north.example" {
		t.Errorf("an ordinary address was changed: %q", got)
	}
	if got := sessionName(""); got != "accessctl" {
		t.Errorf("no name = %q, want a fallback STS accepts", got)
	}
	if got := sessionName("a b/c:d"); strings.ContainsAny(got, " /:") {
		t.Errorf("%q still carries characters STS refuses", got)
	}
	if got := sessionName(strings.Repeat("a", 200)); len(got) != 64 {
		t.Errorf("length = %d, want it truncated to 64", len(got))
	}
}

// The block this tool owns is rewritten; everything outside it belongs
// to somebody else and must survive untouched. A profile for a role
// somebody no longer holds must NOT survive: an entry that fails only
// when used is worse than one that is gone.
func TestOnlyOurOwnBlockIsRewritten(t *testing.T) {
	t.Parallel()

	theirs := "[profile personal]\nregion = eu-west-1\n"
	ours := marker + "\n\n[profile old@1111]\ncredential_process = accessctl aws\n" + endMarker + "\n"

	if got := strip(theirs + ours); got != theirs {
		t.Errorf("strip left %q, want only what was not ours", got)
	}
	// Nothing of ours yet: the file is returned as it was, with a
	// newline so the block that follows starts on its own line.
	if got := strip("[profile personal]\nregion = eu-west-1"); !strings.HasSuffix(got, "\n") {
		t.Errorf("strip = %q, want a trailing newline before our block", got)
	}
	// A half-written block — interrupted, or edited by hand — must not
	// take the rest of the file with it.
	if got := strip(theirs + marker + "\n[profile half]\n"); got != theirs {
		t.Errorf("an unterminated block left %q", got)
	}
}
