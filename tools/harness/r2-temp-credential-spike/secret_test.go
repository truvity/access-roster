package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestASecretPrintsAsAPlaceholderInEveryVerb(t *testing.T) {
	c := credentials{AccessKeyID: "key-id-for-the-test", Secret: "secret-for-the-test", SessionToken: "session-for-the-test"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		out := fmt.Sprintf(verb, c) + fmt.Sprintf(verb, c.Secret)
		for _, leak := range []string{"for-the-test"} {
			if strings.Contains(out, leak) {
				t.Errorf("%s printed a secret: %s", verb, out)
			}
		}
	}
}

func TestTheRedactorReplacesWhatItWasToldAboutAndNothingShort(t *testing.T) {
	r := newRedactor()
	r.add("a1b2c3d4e5f60718293a4b5c6d7e8f90", "<account>")
	r.add("ab", "<short>")
	got := r.clean(`Get "https://a1b2c3d4e5f60718293a4b5c6d7e8f90.r2.cloudflarestorage.com/b": abort`)
	if strings.Contains(got, "a1b2c3d4") || !strings.Contains(got, "<account>.r2.") || !strings.Contains(got, "abort") {
		t.Errorf("clean = %q", got)
	}
}
