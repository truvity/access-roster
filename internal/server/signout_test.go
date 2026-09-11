package server

import "testing"

// What the console is told to point its sign-out at.
//
// It treats a bare "/logout" as its OWN route and posts to it with a
// fetch, which is right in the split deployment where it serves that
// route. On one origin the route belongs to the ISSUER, answers with a
// redirect, and a fetch would swallow the redirect — leaving somebody
// looking at a page that says they signed out while the session is open.
//
// So an issuer serving this console reports its sign-out ABSOLUTELY,
// which is what makes the console navigate instead of fetch. Reported
// twice before it was right: once as a 404 from the button, and again
// after the route existed but only answered GET.
func TestWhereTheConsoleSendsSignOut(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		signOutURL string
		issuerURL  string
		want       string
	}{
		{
			name:      "the issuer serving this console owns sign-out",
			issuerURL: "https://access.example",
			want:      "https://access.example/logout",
		},
		{
			// A proxy in front ends the session it holds, and only it can.
			name:       "a proxy in front wins",
			signOutURL: "/console/oauth2/sign_out",
			issuerURL:  "https://access.example",
			want:       "/console/oauth2/sign_out",
		},
		{
			// No issuer beside it: the console's own route, which it
			// serves and posts to.
			name: "alone, it is the console's own",
			want: "/logout",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := &ConsoleServer{signOutURL: tc.signOutURL}
			s.UseIssuerURL(tc.issuerURL)

			if got := s.signOut(); got != tc.want {
				t.Errorf("signOut() = %q, want %q", got, tc.want)
			}
		})
	}
}
