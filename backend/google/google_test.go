package google

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/truvity/access-roster/backend"
)

// The four scopes are read-only, and the console shows this same list for
// an operator to paste into a cloud console. A write scope arriving here
// would be granted by everyone who followed the setup, so the list is
// worth asserting rather than trusting.
func TestScopesAreReadOnlyAndComplete(t *testing.T) {
	t.Parallel()

	want := map[string]bool{
		"https://www.googleapis.com/auth/admin.directory.user.readonly":         false,
		"https://www.googleapis.com/auth/admin.directory.group.readonly":        false,
		"https://www.googleapis.com/auth/admin.directory.group.member.readonly": false,
		"https://www.googleapis.com/auth/admin.directory.domain.readonly":       false,
	}
	for _, scope := range Scopes {
		if !strings.HasSuffix(scope, ".readonly") {
			t.Errorf("scope %q is not read-only", scope)
		}
		if _, expected := want[scope]; !expected {
			t.Errorf("unexpected scope %q", scope)
		}
		want[scope] = true
	}
	for scope, seen := range want {
		if !seen {
			t.Errorf("missing scope %q", scope)
		}
	}
}

// Suspended and archived accounts are both not live. A consumer acts on
// that by removing access, so counting an archived leaver as live would
// keep access for someone who has gone.
func TestAccountLiveness(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		user *directory.User
		live bool
	}{
		{"active", &directory.User{PrimaryEmail: "Ada@North.Example"}, true},
		{"suspended", &directory.User{PrimaryEmail: "a@b.c", Suspended: true}, false},
		{"archived", &directory.User{PrimaryEmail: "a@b.c", Archived: true}, false},
	} {
		got := account(tc.user)
		if got.Live != tc.live {
			t.Errorf("%s: live = %v, want %v", tc.name, got.Live, tc.live)
		}
	}

	// Addresses are lower-cased on the way in, because every index above
	// this compares them as written.
	named := account(&directory.User{
		PrimaryEmail: "Ada@North.Example",
		Name:         &directory.UserName{GivenName: "Ada", FamilyName: "North"},
	})
	if named.Email != "ada@north.example" {
		t.Errorf("email = %q, want it lower-cased", named.Email)
	}
	if named.GivenName != "Ada" || named.FamilyName != "North" {
		t.Errorf("name = %q %q", named.GivenName, named.FamilyName)
	}
	// A user with no name block must not panic; callers tolerate empty.
	if bare := account(&directory.User{PrimaryEmail: "b@c.d"}); bare.GivenName != "" {
		t.Errorf("given name = %q, want empty", bare.GivenName)
	}
}

// A not-found is an answer and everything else is a failure. The hub
// draws its whole authoritative/hold distinction on that line: a
// not-found means the account is gone, an error means nothing may be
// concluded.
func TestNotFoundIsDistinguishedFromFailure(t *testing.T) {
	t.Parallel()

	if !isNotFound(&googleapi.Error{Code: http.StatusNotFound}) {
		t.Errorf("a 404 was not recognised")
	}
	for _, err := range []error{
		&googleapi.Error{Code: http.StatusForbidden},
		&googleapi.Error{Code: http.StatusInternalServerError},
		errors.New("dial: connection refused"),
		nil,
	} {
		if isNotFound(err) {
			t.Errorf("%v was taken for a not-found", err)
		}
	}
}

// The two errors an operator will actually hit during setup are the two
// worth explaining. The raw messages name neither the missing grant nor
// the missing privilege.
func TestErrorsExplainTheLikelyCause(t *testing.T) {
	t.Parallel()

	unauthorized := reason(&googleapi.Error{Code: http.StatusUnauthorized})
	if !strings.Contains(unauthorized.Error(), "client id") {
		t.Errorf("401 = %q, want it to name the missing grant", unauthorized)
	}
	forbidden := reason(&googleapi.Error{Code: http.StatusForbidden, Message: "insufficient permission"})
	if !strings.Contains(forbidden.Error(), "privileges") {
		t.Errorf("403 = %q, want it to name the missing privilege", forbidden)
	}
	// A transport failure keeps its own words AND is marked as one the
	// directory never answered: nothing was asked, so nothing was learned
	// about the credential, and a probe may honestly try again.
	plain := errors.New("dial: connection refused")
	transport := reason(plain)
	if !strings.Contains(transport.Error(), plain.Error()) {
		t.Errorf("a transport error lost its words: %v", transport)
	}
	if !errors.Is(transport, backend.ErrUnavailable) {
		t.Errorf("a transport error = %v, want it marked unavailable", transport)
	}
	// So is a 5xx: the provider apologising, not refusing.
	unavailable := reason(&googleapi.Error{Code: http.StatusServiceUnavailable, Message: "try later"})
	if !errors.Is(unavailable, backend.ErrUnavailable) {
		t.Errorf("503 = %v, want it marked unavailable", unavailable)
	}
	// A refusal is NOT: retrying it would only delay the truth.
	if errors.Is(forbidden, backend.ErrUnavailable) {
		t.Error("403 was marked unavailable; a refusal is an answer")
	}
	// Nor is a cancellation, which is this process stopping rather than
	// the directory failing.
	if errors.Is(reason(context.Canceled), backend.ErrUnavailable) {
		t.Error("a cancellation was marked unavailable")
	}
}

// Opening refuses what cannot work, before any network call, so a
// misconfiguration is a startup error rather than a puzzling 401 later.
func TestOpenRefusesIncompleteCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	if _, err := Open(ctx, []byte(`{"type":"service_account"}`), ""); err == nil {
		t.Errorf("opening with no admin was accepted")
	}
	if _, err := Open(ctx, nil, "admin@example.com"); err == nil {
		t.Errorf("opening with no key was accepted")
	}
	if _, err := Open(ctx, []byte("not json"), "admin@example.com"); err == nil {
		t.Errorf("opening with a key that is not JSON was accepted")
	}
	// A credentials file may also describe an external account, which
	// fetches its token from a URL the file names. Accepting one would
	// turn "read this key" into "authenticate as whatever answers that
	// endpoint", so only a service-account key is admitted.
	external := `{"type":"external_account","audience":"//iam.example/x","token_url":"https://example.invalid/token"}`
	if _, err := Open(ctx, []byte(external), "admin@example.com"); err == nil {
		t.Errorf("an external-account credential was accepted as a service-account key")
	}
}

// A service-account key cannot be retired from here, and saying so is
// more useful than pretending: the hub reports it as "deleted locally,
// retire the credential yourself".
func TestRevokeIsUnsupported(t *testing.T) {
	t.Parallel()

	err := (&Backend{}).Revoke(context.Background())
	if !errors.Is(err, backend.ErrUnsupported) {
		t.Errorf("revoke = %v, want ErrUnsupported", err)
	}
}

// The customer id is read from the admin's own user record.
//
// Customers.Get returns the same id but needs a FIFTH scope,
// `admin.directory.customer.readonly`, which is not in [Scopes] — so
// calling it means every administrator who has already consented has to
// consent again. Found live: Google granted the consent, and the first
// read failed with "Request had insufficient authentication scopes",
// naming no scope.
func TestTheCustomerIdComesFromTheAdminNotTheCustomersEndpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/users/"):
			_, _ = io.WriteString(w, `{"primaryEmail":"ada@north.example","customerId":"C0north"}`)
		case strings.HasSuffix(r.URL.Path, "/domains"):
			_, _ = io.WriteString(w, `{"domains":[{"domainName":"north.example","verified":true},`+
				`{"domainName":"unverified.example","verified":false}]}`)
		default:
			// Customers.Get would land here. In production it is a 403
			// that names no scope; here it is a failure with a name.
			http.Error(w, `{"error":{"code":403,"message":"insufficient scopes"}}`, http.StatusForbidden)
		}
	}))
	defer server.Close()

	svc, err := directory.NewService(ctx,
		option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	b := &Backend{svc: svc, admin: "ada@north.example"}

	tenant, err := b.Tenant(ctx)
	if err != nil {
		t.Fatalf("reading the tenant: %v", err)
	}
	if tenant.ID != "C0north" {
		t.Errorf("customer id = %q, want C0north", tenant.ID)
	}
	// Unverified domains are refused: a domain anyone may claim in a
	// console is not evidence of anything.
	if len(tenant.Domains) != 1 || tenant.Domains[0] != "north.example" {
		t.Errorf("domains = %v, want just the verified one", tenant.Domains)
	}
	var askedTheAdmin bool
	for _, path := range paths {
		if strings.Contains(path, "customers") {
			t.Errorf("Tenant called %q, which needs a scope the hub does not ask for", path)
		}
		askedTheAdmin = askedTheAdmin || strings.Contains(path, "/users/")
	}
	if !askedTheAdmin {
		t.Errorf("Tenant never read the admin's user record; it called %v", paths)
	}
}

// A backend with no admin has nothing to read the customer id from, and
// must say so rather than asking about the empty user.
func TestTheTenantNeedsAnAdmin(t *testing.T) {
	t.Parallel()

	if _, err := (&Backend{}).Tenant(context.Background()); err == nil {
		t.Error("a backend with no admin read a tenant")
	}
}

// A tenant's groups are read concurrently, and the pass is still atomic.
//
// One round trip per group means a tenant with sixty of them is sixty
// sequential reads; the first live workspace had sixty-two, and a full
// pass was minutes of wall clock. The bound is deliberate — the Admin
// SDK's quota is per tenant, not per reader — so this asserts that the
// reads overlap, that the order is the directory's however they finish,
// and that one failure still fails the whole pass.
func TestGroupMembersAreReadConcurrentlyAndAtomically(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const groupCount = 40
	const delay = 20 * time.Millisecond
	var inFlight, peak int64
	var failing string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/groups"):
			var entries []string
			for i := range groupCount {
				entries = append(entries, fmt.Sprintf(`{"email":"g%02d@north.example"}`, i))
			}
			_, _ = io.WriteString(w, `{"groups":[`+strings.Join(entries, ",")+`]}`)
		case strings.Contains(r.URL.Path, "/members"):
			now := atomic.AddInt64(&inFlight, 1)
			for {
				was := atomic.LoadInt64(&peak)
				if now <= was || atomic.CompareAndSwapInt64(&peak, was, now) {
					break
				}
			}
			time.Sleep(delay)
			atomic.AddInt64(&inFlight, -1)
			if failing != "" && strings.Contains(r.URL.Path, failing) {
				http.Error(w, `{"error":{"code":503,"message":"nope"}}`, http.StatusServiceUnavailable)
				return
			}
			_, _ = io.WriteString(w, `{"members":[{"email":"ada@north.example","type":"USER"}]}`)
		default:
			http.Error(w, `{"error":{"code":404}}`, http.StatusNotFound)
		}
	}))
	defer server.Close()

	svc, err := directory.NewService(ctx, option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	b := &Backend{svc: svc, admin: "ada@north.example"}

	start := time.Now()
	groups, err := b.Groups(ctx)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if len(groups) != groupCount {
		t.Fatalf("groups = %d, want %d", len(groups), groupCount)
	}
	// Sequential would be groupCount*delay; concurrent is a fraction of it.
	if elapsed > groupCount*delay/2 {
		t.Errorf("a full pass took %v, want the member reads to overlap", elapsed)
	}
	if got := atomic.LoadInt64(&peak); got < 2 || got > memberReaders {
		t.Errorf("peak concurrency = %d, want between 2 and the bound of %d", got, memberReaders)
	}
	// The directory's order, however the reads finished.
	for i := range groups {
		if want := fmt.Sprintf("g%02d@north.example", i); groups[i].Email != want {
			t.Fatalf("groups[%d] = %q, want %q — the order follows completion, not the directory", i, groups[i].Email, want)
		}
	}

	// One group failing fails the pass: a snapshot short of a group would
	// drop people out of their access with nothing having changed.
	failing = "g07"
	if _, err = b.Groups(ctx); err == nil {
		t.Error("one failing group did not fail the pass")
	}
}
