// The policy of the local installation (tests/installations/local), written against the Cedar
// schema of sluis policy, version 1, and the vocabulary beside it. The ids are stable: audit
// records and tests name them.

// ---- A held person gets nothing --------------------------------------------------------

// An operator's hold takes effect at once and outlasts every binding (ADR 0019).
@id("person-not-live")
forbid (principal is Person, action, resource)
when { principal.state != "live" };

// ---- Which accounts hold which grants (the bindings) -----------------------------------

// A binding names accounts, by the upstream's declared name and the value of its subject claim,
// never by e-mail address. These two hold the user role of the example app.
@id("bind-example-users")
permit (
  principal is Person,
  action == Action::"grant.hold",
  resource == Grant::"dev:example-app:user"
)
when { principal in [Account::"workforce/u-1001", Account::"workforce/u-1002"] };

// A wildcard in the thing position: this account holds the admin role of every thing in the
// scope `dev`.
@id("bind-dev-admins")
permit (principal in Account::"workforce/u-2001", action == Action::"grant.hold", resource)
when { resource.scope == "dev" && resource.role == "admin" };

// A sensitive scope is named in full.
@id("bind-prod-admins")
permit (
  principal in Account::"workforce/u-3001",
  action == Action::"grant.hold",
  resource == Grant::"prod:example-app:admin"
);

// A wildcard that reaches a sensitive scope. Cedar permits it, and `policy` does not count the
// grants it reaches in `prod`, because only a policy that names a sensitive grant in full may
// give it (REQ-POLICY-011).
@id("bind-all-admins")
permit (principal in Account::"workforce/u-4001", action == Action::"grant.hold", resource)
when { resource.role == "admin" };

// ---- What a person may get a token for -------------------------------------------------

// A person who holds one of a client's required grants may have a token for it.
@id("token-requires")
permit (
  principal is Person,
  action in [Action::"token.issue", Action::"token.exchange"],
  resource is Client
)
when { principal has grants && resource.requires.containsAny(principal.grants) };

// ---- Step-up ---------------------------------------------------------------------------

// `example-app` of the `dev` boundary wants multi-factor authentication no older than 15
// minutes. When a request carries no `amr` or no `auth_age`, as with an upstream that sends
// none, the answer is "not shown", so the person is asked to step up. The annotation tells
// `session` what to ask for (RFC 9470): the values of `acr_values` and `max_age` that it puts
// in `insufficient_user_authentication`.
@id("example-app-fresh-mfa")
@step_up("acr_values=urn:example:acr:mfa max_age=900")
forbid (
  principal is Person,
  action in [Action::"token.issue", Action::"token.exchange"],
  resource == Client::"dev/example-app"
)
unless {
  context has amr && context.amr.contains("mfa") &&
  context has auth_age && context.auth_age <= 900
};

// ---- Signing a release ------------------------------------------------------------------

// The release workflow of one repository, on a version tag, in the `release` environment, may
// have the release key sign.
@id("release-signing-from-tag")
permit (
  principal is Workload,
  action == Action::"artifact.sign",
  resource == SigningKey::"release-signing"
)
when {
  principal.verifier == "github-oidc" &&
  principal has repository && principal.repository == "acme/app" &&
  principal has ref && principal.ref like "refs/tags/v*" &&
  principal has workflow && principal.workflow == ".github/workflows/release.yaml" &&
  principal has environment && principal.environment == "release"
};

// ---- Templates, for bindings that operators link at run time ---------------------------

// An account holds a grant. Linked per tenant.
@id("bind-account-to-grant")
permit (
  principal in ?principal,
  action == Action::"grant.hold",
  resource == ?resource
);

// An account does not hold a grant, whatever else gives it. A forbid can only narrow, so
// it is what the console offers for "revoke".
@id("revoke-grant-from-account")
forbid (
  principal in ?principal,
  action == Action::"grant.hold",
  resource == ?resource
);

// ---- Who may link which template (the delegation policy) -------------------------------

// The administrators of a company, named by account, may bind accounts of their own company to
// grants in their own company's scope.
@id("delegate-company-bindings")
permit (
  principal is Person,
  action == Action::"policy.link",
  resource == Boundary::"dev"
)
when {
  principal in [Account::"acme/a-01", Account::"globex/a-01"] &&
  context.template == "bind-account-to-grant" &&
  context has principal_account && context.principal_account.org == principal.org &&
  context has resource_grant && context.resource_grant.scope == principal.org &&
  !context.resource_grant.sensitive
};

// The security account may revoke any grant from any account.
@id("delegate-revocation")
permit (
  principal in Account::"workforce/u-9001",
  action == Action::"policy.link",
  resource == Boundary::"dev"
)
when { context.template == "revoke-grant-from-account" };
