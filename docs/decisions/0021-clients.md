# 0021 — Clients: installation clients are config, tenant clients are durable, and a self-described client is admitted only from allow-listed hosts

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #789](https://github.com/truvity/sluis/issues/789).

## Context

The first working version reads a cut of v1's client model: `kind`, `redirects`, `secret`, `requires` and `ttl_cap`. Parity adds the rest of it: the full client declaration ([#789](https://github.com/truvity/sluis/issues/789)), generated secrets with rotation ([#790](https://github.com/truvity/sluis/issues/790)), resources with RFC 8707 ([#791](https://github.com/truvity/sluis/issues/791)), clients that identify themselves with a metadata document ([#792](https://github.com/truvity/sluis/issues/792)), MCP authorization ([#822](https://github.com/truvity/sluis/issues/822)) and the sidecar that fronts a stock MCP server ([#823](https://github.com/truvity/sluis/issues/823)). Agent-class sessions and their consent are already decided ([0018](/decisions/0018-sessions/#agent-sessions)), and so is the audience rule: a token has one audience, a registered client id, and a resource indicator selects a client and is never copied into `aud` ([0017](/decisions/0017-identity-and-sign-in/#audiences)).

The data model adds a second question: who writes a client. A client is authority, so the installation's own clients are config that a reviewer sees. But a customer that arrives at run time cannot wait for a pull request, and a tenant never appears in config ([0004](/decisions/0004-the-data-model/#storage-classes)). The answer is the pattern of the Tenant-adjustable profile: config declares a template with bounds, and a tenant admin, or a product for its tenant, makes an instance inside them ([0004](/decisions/0004-the-data-model/#profiles)).

The other forces: a document that anyone can publish must not be able to widen anything (principle 4); sluis takes the core of a standard before its extensions (principle 5); and the MCP authorization specification names the pieces an agent client relies on. On 2026-11-02 the current revision of the MCP specification is `2026-07-28` (READ at modelcontextprotocol.io/specification/versioning). It makes Client ID Metadata Documents (`draft-ietf-oauth-client-id-metadata-document-00`) a SHOULD for authorization servers and dynamic registration a MAY, now deprecated; it requires servers to publish RFC 9728 metadata and clients to send `resource` on every request.

## Decision

### The client declaration

- **Installation clients are config.** The installation's own clients and their resources are the config kind `InstallationClient`: declared, reviewed and delivered read-only as a signed document. It is Fixed, and IaC writes it.
- **Tenant clients are durable.** A client that a tenant admin, or a product for its tenant, registers is the durable kind `TenantClient` of that tenant, written by `exchange` after policy has decided ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). It is an instance under a template: the config kind `ClientTemplate` says which slots an instance may fill (redirect hosts, profiles such as FAPI 2.0, rates) and the bound on each, and the store refuses an out-of-bound write ([0005](/decisions/0005-the-store/#rules)). An instance holds no authority the template did not carry: no new grant name, no claim and no logic. A tenant may lower the rate limits of its own clients, checked against `RateBound` on write.
- **A client is exactly one of three kinds:** `public`, `confidential`, `exchange`. A `public` client has a `profile`: `browser` (exact `https` redirects) or `native` (the loopback redirects of RFC 8252 with any port, or a claimed `https` redirect). The four typed profiles of v1 parity are therefore `browser`, `native`, `service` (a `confidential` client) and `machine` (an `exchange` client). A kind fixes the defaults that belong together (PKCE, the allowed grants, the client authentication method), and the loader refuses a declaration that mixes them (REQ-CLIENT-005, REQ-CLIENT-020).
- **There is no `client_credentials` grant.** A machine uses token exchange with a workload proof ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)).
- **The fields added at parity:** `display_name` and `description` (shown on the sign-in and consent pages; control and bidirectional characters refused, length bounded), `post_logout_redirects`, `backchannel_logout_uri`, `signing_alg` where a relying party cannot take the default ([0006](/decisions/0006-keys-and-sealing/#named-exceptions)), and `harness` for the conformance harness client ([Conformance](/standards/conformance/)). `requires` is never empty (an empty list is refused), and `frontchannel_logout_uri` and `initiate_login_uri` are refused (REQ-AUTHN-062). The fields are the Protobuf message of the kind ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)).
- **The login domain of a client is a reference.** A client names an entry of the config kind `FrontHost`, which holds the domain and its relying-party ID. A domain needs DNS and a certificate, so it is Fixed and shared by clients; a tenant client may pick only from the entries config allows. Branding per client is [0035](/decisions/0035-customer-pages/)'s.
- **The class of a session comes from policy, not from the client** ([0018](/decisions/0018-sessions/#the-classes)).
- **A generated secret is 32 random bytes** from a cryptographic source. `exchange` stores its hash as the durable kind `ClientSecret`, one item per version, and `session` verifies it at the token endpoint, which is a read. The current and the previous version both authenticate for an overlap that the operator sets at rotation, up to a maximum that config declares, compared in constant time (REQ-CLIENT-003, REQ-CLIENT-015, REQ-CLIENT-016). The value is shown once, to the operator or the product that generated or rotated it; afterwards only the version, its creation and its retirement are visible.
- **A secret that must leave sluis is stored twice.** A client marked exportable also has a sealed copy, `ClientSecretExport`, which exporter@ writes to the client's destination ([0009](/decisions/0009-export/#what-is-exportable)). A secret that is not exported keeps only its hash. A secret that IaC provides for an installation client is a secret kind, `InstallationClientSecret`, read from the secret source ([0005](/decisions/0005-the-store/#secret-sources)).
- **A secret version is authoritative durable data.** It is backed up as the hash or the sealed copy and rolled forward after a restore ([0010](/decisions/0010-backup-and-recovery/)).

### Resources

- **A resource is declared with the installation's clients:** `resources` maps an absolute `https` URI, without a fragment, to `client` (the registered client whose id is the token's `aud`), `requires`, `ttl_cap` and `display_name`.
- **A request names at most one resource** with the `resource` parameter, in the authorization and the token request. Several, a relative URI or a fragment are refused; an undeclared resource is refused with `invalid_target` (REQ-TOKEN-021). The URI is matched literally.
- **Two gates apply:** the caller must satisfy the client's `requires` and the resource's. The shorter of the two caps wins. A refusal for an entitlement shows the generic message and puts the reason in the log only (REQ-UX-001, REQ-UX-006).
- **The resource is recorded on the session chain and checked again at every refresh** ([0018](/decisions/0018-sessions/#session-chains)).
- **v1's read-only resource with a longer session is not carried.** A long-running caller is an agent-class session ([0018](/decisions/0018-sessions/#agent-sessions)).

### Self-described clients

A client may present an `https` URL as its `client_id`; sluis then fetches its metadata document.

- **It is off until a host is named.** The config kind `ClientDocumentGate` has `hosts` (host names, no scheme, path or wildcard), `requires` (mandatory with `hosts`: the one gate for every such client), and optionally `ttl_cap` and `class`. Discovery advertises `client_id_metadata_document_supported` only while a host is named. A declared client with the same id always wins.
- **The host is decided before any connection** (REQ-CLIENT-007). `session` makes the fetch with the egress policy that checks addresses after name resolution and refuses loopback, link-local and private ones (REQ-FED-008), follows no redirect, accepts at most 64 KiB, allows 10 seconds per attempt with one retry, and is limited to 30 fetches a minute per host. A failure is remembered for a minute.
- **A document client is always public.** The document's `client_id` must equal its URL, it must have `redirect_uris`, its `token_endpoint_auth_method` must be `none`, and a secret in it is refused.
- **The document grants nothing.** Its `kind`, `requires`, `ttl_cap` and any session class are ignored; the gate, the cap and the class come from `ClientDocumentGate`. A client cannot choose a longer session by publishing a document ([0018](/decisions/0018-sessions/#the-classes)).
- **The fetched document is the temp kind `ClientDocument`,** written by `session`: 10 minutes, and the last good copy may be used for up to one hour past expiry, for transport failures only. A refused answer (invalid document, redirect, 4xx, too large) is never served stale.
- **The consent and sign-in pages show the client's cleaned display name and its host,** and audit records the URL (REQ-UX-004).
- **Dynamic client registration is not offered** (REQ-CLIENT-008).

### MCP authorization

- **sluis implements one revision of the MCP authorization specification at a time, and pins it:** `2026-07-28` today. Moving the pin is a change to this record's pin and to the conformance vectors in the same pull request.
- **sluis is the authorization server only.** It publishes RFC 8414 and OpenID Connect discovery, advertises `authorization_response_iss_parameter_supported` and sends `iss` on every redirect, requires PKCE S256, accepts CIMD clients and `resource`, and issues the agent-class sessions of [0018](/decisions/0018-sessions/#agent-sessions) for them.
- **A resource server publishes its own RFC 9728 metadata,** naming sluis as authorization server. The declared resource carries what is needed to render it (the URI, the issuer, the supported scopes), so the Go and TypeScript libraries and the sidecar write the same document from one declaration (REQ-CLIENT-012).
- **A resource server checks that `aud` is the registered client of its resource,** not its URL. A stock MCP server that compares `aud` with its own URL is fronted by the sidecar.

### The resource-proxy sidecar

- **It is a release image beside the server and not a sluis actor.** It has no state, no key and no entry in the actor registry; it is configured with the issuer, the resource URI and the upstream.
- **It verifies the token** (signature against the issuer's key set, `iss`, `exp`, and `aud` equal to the resource's client), **serves the RFC 9728 metadata without authentication, strips the caller's `Authorization` header before it forwards,** and writes one structured log line per request in the fixed format ([0016](/decisions/0016-telemetry/)). It reads no group.
- **An optional outbound forwarder** adds the workload's own token, obtained by token exchange with the workload proof of the pod. Inconsistent outbound settings are refused at start.

## Consequences

- An MCP client that sends a resource and a metadata-document client id works against sluis with no registration step. The cost is the fetcher: an outbound request to a URL that a stranger names, bounded by the host list, the egress policy and the limits above.
- A self-described client is only as trusted as the group its gate admits. An operator who allows a host admits everyone who can publish there.
- A customer's client is made at run time and never waits for a review, yet cannot step outside its template. The cost is a template to write and keep, and a bound for every slot that a tenant may fill.
- A generated secret is stored twice when it must leave sluis, so an exportable client carries a sealed copy that a plain one does not.
- Because `aud` is a client id and not a URL, an MCP server written against the plain specification needs the library or the sidecar. The price of keeping one audience rule.
- Moving the MCP pin is a deliberate change with tests, not a drift.
- Requirements: REQ-CLIENT-024 to REQ-CLIENT-034 are added.

## Roads not taken

- **Dynamic client registration.** An endpoint that mints trust for anyone; the specification now treats it as deprecated.
- **Take the resource URL as `aud`, as v1 did.** It would break the one-audience rule of [0017](/decisions/0017-identity-and-sign-in/#audiences) and tie a token to a URL that the client typed.
- **Let the document set the session class, the gate or the lifetime.** Anyone who publishes a document could give their client an agent session of a month.
- **Allow redirects or private addresses in the fetch.** Both are the classic route from a client URL to an internal service.
- **Make sluis host the metadata of every resource.** It would put a resource server's facts in sluis and make sluis a registry of other products' endpoints.
- **Follow the newest MCP revision automatically.** A client library or a server would change behaviour between two releases with no test that says so.
- **The sidecar as an audit emitter.** It would need an audit identity and a transport; a log line serves the one consumer that exists.
- **A tenant's clients as config committed by the operator.** A tenant never appears in config, and every customer client would wait for a review.
- **A template that lets an instance add a grant name or a claim.** The instance would carry authority that no reviewer saw.
- **The login domain as a field of each client.** A tenant client could then name a domain that config never provisioned.

## Follow-ups

- Resources as policy entities: [#979](https://github.com/truvity/sluis/issues/979).
- Build: client model [#789](https://github.com/truvity/sluis/issues/789), secrets [#790](https://github.com/truvity/sluis/issues/790), resources [#791](https://github.com/truvity/sluis/issues/791), metadata documents [#792](https://github.com/truvity/sluis/issues/792), MCP authorization [#822](https://github.com/truvity/sluis/issues/822), the sidecar [#823](https://github.com/truvity/sluis/issues/823).
