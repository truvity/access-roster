# 0021 — Clients are declared, a resource maps to a registered client, and a self-described client is admitted only from an allow-listed origin

**Status:** Accepted
**Date:** 2026-11-02

Proposal: [issue #789](https://github.com/truvity/sluis/issues/789).

## Context

The first working version reads a cut of v1's client model: `kind`, `redirects`, `secret`, `requires` and `ttl_cap` ([Install file](/reference/install-file/#clients)). Parity adds the rest of it: the full client declaration ([#789](https://github.com/truvity/sluis/issues/789)), generated secrets with rotation ([#790](https://github.com/truvity/sluis/issues/790)), resources with RFC 8707 ([#791](https://github.com/truvity/sluis/issues/791)), clients that identify themselves with a metadata document ([#792](https://github.com/truvity/sluis/issues/792)), MCP authorization ([#822](https://github.com/truvity/sluis/issues/822)) and the sidecar that fronts a stock MCP server ([#823](https://github.com/truvity/sluis/issues/823)). Agent-class sessions and their consent are already decided ([0018](/decisions/0018-sessions/#agent-sessions)), and so is the audience rule: a token has one audience, a registered client id, and a resource indicator selects a client and is never copied into `aud` ([0017](/decisions/0017-identity-and-sign-in/#audiences)).

The forces: a client is authority, so it is declared and never operator-set ([0004](/decisions/0004-the-data-model/#storage-classes)); a document that anyone can publish must not be able to widen anything (principle 4); sluis takes the core of a standard before its extensions (principle 5); and the MCP authorization specification names the pieces an agent client relies on. On 2026-11-02 the current revision of the MCP specification is `2026-07-28` (READ at modelcontextprotocol.io/specification/versioning). It makes Client ID Metadata Documents (`draft-ietf-oauth-client-id-metadata-document-00`) a SHOULD for authorization servers and dynamic registration a MAY, now deprecated; it requires servers to publish RFC 9728 metadata and clients to send `resource` on every request.

## Decision

### The client declaration

- **These are the installation's own clients, and they are authority:** declared, reviewed and delivered read-only. A client that a tenant registers for itself is an instance issued under a declared template, not a declaration ([0004](/decisions/0004-the-data-model/#storage-classes)); this record covers the first kind.
- **A client is exactly one of three kinds,** as in the install file: `public`, `confidential`, `exchange`. A `public` client has a `profile`: `browser` (exact `https` redirects) or `native` (the loopback redirects of RFC 8252 with any port, or a claimed `https` redirect). The four typed profiles of v1 parity are therefore `browser`, `native`, `service` (a `confidential` client) and `machine` (an `exchange` client). A kind fixes the defaults that belong together (PKCE, the allowed grants, the client authentication method), and the loader refuses a declaration that mixes them (REQ-CLIENT-005, REQ-CLIENT-020).
- **There is no `client_credentials` grant.** A machine uses token exchange with a workload proof ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)).
- **The fields added at parity:** `display_name` and `description` (shown on the sign-in and consent pages; control and bidirectional characters refused, length bounded), `post_logout_redirects`, `backchannel_logout_uri`, `signing_alg` where a relying party cannot take the default ([0006](/decisions/0006-keys-and-sealing/#named-exceptions)), and `harness` for the conformance harness client ([Conformance](/standards/conformance/)). `requires` is never empty (an empty list is refused), and `frontchannel_logout_uri` and `initiate_login_uri` are refused (REQ-AUTHN-062). The exact fields and their schema are on [Install file](/reference/install-file/#clients).
- **The class of a session comes from policy, not from the client** ([0018](/decisions/0018-sessions/#the-classes)).
- **A generated secret is 32 random bytes** from a cryptographic source, kept in the `secrets` port as one immutable item per version ([0009](/decisions/0009-export/)). The current and the previous version both authenticate for an overlap that the operator sets at rotation, up to a declared maximum, compared in constant time (REQ-CLIENT-003, REQ-CLIENT-015, REQ-CLIENT-016). The value is shown once, to the operator who generated or rotated it; afterwards only the version, its creation and its retirement are visible. A secret version is an issued, durable record: it is backed up sealed and rolled forward ([0010](/decisions/0010-backup-and-recovery/)).

### Resources

- **A resource is declared:** `resources` maps an absolute `https` URI, without a fragment, to `client` (the registered client whose id is the token's `aud`), `requires`, `ttl_cap` and `display_name`. Adding `resources` is compatible with schema v1 of the install file.
- **A request names at most one resource** with the `resource` parameter, in the authorization and the token request. Several, a relative URI or a fragment are refused; an undeclared resource is refused with `invalid_target` (REQ-TOKEN-021). The URI is matched literally.
- **Two gates apply:** the caller must satisfy the client's `requires` and the resource's. The shorter of the two caps wins. A refusal for an entitlement shows the generic message and puts the reason in the log only (REQ-UX-001, REQ-UX-006).
- **The resource is recorded with the session and checked again at every refresh.**
- **v1's read-only resource with a longer session is not carried.** A long-running caller is an agent-class session ([0018](/decisions/0018-sessions/#agent-sessions)).

### Self-described clients

A client may present an `https` URL as its `client_id`; sluis then fetches its metadata document.

- **It is off until an origin is named.** The declared block `client_documents` has `origins` (host names, no scheme, path or wildcard), `requires` (mandatory with `origins`: the one gate for every such client), and optionally `ttl_cap` and `class`. Discovery advertises `client_id_metadata_document_supported` only while an origin is named. A declared client with the same id always wins.
- **The origin is decided before any connection** (REQ-CLIENT-007). The fetch uses the egress policy that checks addresses after name resolution and refuses loopback, link-local and private ones (REQ-FED-008), follows no redirect, accepts at most 64 KiB, allows 10 seconds per attempt with one retry, and is limited to 30 fetches a minute per host. A failure is remembered for a minute.
- **A document client is always public.** The document's `client_id` must equal its URL, it must have `redirect_uris`, its `token_endpoint_auth_method` must be `none`, and a secret in it is refused.
- **The document grants nothing.** Its `kind`, `requires`, `ttl_cap` and any session class are ignored; the gate, the cap and the class come from `client_documents`. A client cannot choose a longer session by publishing a document ([0018](/decisions/0018-sessions/#the-classes)).
- **Cache:** 10 minutes. The last good copy may be used for up to one hour past expiry, for transport failures only; a refused answer (invalid document, redirect, 4xx, too large) is never served stale.
- **The consent and sign-in pages show the client's cleaned display name and its host,** and audit records the URL (REQ-UX-004).
- **Dynamic client registration is not offered** (REQ-CLIENT-008).

### MCP authorization

- **sluis implements one revision of the MCP authorization specification at a time, and pins it:** `2026-07-28` today. Moving the pin is a change to this record's pin and to the conformance vectors in the same pull request.
- **sluis is the authorization server only.** It publishes RFC 8414 and OpenID Connect discovery, advertises `authorization_response_iss_parameter_supported` and sends `iss` on every redirect, requires PKCE S256, accepts CIMD clients and `resource`, and issues the agent-class sessions of 0023 for them.
- **A resource server publishes its own RFC 9728 metadata,** naming sluis as authorization server. The declared resource carries what is needed to render it (the URI, the issuer, the supported scopes), so the Go and TypeScript libraries and the sidecar write the same document from one declaration (REQ-CLIENT-012).
- **A resource server checks that `aud` is the registered client of its resource,** not its URL. A stock MCP server that compares `aud` with its own URL is fronted by the sidecar.

### The resource-proxy sidecar

- **It is a release image beside the server and not a sluis actor.** It has no state, no key and no manifest; it is configured with the issuer, the resource URI and the upstream.
- **It verifies the token** (signature against the issuer's key set, `iss`, `exp`, and `aud` equal to the resource's client), **serves the RFC 9728 metadata without authentication, strips the caller's `Authorization` header before it forwards,** and writes one structured log line per request in the fixed format ([0016](/decisions/0016-telemetry/)). It reads no group.
- **An optional outbound forwarder** adds the workload's own token, obtained by token exchange with the workload proof of the pod. Inconsistent outbound settings are refused at start.

## Consequences

- An MCP client that sends a resource and a metadata-document client id works against sluis with no registration step. The cost is the fetcher: an outbound request to a URL that a stranger names, bounded by the origin list, the egress policy and the limits above.
- A self-described client is only as trusted as the group its gate admits. An operator who allows an origin admits everyone who can publish there.
- Because `aud` is a client id and not a URL, an MCP server written against the plain specification needs the library or the sidecar. The price of keeping one audience rule.
- Moving the MCP pin is a deliberate change with tests, not a drift.
- Requirements: REQ-CLIENT-024 to REQ-CLIENT-034 are added.

## Roads not taken

- **Dynamic client registration.** An endpoint that mints trust for anyone; the specification now treats it as deprecated.
- **Take the resource URL as `aud`, as v1 did.** It would break the one-audience rule of 0006 and tie a token to a URL that the client typed.
- **Let the document set the session class, the gate or the lifetime.** Anyone who publishes a document could give their client an agent session of a month.
- **Allow redirects or private addresses in the fetch.** Both are the classic route from a client URL to an internal service.
- **Make sluis host the metadata of every resource.** It would put a resource server's facts in sluis and make sluis a registry of other products' endpoints.
- **Follow the newest MCP revision automatically.** A client library or a server would change behaviour between two releases with no test that says so.
- **The sidecar as an audit emitter.** It would need an audit identity and a transport; a log line serves the one consumer that exists.

## Follow-ups

- Resources as policy entities: [#979](https://github.com/truvity/sluis/issues/979).
- Build: client model [#789](https://github.com/truvity/sluis/issues/789), secrets [#790](https://github.com/truvity/sluis/issues/790), resources [#791](https://github.com/truvity/sluis/issues/791), metadata documents [#792](https://github.com/truvity/sluis/issues/792), MCP authorization [#822](https://github.com/truvity/sluis/issues/822), the sidecar [#823](https://github.com/truvity/sluis/issues/823).
