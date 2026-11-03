---
title: Contracts and errors
description: "How every sluis contract is written: Protobuf packages and versions, which services are public, deadlines, ids, idempotency, pagination and the error model."
status: target
sidebar:
  order: 4
---

Every major component of sluis is a ConnectRPC contract, written in Protobuf under `proto/`, even when caller and callee share a process ([ADR 0002](/decisions/0002-families-of-actors/#contracts)). This page is the rule book every `proto/` file and every HTTP endpoint follows. The endpoints themselves are on [System context](/architecture/context/#the-external-api-surface); the services each actor serves are in its [permission manifest](/architecture/manifest/).

## Packages and files

- **One package per owner, and one service per owning actor.** A contract belongs to the actor that serves it, or to the port or the integration kind it defines:

  | Owner | Package | Example service |
  |---|---|---|
  | An actor | `sluis.<actor>.v2alpha1` | `sluis.exchange.v2alpha1.ExchangeService` |
  | A port, served by its drivers | `sluis.port.<port>.v2alpha1` | `sluis.port.state.v2alpha1.StateService` |
  | The integration contracts | `sluis.integration.v2alpha1` | `IntegrationService`, `UpstreamService`, `FactsSourceService` |
  | Types shared by several packages | `sluis.type.v2alpha1` | `Refusal`, `PageRequest` |

- **A hyphen in an actor's name becomes an underscore:** `sluis.ssh_ca.v2alpha1`.
- **Files live at the package's path:** `proto/sluis/exchange/v2alpha1/exchange.proto`. The Go and Rust code is generated from them and is not committed under `proto/`.
- **Style:** services are `<Noun>Service`; a method is a verb or a verb and a noun (`Get`, `Cas`, `IssueCertificate`); its messages are `<Method>Request` and `<Method>Response`; fields are `snake_case`; every enum's zero value is `<ENUM>_UNSPECIFIED` and means "not set". A field number is never reused: a removed field becomes `reserved`.

## Versions

- **`v2alpha1` until v2.0.0.** Before the first v2 release a contract may change in any pre-release; nothing outside one release depends on it, because every artifact of a release is compatible only with that release ([ADR 0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases)).
- **`v2` from v2.0.0, frozen under the compatibility rule.** A field, a method, a service or an enum value may be added; nothing may be removed, renamed, renumbered or changed in meaning. A breaking change is a new package version beside the old one, for a deprecation window.
- **CI checks `proto/` for breaking changes** against the last release once `v2` exists ([GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md)).

## Surfaces

| Surface | Who calls it | How | Where it is defined |
|---|---|---|---|
| OAuth and OpenID Connect endpoints | Browsers, clients, relying parties | Plain HTTP on the issuer's origin, not Connect: `entry` parses and routes each request to `session` or `exchange` | The standards ([Endpoints](/architecture/context/#oidc-and-oauth-endpoints)) |
| Discovery and the key set | Anyone | Static documents in a bucket of the boundary ([ADR 0017](/decisions/0017-identity-and-sign-in/#issuers)) | The standards |
| Public Connect services: the console API, Quota, the signing API | The console's single-page application, declared clients, CI jobs | Connect over HTTPS through `entry`, JSON or binary Protobuf | `proto/`, published as generated OpenAPI |
| Internal services: actor to actor | The callers the call graph allows | Connect over a Unix socket with peer credentials, a Lambda invoke, or HTTPS with mutual TLS between boundaries; binary Protobuf | `proto/` |
| Port contracts | An actor's port library | Connect over the driver's Unix socket | `proto/sluis/port/` ([Storage](/reference/storage/#port-contracts)) |
| Integration contracts | Core actors | As internal services | `proto/sluis/integration/` ([Integration contracts](/architecture/components/#integration-contracts)) |

- **`entry` serves no business logic of its own.** It validates each request against closed parameter lists generated from these contracts and from the standards, and forwards it to the owning actor ([ADR 0002](/decisions/0002-families-of-actors/#the-four-families)).
- **An internal service is never reachable through `entry`.** The generated routing table lists the public methods only; any other path is refused as unknown.
- **The call graph is default deny.** A caller may call a method only if both manifests name the edge; one interceptor in every process enforces it ([ADR 0002](/decisions/0002-families-of-actors/#registries-generate-the-enforcement)).

## Every call

- **A deadline.** Every call carries one (`Connect-Timeout-Ms`); a method without one gets the default its contract declares. A callee never extends its caller's deadline, and passes what is left to the calls it makes.
- **A correlation id.** `entry` gives every request a random 128-bit id (UUID version 4), returns it in the `Sluis-Correlation-Id` response header, and passes it in the metadata of every internal call that request causes. Every audit record of the request carries it, so a support question with the id finds the records. A client cannot choose it; one it sends is ignored.
- **Trace context.** W3C Trace Context headers are passed on; only internal actors use a remote parent, and the telemetry rules are [ADR 0016](/decisions/0016-telemetry/). A span never carries what an audit record says ([ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf)).
- **Idempotency.** Every public method that changes something takes a `request_id` field, chosen by the client; `entry` also accepts an `Idempotency-Key` header and copies it in, and refuses both with different values. A request id is scoped to the client and the method and remembered for 24 hours with its outcome. A repeat returns the first outcome; a reused id with another payload is refused (`failed_precondition`); a repeat while the first is still running is `aborted` (HTTP 409) ([ADR 0030](/decisions/0039-quota-allowance/#the-allowance)).
- **Pagination by cursor.** A list method takes `page_size` (at most the maximum its contract declares) and `page_token`, and returns `next_page_token`, empty on the last page. A token is opaque, bound to the query that made it and to the caller, and expires; a token used with another query is `invalid_argument`.

## Errors

### Connect codes

A Connect error has a code and, inside sluis, a `sluis.type.v2alpha1.Refusal` detail with a reason from a closed list. The codes sluis uses, with the HTTP status of the Connect protocol:

| Code | HTTP | When |
|---|---|---|
| `invalid_argument` | 400 | The request does not fit the contract: a missing or malformed field, a value outside its range, a bad page token |
| `unauthenticated` | 401 | No credential, or one that does not verify |
| `permission_denied` | 403 | The caller is known and is not allowed this |
| `not_found` | 404 | No such object, or one the caller may not know exists |
| `already_exists` | 409 | A create-only write found the key taken |
| `aborted` | 409 | A compare-and-set lost to another writer, or a repeat of a request that is still running |
| `failed_precondition` | 400 | The state does not allow it: a reused request id with another payload, a revision the caller did not read |
| `resource_exhausted` | 429 | A quota or a rate limit, with `Retry-After` |
| `deadline_exceeded` | 504 | The deadline passed |
| `unimplemented` | 501 | A method or a feature the callee does not serve |
| `unavailable` | 503 | A dependency is down; sluis fails closed and never answers on a weaker basis |
| `internal` | 500 | A bug |

The integration contracts keep their own closed list as the `Refusal` reason, each with one Connect code ([Integration contracts](/architecture/components/#integration-contracts)):

| Reason | Code |
|---|---|
| `UNAVAILABLE` | `unavailable` |
| `UPSTREAM_REJECTED` | `failed_precondition` |
| `INVALID` | `invalid_argument` |
| `NOT_FOUND` | `not_found` |
| `RATE_LIMITED` | `resource_exhausted` |
| `UNSUPPORTED` | `unimplemented` |
| `STALE` | `failed_precondition` |

No vendor error text crosses the contract.

### Uniform refusals at the edge

A refusal tells a caller what to do, never why someone else may do more:

- **Inside sluis** the `Refusal` detail travels with the error, so the calling actor can act on it.
- **At `entry`** the detail is removed. A public caller gets the code, a fixed message for that code and the correlation id, nothing that names a client, an audience, a group, a grant or a policy rule. The reason goes into the audit record of the refusal.
- **A refused and an unknown object look the same:** an audience the caller may not use and one that does not exist give the same answer ([System context](/architecture/context/#token-exchange-and-mint)).
- **Errors never show a value** of configuration or of a request, only the path of the field ([ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf)).

### OAuth and OpenID Connect endpoints

These endpoints answer in the error format of their standard, as clients implement it ([principle 5](/principles/#5-open-standards-as-their-consumers-implement-them)):

| Endpoint | Errors |
|---|---|
| Authorization | Redirected to the client with `error` and `state` (RFC 6749, section 4.1.2.1): `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`, `temporarily_unavailable`, and OpenID Connect's `login_required` and `interaction_required`. A bad `redirect_uri` or `client_id` is never redirected: the browser gets an error page with the correlation id |
| Token | JSON with `error` (RFC 6749, section 5.2): `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`; RFC 8693 adds `invalid_target`, which is also the answer for a refused audience |
| A protected resource (UserInfo) | `WWW-Authenticate` with `invalid_request`, `invalid_token` or `insufficient_scope` (RFC 6750), and `insufficient_user_authentication` with `acr_values` and `max_age` for step-up (RFC 9470) |

`error_description` is a fixed text per code, never built from the request. Other plain HTTP endpoints answer with RFC 9457 problem details whose `type` is a fixed URN per error.

## Open items

None on this page: what it fixes follows from ADR 0002, ADR 0004, ADR 0030, v1's uniform refusals ([#796](https://github.com/truvity/sluis/issues/796)) and the standards. The list of `Refusal` reasons is written with the first contract that needs one, in `proto/sluis/type/`.
