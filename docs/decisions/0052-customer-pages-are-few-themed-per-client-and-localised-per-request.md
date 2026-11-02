# 0052 — sluis serves a short list of customer pages from templates, themed per client and localised per request, on the host of the customer boundary

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #927](https://github.com/truvity/sluis/issues/927).

## Context

With sign-in done at the upstream ([0046](/decisions/0046-ciam-is-a-broker-the-upstream-owns-accounts-and-sluis-owns-sessions-and-tokens/)), the pages that sluis itself shows a customer are few. The requirements already say that pages come from templates with message catalogues ([REQ-UX-002](/requirements/ux/#REQ-UX-002)), that locales are configurable ([REQ-UX-007](/requirements/ux/#REQ-UX-007)), that a client names a theme from a declared set ([REQ-UX-003](/requirements/ux/#REQ-UX-003)), that a refusal shows only a generic message and a request identifier ([REQ-UX-001](/requirements/ux/#REQ-UX-001)), and that every page meets WCAG 2.1 AA ([REQ-A11Y-001](/requirements/a11y/#REQ-A11Y-001)) under a strict content security policy ([REQ-SEC-004](/requirements/sec/#REQ-SEC-004)). Open were the list of pages, the grain of the theme and the locale, and custom domains.

A custom domain does not fit the host model. One issuer is one host and one origin ([0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#issuers)); cookies are host-prefixed with no `Domain` ([REQ-SESS-007](/requirements/sess/#REQ-SESS-007)); every relying party pins `iss`; and passkey verifiers keep an allow-list of origins ([REQ-ISO-034](/requirements/iso/#REQ-ISO-034)). A domain per tenant would be an issuer, cookies, a certificate and a passkey origin per tenant.

## Decision

### The pages

sluis serves these pages for a customer, and no others:

| Page | When |
|---|---|
| Account chooser and identifier prompt | Only for a client that routes by domain ([0049](/decisions/0049-a-domain-routes-only-after-dns-proof-and-a-connection-has-a-trust-level/#choosing-the-connection)) |
| Redirect and form-post pages | While a sign-in is handed to the upstream or to the client |
| Step-up notice | Before the person is sent to authenticate again ([0023](/decisions/0023-sessions-have-three-classes-with-limits-per-class/#customers)) |
| Agent consent | When an agent asks for access ([REQ-CIAM-004](/requirements/ciam/#REQ-CIAM-004)) |
| My sessions | The person lists and revokes their sessions and agent sessions ([REQ-SESS-006](/requirements/sess/#REQ-SESS-006), [REQ-SESS-034](/requirements/sess/#REQ-SESS-034)) |
| Sign-out confirmation | RP-initiated logout |
| Refusals and errors | A generic message and a request identifier |

Registration, sign-in with a password or a factor, recovery and profile pages are the upstream's and are not served ([REQ-CIAM-018](/requirements/ciam/#REQ-CIAM-018)).

### Templates, locales and themes

- **Pages are rendered from templates with message catalogues** that ship with the release and are declared configuration. English is required; other locales are added to the declared list.
- **The locale is chosen per request:** the `ui_locales` parameter if it names a supported locale, otherwise the product's default, otherwise the `Accept-Language` header, otherwise English. sluis passes `ui_locales` to the upstream so that both sides speak the same language.
- **A theme is a declared bundle:** a name, a logo reference to a static asset, colours, a support link. A client names one theme. A tenant has no theme: the pages a tenant's people mostly see are the upstream's sign-in, which the customer-identity module brands.
- **There is no custom CSS, script or HTML from a tenant or a product.** A theme sets values; the template and the content security policy stay sluis's. `sluis config check` computes the contrast of a theme's colours and refuses a pair below the WCAG AA ratio.
- **Static assets** (a logo) are served from the blob store or a content delivery network, with fixed types, a size limit and a policy that allows `img-src` for the asset host only.
- **Every page carries stable machine-readable hooks** for test drivers ([REQ-UX-005](/requirements/ux/#REQ-UX-005)).

### Hosts

- **A customer boundary has one host,** declared in the install file, one origin and one issuer. A tenant has none: its relying parties use the product's issuer and its people see the product's host.
- **Custom domains are not supported,** neither per tenant nor per client. A product that wants a vanity name for its own issuer declares it as its boundary host; a domain per tenant is a different issuer, with its own cookies and certificate, and no consumer asks for it.

## Consequences

- The customer sees few sluis pages, and each is small, generic and tested for accessibility and for the content security policy once.
- A tenant's brand is on the upstream's pages only. A product that needs the tenant's logo on a sluis page needs a record for that, with its consumer.
- Moving a product to another host changes its issuer, so relying parties repin; that is a deliberate change, as for any issuer.
- Requirements: [REQ-UX-012](/requirements/ux/#REQ-UX-012), [REQ-UX-013](/requirements/ux/#REQ-UX-013), [REQ-UX-014](/requirements/ux/#REQ-UX-014) are added.

## Roads not taken

- **A theme per tenant.** It needs tenant-supplied assets on a page that the customer rarely sees, and a way to keep them from carrying markup.
- **Custom CSS or templates from a product.** A tenant could rebuild the page into a phishing page on sluis's origin.
- **A custom domain per tenant.** It multiplies issuers, cookies, certificates and passkey origins by the number of tenants, and breaks the relying parties that pin `iss`.
- **Hosted sign-in, registration and recovery pages in sluis.** They are the upstream's job and the account hosting that [0046](/decisions/0046-ciam-is-a-broker-the-upstream-owns-accounts-and-sluis-owns-sessions-and-tokens/) refuses.
- **Locale from the tenant's setting.** A person's language is not their organisation's; the request carries the better signal.

## Follow-ups

- Templated, accessible, localised pages: [#927](https://github.com/truvity/sluis/issues/927).
