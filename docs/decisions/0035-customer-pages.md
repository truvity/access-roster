# 0035 — Customer pages are few, branded per client and login domain, and localised per request

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #927](https://github.com/truvity/sluis/issues/927).

## Context

With sign-in done at the upstream ([0031](/decisions/0031-ciam-is-a-broker/)), the pages that sluis itself shows a customer are few. The requirements already say that pages come from templates with message catalogues ([REQ-UX-002](/requirements/ux/#REQ-UX-002)), that locales are configurable ([REQ-UX-007](/requirements/ux/#REQ-UX-007)), that a refusal shows only a generic message and a request identifier ([REQ-UX-001](/requirements/ux/#REQ-UX-001)), and that every page meets WCAG 2.1 AA ([REQ-A11Y-001](/requirements/a11y/#REQ-A11Y-001)) under a strict content security policy ([REQ-SEC-004](/requirements/sec/#REQ-SEC-004)).

A product wants its customers to see its own brand on those pages, and a client may want its own login domain. Both raise a safety question.

- **A brand is data that a tenant or a product writes.** A page that renders it must not carry the tenant's markup, or a tenant could rebuild the page into a phishing page served from sluis's own host.
- **A login domain is an origin.** It needs DNS and a certificate, its cookies are host-prefixed with no `Domain` ([REQ-SESS-007](/requirements/sess/#REQ-SESS-007)), and every passkey verifier keeps an allow-list of origins ([REQ-ISO-034](/requirements/iso/#REQ-ISO-034)). A domain that a tenant could add at run time would be an origin that nobody reviewed.

The data model answers both: branding is a layered kind that is bounded by config ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)), and a login domain is a config kind that clients reference. Operators and staff are a different audience from customers. They confirm ceremonies and sign in with passkeys, and which domain those passkeys belong to needs one answer.

## Decision

### The pages

sluis serves these pages for a customer, and no others. `session` renders them.

| Page | When |
|---|---|
| Account chooser and identifier prompt | Only for a client that routes by domain, which needs more than one upstream ([0033](/decisions/0033-customer-connections/#choosing-the-connection)) |
| Redirect and form-post pages | While a sign-in is handed to the upstream or to the client |
| Step-up notice | Before the person is sent to authenticate again ([0018](/decisions/0018-sessions/#customers)) |
| Agent consent | When an agent asks for access ([REQ-CIAM-004](/requirements/ciam/#REQ-CIAM-004)) |
| My sessions | The person lists and revokes their sessions and agent sessions ([REQ-SESS-006](/requirements/sess/#REQ-SESS-006), [REQ-SESS-034](/requirements/sess/#REQ-SESS-034)) |
| Sign-out confirmation | RP-initiated logout |
| Refusals and errors | A generic message and a request identifier |

Registration, sign-in with a password or a factor, recovery and profile pages are the upstream's and are not served ([REQ-CIAM-018](/requirements/ciam/#REQ-CIAM-018)).

### Templates and locales

- **Pages are rendered from templates with message catalogues** that ship with the release. The templates and the catalogues are built-in, so they change only with a release ([0004](/decisions/0004-the-data-model/#built-in)). English is required.
- **The supported locales are a declared list** in config, a subset of the catalogues the release ships.
- **The locale is chosen per request:** the `ui_locales` parameter if it names a supported locale, otherwise the default locale of the client's branding, otherwise the `Accept-Language` header, otherwise English ([REQ-UX-012](/requirements/ux/#REQ-UX-012)). sluis passes `ui_locales` to the upstream so that both sides speak the same language.
- **A locale is never taken from a tenant's setting.** A person's language is not their organisation's. The default locale of a brand is a fallback, and the request carries the better signal.

### Branding

- **Branding is a layered kind** with three layers: the built-in default theme, the config kind `Branding`, and the durable kind `TenantBranding` ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)). `Branding` has the id `default` for the boundary or the id of an installation client. `TenantBranding` has the id `default` for a tenant or the id of a tenant client.
- **The most specific layer wins, field by field:** a tenant client, then its tenant, then an installation client, then the boundary default. A tenant's brand therefore shows on the pages its people see, and a client's own brand wins over the tenant's.
- **A theme is a set of values:** a name, a logo reference, colours, a support link and a default locale. A theme is data and holds no markup. Its name and support link are free text that a tenant admin types, so `TenantBranding` is sealed under the tenant's `data` key ([0004](/decisions/0004-the-data-model/#treatment)).
- **Branding is exempt from the direction rule.** It has no tighter or looser direction, so the most specific layer wins, bounded by config ([0004](/decisions/0004-the-data-model/#branding-is-exempt)). The bound lists the asset hosts a theme may name, and the content security policy of the pages.
- **A tenant admin, or a product for its tenant, writes `TenantBranding`** as for any Tenant-adjustable kind ([0004](/decisions/0004-the-data-model/#profiles)); `exchange` is its one writer. `exchange` refuses a pair of colours below the WCAG AA contrast ratio before it writes, and the loader refuses it in config ([REQ-UX-013](/requirements/ux/#REQ-UX-013)). The store refuses a logo reference outside the allowed asset hosts.
- **There is no custom CSS, script or HTML from a tenant or a product** ([REQ-UX-014](/requirements/ux/#REQ-UX-014)). A theme sets values; the template and the content security policy stay sluis's.
- **A logo is a reference to an image on an allowed asset host,** with a fixed set of image types and a size limit. The page loads it as an image and never inlines it, and `img-src` allows the allowed asset hosts only.
- **Every page carries stable machine-readable hooks** for test drivers ([REQ-UX-005](/requirements/ux/#REQ-UX-005)).

### Login domains

- **A login domain is a `FrontHost` entry,** a config kind with a host and a name. The entry named `default` serves a client that names none. A domain needs DNS and a certificate, so the kind is Fixed: a new domain is a reviewed, signed change.
- **A client references a `FrontHost` entry by name.** An installation client names it in config. A tenant client has the entry that its tenant's `Tenant` item names ([0021](/decisions/0021-clients/#the-client-declaration)), so a tenant cannot use a domain that config never provisioned.
- **A tenant's issuer host is a `FrontHost` entry.** The `Tenant` item names it and an operator sets it; a new host is a reviewed, signed change, and a tenant cannot add a domain at run time. What a tenant brings besides is a brand. The e-mail domains that an upstream serves ([0033](/decisions/0033-customer-connections/#which-upstreams-an-installation-has)) route a person's address to an upstream and are a different thing.
- **Each login domain is one origin.** Its cookies are host-prefixed with no `Domain`, so a session started on one login domain does not reach another, and the origins a passkey verifier accepts are those of [0017](/decisions/0017-identity-and-sign-in/#passkeys) ([REQ-ISO-034](/requirements/iso/#REQ-ISO-034)).
- **The issuer URL of a client is the host of its login domain,** which is its tenant's issuer ([0017](/decisions/0017-identity-and-sign-in/#issuers)). Relying parties pin `iss`, so a client that moves to another login domain is a new issuer for them; a tenant that moves to another boundary keeps its host.

### Passkeys and the relying-party ID

- **Ceremonies and staff passkeys use the one shared sign-in domain.** The ceremonies are the ones that need a person's passkey, such as the certification of a PKI intermediate and GPG signing. Staff passkeys are the `StaffPasskey` kind. Both belong to the `rp_id` of the `FrontHost` entry of that domain, so there is one `rp_id` for them.
- **End-user passkeys belong to the upstream.** sluis enrols no factor and asks for no passkey of a person who signs in through a customer upstream ([0018](/decisions/0018-sessions/#customers)). No customer-facing login domain enrols a passkey, so no such domain needs an `rp_id` of its own.
- **How a verifier checks a passkey assertion** is in [0017](/decisions/0017-identity-and-sign-in/#passkeys).

## Consequences

- The customer sees few sluis pages, and each is small, generic and tested for accessibility and for the content security policy once.
- A brand reaches a customer on sluis's pages as well as on the upstream's sign-in, and it costs a tenant one durable item to change, with no pull request.
- A theme cannot carry markup, script or a stylesheet, and a logo can come only from a host that config named. A tenant's worst case is an ugly page.
- Each login domain costs DNS, a certificate and a reviewed config change, and it is a new web origin: its sessions and, for relying parties, its issuer.
- One `rp_id` serves every ceremony and every staff passkey, so a staff member enrols once.
- Requirements: [REQ-UX-012](/requirements/ux/#REQ-UX-012), [REQ-UX-013](/requirements/ux/#REQ-UX-013) and [REQ-UX-014](/requirements/ux/#REQ-UX-014) state these rules.

## Roads not taken

- **A logo uploaded into sluis.** It needs a blob, a kind for it and a check of the image itself ([principle 8](/principles/#8-nothing-without-a-consumer)); a reference to an allowed host needs none of that.
- **Branding as a loosening that expires.** Branding has no tighter or looser direction, so an expiry would be absurd; config's bound is the limit.
- **Custom CSS or templates from a product.** A tenant could rebuild the page into a phishing page served from sluis's own host.
- **A custom domain per tenant.** It multiplies origins, certificates and passkey allow-list entries by the number of tenants, and nobody reviews them. A tenant picks among reviewed entries.
- **The login domain as a field of each client.** A tenant client could then name a domain that config never provisioned. A `FrontHost` entry that clients reference is Fixed and shared.
- **Hosted sign-in, registration and recovery pages in sluis.** They are the upstream's job and the account hosting that [0031](/decisions/0031-ciam-is-a-broker/) refuses.
- **End-user passkeys in sluis, with an `rp_id` per login domain.** sluis would hold customer credentials, and every login domain would need its own enrolment of the same person.
- **An `rp_id` per login domain for staff.** A staff member would enrol a passkey on every domain.
- **Locale from the tenant's setting.** A person's language is not their organisation's; the request carries the better signal.

## Follow-ups

- Templated, accessible, localised, branded pages: [#927](https://github.com/truvity/sluis/issues/927).
