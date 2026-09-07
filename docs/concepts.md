# Concepts

Ten words this repository uses precisely.

| Term | Means |
|---|---|
| **workspace** | one directory tenant the hub holds a credential for — a Google customer, later an Entra tenant. Identified by the backend's tenant id, never by a domain |
| **domain** | discovered from the workspace, re-read on every probe, never typed. Addresses route to workspaces by domain |
| **snapshot** | the hub's copy of one workspace: accounts with liveness, groups with flat members, domains, taken every refresh interval. Every read answers from it and says which one (`snapshot_at`) |
| **authoritative** | a domain's answers may be acted on: its workspace's last probe succeeded, its snapshot is inside the freshness window, and no other workspace claims the domain. Anything else is a hold |
| **`max_age`** | a caller's freshness demand: omitted serves the snapshot, a value makes it fresher first, zero fetches now. Point lookups satisfy it with one live read, never a full refresh |
| **proof** | something the issuer can verify without authenticating anyone: a corporate sign-in's ID token, a CI platform's identity token, a Kubernetes ServiceAccount token |
| **rule** | subject → grant. Subjects: a directory group, a claim on a named issuer, an email, an email domain. Grants: a `groups` claim, audiences, a hub role. Ordered, default deny |
| **audience** | one relying party and one entitlement, minted into a token only when a rule allows it: `k8s:<cluster>`, `aws:<account>:<role>`. For a custom issuer it is the only claim a cloud trust policy can gate on, so it carries the decision |
| **exposure** | a console placed behind `access-proxy`: a hostname, a backend, a posture. The proxy runs the login against the issuer, keeps the session, forwards the bearer |
| **posture** | what an exposure enforces: `groups` — only listed claim values pass; `authenticated` — any signed-in employee passes and the application authorizes itself |
