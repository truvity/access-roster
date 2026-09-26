# Adopting it with plain Helm

Nothing in access-roster assumes a GitOps controller. Both charts are
ordinary OCI Helm charts, every value an installation needs is in its own
values file, and every Secret they read is one the installation creates.
This page installs the issuer and one `access-proxy` with `helm install`,
signs in for the first time, and says how to take new releases without
ArgoCD or Kargo. Every name below is a placeholder: `example.com` for
your domain, `eu-example-1` for your region.

`access-proxy` is deprecated, with removal planned
([ADR 0003](../decisions/0003-deprecate-access-proxy.md)). It is, and has
only ever been, Envoy Gateway's own external authorization backend, so it
runs nowhere else. On that same Envoy Gateway, gateway-native OIDC — a
`SecurityPolicy` with `oidc:` against a declared client — is the default
replacement now, and needs no chart of ours; see
[design/access-proxy.md](../design/access-proxy.md) for why. For a
gateway that is not Envoy Gateway, this chart was never an option: run
upstream oauth2-proxy yourself, with a declared confidential client row —
a documentation page for that is planned, and it is not a chart of ours.
Step 4 below is the `access-proxy` walk-through, kept for as long as the
chart lasts on Envoy Gateway.

## Prerequisites

| Needed | For | Notes |
|---|---|---|
| Kubernetes | both charts | the issuer's recovery sign-in asks the API server to review a ServiceAccount token, so it runs in the cluster it trusts |
| cert-manager, and a `ClusterIssuer` | the issuer | two certificates: the **signing key** (by default from a `ClusterIssuer` named `selfsigned`; only the key is used) and the TLS certificate for its Gateway (`route.certificate`). Or deliver the signing key yourself and set `signingKey.existingSecret` |
| Gateway API, and a controller that serves a `GatewayClass` | the issuer's route | the chart renders a `Gateway` of `route.gatewayClassName` and two `HTTPRoute`s. With `route.parentRefs` it attaches to a parent you already have and renders no Gateway. Without `route.host` it renders no route at all, for a trial by port-forward |
| Envoy Gateway | `access-proxy` only | the proxy is Envoy's external authorization backend, through a `SecurityPolicy` (`gateway.envoyproxy.io/v1alpha1`) |
| a Valkey (or any Redis-protocol store) | the issuer with more than one replica; every `access-proxy` | neither chart installs one. One replica of the issuer may run without it (`replicaCount: 1`, `valkey.address: ""`), keeping sessions in memory |
| a Google Workspace, and an OAuth client in a Google Cloud project | people signing in, and the directory the groups are read from | the one upstream that is built; a second directory backend (Entra) is designed and not written. [connect-runbook.md](connect-runbook.md) walks through the client |
| an audit installation ([truvity/audit](https://github.com/truvity/audit)) | the audit trail (optional) | without `audit.writer` nothing is kept beyond the log line every record also is, and the service says so at start. This service writes no object itself: the installation owns the archive |
| OpenBAO, or a Vault with the same API | short-lived SSH, database and client certificates (optional) | not installed by these charts; [../connect/openbao.md](../connect/openbao.md) |

## Install order

1. **Valkey**, from whatever chart you already use.
2. **The Secrets** the values will name. The issuer holds no RBAC to read
   a Secret through the API; each one is mounted as a file.

   ```sh
   kubectl create namespace access-issuer
   kubectl -n access-issuer create secret generic access-issuer-google-client \
     --from-literal=client-id=<google client id> \
     --from-literal=client-secret=<google client secret>
   # one per confidential client in the policy, key client-secret
   kubectl -n access-issuer create secret generic dashboard-oidc-client \
     --from-literal=client-secret=<a long random string>
   ```

3. **The issuer.** One tag releases every artifact here; pin the charts
   at the same version.

   ```sh
   helm install access-issuer oci://ghcr.io/truvity/charts/access-issuer \
     --version X.Y.Z --namespace access-issuer --values issuer-values.yaml
   ```

   ```yaml
   issuerURL: https://access.example.com      # stable for the life of the installation

   route:
     host: access.example.com
     rootRedirect: /console/
     gatewayClassName: example-gateway-class  # a GatewayClass your controller serves
     certificate:
       issuerName: example-ca                 # a cert-manager issuer you own
       issuerKind: ClusterIssuer

   valkey:
     address: valkey.access-issuer.svc:6379   # two replicas share sessions here

   oauthClient:
     secret:
       name: access-issuer-google-client      # keys client-id and client-secret

   console:
     client: access-console

   audit:                                     # optional; see the prerequisites
     writer: http://audit.example-ns.svc:8080        # the installation's receiver
     query: http://audit-query.example-ns.svc:8080   # its query service, for the Audit page

   policy:
     groups:
       all:access-roster:operator:
         members: [platform-admins@example.com]
         matchers:
           # the recovery account: how the first operator gets in
           - service_account: { namespace: access-issuer, name: access-issuer-recovery }
       all:access-roster:viewer:
         matchers: [{ email_domain: example.com }]
       all:dashboard:viewer:
         members: [everyone@example.com]
     clients:
       access-console:
         kind: public
         display_name: access-roster
         redirects: [https://access.example.com/console/]
         requires: [all:access-roster:operator, all:access-roster:viewer]
       dashboard.example.com:                 # the proxy's client: its id is the proxied host
         kind: confidential
         secret: dashboard-oidc-client        # key client-secret, in the issuer's namespace
         display_name: Dashboard
         redirects: [https://dashboard.example.com/oauth2/callback]
         signed_out: [https://dashboard.example.com/]
         requires: [all:dashboard:viewer]
   ```

   The policy is the whole of who may do what; its format is
   [../reference/policy.md](../reference/policy.md), and every value is
   in [../reference/configuration.md](../reference/configuration.md). A
   malformed policy fails the rollout, not a sign-in: the previous pods
   keep serving.

4. **For a console that has no OpenID flow of its own**, use the gateway's
   native OIDC support — declare a `SecurityPolicy` with an `oidc:` block
   ([../connect/console-app.md](../connect/console-app.md)). The
   `access-proxy` chart was removed in v1.32.0
   ([../decisions/0003-deprecate-access-proxy.md](../decisions/0003-deprecate-access-proxy.md)).
   If your gateway is not Envoy Gateway, run upstream `oauth2-proxy`
   yourself following the recipe in
   [../design/access-proxy.md](../design/access-proxy.md).

Both values files above render with the charts in this repository
(`helm template` with `--namespace` as shown), and the policy loads.

## First sign-in

Nobody can sign in through the directory until a directory is connected,
and it is connected from the console. The way in before that is the
**recovery sign-in**: a short-lived ServiceAccount token that the API
server vouches for, which the policy above puts in the operators group.

```sh
kubectl -n access-issuer create token access-issuer-recovery \
  --audience access-issuer-recovery --duration 10m
```

Open `https://access.example.com/login` (or port-forward the Service's
port 8080), expand **Recovery sign-in**, and paste the token. The
console's Overview then lists what is left: connect the Google Workspace
by admin consent (the OAuth client needs the two redirect URIs
`https://access.example.com/connect/google/callback` and
`https://access.example.com/login/google/callback`), and check that your
own directory group lands you in the operators group. Sign out, sign in
as yourself, and search for yourself: your page shows the membership
that granted each group. Who may mint a recovery token is the cluster's
RBAC on `serviceaccounts/token` for that one account
([runbook.md](runbook.md#day-one)).

From there each connection is one guide: a
[cluster](../connect/kubernetes-cluster.md), an
[AWS account](../connect/aws-account.md),
[GitHub Actions](../connect/github-actions.md), a
[laptop](../reference/accessctl.md).

## Without ArgoCD or Kargo

ArgoCD and Kargo appear in these docs as **relying parties** — consoles
that sign in against the issuer ([argocd.md](../connect/argocd.md),
[kargo.md](../connect/kargo.md)) — not as the way to deploy it. With plain
Helm:

- **Pin one version for both charts** and keep the values files in your
  own repository. The policy is values, so a change of who may do what is
  a reviewed change to that file followed by `helm upgrade`; the pods
  roll on a policy change by checksum.
- **Take a release through the zero-diff gate** ([../adoption.md](../adoption.md)):
  render the pinned version and the new one with your values and compare.

  ```sh
  helm template access-issuer oci://ghcr.io/truvity/charts/access-issuer \
    --version OLD --namespace access-issuer -f issuer-values.yaml > old.yaml
  helm template access-issuer oci://ghcr.io/truvity/charts/access-issuer \
    --version NEW --namespace access-issuer -f issuer-values.yaml > new.yaml
  diff -u old.yaml new.yaml
  ```

  An image tag and the version labels move on every release; anything
  else in the diff should be a line of [CHANGELOG.md](../../CHANGELOG.md).
  Then `helm upgrade` with the same values.
- **Back up what the console adds.** Five Secrets hold everything that
  cannot be minted again; with no controller copying them, copy them
  yourself
  ([restoring from the Secrets alone](../reference/configuration.md#restoring-from-the-secrets-alone)).
- **Adopting objects that already exist.** Moving an issuer or a proxy
  that was installed another way into these charts is the same gate:
  choose the release name and values so the render reproduces the live
  objects' names, and make the switch one change whose diff is empty.
  Moving from another identity provider is
  [migration-from-an-idp.md](migration-from-an-idp.md).
