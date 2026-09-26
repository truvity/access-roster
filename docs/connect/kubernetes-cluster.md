# Connect a Kubernetes cluster

**Anchor:** the issuer. The API server trusts it with one client id per
cluster and reads the `groups` claim into RBAC, binding the internal
group names exactly as the policy spells them. People use **kubelogin**
or `accessctl`, and both work today: `accessctl kubeconfig` writes a
context per cluster you are granted, with `accessctl kube-token` as the
exec plugin behind it.
(A workload *inside* the cluster calling a service inside the cluster
is the other anchor and does not come here:
[service-to-service.md](service-to-service.md).)

## Cluster side

- A static, public client per cluster: `id: k8s:<cluster>`.
- The API server's OIDC configuration (EKS: an identity provider config;
  kubeadm: `--oidc-*` flags): issuer URL, client id `k8s:<cluster>`,
  username claim `email`, groups claim `groups`, a groups prefix if you
  want one.
- The signing algorithm. kube-apiserver's `--oidc-signing-algs` defaults
  to `RS256`, and the chart's default key signs ES384, so the flag must
  list `ES384` (its allowed values include it). An `AuthenticationConfiguration`
  file has no such setting: kube-apiserver's source allows every known
  algorithm when the file is used. A managed cluster's identity-provider
  configuration exposes no algorithm setting either (EKS takes the issuer
  URL, client id, claims and prefixes and documents no algorithm), so
  confirm with the cluster's documentation that it verifies ES384 tokens,
  or give the installation an RSA key: `signingKey.certificate:
  {algorithm: RSA, size: 2048, encoding: PKCS1}`
  ([reference](../reference/configuration.md)).
- RBAC bindings by group name — the internal group's name, as it stands
  in the policy. Name the groups after what the bindings already say and
  the cutover changes no binding.

## Policy

The cluster is a public client. The group names its RBAC binds **are**
the internal groups; nothing is re-mapped on the way:

```yaml
groups:
  prod:k8s:admin:  { members: [role-sre@example.com, role-admin@example.com] }
  prod:k8s:viewer: { members: [team-eng@example.com] }
clients:
  k8s:prod: { kind: public, requires: [prod:k8s:admin, prod:k8s:viewer] }
```

The sign-in page names a `k8s:<cluster>` client *Kubernetes — `<cluster>`*
on its own, or as `display_name` says; when the redirect is on the
person's own computer it says a program there is asking. `requires` is
what lets `accessctl kubeconfig` know this person may use this cluster; the group names in the token are what the cluster's RBAC
binds — `<env>:k8s:<role>`, the cluster tier of the
[naming rule](../design/trust.md#naming). An installation that renders
its policy from an access matrix mints these
names from one function, so the binding and the token cannot drift
apart. Renaming an installation's existing bindings is safe to do
gradually: RBAC binds any number of group names to one ClusterRole, so
the old and the new spelling coexist until the old issuer is gone.

## Person side

Either `accessctl kubeconfig`, which writes a context per granted
cluster with `accessctl kube-token` as the exec plugin, or a hand-written
context with kubelogin:

```yaml
users:
  - name: prod
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args: [oidc-login, get-token, --oidc-issuer-url=https://issuer.example.internal, --oidc-client-id=k8s:prod, --oidc-extra-scope=groups]
```

On a laptop, `accessctl kube-token` trades the cached sign-in for the
cluster's audience, which the issuer allows only because accessctl's own
client declares `sign_in_exchange: true`
([service-to-service.md](service-to-service.md#calling-with-an-issuer-token-anywhere-else)).

## Job side

The API server trusts one issuer, access-issuer, so a job's GitHub token is
never presented to it. Either the action, `truvity/access-roster` pinned
to a release with `audiences: k8s:<cluster>`, exchanges the job's token
at the issuer and writes a kubeconfig with the resulting token; or the
same kubeconfig a person uses works unchanged in a job granted
`id-token: write`, because `accessctl kube-token` exchanges the job's
own token there ([github-actions.md](github-actions.md#or-the-same-files-a-laptop-uses)).
The machine group's matchers on repository, ref and visibility decide
which jobs may. The token's lifetime is the issuer's CI client setting;
a step that outlives it re-runs the action.

## Break-glass

Outside the issuer: the cloud's own cluster access mechanism bound to a
break-glass cloud role.
