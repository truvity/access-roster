# Connect a Kubernetes cluster

**Anchor:** the issuer. The API server trusts it with one client id per
cluster and reads the `groups` claim into RBAC, binding the internal
group names exactly as the policy spells them. People use kubelogin or
`accessctl`; jobs use `accessctl kube-token` from their exchanged token.
(A workload *inside* the cluster calling a service inside the cluster
is the other anchor and does not come here:
[service-to-service.md](service-to-service.md).)

## Cluster side

- A static, public client per cluster: `id: k8s:<cluster>`.
- The API server's OIDC configuration (EKS: an identity provider config;
  kubeadm: `--oidc-*` flags): issuer URL, client id `k8s:<cluster>`,
  username claim `email`, groups claim `groups`, a groups prefix if you
  want one.
- RBAC bindings by group name — the internal group's name, as it stands
  in the policy. Name the groups after what the bindings already say and
  the cutover changes no binding.

## Policy

The cluster is a public client. The group names its RBAC binds **are**
the internal groups; nothing is re-mapped on the way:

```yaml
groups:
  kernel:k8s:admin:  { members: [role-sre@example.com, role-admin@example.com] }
  kernel:k8s:viewer: { members: [team-eng@example.com] }
clients:
  k8s:kernel: { kind: public, requires: [kernel:k8s:admin, kernel:k8s:viewer] }
```

`requires` is what lets `accessctl kubeconfig` know this person may use
this cluster; the group names in the token are what the cluster's RBAC
binds — `<env>:k8s:<role>`, the cluster tier of the
[naming rule](../design/trust.md#naming). An installation that renders
its policy from an access matrix (see the gitops repository) mints these
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
  - name: kernel
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args: [oidc-login, get-token, --oidc-issuer-url=https://issuer.example.internal, --oidc-client-id=k8s:kernel, --oidc-extra-scope=groups]
```

## Job side

The API server trusts one issuer, access-issuer, so a job's GitHub token is
never presented to it. `truvity/access-roster@v1` with
`audiences: k8s:<cluster>` exchanges the job's token at the issuer and
writes a kubeconfig with the resulting token; the machine group's
matchers on repository and ref decide which jobs may. The token's lifetime is the issuer's CI client
setting; a step that outlives it re-runs the action.

## Break-glass

Outside the issuer: the cloud's own cluster access mechanism bound to a
break-glass cloud role.
