# Connect a Kubernetes cluster

The API server trusts the issuer with one client id per cluster and reads
the `groups` claim into RBAC. People use kubelogin or `accessctl`; jobs use
`accessctl kube-token` from their exchanged token.

## Cluster side

- A static, public client per cluster: `id: k8s:<cluster>`.
- The API server's OIDC configuration (EKS: an identity provider config;
  kubeadm: `--oidc-*` flags): issuer URL, client id `k8s:<cluster>`,
  username claim `email`, groups claim `groups`, a groups prefix if you
  want one.
- RBAC bindings by group name, unchanged if the rules mint the same
  values as before.

## Rules

```yaml
- when: { directory_group: platform-admins@example.com }
  grant: { groups: [cluster-kernel:admin], audiences: [k8s:kernel] }
```

The audience is what lets `accessctl kubeconfig` know this person may use
this cluster; the `groups` value is what the cluster's RBAC binds.

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

`truvity/access-roster/actions/exchange` with `audiences: k8s:<cluster>`
writes a kubeconfig whose exec plugin re-exchanges the job's token when
needed. Rules on repository and ref decide which jobs may.

## Break-glass

Outside the issuer: the cloud's own cluster access mechanism bound to a
break-glass cloud role.
