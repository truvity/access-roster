# Connect ArgoCD

**Anchor:** the issuer; ArgoCD runs its own OIDC code flow, so no proxy.
It reads groups from the ID token and maps them in its own policy;
nothing about that policy changes when the issuer does.

1. A client in the issuer's policy:
   ```yaml
   clients:
     argocd:
       kind: confidential
       secret: argocd-oidc-client
       redirects:  [https://argocd.example.internal/auth/callback]
       signed_out: [https://argocd.example.internal/]
       requires:   [cluster-kernel:cluster:admin, cluster-kernel:cluster:viewer]
   ```
2. ArgoCD's `oidc.config`:
   ```yaml
   name: Corporate
   issuer: https://issuer.example.internal
   clientID: $argocd-secret:oidc.clientID
   clientSecret: $argocd-secret:oidc.clientSecret
   requestedScopes: [openid, profile, email, groups]
   logoutURL: https://issuer.example.internal/end_session?id_token_hint={{token}}&post_logout_redirect_uri=https://argocd.example.internal
   ```
3. `policy.csv` keeps its `g, <group>, role:<x>` lines: the `groups`
   values are the internal group names themselves, so name the groups
   what the lines already say and nothing here changes.
4. Keep ArgoCD's local admin until a policy-granted identity has signed in
   as an admin, then `admin.enabled: "false"`.

The `argocd` CLI logs in through the same client with the browser flow;
no separate client is needed unless you want the device flow, in which
case add a public client and point the CLI at it.
