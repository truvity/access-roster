# Connect ArgoCD

ArgoCD reads groups from the ID token and maps them in its own policy;
nothing about that policy changes when the issuer does.

1. A static client in the issuer's values:
   ```yaml
   clients:
     static:
       - id: argocd
         secretName: argocd-oidc-client
         redirectUris: [https://argocd.example.internal/auth/callback]
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
3. `policy.csv` keeps its `g, <group>, role:<x>` lines: the `groups` values
   come from the rules and can be identical to the ones ArgoCD reads
   today.
4. Keep ArgoCD's local admin until a rule-granted identity has signed in
   as an admin, then `admin.enabled: "false"`.

The `argocd` CLI logs in through the same client with the browser flow;
no separate client is needed unless you want the device flow, in which
case add a public client and point the CLI at it.
