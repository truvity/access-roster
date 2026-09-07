# directory-roster

The directory hub: one deployment holding every corporate-directory
credential so that its consumers hold none. Answers "is this account live"
and "who is in this group" over ConnectRPC and REST, routed by email domain,
with a per-domain authoritative flag. Google Workspace today, Microsoft
Entra next.

Design: [docs/design/hub.md](docs/design/hub.md). Successor to
[google-group-sync](https://github.com/truvity/google-group-sync).
