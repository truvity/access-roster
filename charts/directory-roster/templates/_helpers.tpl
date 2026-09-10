{{- define "directory-roster.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "directory-roster.labels" -}}
app.kubernetes.io/name: directory-roster
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "directory-roster.selectorLabels" -}}
app.kubernetes.io/name: directory-roster
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{- define "directory-roster.serviceAccountName" -}}
{{- .Values.serviceAccount.name | default (include "directory-roster.fullname" .) }}
{{- end }}

{{/*
The recovery ServiceAccount and audience. Both default to
`<release>-recovery`, so an installation that changes neither still has
two names that match — a token minted for one audience and checked
against another fails with nothing to see, which is a bad way to spend
the day recovery is needed.
*/}}
{{- define "directory-roster.recoveryServiceAccountName" -}}
{{- .Values.access.recovery.serviceAccountName | default (printf "%s-recovery" (include "directory-roster.fullname" .)) }}
{{- end }}

{{- define "directory-roster.recoveryAudience" -}}
{{- .Values.access.recovery.audience | default (printf "%s-recovery" (include "directory-roster.fullname" .)) }}
{{- end }}

{{/*
The audience a consumer's projected token must carry, and the consumers
themselves as `namespace/serviceaccount` pairs. The audience defaults to
the release name rather than to a fixed string, so two hubs in one
cluster cannot accept each other's callers.
*/}}
{{- define "directory-roster.apiAudience" -}}
{{- .Values.listeners.api.audience | default (include "directory-roster.fullname" .) }}
{{- end }}

{{- define "directory-roster.apiConsumers" -}}
{{- $pairs := list -}}
{{- range .Values.consumers -}}
{{- $pairs = append $pairs (printf "%s/%s" .namespace .serviceAccount) -}}
{{- end -}}
{{- join "," $pairs }}
{{- end }}

{{/*
directory-roster.signOutURL is where the console's sign-out control goes.

An explicit `access.signOutURL` wins. Otherwise, with
`access.signOutThroughIssuer`, the chart builds both halves of the
sign-out: the proxy's own (which clears this application's session
cookie) with the issuer's RP-initiated logout as its `rd` (which ends the
sign-in itself), landing back on this console's front page.

Half a sign-out is worse than none: the screen says signed out, the
issuer still holds the session, and the next click is admitted with no
password. So the two inputs the chain needs are REQUIRED when it is asked
for, rather than skipped into a URL that ends only the near half.
*/}}
{{/*
directory-roster.gatewayParentRef renders the one parentRefs entry both
HTTPRoutes this chart owns share.

Default: this chart's own Gateway, named "console" -- today's shape.

Set route.gateway.name (INF-687): an EXISTING Gateway instead, in
route.gateway.namespace, with route.gateway.sectionName if given. This is
how the console attaches to the ISSUER's Gateway rather than rendering
its own for the same route.host: Envoy Gateway merges every Gateway of
one gatewayClassName into a single deployment, so two Gateways each
declaring a listener for the same hostname collide on that listener
rather than coexisting as two independent routes. Exactly one of the two
charts may own the Gateway for a shared hostname; the other attaches --
the same shape access-proxy's exposure.gateway already has, one level up
(a Gateway rather than a route).
*/}}
{{- define "directory-roster.gatewayParentRef" -}}
{{- $gw := .Values.route.gateway -}}
- group: gateway.networking.k8s.io
  kind: Gateway
{{- if $gw.name }}
  name: {{ $gw.name }}
  namespace: {{ required "route.gateway.namespace is required when route.gateway.name is set: the Gateway it names lives in another chart's namespace" $gw.namespace }}
  {{- with $gw.sectionName }}
  sectionName: {{ . }}
  {{- end }}
{{- else }}
  name: {{ include "directory-roster.fullname" . }}
  sectionName: console
{{- end }}
{{- end }}

{{- define "directory-roster.signOutURL" -}}
{{- $access := .Values.access -}}
{{- if $access.signOutURL -}}
{{- $access.signOutURL -}}
{{- else if $access.signOutThroughIssuer -}}
{{- $issuer := "" -}}
{{- $client := "" -}}
{{- with $access.login.forwardedBearer }}{{ $issuer = trimSuffix "/" (.issuer | default "") }}{{ $client = .audience | default "" }}{{ end -}}
{{- if not $issuer -}}
{{- fail "access.signOutThroughIssuer needs access.login.forwardedBearer.issuer: without it the chain would clear this console's cookie and leave the person signed in at the issuer, which looks exactly like a sign-out and is not one" -}}
{{- end -}}
{{- if not .Values.route.host -}}
{{- fail "access.signOutThroughIssuer needs route.host: it is where the person lands once their session is gone" -}}
{{- end -}}
{{- if not $client -}}
{{- fail "access.signOutThroughIssuer needs access.login.forwardedBearer.audience: it is this console's client id at the issuer, and without it the issuer cannot tell whose landing page it is being handed, so it drops the person on its own signed-out page instead of back here" -}}
{{- end -}}
{{/* The console's own front page, INCLUDING route.pathPrefix: mounted
     under a path, "https://host/" is the ISSUER's page, not this
     console's. It also has to match the client's `signed_out` entry at
     the issuer character for character, or the issuer ends the session
     and lands the person on its own page -- a sign-out that worked and
     looks like it did not. */}}
{{- $home := printf "https://%s%s/" .Values.route.host .Values.route.pathPrefix -}}
{{/* client_id, because there is no id_token_hint to carry: oauth2-proxy's
     `rd` is a plain redirect and adds nothing of its own. Without it the
     issuer has no client whose `signed_out` list to match, so it ends the
     session -- the half that matters -- and then lands the person on its
     OWN page rather than this console's. RP-Initiated Logout allows
     either; this is the one we can send. */}}
{{- $end := printf "%s/end_session?client_id=%s&post_logout_redirect_uri=%s" $issuer (urlquery $client) (urlquery $home) -}}
{{/* And the proxy's own paths move with the console: under a prefix the
     root's /oauth2 belongs to the issuer, not to this proxy. Defaulting
     it from route.pathPrefix rather than asking a deployment to set both
     is what stops the two from drifting -- and a sign-out link pointing
     at a path the proxy does not own is a button that 404s. */}}
{{- printf "%s/sign_out?rd=%s" (trimSuffix "/" ($access.proxyPrefix | default (printf "%s/oauth2" .Values.route.pathPrefix))) (urlquery $end) -}}
{{- end -}}
{{- end -}}

