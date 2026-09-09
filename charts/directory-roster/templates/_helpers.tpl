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
{{- define "directory-roster.signOutURL" -}}
{{- $access := .Values.access -}}
{{- if $access.signOutURL -}}
{{- $access.signOutURL -}}
{{- else if $access.signOutThroughIssuer -}}
{{- $issuer := "" -}}
{{- with $access.login.forwardedBearer }}{{ $issuer = trimSuffix "/" (.issuer | default "") }}{{ end -}}
{{- if not $issuer -}}
{{- fail "access.signOutThroughIssuer needs access.login.forwardedBearer.issuer: without it the chain would clear this console's cookie and leave the person signed in at the issuer, which looks exactly like a sign-out and is not one" -}}
{{- end -}}
{{- if not .Values.route.host -}}
{{- fail "access.signOutThroughIssuer needs route.host: it is where the person lands once their session is gone" -}}
{{- end -}}
{{- $home := printf "https://%s/" .Values.route.host -}}
{{- $end := printf "%s/end_session?post_logout_redirect_uri=%s" $issuer (urlquery $home) -}}
{{- printf "%s/sign_out?rd=%s" (trimSuffix "/" ($access.proxyPrefix | default "/oauth2")) (urlquery $end) -}}
{{- end -}}
{{- end -}}

