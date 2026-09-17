{{- define "access-issuer.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "access-issuer.fullname" -}}
{{- if eq .Release.Name .Chart.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "access-issuer.labels" -}}
app.kubernetes.io/name: {{ include "access-issuer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "access-issuer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "access-issuer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "access-issuer.serviceAccountName" -}}
{{- .Values.serviceAccount.name | default (include "access-issuer.fullname" .) }}
{{- end }}

{{/*
The Secret the signing key is read from: one external-secrets delivered,
or the one cert-manager issues for this release.
*/}}
{{- define "access-issuer.signingKeySecret" -}}
{{- .Values.signingKey.existingSecret | default (printf "%s-signing-key" (include "access-issuer.fullname" .)) }}
{{- end }}

{{/*
The audience a workload token must be minted for. Defaults to the release
name so that two issuers in one cluster cannot accept each other's
exchange proofs.
*/}}
{{- define "access-issuer.exchangeAudience" -}}
{{- .Values.exchange.audience | default (include "access-issuer.fullname" .) }}
{{- end }}

{{/*
The account a recovery token must be minted for, and the audience it must
carry. Both default to the release's own name so that an installation
that turns recovery on gets working names without choosing any.
*/}}
{{- define "access-issuer.recoveryServiceAccountName" -}}
{{- .Values.recovery.serviceAccountName | default (printf "%s-recovery" (include "access-issuer.fullname" .)) }}
{{- end }}

{{- define "access-issuer.recoveryAudience" -}}
{{- .Values.recovery.audience | default (printf "%s-recovery" (include "access-issuer.fullname" .)) }}
{{- end }}

{{/*
Non-empty when any declared client carries a secret, which is what decides
whether the client-secrets volume is rendered at all. A deployment whose
clients are all public or exchange-only mounts nothing.
*/}}
{{- define "access-issuer.confidentialClients" -}}
{{- range $id, $client := (.Values.policy.clients | default dict) }}
{{- if $client.secret }}yes{{ end }}
{{- end }}
{{- end }}

{{/*
The console's mount, with any trailing slash removed.

`/console` and `/console/` are the same place to a person and the chart
took them as different: the route matched "/console/" exactly and then
redirected to "/console//", which is a path the console does not serve.
Nothing rejected it, because both are legal strings.

The value is written both ways across our own configuration -- a declared
client carries `prefix: /console` and `mount: /console/` -- so normalising
here is what keeps either spelling working. The Go side already trims it.
*/}}
{{- define "access-issuer.consoleMount" -}}
{{- $mount := .Values.console.mount | default "" | trimSuffix "/" -}}
{{- $mount -}}
{{- end -}}

{{/*
The GitHub controller's pods, told apart from the service's. They must not
carry the service's selector labels: the service's Service would then send
logins to a process that has no listener.
*/}}
{{- define "access-issuer.githubRosterSelectorLabels" -}}
app.kubernetes.io/name: {{ include "access-issuer.name" . }}-github-roster
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Where the issuer's routes attach. route.parentRefs, when given, is used as
written -- the platform's ListenerSet carrying route.host -- and the chart
then renders no Gateway or Certificate of its own: the listener and its
certificate belong to whatever that parent is. Otherwise the chart's own
Gateway listener, as before.
*/}}
{{- define "access-issuer.parentRefs" -}}
{{- if .Values.route.parentRefs -}}
{{- range .Values.route.parentRefs }}
{{- if not .name }}{{ fail "route.parentRefs: every entry needs a name" }}{{ end }}
{{- end -}}
{{ toYaml .Values.route.parentRefs }}
{{- else -}}
- group: gateway.networking.k8s.io
  kind: Gateway
  name: {{ include "access-issuer.fullname" . }}
  sectionName: issuer
{{- end -}}
{{- end -}}
