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

{{- define "access-issuer.hubAudience" -}}
{{- .Values.hub.audience | default "directory-roster" }}
{{- end }}
