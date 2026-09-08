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
