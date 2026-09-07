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
