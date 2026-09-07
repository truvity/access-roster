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
