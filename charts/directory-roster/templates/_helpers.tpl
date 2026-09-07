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

{{/*
Whether the break-glass admin account is on.

It exists for one situation: nobody can sign in through the directory,
because the operators group is empty, or was renamed, or directory
sign-in is itself what broke. Recovery, in other words — the runbook
turns it back on, rolls the deployment and uses it.

Setting it up is the *other* thing it has been used for, and only a
standalone installation needs that: one that starts empty and configures
itself through the console. A deployment that already declares a
workspace and a non-empty `hub-operators` has a way in on its first
boot, so leaving a live password in a Secret it will never use is a
standing credential for no reason.

So the default is computed rather than fixed, and an explicit
`access.admin.enabled` still wins either way.
*/}}
{{- define "directory-roster.adminEnabled" -}}
{{- $chosen := .Values.access.admin.enabled -}}
{{- if kindIs "invalid" $chosen -}}
  {{- $operators := dig "groups" "hub-operators" dict .Values.policy -}}
  {{- $hasOperators := or (gt (len (dig "members" list $operators)) 0) (gt (len (dig "matchers" list $operators)) 0) -}}
  {{- $wayIn := and (gt (len .Values.workspaces) 0) $hasOperators -}}
  {{- not $wayIn -}}
{{- else -}}
  {{- $chosen -}}
{{- end -}}
{{- end }}

{{- define "directory-roster.serviceAccountName" -}}
{{- .Values.serviceAccount.name | default (include "directory-roster.fullname" .) }}
{{- end }}
