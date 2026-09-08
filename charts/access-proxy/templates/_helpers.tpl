{{- define "access-proxy.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "access-proxy.fullname" -}}
{{- if eq .Release.Name .Chart.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "access-proxy.labels" -}}
app.kubernetes.io/name: {{ include "access-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "access-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "access-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The issuer's key set. Nothing but Zitadel serves keys at
/oauth/v2/keys, so the default is the ordinary one and an installation in
front of something else overrides it.
*/}}
{{- define "access-proxy.jwksUri" -}}
{{- .Values.issuer.jwksUri | default (printf "%s/keys" (trimSuffix "/" .Values.issuer.url)) }}
{{- end }}

{{/*
The HTTPRoute the SecurityPolicy binds to. ATTACH mode names a route
another chart owns -- the console's own chart usually does, because the
hostname is its business -- and this chart then renders no app route.
*/}}
{{- define "access-proxy.targetRoute" -}}
{{- .Values.exposure.attachRouteName | default (include "access-proxy.fullname" .) }}
{{- end }}
