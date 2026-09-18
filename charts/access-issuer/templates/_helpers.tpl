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

{{/*
Whether an audit installation is connected: its writer and registry, both
or neither. One without the other is refused here rather than at start-up,
where it would be a crash loop.
*/}}
{{- define "access-issuer.auditConnected" -}}
{{- $a := .Values.audit -}}
{{- if and $a.writer (not $a.registry) }}{{ fail "audit.writer needs audit.registry: the catalogue its records are held to would never be registered" }}{{ end -}}
{{- if and $a.registry (not $a.writer) }}{{ fail "audit.registry needs audit.writer: records would have nowhere to go" }}{{ end -}}
{{- if and $a.query (not $a.audience) }}{{ fail "audit.query needs audit.audience: the client the page's tokens are minted for" }}{{ end -}}
{{- if $a.writer }}true{{ end -}}
{{- end -}}

{{/*
The environment that connects a process to the audit installation: the
service and the GitHub controller both record, each with its own identity.
*/}}
{{- define "access-issuer.auditEnv" -}}
- name: AUDIT_WRITER_URL
  value: {{ .Values.audit.writer | quote }}
- name: AUDIT_REGISTRY_URL
  value: {{ .Values.audit.registry | quote }}
{{- if include "access-issuer.auditConnected" . }}
- name: AUDIT_TOKEN_FILE
  value: /var/run/audit/token
- name: AUDIT_OUTBOX_DIR
  value: /var/lib/audit-outbox
{{- else }}
- name: AUDIT_TOKEN_FILE
  value: ""
- name: AUDIT_OUTBOX_DIR
  value: ""
{{- end }}
{{- end -}}

{{- define "access-issuer.auditMounts" -}}
{{- if include "access-issuer.auditConnected" . }}
- name: audit-token
  mountPath: /var/run/audit
  readOnly: true
- name: audit-outbox
  mountPath: /var/lib/audit-outbox
{{- end }}
{{- end -}}

{{/*
The projected token the installation knows this workload by, with its
audience, and the outbox records wait in.
*/}}
{{- define "access-issuer.auditVolumes" -}}
{{- if include "access-issuer.auditConnected" . }}
- name: audit-token
  projected:
    sources:
      - serviceAccountToken:
          audience: {{ .Values.audit.token.audience | quote }}
          expirationSeconds: {{ .Values.audit.token.expirationSeconds }}
          path: token
- name: audit-outbox
  emptyDir:
    sizeLimit: {{ .Values.audit.outbox.sizeLimit }}
{{- end }}
{{- end -}}
