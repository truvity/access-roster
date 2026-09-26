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
access-issuer.privateKey refuses a key the issuer could not use.

A size that does not belong to its algorithm renders a Certificate
cert-manager declines, and an ECDSA key in PKCS1 cannot be encoded at all --
both of which fail after the render, on a CertificateRequest nobody is
watching, with the listener simply dark. The schema states the shape; this
states the combination, because a JSON Schema `allOf` reports only that
`allOf` failed and three different mistakes would read the same.

Takes a dict: `spec` (the privateKey map) and `path` (where to say it is).
*/}}
{{- define "access-issuer.privateKey" -}}
{{- $spec := .spec | default dict -}}
{{- $alg := $spec.algorithm | default "" -}}
{{- $size := $spec.size | default 0 -}}
{{- $encoding := $spec.encoding | default "" -}}
{{- if and (eq $alg "ECDSA") $size (not (has (int $size) (list 256 384 521))) -}}
{{- fail (printf "%s: an ECDSA key takes size 256, 384 or 521, not %v -- the curve decides the algorithm, so P-256 signs ES256, P-384 ES384 and P-521 ES512" .path $size) -}}
{{- end -}}
{{- if and (eq $alg "RSA") $size (not (has (int $size) (list 2048 3072 4096))) -}}
{{- fail (printf "%s: an RSA key takes size 2048, 3072 or 4096, not %v" .path $size) -}}
{{- end -}}
{{- if and (eq $alg "ECDSA") (eq $encoding "PKCS1") -}}
{{- fail (printf "%s: PKCS1 encodes only RSA keys; an ECDSA key is PKCS8" .path) -}}
{{- end -}}
{{- end -}}

{{/*
Whether an audit installation is connected: the address its receiver serves.

One address is the whole connection. The receiver takes the records and
answers RegisterCatalogue on the same port, because an installation belongs
to one application and a registry of its own would be a Deployment for a
single call.
*/}}
{{- define "access-issuer.auditConnected" -}}
{{- $a := .Values.audit -}}
{{- if and $a.query (not $a.writer) }}{{ fail "audit.query needs audit.writer: the page would read a trail nothing writes" }}{{ end -}}
{{- if and $a.query (not $a.audience) }}{{ fail "audit.query needs audit.audience: the client the page's tokens are minted for" }}{{ end -}}
{{- if $a.writer }}true{{ end -}}
{{- end -}}

{{/*
access-issuer.simpleDurationNanos converts a SINGLE-UNIT duration string
("24h", "90m", "500ms") to nanoseconds, as an integer, for comparing two
durations written in different units. It is not a general parser: a
compound duration ("1h30m") is not this shape, and a caller must check
that with the pattern below before calling it.
*/}}
{{- define "access-issuer.simpleDurationNanos" -}}
{{- $num := regexFind "^[0-9]+" . | int64 -}}
{{- $unit := regexFind "[a-zµ]+$" . -}}
{{- if eq $unit "h" -}}{{ mul $num 3600000000000 }}
{{- else if eq $unit "m" -}}{{ mul $num 60000000000 }}
{{- else if eq $unit "s" -}}{{ mul $num 1000000000 }}
{{- else if eq $unit "ms" -}}{{ mul $num 1000000 }}
{{- else if or (eq $unit "us") (eq $unit "µs") -}}{{ mul $num 1000 }}
{{- else -}}{{ $num }}
{{- end -}}
{{- end -}}

{{/*
access-issuer.validateLifetimes refuses lifetimes.absolute: zero (a
session that ends before or the instant it begins is not a limit, it is a
login that can never complete) or, for the common case of a single-unit
duration, shorter than lifetimes.token (an access token cannot outlive
the session that grants it).

A compound duration ("1h30m") is not compared against lifetimes.token:
parsing one fully needs a real duration parser, which Helm's template
language has none of, and a comparison that WRONGLY refuses a valid value
is worse than one silently skipped. The running service checks this
exactly, with Go's time.ParseDuration, and refuses to start if it is
wrong -- see issuerapp.Load. The zero check does not have this problem:
"contains no digit but 0" is true or false regardless of how many units
a duration mixes.
*/}}
{{- define "access-issuer.validateLifetimes" -}}
{{- $l := .Values.lifetimes -}}
{{- $simple := "^[0-9]+(ns|us|µs|ms|s|m|h)$" -}}
{{- if not (regexMatch "[1-9]" $l.absolute) -}}
{{- fail (printf "lifetimes.absolute: %q is zero -- a session has to end SOMETIME after sign-in, not before it" $l.absolute) -}}
{{- end -}}
{{- if and (regexMatch $simple $l.absolute) (regexMatch $simple $l.token) -}}
{{- $absoluteNanos := include "access-issuer.simpleDurationNanos" $l.absolute | int64 -}}
{{- $tokenNanos := include "access-issuer.simpleDurationNanos" $l.token | int64 -}}
{{- if lt $absoluteNanos $tokenNanos -}}
{{- fail (printf "lifetimes.absolute (%s) must be at least lifetimes.token (%s): an access token cannot outlive the session that grants it" $l.absolute $l.token) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The environment that connects a process to the audit installation: the
service and the GitHub controller both record, each with its own identity.
*/}}
{{- define "access-issuer.auditEnv" -}}
- name: AUDIT_WRITER_URL
  value: {{ .Values.audit.writer | quote }}
{{- if include "access-issuer.auditConnected" . }}
- name: AUDIT_TOKEN_FILE
  value: /var/run/audit/token
{{- else }}
- name: AUDIT_TOKEN_FILE
  value: ""
{{- end }}
{{- end -}}

{{- define "access-issuer.auditMounts" -}}
{{- if include "access-issuer.auditConnected" . }}
- name: audit-token
  mountPath: /var/run/audit
  readOnly: true
{{- end }}
{{- end -}}

{{/*
The projected token the installation knows this workload by, with its
audience. There is nothing else to mount: a record that cannot be delivered
waits in the emitter's own queue, in memory, and the pod's disk holds none
of the trail.
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
{{- end }}
{{- end -}}

{{/*
The console's secret-store view was removed in v1.30.0. Refuse render if an
old configuration tries to activate it, with a message pointing to the
migration.
*/}}
{{- define "access-issuer.validateSecretManagers" -}}
{{- if .Values.secretManagers }}{{ fail "secretManagers was removed in v1.30.0: delete this key from your values. To sign in to OpenBAO, use its own OIDC login (see docs/connect/openbao.md)." }}{{ end -}}
{{- end -}}
