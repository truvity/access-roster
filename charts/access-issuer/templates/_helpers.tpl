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
The name this installation's objects carry: the config's `release`, which the
binary defaults to access-issuer. The chart requires it to be the release's
full name (see access-issuer.checks): the Role names, the ConfigMaps and the
Secrets the service writes and the controllers read are `<full name>-...`.
*/}}
{{- define "access-issuer.release" -}}
{{- dig "release" "access-issuer" .Values.config -}}
{{- end }}

{{/*
The audience a workload token must be minted for: the config's
`exchange.audience`, which the binary defaults to the release name so that
two issuers in one cluster cannot accept each other's exchange proofs. The
controllers' projected tokens are minted for it.
*/}}
{{- define "access-issuer.exchangeAudience" -}}
{{- (dig "exchange" "audience" "" .Values.config) | default (include "access-issuer.release" .) }}
{{- end }}

{{/*
The listeners' ports, from the addresses the config gives. The config says
`host:port`; what the chart needs is the port, for the container, the Service,
the NetworkPolicy and the routes. A port outside 1-65535 is refused here, at
render: the binary would start on a port nothing can reach.
*/}}
{{- define "access-issuer.portOf" -}}
{{- $port := regexFind "[0-9]+$" .address | int -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "%s: the port in %q must be between 1 and 65535" .path .address) -}}
{{- end -}}
{{- $port -}}
{{- end -}}

{{- define "access-issuer.port" -}}
{{- include "access-issuer.portOf" (dict "path" "config.listen.address" "address" (dig "listen" "address" ":8080" .Values.config)) -}}
{{- end -}}

{{- define "access-issuer.healthPort" -}}
{{- include "access-issuer.portOf" (dict "path" "config.probes.address" "address" (dig "probes" "address" ":7070" .Values.config)) -}}
{{- end -}}

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
The Slack controller's pods, told apart from the service's, for the same
reason as the GitHub controller's.
*/}}
{{- define "access-issuer.slackRosterSelectorLabels" -}}
app.kubernetes.io/name: {{ include "access-issuer.name" . }}-slack-roster
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
access-issuer.signingAlgorithmOf is the JOSE algorithm one private key
spec signs with: RSA is always RS256, and ECDSA's SIZE decides ES256,
ES384 or ES512 -- the pairing RFC 7518 fixes, not a preference, and the
same rule internal/issuer.signatureAlgorithm applies in Go. It is what
tells two `signingKey.additional` entries apart for the "one key per
algorithm" refusal below: `algorithm: ECDSA` alone is not unique enough,
since a 256 and a 384 size both say ECDSA but sign two different
algorithms, and two 384s say it twice.

Takes the privateKey spec directly (the certificate or one
`signingKey.additional` entry), not the {spec,path} wrapper
access-issuer.privateKey takes. Empty for a spec naming neither, which
access-issuer.privateKey has already refused by the time this is asked to
name one.
*/}}
{{- define "access-issuer.signingAlgorithmOf" -}}
{{- $spec := . | default dict -}}
{{- $alg := $spec.algorithm | default "" -}}
{{- $size := int ($spec.size | default 0) -}}
{{- if eq $alg "RSA" -}}
RS256
{{- else if eq $alg "ECDSA" -}}
{{- if eq $size 256 -}}ES256
{{- else if eq $size 384 -}}ES384
{{- else if eq $size 521 -}}ES512
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
access-issuer.additionalSigningKeyName is the Secret, volume and mount
name for one `signingKey.additional` entry: the algorithm it signs with,
lowercased -- `signing-key-rs256`, `signing-key-es256` -- which is what
[access-issuer.signingAlgorithmOf] already guarantees is unique across
every entry (see the refusal in templates/signing-key.yaml). Named by
what it SIGNS rather than by position, so adding or reordering entries in
`values.yaml` renames nothing already running.

Takes one `signingKey.additional` entry.
*/}}
{{- define "access-issuer.additionalSigningKeyName" -}}
signing-key-{{ include "access-issuer.signingAlgorithmOf" . | lower }}
{{- end -}}

{{/*
access-issuer.additionalSigningKeyFiles is `config.signingKey.additionalFiles`: every
`signingKey.additional` entry's mounted key file, comma-joined, in the
order they are declared. Empty when there are none, which is every
deployment before per-audience signing existed.
*/}}
{{- define "access-issuer.additionalSigningKeyFiles" -}}
{{- $paths := list -}}
{{- range .Values.signingKey.additional -}}
{{- $name := include "access-issuer.additionalSigningKeyName" . -}}
{{- $paths = append $paths (printf "/var/run/access-issuer/%s/%s" $name (.key | default "tls.key")) -}}
{{- end -}}
{{- join "," $paths -}}
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
access-issuer.validateLifetimes refuses config.lifetimes.absolute: zero (a
session that ends before or the instant it begins is not a limit, it is a
login that can never complete) or, for the common case of a single-unit
duration, shorter than config.lifetimes.token (an access token cannot outlive
the session that grants it). Unset is the binary's default: 1h and 24h.

A compound duration ("1h30m") is not compared against the token lifetime:
parsing one fully needs a real duration parser, which Helm's template
language has none of, and a comparison that WRONGLY refuses a valid value
is worse than one silently skipped. The running service checks this
exactly, with Go's time.ParseDuration, and refuses to start if it is
wrong -- see issuerapp.FromConfig. The zero check does not have this problem:
"contains no digit but 0" is true or false regardless of how many units
a duration mixes.
*/}}
{{- define "access-issuer.validateLifetimes" -}}
{{- $l := dig "lifetimes" dict .Values.config -}}
{{- $absolute := $l.absolute | default "24h" -}}
{{- $token := $l.token | default "1h" -}}
{{- $simple := "^[0-9]+(ns|us|µs|ms|s|m|h)$" -}}
{{- if not (regexMatch "[1-9]" $absolute) -}}
{{- fail (printf "config.lifetimes.absolute: %q is zero -- a session has to end SOMETIME after sign-in, not before it" $absolute) -}}
{{- end -}}
{{- if and (regexMatch $simple $absolute) (regexMatch $simple $token) -}}
{{- $absoluteNanos := include "access-issuer.simpleDurationNanos" $absolute | int64 -}}
{{- $tokenNanos := include "access-issuer.simpleDurationNanos" $token | int64 -}}
{{- if lt $absoluteNanos $tokenNanos -}}
{{- fail (printf "config.lifetimes.absolute (%s) must be at least config.lifetimes.token (%s): an access token cannot outlive the session that grants it" $absolute $token) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Whether a component's config connects it to an audit installation: the
address its receiver serves. One address is the whole connection. The receiver
takes the records and answers RegisterCatalogue on the same port, because an
installation belongs to one application and a registry of its own would be a
Deployment for a single call.

Takes the component's config.
*/}}
{{- define "access-issuer.auditConnected" -}}
{{- if (dig "audit" "writer" "" .) }}true{{ end -}}
{{- end -}}

{{/*
The mount and the projected token the installation knows a workload by, with
its audience. There is nothing else to mount: a record that cannot be
delivered waits in the emitter's own queue, in memory, and the pod's disk
holds none of the trail. Both take (dict "root" $ "cfg" <the component's config>).
*/}}
{{- define "access-issuer.auditMounts" -}}
{{- if include "access-issuer.auditConnected" .cfg }}
- name: audit-token
  mountPath: /var/run/audit
  readOnly: true
{{- end }}
{{- end -}}

{{- define "access-issuer.auditVolumes" -}}
{{- if include "access-issuer.auditConnected" .cfg }}
- name: audit-token
  projected:
    sources:
      - serviceAccountToken:
          audience: {{ .root.Values.audit.token.audience | quote }}
          expirationSeconds: {{ .root.Values.audit.token.expirationSeconds }}
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
