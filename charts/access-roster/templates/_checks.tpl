{{/*
What the chart holds a config to.

The config is rendered as it stands, so the chart cannot compute a value into
it. What it can do is refuse a config that disagrees with what the chart itself
renders and mounts: a path where the chart mounts nothing, a release name that
is not the one the objects carry, a console address that is not this release's
Service. Each of these used to be set by the chart and could not be wrong; each
is now said in the config and checked here, and each refusal names the value to
write.

Two kinds of check live here and nowhere else:
  - what spans a component's config and the values around it (this file);
  - what is local to one config is the schema's, or the binary's own start-up
    (schemas/config/*.schema.json, internal/config, issuerapp.FromConfig).
*/}}

{{/*
access-roster.expectPath: a config key names a file or directory the chart
mounts. Takes (dict "key" "config.exchange.clustersFile" "got" <the config's
value> "want" <where the chart mounts it> "source" "exchange.clusters"
"present" <whether the chart renders and mounts it>).

Present: the key must be exactly where the chart mounts it. Absent: the key
must be unset, because it names a file nothing provides.
*/}}
{{- define "access-roster.expectPath" -}}
{{- $got := .got | default "" -}}
{{- if and .present (ne $got .want) -}}
{{- fail (printf "%s must be %s, where the chart mounts what %s renders (got %q)" .key .want .source $got) -}}
{{- end -}}
{{- if and (not .present) $got -}}
{{- fail (printf "%s is %q and the chart renders nothing there: set %s, which the chart mounts at %s, or remove the key" .key $got .source .want) -}}
{{- end -}}
{{- end -}}

{{/*
access-roster.expectRelease: a config's `release` is the name its objects
carry. Takes (dict "key" "config.release" "root" $ "got" <the config's release>).
*/}}
{{- define "access-roster.expectRelease" -}}
{{- $want := include "access-roster.fullname" .root -}}
{{- $got := .got | default "access-roster" -}}
{{- if ne $got $want -}}
{{- fail (printf "%s must be %q, this release's full name: the Roles, ConfigMaps and Secrets the service and the controllers share are named from it (got %q; unset is access-roster; an installation moving from the access-issuer chart sets fullnameOverride to its old full name)" .key $want $got) -}}
{{- end -}}
{{- end -}}

{{/*
access-roster.expectAudit: a config that names an audit receiver must say where
the chart mounts the projected token it presents. Without a receiver there is
nothing to present it to, and the key may be unset or left at the default.
Takes (dict "key" "config.audit.tokenFile" "cfg" <the component's config>).
*/}}
{{- define "access-roster.expectAudit" -}}
{{- $got := dig "audit" "tokenFile" "" .cfg -}}
{{- if dig "audit" "writer" "" .cfg -}}
{{- include "access-roster.expectPath" (dict "key" .key "got" $got "want" "/var/run/audit/token" "source" "audit.token" "present" true) -}}
{{- else if and $got (ne $got "/var/run/audit/token") -}}
{{- fail (printf "%s is %q and no audit receiver is named: set audit.writer, whose token the chart mounts at /var/run/audit/token, or remove the key" .key $got) -}}
{{- end -}}
{{- end -}}

{{/*
access-roster.checks: everything the service's config must agree with.
*/}}
{{- define "access-roster.checks" -}}
{{- $c := .Values.config -}}
{{- $_ := required "config.issuerURL is required: it is baked into every token and every relying party's trust" $c.issuerURL -}}
{{- include "access-roster.validateLifetimes" . -}}
{{- include "access-roster.validateSecretManagers" . -}}
{{- include "access-roster.validateTelemetry" . -}}
{{- $_ := include "access-roster.port" . -}}
{{- $_ := include "access-roster.healthPort" . -}}
{{- include "access-roster.expectRelease" (dict "key" "config.release" "root" . "got" $c.release) -}}
{{- include "access-roster.expectPath" (dict "key" "config.policyDir" "got" $c.policyDir "want" "/var/run/access-issuer/policy" "source" "policy" "present" true) -}}
{{- $signing := dig "signingKey" dict $c -}}
{{- include "access-roster.expectPath" (dict "key" "config.signingKey.file" "got" $signing.file "want" (printf "/var/run/access-issuer/signing-key/%s" .Values.signingKey.key) "source" "signingKey.key" "present" true) -}}
{{- $additional := include "access-roster.additionalSigningKeyFiles" . -}}
{{- if ne (join "," ($signing.additionalFiles | default list)) $additional -}}
{{- fail (printf "config.signingKey.additionalFiles must be [%s], one file per signingKey.additional entry in the order they are declared (got [%s])" $additional (join ", " ($signing.additionalFiles | default list))) -}}
{{- end -}}
{{- $exchange := dig "exchange" dict $c -}}
{{- include "access-roster.expectPath" (dict "key" "config.exchange.clustersFile" "got" $exchange.clustersFile "want" "/var/run/access-issuer/clusters.yaml" "source" "exchange.clusters" "present" (not (empty .Values.exchange.clusters))) -}}
{{- include "access-roster.expectPath" (dict "key" "config.exchange.awsFile" "got" $exchange.awsFile "want" "/var/run/access-issuer/aws.yaml" "source" "exchange.aws.accounts" "present" (not (empty .Values.exchange.aws.accounts))) -}}
{{- include "access-roster.expectPath" (dict "key" "config.overlayFile" "got" $c.overlayFile "want" "/var/run/access-issuer/directory/overlay.yaml" "source" "directory.workspaces" "present" (not (empty .Values.directory.workspaces))) -}}
{{- include "access-roster.expectPath" (dict "key" "config.github.catalogueFile" "got" (dig "github" "catalogueFile" "" $c) "want" "/var/run/access-issuer/github-apps-catalogue.yaml" "source" "githubApps.catalogue" "present" (not (empty .Values.githubApps.catalogue))) -}}
{{- include "access-roster.expectPath" (dict "key" "config.slack.catalogueFile" "got" (dig "slack" "catalogueFile" "" $c) "want" "/var/run/access-issuer/slack-apps-catalogue.yaml" "source" "slackApps" "present" (not (empty .Values.slackApps))) -}}
{{- include "access-roster.expectPath" (dict "key" "config.clientSecretsDir" "got" $c.clientSecretsDir "want" "/var/run/access-issuer/clients" "source" "policy.clients[].secret" "present" (not (empty (include "access-roster.confidentialClients" .)))) -}}
{{- include "access-roster.expectAudit" (dict "key" "config.audit.tokenFile" "cfg" $c) -}}
{{- /*
  Recovery is the one thing left that asks the API server, and deliberately
  so: on the day everything else is broken it should depend on nothing but
  the cluster. The chart creates the account, so it has to be named, and the
  process has to know it runs in a cluster.
*/ -}}
{{- $recovery := dig "recovery" dict $c -}}
{{- if $recovery.enabled -}}
{{- if not $c.inCluster -}}
{{- fail "config.recovery.enabled needs config.inCluster: true: recovery proves access to the cluster the pod runs in, and without it the service builds no recovery and says so only in its log" -}}
{{- end -}}
{{- if not $recovery.serviceAccount -}}
{{- fail "config.recovery.enabled needs config.recovery.serviceAccount: the account a recovery token is minted for, which the chart creates and binds to nothing" -}}
{{- end -}}
{{- if not $recovery.audience -}}
{{- fail "config.recovery.enabled needs config.recovery.audience: without one, every mounted ServiceAccount token in the cluster would be a proof" -}}
{{- end -}}
{{- end -}}
{{- /*
  The public URLs were built from the route: the browser reaches the console
  at https://<host><mount>, and the admin-consent callback stays at the
  origin ROOT, registered with every corporate tenant. Served over TLS, the
  cookies say so.
*/ -}}
{{- if .Values.route.host -}}
{{- if and (hasKey $c "secureCookies") (not $c.secureCookies) -}}
{{- fail "config.secureCookies: false, and the service is served over TLS at route.host: its session cookies would be sent without the Secure flag" -}}
{{- end -}}
{{- if .Values.console.mount -}}
{{- $root := printf "https://%s" .Values.route.host -}}
{{- if ne ($c.publicRootURL | default "") $root -}}
{{- fail (printf "config.publicRootURL must be %s, the origin route.host serves: the admin-consent callback is registered at the origin root (got %q)" $root ($c.publicRootURL | default "")) -}}
{{- end -}}
{{- $public := printf "%s%s" $root (include "access-roster.consoleMount" .) -}}
{{- if ne ($c.publicURL | default "") $public -}}
{{- fail (printf "config.publicURL must be %s, where a browser reaches the console: route.host plus console.mount (got %q)" $public ($c.publicURL | default "")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
access-roster.rosterChecks: what a controller's config must agree with. Takes
(dict "root" $ "name" "controllerGithub" "cfg" <its config> "dir" "github-roster").
*/}}
{{- define "access-roster.rosterChecks" -}}
{{- $root := .root -}}
{{- $c := .cfg -}}
{{- $dir := .dir -}}
{{- if not $root.Values.exchange.clusters -}}
{{- fail (printf "%s.enabled needs exchange.clusters to name this cluster: the service verifies the controller's ServiceAccount token against that key set, and with no row it verifies nothing" .name) -}}
{{- end -}}
{{- if not (include "access-roster.consoleMount" $root) -}}
{{- fail (printf "%s.enabled needs console.mount: the controller reads the console's API, and with no mount there is none" .name) -}}
{{- end -}}
{{- $want := printf "http://%s.%s.svc:%s%s" (include "access-roster.fullname" $root) $root.Release.Namespace (include "access-roster.port" $root) (include "access-roster.consoleMount" $root) -}}
{{- if not $c.consoleURL -}}
{{- fail (printf "%s.config.consoleURL is required: who holds a group is the console's to answer; write %s, this release's own Service" .name $want) -}}
{{- end -}}
{{- if ne (trimSuffix "/" $c.consoleURL) $want -}}
{{- fail (printf "%s.config.consoleURL must be %s, the console this release serves (got %q)" .name $want $c.consoleURL) -}}
{{- end -}}
{{- include "access-roster.expectRelease" (dict "key" (printf "%s.config.release" .name) "root" $root "got" $c.release) -}}
{{- include "access-roster.expectPath" (dict "key" (printf "%s.config.policyDir" .name) "got" $c.policyDir "want" (printf "/var/run/%s/policy" $dir) "source" "policy" "present" true) -}}
{{- include "access-roster.expectPath" (dict "key" (printf "%s.config.tokenFile" .name) "got" $c.tokenFile "want" (printf "/var/run/secrets/%s/token" $dir) "source" "the projected ServiceAccount token" "present" true) -}}
{{- include "access-roster.expectAudit" (dict "key" (printf "%s.config.audit.tokenFile" .name) "cfg" $c) -}}
{{- end -}}

{{/*
access-roster.validateTelemetry: what `telemetry.otlp` may say. The endpoint is
an http(s) URL with a host; `extraEnv` holds other OTEL_* variables only, and
never the endpoint, which has a value of its own so that one place sets it.
*/}}
{{- define "access-roster.validateTelemetry" -}}
{{- $t := .Values.telemetry | default dict -}}
{{- $o := $t.otlp | default dict -}}
{{- $endpoint := $o.endpoint | default "" -}}
{{- if and $endpoint (not (regexMatch "^https?://[^/?#[:space:]]+" $endpoint)) -}}
{{- fail (printf "telemetry.otlp.endpoint must be an http(s) URL naming the collector or gateway, such as http://gateway.observability.svc:4318 (got %q)" $endpoint) -}}
{{- end -}}
{{- range $name, $_ := ($o.extraEnv | default dict) -}}
{{- if eq $name "OTEL_EXPORTER_OTLP_ENDPOINT" -}}
{{- fail "telemetry.otlp.extraEnv must not carry OTEL_EXPORTER_OTLP_ENDPOINT: set telemetry.otlp.endpoint, which is where the chart takes it from" -}}
{{- end -}}
{{- if not (hasPrefix "OTEL_" $name) -}}
{{- fail (printf "telemetry.otlp.extraEnv holds OpenTelemetry SDK variables only: %q does not start with OTEL_ (a secret reaches a pod through secretEnv, the rest through config)" $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
