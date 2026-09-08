{{/*
The routes this exposure protects, as a list, whichever way the values
described them.

One route is the ordinary case and `exposure` describes it directly, so
the simple exposure stays four lines. `exposure.routes` is for a host with
more than one, and the two are mutually exclusive: a values file that set
both would have one of them silently ignored, and the ignored one would be
the protection somebody thought they had configured.
*/}}
{{- define "access-proxy.routes" -}}
{{- $e := .Values.exposure -}}
{{- $simple := or $e.backend.name $e.attachRouteName -}}
{{- if and $e.routes $simple -}}
{{- fail "exposure.routes is set alongside exposure.backend/attachRouteName; those describe one route between them, so set either the single-route fields or the list, never both" -}}
{{- end -}}
{{- if $e.routes -}}
{{- toYaml $e.routes -}}
{{- else -}}
{{- toYaml (list (dict
      "name" "app"
      "attachRouteName" $e.attachRouteName
      "backend" $e.backend
      "paths" $e.paths
      "posture" $e.posture
      "allow" $e.allow)) -}}
{{- end -}}
{{- end }}

{{/*
The SecurityPolicy name for one route. The single-route case keeps the
release's own name, so adopting `routes` later does not rename the policy
of an exposure that had one all along.
*/}}
{{- define "access-proxy.policyName" -}}
{{- $root := .root -}}{{- $route := .route -}}
{{- if $root.Values.exposure.routes -}}
{{- printf "%s-%s" (include "access-proxy.fullname" $root) $route.name -}}
{{- else -}}
{{- include "access-proxy.fullname" $root -}}
{{- end -}}
{{- end }}

{{/* The HTTPRoute name this chart renders for a route it owns. */}}
{{- define "access-proxy.routeName" -}}
{{- $root := .root -}}{{- $route := .route -}}
{{- if $root.Values.exposure.routes -}}
{{- printf "%s-%s" (include "access-proxy.fullname" $root) $route.name -}}
{{- else -}}
{{- include "access-proxy.fullname" $root -}}
{{- end -}}
{{- end }}
