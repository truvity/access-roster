#!/usr/bin/env bash
# Add the JSON schemas to the site GitHub Pages serves: every schema this
# repository names by an $id, at the path its $id says. A file whose $id does
# not match the path it would be served at fails here, because an identifier
# that does not resolve is the fault this exists to remove.
#
# usage: hack/pages-site.sh [out]   (default _site; the documentation is built
# into it first by `mkdocs build -d out`, this adds out/schemas)
set -euo pipefail
cd "$(dirname "$0")/.."

base="https://truvity.github.io/sluis"
out="${1:-_site}"
rm -rf "$out/schemas"
mkdir -p "$out/schemas"

id_of() { jq -r '."$id"' "$1"; }

# publish <source file> <path under the site>: the $id must be base/<path>.
publish() {
  local id
  id=$(id_of "$1")
  if [ "$id" != "$base/$2" ]; then
    echo "pages-site: $1 has \$id $id, want $base/$2" >&2
    exit 1
  fi
  mkdir -p "$out/$(dirname "$2")"
  cp "$1" "$out/$2"
}

# sluis: the path is whatever the $id says under the base, and a schema that
# names another host fails.
for f in schemas/config/*.schema.json schemas/config/v1/*.schema.json; do
  id=$(id_of "$f")
  case "$id" in
    "$base/schemas/"*) publish "$f" "${id#"$base/"}" ;;
    *) echo "pages-site: $f has \$id $id, want one under $base/schemas/" >&2; exit 1 ;;
  esac
done

# The fragment and ceiling schemas of a company's own access rows.
for f in schemas/policy/tenant/*.schema.json; do
  id=$(id_of "$f")
  case "$id" in
    "$base/schemas/"*) publish "$f" "${id#"$base/"}" ;;
    *) echo "pages-site: $f has \$id $id, want one under $base/schemas/" >&2; exit 1 ;;
  esac
done

# audit: its record schema, meta-schemas, configuration schemas and the common
# catalogue's payload schemas, under schemas/audit/.
publish audit/gen/jsonschema/record.v1.schema.json schemas/audit/v1/record.schema.json
for f in catalogue extension profile; do
  publish "audit/sdk/schemas/$f.schema.json" "schemas/audit/v1/$f.schema.json"
done
# The configuration schemas are versioned by the shape of the document: v2 is
# current, and v1 is kept, frozen, for the one minor in which it is still read.
for f in audit/schemas/config/*.schema.json; do
  publish "$f" "schemas/audit/v2/config/$(basename "$f")"
done
for f in audit/schemas/config/v1/*.schema.json; do
  publish "$f" "schemas/audit/v1/config/$(basename "$f")"
done
for f in audit/sdk/catalogue/*.json; do
  publish "$f" "schemas/audit/v1/common/$(basename "$f")"
done

echo "pages-site: $(find "$out/schemas" -name '*.json' | wc -l) schemas in $out"
