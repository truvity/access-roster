#!/usr/bin/env bash
# What the built site must contain, checked in site/dist (or the directory
# given, relative to the repository root). Each check fails closed: a missing
# file or an empty match is a failure.
#
# usage: site/scripts/check-built.sh [dist]
set -euo pipefail
cd "$(dirname "$0")/../.."
dist=${1:-site/dist}
fail=0
bad() { echo "check-built: $*" >&2; fail=1; }

for f in index.html 404.html llms.txt llms-full.txt sitemap-index.xml robots.txt \
         overview/index.html architecture/index.html architecture/context/index.html \
         decisions/index.html roadmap/index.html contributing/index.html \
         requirements/index.html requirements/matrix/index.html requirements/coverage/index.html requirements.json \
         status/index.html data/repo.json data/repo.schema.json; do
  [ -s "$dist/$f" ] || bad "missing or empty: $f"
done

# Search: Pagefind's index and its entry point.
[ -s "$dist/pagefind/pagefind.js" ] || bad "no Pagefind entry point in $dist/pagefind"
[ -n "$(ls "$dist"/pagefind/index 2>/dev/null)" ] || bad "no Pagefind index shards in $dist/pagefind/index"

# Git LFS: a pointer file in the output means the checkout did not fetch its LFS
# objects (images and fonts would be broken on the site).
lfs=$(grep -rlI --null -m1 '^version https://git-lfs.github.com/spec/v1' "$dist" 2>/dev/null | tr '\0' '\n' | head -3 || true)
[ -z "$lfs" ] || bad "Git LFS pointer files in the output (the checkout has no LFS objects): $(echo "$lfs" | tr '\n' ' ')"

# Response headers (CSP and the rest): the Workers target serves them from _headers.
[ -s "$dist/_headers" ] || bad "no _headers: site/public/_headers did not reach the output"
site/scripts/check-csp.mjs "$dist" || bad "the Content-Security-Policy does not match the pages (above)"

# On the Workers target: the redirects of astro.config.mjs are a _redirects file, and
# the Worker configuration is there; and neither workers.dev nor preview URLs may be on.
# The Worker's code is named, runs first for /api/* only (so static pages never invoke
# it), and has its cron (ADR 0014).
if [ -f "$dist/wrangler.json" ]; then
  grep -q '^/shapes/ ' "$dist/_redirects" 2>/dev/null || bad "the Workers build has no _redirects with the renamed pages"
  grep -q '"workers_dev":false' "$dist/wrangler.json" || bad "wrangler.json does not set workers_dev false"
  grep -q '"preview_urls":false' "$dist/wrangler.json" || bad "wrangler.json does not set preview_urls false"
  jq -e '.main == "../../src/worker/index.ts"' "$dist/wrangler.json" >/dev/null || bad "wrangler.json does not name src/worker/index.ts as main"
  jq -e '.assets.run_worker_first == ["/api/*"]' "$dist/wrangler.json" >/dev/null || bad "wrangler.json must run the Worker first for /api/* and nothing else"
  jq -e '.assets.binding == "ASSETS"' "$dist/wrangler.json" >/dev/null || bad "wrangler.json has no ASSETS binding"
  jq -e '(.triggers.crons | length) == 1' "$dist/wrangler.json" >/dev/null || bad "wrangler.json has no cron trigger"
  jq -e '(.cache.enabled // false) == false' "$dist/wrangler.json" >/dev/null || bad "wrangler.json turns on Workers Cache, which bills static requests"
fi

# Mermaid: the diagram must be a <pre class="mermaid"> that the browser script
# draws, never a code listing that merely looks like one.
ctx="$dist/architecture/context/index.html"
if [ -s "$ctx" ]; then
  grep -q '<pre class="mermaid"' "$ctx" || bad "$ctx has no <pre class=\"mermaid\">: Mermaid is not rendering"
  if grep -q 'language-mermaid' "$ctx"; then bad "$ctx still has a language-mermaid code block"; fi
fi
if grep -rl 'language-mermaid' "$dist" --include=index.html >/dev/null 2>&1; then
  bad "a page ships a mermaid fence as a code listing: $(grep -rl 'language-mermaid' "$dist" --include=index.html | head -3 | tr '\n' ' ')"
fi

# Bundled scripts: no Astro or Vite build-time placeholder (__PREFETCH_PREFETCH_ALL__
# and the like) may survive into the output. One unreplaced placeholder in the
# page script throws a ReferenceError and stops every script after it, including
# the one that draws the Mermaid diagrams. The pattern is the prefixes Astro
# uses, not any __NAME__: Mermaid's own CSS has class names such as __APA__.
# site/scripts/check-render.mjs (just site-render) is the same guard in a real
# browser.
placeholder='__(PREFETCH|EXPERIMENTAL|ASTRO|VITE)_[A-Z0-9_]*__'
if [ -d "$dist/_astro" ]; then
  left=$(grep -rEl "$placeholder" "$dist/_astro" --include='*.js' || true)
  if [ -n "$left" ]; then
    bad "an unreplaced build-time placeholder is left in: $(echo "$left" | head -3 | tr '\n' ' ')($(grep -rEoh "$placeholder" "$dist/_astro" --include='*.js' | sort -u | head -5 | tr '\n' ' '))"
  fi
else
  bad "no $dist/_astro: the site has no bundled scripts"
fi

# /data/repo.json: valid against its schema and equal to the records it is built from.
site/scripts/check-repo-json.mjs "$dist" || bad "/data/repo.json does not match its schema or its sources (above)"

# "Edit page" links: each one is a file in this checkout (and the page's own source).
site/scripts/check-edit-links.mjs "$dist" || bad "an edit link does not point at its file in the repository (above)"

# The decisions index lists records, not the template, and shows each record's status.
if [ -s "$dist/decisions/index.html" ]; then
  if grep -q '0000-template' "$dist/decisions/index.html"; then bad "decisions/index.html lists the template"; fi
  [ ! -e "$dist/decisions/0000-template" ] || bad "the template is built as a decision page: $dist/decisions/0000-template"
fi

# The landing page says what v2 is and where v1 went.
grep -q 'What runs today is sluis v1' "$dist/index.html" || bad "the landing page lacks the v1 and v2 status paragraph"
grep -q 'Code: [0-9]* lines\?\.' "$dist/index.html" || bad "the landing page lacks the design and code line"
grep -q 'Code: [0-9]* lines\?\.' "$dist/status/index.html" || bad "the status page lacks the design and code line"
# With the board read, each milestone card on the status page has a Design bar and a Build bar, named apart.
if grep -q 'data-project="available"' "$dist/status/index.html"; then
  cards=$( (grep -o '<article class="ps-card' "$dist/status/index.html" || true) | wc -l)
  design=$( (grep -o 'class="ps-bargroup ps-bargroup-design"' "$dist/status/index.html" || true) | wc -l)
  build=$( (grep -o 'class="ps-bargroup ps-bargroup-build"' "$dist/status/index.html" || true) | wc -l)
  [ "$cards" -gt 0 ] && [ "$design" -eq "$cards" ] && [ "$build" -eq "$cards" ] \
    || bad "the status page has $cards milestone cards, $design Design bars and $build Build bars"
fi
grep -q 'a pluggable identity and access broker' "$dist/index.html" || bad "the landing page lacks the tagline"

# The v1 documentation, when it was built in.
if [ -d "$dist/v1" ]; then
  [ -s "$dist/v1/index.html" ] || bad "v1/index.html missing"
  grep -q 'https://sluis.id/v1/' "$dist/v1/index.html" || bad "v1 was not built with site_url https://sluis.id/v1/"
  [ -s "$dist/v1/assets/vendor/mermaid.min.js" ] || bad "v1 has no Mermaid bundle"
  [ -d "$dist/schemas" ] || bad "no /schemas/ at the site root: the \$id URLs of v1's schemas would not resolve"
fi

[ "$fail" -eq 0 ] || exit 1
echo "check-built: ok ($(find "$dist" -name '*.html' | wc -l) HTML files)"
