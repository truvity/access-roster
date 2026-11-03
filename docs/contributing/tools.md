---
title: Tools, checks and verification
description: Where the sluis tools come from, which recipe runs a check, how to run commands from an agent shell, and when a result counts as verified.
status: partial
sidebar:
  order: 2
---

## Tools come from devbox

Every tool the repository uses is pinned in `devbox.json`, at an exact version, and locked in `devbox.lock`. Run commands inside the devbox environment: `devbox shell`, or one command at a time with `devbox run -- <command>`.

- Pin exact versions, of tools and of the standards they implement. A range is not a pin.
- Prefer a pinned release binary over a container for a tool.
- Do not use testcontainers.

## Standards first

Follow specifications and standards. Where a standard exists for a protocol, a format or an algorithm, do not invent one; a deliberate deviation from a standard needs a [decision record](/contributing/decisions/). Pin the version of the standard you follow, as you pin the version of a tool.

## Run the recipe, not the tool

The `Justfile` holds the recipes, and CI runs the same recipes. Run the recipe, not the bare tool underneath it: the recipe carries the flags, the order and the extra checks that CI applies.

| Recipe | What it checks |
|---|---|
| `just check` | Everything a pull request must pass: `check-rules`, `site-check` and `site-workers` |
| `just check-rules` | The repository rules, below, after a self-test of the checks |
| `just check-decisions` | The decision records: file names, the template's sections, the status, the index rows |
| `just check-requirements` | The requirements catalogue: schema, ids, statement and traceability rules |
| `just check-public` | Content that must not be public, in every tracked text file |
| `just check-yaml-ext` | YAML files use `.yaml` |
| `just check-mdx-pages` | Markdown everywhere: an `.mdx` file under `docs/` imports a component and places it ([Page format](/contributing/pages/#page-format)) |
| `just check-agent-links` | `AGENTS.md` exists, `CLAUDE.md` imports it, and every path that they and the skills point to exists |
| `just site-check` | The site: `site-lint`, `site-build`, `site-render` and `site-links` |
| `just site-lint` | Page descriptions and statuses, open-decision ids, and the requirements catalogue |
| `just site-build` | A strict site build: no warning and no broken internal link |
| `just site-links` | Every link in the built site, internal and external |
| `just site-render` | Every diagram is drawn, in light and dark mode |
| `just site-workers` | The Cloudflare Workers build with a fake KV id: the strict build for the Worker, `/v1/`, the headers and redirects checks, and `wrangler deploy --dry-run`. Part of `just check`; the `workers` job of `checks.yaml` runs it |
| `just site-test-worker` | The Worker's tests (`site/scripts/check-worker.mjs`): the status API, the webhook signature, the CI token rules and the KV write rules, with GitHub and KV faked. Part of `just site-workers` |

Read the recipe, and the workflow in `.github/workflows/` that calls it, to know what CI really runs. Build and test recipes for the code arrive with the code, and this table grows with them.

## The site

The site is built from `docs/` and `site/` with Astro Starlight, and every page is prerendered into static files.

- `just site-dev` serves it on `http://localhost:4321` with live reload; it runs `astro dev`.
- `just site-build` makes the strict build into `site/dist`, the same build CI checks.
- The [project status](/status/) page and `/data/repo.json` are built with the rest ([ADR 0014](/decisions/0014-the-site-is-static-on-cloudflare-workers/)). The page reads the v2 project board during the build, with the token in `GH_TOKEN` or `GITHUB_TOKEN`. Reading an organisation's project needs a token that may read it: locally, `GH_TOKEN=$(gh auth token) devbox run -- just check`. The `GITHUB_TOKEN` of GitHub Actions cannot read organisation projects, so `site.yaml` mints a short-lived read-only token from the `sluis-status` GitHub App instead (`actions/create-github-app-token`, with the repository variable `SLUIS_STATUS_APP_CLIENT_ID` and the secret `SLUIS_STATUS_APP_KEY`); a pull request build has neither, says "project data not available at build time" on the page and in its log, and does not fail. `site/scripts/check-repo-json.mjs` checks `/data/repo.json` against its schema, `site/public/data/repo.schema.json`, and against the records it is built from.

How the site is hosted is decided in [ADR 0014](/decisions/0014-the-site-is-static-on-cloudflare-workers/). `site.yaml` builds it for Cloudflare Workers and deploys it on every push to `main`, after its checks have passed. GitHub Pages is off (2026-11-01): nothing publishes there, and the names `sluis.id` and `www.sluis.id` are custom domains of the Worker. The build has two targets, chosen by `SLUIS_TARGET` (`pages`, the default, or `workers`). They build the same pages.

- **Pages** is the plain static build. It writes `site/dist` and turns the renamed-page redirects of `astro.config.mjs` into meta-refresh pages. `just site-build`, the pull request checks and the `build` job of `site.yaml` use it; nothing deploys it. The name is historical, from when GitHub Pages served the site.
- **Workers** goes through the `@astrojs/cloudflare` adapter and writes `site/dist/client`, the Worker's assets directory, with the Worker configuration, and turns the redirects into a `_redirects` file. Every docs page is prerendered, so Pagefind search keeps working. Only `/api/*` runs as Worker code: the [live status API](#the-live-status-api). The experimental route cache `cacheCloudflare()` stays off, because it bills static asset requests.
- `site/wrangler.jsonc` names the Worker `sluis-site`, a KV binding `STATUS` and the static assets. It holds no account id and no namespace id. The id of the KV namespace is the environment variable `SLUIS_STATUS_KV_ID`: Wrangler does not read variables in its configuration, so `src/cloudflare-kv-id.mjs` writes the id into the configuration the build generates whenever the variable is set. A build without it (a laptop, a pull request) keeps a placeholder id and deploys nothing; `just site-workers` sets a fake one.
- `workers_dev` and `preview_urls` are off, for good. Wrangler turns both on by default, and each publishes a hostname that contains the operator's account subdomain. There is no preview per pull request for that reason ([ADR 0014](/decisions/0014-the-site-is-static-on-cloudflare-workers/)); a pull request is judged by `just site-workers` in CI, and you can serve the same build with `yarn wrangler dev` in `site/`.
- The adapter and Wrangler are pinned at releases at least two weeks old (`@astrojs/cloudflare` 14.4.0, `wrangler` 4.151.0). The adapter's Vite plugin is pinned to 1.64.0 in `resolutions` so that it brings that Wrangler and no newer one, and `.yarnrc.yml` adds the `prismjs` package that the adapter imports without declaring, and five packages that Starlight asks Vite to pre-bundle through the wrong owner (without them a cold build warns, and the strict build fails). Drop them when an upgrade makes them unnecessary.
- `site/public/_headers` holds the Content-Security-Policy and the other security headers. Inline scripts are listed by hash, and `site/scripts/check-csp.mjs` (run by `check-built.sh`) fails when a page runs one that is not listed, or a listed one is gone, and prints the hashes to paste. The site loads nothing from outside except Cloudflare Web Analytics, which the CDN injects at the edge (privacy-first, no cookies, pinned by an integrity hash): `script-src` names `https://static.cloudflareinsights.com` and `connect-src` names `https://cloudflareinsights.com`, and the check fails on any other external origin. Two further exceptions are written in the file: `style-src` keeps `'unsafe-inline'` for the style attributes of Starlight and Mermaid, and `/v1/*` has its own policy with inline scripts, because MkDocs Material emits a different one on almost every page.
- **The deploy** is the `deploy-workers` job of `.github/workflows/site.yaml`. It runs on a push to `main` and on a manual run from `main`, after the `build` job has passed, and never on a pull request. It builds the site for the Worker with the same steps as `build` (the strict build with `SLUIS_TARGET=workers`, the v1 documentation under `/v1/`, the build checks) and a `build.json` stamp with the commit, then runs `just site-deploy`, which is `yarn wrangler deploy` in `site/`. It rebuilds instead of passing the output of `build` on, because the KV id is written into the generated Worker configuration at build time, from a secret that only this job can read. Deploys never overlap: a deploy waits for the one that is running, and a newer one replaces a deploy that is still waiting.
- The job runs in the GitHub environment `cloudflare`. The environment allows deployments from `main` only, and has no required reviewers. It holds three secrets:

  | Secret | Value |
  |---|---|
  | `CLOUDFLARE_API_TOKEN` | A Cloudflare API token limited to deploying this one Worker, with an expiry |
  | `CLOUDFLARE_ACCOUNT_ID` | The identifier of that account |
  | `SLUIS_STATUS_KV_ID` | The id of the KV namespace for the `STATUS` binding |

  The maintainer creates the token and rotates it before it expires; a deploy that fails with an authentication error is the sign that it has. The token is long-lived; it cannot create or delete Workers, and only `main` can read it. The job gives each secret to the one step that needs it, and checks first that all three are set, without printing them. GitHub masks a secret's value in the log, and no step prints the KV id or the account id. The status page data comes from the `sluis-status` GitHub App, as in the `build` job.
- Security headers and redirects are files in the repository, and the Worker, its KV namespace and the routes of the domain are declared in the operator's own infrastructure code, outside it. The deploy uploads a new version of the Worker and changes none of them. `just site-workers` and every pull request check hold no Cloudflare credential.

## The live status API

The [project status](/status/) page shows live issue figures and the checks on `main`, read by the site's Worker ([ADR 0014](/decisions/0014-the-site-is-static-on-cloudflare-workers/)). The Worker is `site/src/worker/`, a plain module that `wrangler deploy` bundles; it has no Astro server in it. `wrangler.jsonc` runs it first for `/api/*` only, so a static page never invokes it.

| Route | What it does |
|---|---|
| `GET /api/status` | The live status as JSON: per milestone the issue figures, the open issues and the build-time requirement and decision counts, the latest run of each workflow on `main`, and the coverage and conformance summaries. `cache-control: public, max-age=60`; 503 until the first refresh |
| `GET /api/status/live/` | The data part of the status page as HTML, drawn by `site/src/lib/status-html.ts`, the renderer the build uses for the snapshot. The page's script (`site/src/scripts/status-live.ts`) swaps it in; when it cannot, the snapshot stays and the page says so with its time |
| `POST /api/hooks/github` | A webhook delivery from the `sluis-status` GitHub App. The Worker checks `X-Hub-Signature-256` against the webhook secret, answers at once and refreshes the board in the background |
| `POST /api/ci` | A summary from a CI run on `main`: `{"coverage": {"percent": 81.5}}`, `{"conformance": {"passing": 3, "total": 4}}` or both. Authenticated by the run's GitHub Actions OIDC token, pinned to the audience `https://sluis.id/api/ci`, the repository, `refs/heads/main` and the workflows listed in `site/src/worker/verify.ts`; no secret is stored for it |

- **The data** is two documents in the KV namespace `STATUS`: `board` (the project board and the runs on `main`) and `ci` (the summaries). The Worker joins the board with the `/data/repo.json` of the same deployment, read from the static assets.
- **Refreshes** come from webhooks within seconds, and from a cron every 15 minutes that catches missed deliveries. A refresh reads the board with GraphQL and the runs with a conditional request, and writes KV only when the content changed or the stored copy is more than an hour old. Each document stops writing for the rest of the UTC day at its cap (800 for `board`, 100 for `ci`), inside the Free plan's 1,000 writes a day.
- **Secrets.** The Worker reads GitHub as the read-only `sluis-status` App: its client id (`GITHUB_APP_CLIENT_ID`) and private key (`GITHUB_APP_PRIVATE_KEY`, the PKCS#1 PEM that GitHub issues), and checks webhooks with `GITHUB_WEBHOOK_SECRET`. The deploy job uploads all three with each version (`wrangler deploy --secrets-file`) from the repository variable `SLUIS_STATUS_APP_CLIENT_ID`, the secret `SLUIS_STATUS_APP_KEY` and the `cloudflare` environment's secret `SLUIS_STATUS_WEBHOOK_SECRET`. Nobody runs `wrangler secret put`; rotating a secret is changing it in GitHub and running the Site workflow. Without the webhook secret, `/api/hooks/github` answers 503 and the cron alone refreshes.
- **The webhook** is set on the App by the maintainer: the URL `https://sluis.id/api/hooks/github`, content type `application/json`, the same secret as `SLUIS_STATUS_WEBHOOK_SECRET`, and the events Issues, Label, Projects v2 item and Workflow run. The App's permissions stay read-only: issues, organisation projects, actions, checks and metadata.
- **Locally**, `just site-test-worker` runs the tests. To see the Worker, run `just site-workers`, put a document into the local KV with `yarn wrangler kv key put --local --config dist/client/wrangler.json --binding STATUS board --path <file>` in `site/`, then `yarn wrangler dev` there.

## Changing the site

These rules hold for a change to the site itself: the layout, the home page, the Worker, the headers. A change to the text of a page follows [Pages and writing style](/contributing/pages/). The `site-change` skill (`.claude/skills/site-change/SKILL.md`) is the checklist.

- **HSTS is one-way.** The domain is a custom domain of the Worker with `ssl: strict` and DNSSEC, and it serves `Strict-Transport-Security` for one year with `includeSubDomains` and `preload`. The domain is submitted to the browsers' preload list. Never lower the header, never shorten `max-age`, and never serve a name of the domain over plain HTTP.
- **The Content-Security-Policy is exact.** It is the one in `site/public/_headers`, described under [The site](#the-site): `'self'` plus exactly the two origins of Cloudflare Web Analytics, `https://static.cloudflareinsights.com` in `script-src` and `https://cloudflareinsights.com` in `connect-src`, and the inline scripts by hash. Do not widen it to make something work; change the something.
- **No remote assets.** No remote font, script, image or style. Use inline SVG, and embed icons: CC0 icons (simple-icons) are inlined and used nominatively, to name a product and not to imply an endorsement. `site/scripts/check-csp.mjs` fails on any other external origin.
- **Moving a page** needs a line in the `redirects` map of `site/astro.config.mjs` (it becomes a 301 in the Worker's `_redirects` file) in the same pull request, pointing at the final page so nothing chains. After the deploy, check that the old URL answers 301 to the new one ([After every deploy](#after-every-deploy)).
- **Edit links point at the real file.** `site/src/route-middleware.ts` rewrites Starlight's "Edit page" URL from `site/src/content/docs/<id>.md` to `docs/<id>.md`, and `site/scripts/check-edit-links.mjs` (run by `check-built.sh`) fails when a link in the built site is not a file in the checkout or not the source of its page. Do not point `editLink.baseUrl` back at `docs/`.
- **Link checking is bounded.** `just site-links` runs lychee with `-v`, so a stall names its URL, under `timeout --foreground 240` and at most three tries; `lychee.toml` bounds each request (`timeout`, `max_retries`, `max_redirects`). A host that loops on redirects (`www.rfc-editor.org` does) is excluded there, with a dated comment saying why. A CI job that runs far past its usual time is a finding, not bad luck: cancel one run to read its log, find the URL it stalled on, fix the bound or the exclusion, then run again.
- **A strict build fails on one warning.** `site/scripts/strict-build.sh` fails on any warning. A slow external fetch can raise one (fonts in the v1 documentation build did). Retry that one failure, and only that one; keep strict mode for everything else. Do not turn the check off to get a green run.
- **Do not re-run an old pull request run to pick up a fix.** A re-run uses the merge commit the first run made, and so the old configuration. After a fix lands on `main`, a stuck pull request needs a fresh push or a rebuilt branch ([Rebuilding a pull request](/contributing/workflow/#rebuilding-a-pull-request)).
- **See the change, do not assume it.** Build with `just site-build`, serve `site/dist` (`python3 -m http.server -d site/dist`), and take screenshots with headless Chrome at desktop width (1440 px) and phone width (390 px), in light and dark (`site/scripts/check-render.mjs` shows how to emulate `prefers-color-scheme`). Look at them and fix what is off before you open the pull request, and give the screenshot paths in the report. Nothing scrolls sideways at 375 px.
- **Home pages start from the reader's pain** ([Pages and writing style](/contributing/pages/#home-pages)).

### After every deploy

The merge to `main` starts the `deploy-workers` job of the `Site` workflow; wait for it to pass, then check the live site with `curl`, and say what you ran:

1. A page answers 200: `curl -sSI https://sluis.id/`.
2. A moved page answers 301 with the new address in `location`.
3. The headers are intact: `strict-transport-security` is `max-age=31536000; includeSubDomains; preload`, and `content-security-policy` is the one in `site/public/_headers`.
4. The status API answers: `curl -sS https://sluis.id/api/status` is JSON with 200, or 503 with `retry-after` until the first refresh.
5. The webhook refuses an unsigned delivery: `curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://sluis.id/api/hooks/github` prints `401`. A `503` means the webhook secret did not reach the Worker, and is a finding.

## Local work

- Work in a fresh clone, or a worktree off `origin/main`, under your own scratch area ([Branches and pull requests](/contributing/workflow/)). Never work inside someone else's checkout, and never run a command in a checkout that is not yours.
- Run the narrow recipes while you work: `just check-rules`, `just site-lint` and `just site-build`, and `just check-actors`, `just check-examples` and `just check-installations` where the change touches them. Rely on GitHub CI for the rest.
- If `just` is not on `PATH`, run it through devbox: `devbox run -c <dir> -- just <recipe>`.
- If `yarn` fails with `EXDEV` in a scratch area, set `YARN_GLOBAL_FOLDER` to a folder on the same filesystem as the checkout.
- Never print a token, a password or a secret. Read a credential file at run time, from the command that needs it, and do not echo it.
- A deletion that a safety check refuses is left to the maintainer: report the exact command, and do not work around the check.

## Commands from an agent shell

An AI agent's shell may reset its working directory between calls, so a `cd` in one call is gone in the next. Use absolute paths:

- `git -C /abs/path/to/worktree status`, `go -C /abs/path ...`, `cargo --manifest-path /abs/path/Cargo.toml ...`;
- or `cd /abs/path && devbox run -- just check` as one command.

Never run `go mod init`, `go get` or `cargo init` outside the repository: in the wrong directory they create or change a module that is not this one.

## Hardware tokens

Tests that use a hardware token, a smart card or a security key use dedicated test devices only, never a device someone uses for real work. Select the test device by its serial number, never by "the first one found", and reset it to its factory state when the test is done. A serial number is not written into the repository.

## When a result counts

- Measure before you fix. Find the cause in numbers or in a log line before you change anything.
- Read what a tool printed, not only its exit code. A tool can exit 0 and say it did nothing.
- A green check that tests nothing is not green. A check that finds nothing to check, an empty list of files or an empty sweep, fails rather than passes.
- Say what you ran, with the command and its result. Plausible output that nobody ran is not a contribution.
