---
name: site-change
description: Use when changing the sluis site itself rather than one page's text: the layout, the home page, styles, the Worker, the response headers, redirects, or a moved page.
---

Read "Changing the site" and "The site" in `docs/contributing/tools.md`, and "Moving a page" and "Home pages" in `docs/contributing/pages.md`. Those pages are the rules; this is the checklist.

Before you change it:

- [ ] HSTS: the header is one year, `includeSubDomains`, `preload`. It is never lowered, and no name of the domain is served over plain HTTP.
- [ ] CSP: the policy in `site/public/_headers` stays exact. `'self'` plus the two Cloudflare Web Analytics hosts (`https://static.cloudflareinsights.com` in `script-src`, `https://cloudflareinsights.com` in `connect-src`), and the inline scripts by hash. `site/scripts/check-csp.mjs` prints the hashes to paste.
- [ ] No remote assets: no remote font, script, image or style. Inline SVG; embedded, CC0, nominative icons.
- [ ] A moved or renamed page has its line in `redirects` in `site/astro.config.mjs`, pointing at the final page, in the same pull request.
- [ ] A page is `.md`; `.mdx` is only for a page that places components ("Page format" in `docs/contributing/pages.md`, checked by `just check-mdx-pages`).
- [ ] A home page starts from the reader's pain, then the mission, then what the project does about each pain, with honest status (designed, built, planned).

While you build it:

- [ ] `devbox run -- just site-lint` and `just site-build` pass. A strict build fails on one warning; retry only a failure from a slow external fetch, and do not switch strict mode off.
- [ ] Serve the built site (the `dist` directory under the site directory), and take screenshots with headless Chrome at 1440 px and 390 px, light and dark. Look at all four, fix what is off, and give the paths in the report. Nothing scrolls sideways at 375 px.
- [ ] `devbox run -- just site-workers` passes when the Worker, the headers or the redirects changed.

CI and the merge:

- [ ] If a link check or a job runs far past its usual time, do not just re-run it: cancel one run, read its log for the URL it stalled on (lychee runs with `-v`), and fix the bound or exclude the host with a dated reason. See "Link checking is bounded".
- [ ] After a fix lands on `main`, a stuck pull request needs a fresh push or a rebuilt branch. Re-running an old run uses the old merge commit and the old configuration.
- [ ] After the merge, wait for the `deploy-workers` job of the `Site` workflow, then run the curl checks in "After every deploy" in `docs/contributing/tools.md`: the page answers 200, a moved page 301, the HSTS and CSP headers are intact, `/api/status` answers, and an unsigned `POST /api/hooks/github` answers 401 (a 503 is a finding). Report what you ran and what came back.
