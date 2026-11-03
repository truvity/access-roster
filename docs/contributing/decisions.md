---
title: Decisions, requirements and research
description: How a sluis v2 decision becomes a record, how a requirement is written and marked done, and the shape of a spike or research result.
status: page
sidebar:
  order: 4
---

A decision record (ADR) says why sluis is shaped the way it is, a requirement says what sluis v2 must do, and a spike or research result is the evidence a decision is made on. Who decides is in [GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md) ("How a decision is made"); this page is the order of work, and [How we design](/contributing/design/) is the order of thinking before it.

## The maintainer decides

A contributor or an agent presents the options, each with its pros and cons, and a recommendation. It does not pick. The maintainer decides: merging a record with status `Accepted` is the decision.

## Decision records

The format, the numbering and the status values are in [docs/decisions/README.md](https://github.com/truvity/sluis/blob/main/docs/decisions/README.md).

### From proposal to record

1. **Proposal.** Open an issue with the *Decision proposal* form: the question, the context, the options with pros and cons, and the options you would not take. The form labels it `type:decision`; give it a `Product milestone` on the project board, which places the planned record on the [project status](/status/) page.
2. **Record.** When the direction is clear, copy [the template](https://github.com/truvity/sluis/blob/main/docs/decisions/0000-template.md) to `docs/decisions/NNNN-short-title-in-kebab-case.md`, with the next free number. Link the proposal issue in the context.
3. **Index.** Add the record to the index table in `docs/decisions/README.md`, with its status. Every record has a row, and every row has a record.
4. **Requirements.** A decision that creates an obligation adds a requirement or cites an existing one ([Requirements](#requirements)).
5. **Pages.** The pages that the decision changes follow in the same pull request, or in the next one ([Pages and writing style](/contributing/pages/)).
6. **Pull request.** At most five records per pull request. A larger batch is split.

### Accepted means fully decided

A record is `Accepted` only when every part of it is decided. While a part is still open, the record stays `Proposed`, the open part is tracked in an issue, and the record lists it under Follow-ups with a link to that issue. An accepted record never says "not decided here" and never names a future record number: a planned decision has an issue, and the record links the issue.

### Roads not taken

Every record keeps the options it did not take, one line each: the option in bold, then why it lost. Git keeps the merged text, not the dropped reasoning, so this part is required. A road that bounds no live rule can go.

### One rule, stated once

A rule lives in one place: a record, or a reference page with test vectors that the record links. A page with vectors can carry the rule in detail (the format of a token, a signed document, an install file) while the record keeps the reasoning and links the page. Do not restate the rule in a second record; link its heading.

### Rewriting a record

Before the first v2 release the maintainer may have records rewritten, merged and renumbered in place; after it, a changed mind gets a new record. A rewritten record carries no history lines. When records are merged, split or renumbered, update `docs/decisions/renumbered.json` in the same pull request: the site turns each old address into a 301 to the record that took it over, and `just check-decisions` fails when an old slug is still a file or a new one is missing. The rules are in the "Design phase" section of `docs/decisions/README.md`; its last table maps old record numbers to their new records.

v1 records stay on `master`. Refer to one as "v1 ADR NNNN" with a link to `master`; never copy or renumber it.

### What CI checks

CI checks the file name, the required sections, the status value, the one-line roads, the proposal line and the index rows, and that every "ADR NNNN" and every link to a record across the docs and the site names a record and a heading that exist. Run `just check-decisions`, then `just check`, before you push. Passing is necessary, not sufficient: the maintainer reviews the reasoning.

## Requirements

The catalogue in `docs/requirements/*.yaml` is the source of truth for what sluis v2 must do, and the site's [requirements pages](/requirements/) are generated from it. Its fields, its vocabularies and the steps to add a record are in [docs/requirements/README.md](https://github.com/truvity/sluis/blob/main/docs/requirements/README.md); follow that file for every edit.

### When a requirement is needed

A decision that creates an obligation adds a requirement or cites an existing one, and the record names the ids.

### Ids

An id is `REQ-<AREA>-NNN`, for example `REQ-AUTHN-002`. It is never reused and never renumbered, not even for a withdrawn record, so a link or a test name keeps working. A record that no longer applies is withdrawn, not deleted.

### Fields

Every record carries the fields the README defines, among them `source` (where the requirement comes from), `level`, `status` and `runtimes`. Use only the values the README and `index.yaml` declare; a new value is declared there first.

### Linking the issues that deliver it

Add `issues:` with the numbers of the issues that deliver the requirement, for example `issues: [915]`; `features` takes only `parity` or `design`. A requirement may have no issue yet. The field is a link, not a milestone: the project status page groups requirements by the `Product milestone` of their issues ([ADR 0014](/decisions/0014-the-site-is-static-on-cloudflare-workers/)), so set the milestone on the issue. `just check-requirements` warns about every planned or partial requirement without `issues`.

### Marking a requirement done

`done` means the behaviour exists and its tests pass. Nobody sets it for a plan or an intention, and a new record is never `done`.

- **Who.** The author of the pull request that adds the passing test sets it, by hand, in that pull request. The reviewer confirms that the named test proves the clause. There is no automatic promotion.
- **How.** Change `status` to `done` and add `tests:` with the repository paths of the files that hold the passing tests, for example `tests: [core/authn/authorize_test.go]`. A test case names its id (`REQ-AUTHN-002/plain_method`, see the README), so the file carries the id of the record. Drop `features` and `decisions` that no longer apply; `issues` stays, because the status page places the record by the milestone of its issues.
- **What CI checks.** A `done` record has `tests`, every path names an existing file inside the repository, and the file contains the record's id; anything else fails. The check proves that the evidence is present; the reviewer judges whether it proves the clause, and the test's own CI run proves that it passes.
- **Undoing.** When the tests are removed or the behaviour is dropped, the pull request that does it moves the record back (`planned` or `partial`) or withdraws it. A `done` record whose test file is deleted fails the check.

The [status page](/status/) counts `done` records in its Done column, per milestone and per area.

### Checking the catalogue

`just check-requirements` checks the schema, one keyword per statement, unique ids, a verification for every MUST, the tests of every `done` record, known standards, and content that must not be public. `just site-lint` runs it too. Run it, then `just check`, before you push.

## Spikes and research

A spike answers one question by trying it; research answers one by reading and comparing. Both end in a result the maintainer can decide on, posted on the issue and followed by the records and pages it changes.

### Standards first

A spike that compares formats or protocols starts from the standards that exist, and pins their versions ([Standards first](/contributing/tools/#standards-first)).

### The shape of a result

Write the parts in this order:

1. **Question.** The one question the spike or research answers.
2. **When.** The date and time it was measured, in UTC.
3. **Verdict.** The answer, first, in one or two sentences.
4. **Method.** What was run or read, with the exact versions, so someone else can repeat it.
5. **What the setup over- and under-counts.** How the test setup differs from a real installation, and in which direction each difference moves the numbers.
6. **Numbers.** In tables, with units.
7. **Roads not taken.** The approaches you did not try or dropped, each with the reason.
8. **Open questions.** Each as options with pros and cons, and a recommendation.
9. **Changes made.** Every change to any machine, account or device, and whether it was undone.
10. **Raw logs.** Where the raw output is kept.

Label each claim READ, MEASURED or UNVERIFIED ([Measure and date](/contributing/design/#measure-and-date)). Measure before you conclude, and read what each tool printed, not only its exit code ([Tools, checks and verification](/contributing/tools/)).

### Keep it public

A result posted in the repository or on an issue follows [Public content and secrets](/contributing/public-content/): example names for hosts and accounts, no secrets, no device serials. A result that needs private names to make sense stays internal, and only a generic version is posted, as GOVERNANCE.md says in "From internal reasoning to a public ADR".
