# sluis requirements

This directory is the source of truth for what sluis v2 must do. Each requirement is one clause with one
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keyword and one testable behaviour. The files are YAML; the website
generates its pages from them and test tools read the same data.

| File | Content |
|---|---|
| `index.yaml` | The vocabularies, the areas and the gap keys. The only place that declares them. |
| `<area>.yaml` | The requirements of one area, named by the lower-case area code (`authn.yaml`). |
| `standards.yaml` | The standards register as data: the ids (`ST-nn`, `NC-nn`) that records cite. |
| `requirements.schema.json` | JSON Schema 2020-12 for `index.yaml` and every area file. Objects are closed. |

## What the build makes from it

- [sluis.id/requirements/](https://sluis.id/requirements/): counts, the areas, and one table of all records with a filter by area,
  level, status, source and runtime.
- `/requirements/<area>/`: one page per area, with standards, features, decisions and verification for each record.
- `/requirements/matrix/`: requirement to standard, issue or feature, and verification, and back.
- `/requirements/coverage/`: statistics, MUST records without a conformance suite or test vectors, open records by decision,
  and register rows that no requirement cites.
- `/requirements.json`: every record flattened. Test tools in any language read this file and nothing else.

`just site-lint` checks the files (`site/scripts/check-requirements.mjs`): the schema, one keyword per statement and a level that matches
it, unique ids, a verification for every MUST, known standards and open decisions, and a scan for ticket keys and private names.
It also computes the coverage figure that the [conformance page](../standards/conformance.md) shows: the requirements, and the MUSTs,
whose verification includes a conformance suite or test vectors. The figure is a generated block on that page; the lint fails when it is
stale, and `just site-coverage` rewrites it.

## Ids

An id is `REQ-<AREA>-<nnn>`, for example `REQ-AUTHN-002`.

- It is stable and never reused. Ids are not renumbered when records are added, split or withdrawn, so a link or a test name keeps working.
- The area prefix equals the `area` field and the file it sits in.
- A longer record that is cut into clauses keeps its id for the first clause. Each further clause gets the next free id in the same area
  and `split_from: <original id>`. Clauses sit next to their parent in the file, so ids are not always in order.
- A rule that moves to another area is withdrawn in its old area and written as a new record in its new area, because the area prefix equals the file. The old record's `superseded_by` names the new one. The data model and the store moved to `DATA` this way (decisions 0004 and 0005).
- An area whose records are all withdrawn is marked `retired: true` in `index.yaml`. It keeps its file and its ids, and the site leaves it out of the area lists. `SECRETS` is retired. `just site-lint` refuses `retired: true` on an area that still has a record that is not withdrawn.
- Records are not merged. A record that no longer applies gets `status: withdrawn` and `superseded_by: [ids]`. A record about a subject that moved to another product (root custody moved to ritueel on 2026-11-01) gets `status: withdrawn` and `moved_to` instead.

## Record fields

| Field | Rule |
|---|---|
| `statement` | One sentence ending in a period with exactly one of MUST, MUST NOT, SHOULD, SHOULD NOT, MAY. Names a role (sluis, an operator, a relying party), never a person or a company. |
| `rationale` | One sentence ending in a period. |
| `level` | MUST, SHOULD or MAY; equals the class of the keyword (MUST NOT counts as MUST). |
| `source` | Where the requirement comes from (not the storage class of ADR 0004), a category: `v1-parity`, `stakeholder-ciam`, `stakeholder-integrator`, `security-review`, `design-decision`, `standard`. |
| `status` | `done` (implemented, and `tests` names the passing tests), `planned` (an agreed feature or design covers it), `partial` (the plan is weaker), `open` (needs a decision or has no plan), `out-of-scope` (a boundary kept as a refusal), `withdrawn`. |
| `runtimes` | `all`, or a list of `bare-metal`, `serverless`, `kubernetes`. |
| `standards` | `{id, section, depth}`: an id from `standards.yaml`, the section, and `Full` or `Partial`. |
| `features` | Optional: `parity` (part of v1 parity, no single issue) or `design` (specified, no issue yet). Issue numbers go in `issues`, never here. |
| `issues` | Optional: the numbers of the truvity/sluis issues that deliver the record, for example `[915]`. Unique positive integers, at least one when present. The issues' Product milestone places the record on the status page. |
| `tests` | The repository paths of the files that hold the passing tests, for example `[core/authn/authorize_test.go]`. Required when `status` is `done`, optional otherwise. Each path is relative to the repository root, names an existing file, and the file names the record's id. |
| `actors` | Optional: the actors that implement the record, by their names in the [actor registry](../architecture/actors.yaml), for example `[policy]`. Each must be an actor whose requirement areas include the record's area; `just check-actors` checks it. A withdrawn record keeps no `actors`. |
| `verification` | `{kind, ref}`; `kind` is `conformance-suite`, `test-vectors`, `integration-test` or `manual`. Every MUST needs at least one. |
| `gap` | Required for an `open` or `partial` record: a key of `gaps` in `index.yaml` that says what is missing. |
| `manual_reason` | Required for a MUST verified by manual review only; forbidden otherwise. |
| `superseded_by` | A `withdrawn` record needs this or `moved_to`: the ids of the records that replace it. |
| `moved_to` | A `withdrawn` record that moved to another product: the URL of the truvity/ritueel issue that carries it. |

## How a test names a requirement

A test case that proves a requirement carries its id in its name, and a table-driven test adds the case after a slash:

```go
t.Run("REQ-AUTHN-002/plain_method", func(t *testing.T) { /* send code_challenge_method=plain, expect invalid_request */ })
```

Because a record is one clause, one record is one test or one small table of cases. A tool that joins tests to requirements reads
`/requirements.json`, selects records by `verification[].kind`, and reports the ids that a test names and the catalogue lacks (an error)
and the `planned` MUST records that no test names (a gap).

## Adding a requirement

1. Pick the area and the next free number in it. Never reuse an id, not even of a withdrawn record.
2. Write one clause: one keyword, one behaviour, one sentence. If you want to write "and" between two behaviours, write two records.
3. Fill the traceability: the standards it implements (`section` when `depth` is `Full`), the issues that deliver it (`issues`; `features: [design]`
   when there is none yet), and how it is verified. A MUST needs a verification.
4. Set the status honestly. A new record is never `done`: that status is set later, by the pull request that adds the passing test (see "Marking a requirement done" in the [contributing page](../contributing/decisions.md#marking-a-requirement-done)). An `open` or `partial` record names a `gap` key; an undecided point it waits for is an issue in `issues`.
5. Keep it public. No names of people or companies, no tickets, no addresses, no mention of any private infrastructure; the lint scans for them.
6. Run `devbox run -- just check`. The pages and `requirements.json` are generated, never committed.

To add an area, declare it in `index.yaml` (`areas`), create `<area>.yaml` with `schema: 1`, `area` and `requirements`, and keep the file name equal to the lower-case code.
