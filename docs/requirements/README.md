# sluis requirements

This directory is the source of truth for what sluis v2 must do. Each requirement is one clause with one
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keyword and one testable behaviour. The files are YAML; the website
generates its pages from them and test tools read the same data.

| File | Content |
|---|---|
| `index.yaml` | The vocabularies, the areas and the gap keys. The only place that declares them. |
| `<area>.yaml` | The requirements of one area, named by the lower-case area code (`authn.yaml`). |
| `standards.yaml` | The standards register as data: the ids (`ST-nn`, `NC-nn`) that records cite. |
| `attestations.yaml` | The records of manual checks: who checked a requirement, when, and what (see "Attestations"). |
| `requirements.schema.json` | JSON Schema 2020-12 for `index.yaml`, every area file and `attestations.yaml`. Objects are closed. |

## What the build makes from it

- [sluis.id/requirements/](https://sluis.id/requirements/): counts, the areas, and one table of all records with a filter by area,
  level, status, source and runtime.
- `/requirements/<area>/`: one page per area, with standards, features, decisions and verification for each record.
- `/requirements/matrix/`: requirement to standard, issue or feature, and verification, and back.
- `/requirements/coverage/`: statistics, MUST records without a conformance suite or test vectors, open records by decision,
  and register rows that no requirement cites.
- `/requirements.json`: every record flattened, with the `evidence` the build found for it (the tagged tests and the attestations). Test tools in any language read this file and nothing else.
- [sluis.id/status/](https://sluis.id/status/): the records per milestone, with the evidence-backed count beside done and partial.

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
- An area whose records are all withdrawn is marked `retired: true` in `index.yaml`. It keeps its file and its ids, and the site leaves it out of the area lists. `SECRETS` and `VAULT` are retired. `just site-lint` refuses `retired: true` on an area that still has a record that is not withdrawn.
- Records are not merged. A record that no longer applies gets `status: withdrawn` and `superseded_by: [ids]`. A record about a subject that moved to another product (root custody moved to ritueel on 2026-11-01) gets `status: withdrawn` and `moved_to` instead.

## Record fields

| Field | Rule |
|---|---|
| `statement` | One sentence ending in a period with exactly one of MUST, MUST NOT, SHOULD, SHOULD NOT, MAY. Names a role (sluis, an operator, a relying party), never a person or a company. |
| `rationale` | One sentence ending in a period. |
| `level` | MUST, SHOULD or MAY; equals the class of the keyword (MUST NOT counts as MUST). |
| `source` | Where the requirement comes from (not the storage class of ADR 0004), a category: `v1-parity`, `stakeholder-ciam`, `stakeholder-integrator`, `security-review`, `design-decision`, `standard`. |
| `status` | `done` (implemented, and a test that carries the record's id proves it: see "How a test names a requirement"), `planned` (an agreed feature or design covers it), `partial` (the plan is weaker), `open` (needs a decision or has no plan), `out-of-scope` (a boundary kept as a refusal), `withdrawn`. |
| `runtimes` | `all`, or a list of `bare-metal`, `serverless`, `kubernetes`. |
| `standards` | `{id, section, depth}`: an id from `standards.yaml`, the section, and `Full` or `Partial`. |
| `features` | Optional: `parity` (part of v1 parity, no single issue) or `design` (specified, no issue yet). Issue numbers go in `issues`, never here. |
| `milestone` | The Product milestone of the record: a key of `milestones` in `index.yaml` (`first-version`, `v1-parity`, `ciam-upstream`, `quota`, `backlog`), which maps it to the name of an option of the board's `Product milestone` field. Required for a live record once the switch below is on; until then a record without it is placed by its issues and the status page says so. |
| `issues` | Optional: the numbers of the truvity/sluis issues that deliver the record, for example `[915]`. Unique positive integers, at least one when present. They are the work; the `milestone` is where the record belongs. `just check-requirements` warns when a board is at hand and none of the issues is in the record's milestone. |
| `tests` | Optional: the repository paths of the files that hold the tests, for example `[core/authn/authorize_test.go]`, as an index for the reader. Each path is relative to the repository root, names an existing file, and the file names the record's id. What counts as evidence is the tag, not this list. |
| `actors` | Optional: the actors that implement the record, by their names in the [actor registry](../architecture/actors.yaml), for example `[policy]`. Each must be an actor whose requirement areas include the record's area; `just check-actors` checks it. A withdrawn record keeps no `actors`. |
| `verification` | `{kind, ref}`; `kind` is `conformance-suite`, `test-vectors`, `integration-test` or `manual`. Every MUST needs at least one. |
| `gap` | Required for an `open` or `partial` record: a key of `gaps` in `index.yaml` that says what is missing. |
| `manual_reason` | Required for a MUST verified by manual review only; forbidden otherwise. |
| `superseded_by` | A `withdrawn` record needs this or `moved_to`: the ids of the records that replace it. |
| `moved_to` | A `withdrawn` record that moved to another product: the URL of the truvity/ritueel issue that carries it. |

## How a test names a requirement

A test that proves a requirement carries its id in a **tag**, one rule for Go and for Rust: the id follows `verifies:` in the comment block directly above the test function (no blank line between them).

```go
// verifies: REQ-AUTHN-002
func TestAuthorizeRefusesPlainChallenges(t *testing.T) { /* send code_challenge_method=plain, expect invalid_request */ }
```

```rust
/// verifies: REQ-AUTHN-002, REQ-AUTHN-003
#[tokio::test]
async fn authorize_refuses_plain_challenges() { /* ... */ }
```

- Several ids go in one tag, separated by commas. The tag is for the test that fails when the behaviour breaks; a test that only touches the behaviour does not carry it.
- A table-driven Go test whose cases prove different records names the id at the start of the case, in a string literal that begins `REQ-...-nnn/`. That is the same tag, on that line, in exactly three places inside the test function: the first argument of `t.Run` (`t.Run("REQ-AUTHN-002/plain_method", ...)`), the key of a map of cases, or the `name:` field of a struct of cases. The same string in a `t.Fatalf`, `t.Log` or any other string, or outside the test function, is not a tag.
- A Go test function named `TestREQ_AUTHN_002_...` is read as a tag too. This and the case name are the spellings that tests used before the comment tag; write new tests with the comment.
- Rust: `#[test]`, `#[tokio::test]`, `#[rstest]` and `#[test_case]` count. The doc comment (`///`) goes above or between the attributes.
- The comment line must start with `verifies:` (after `//` or `///`); "no longer verifies:" in a sentence is not a tag. A Go test is `func TestXxx(t *testing.T)`.
- An id that is only mentioned (in a comment inside a body, in an assertion message, in the doc of a function that is not a test) is not a tag, and a test with no tag is ignored.
- **A test that CI does not run is no evidence.** The collector leaves out Rust tests with `#[ignore]` (on either side of `#[test]`) and Rust tests behind a `#[cfg(...)]` other than `cfg(test)`, on the test or on its module (or `#![cfg(...)]` on the file); Go files whose `//go:build` line is not satisfied by the tags CI runs with (`sluis_test`, on Linux; `sluis_card` is not one of them); and Go tests whose first statement is an unconditional `t.Skip`.
- **Smoke programs have no tag form.** A program under `tests/e2e/` or a `main` with `harness = false` is not a `#[test]` or a `func TestXxx(t *testing.T)`, and it does not run in CI. A requirement that only such a smoke proves stays `partial` with `gap: smoke-not-in-ci` ("covered only by a smoke that does not run in CI", declared in `index.yaml`), and becomes `done` in the pull request that adds a test CI runs.

`site/scripts/collect-evidence.mjs` scans `actors/`, `cli/`, `drivers/`, `kits/`, `tests/` and `tools/` (Go `*_test.go` files and Rust files; `testdata/`, `target/` and `node_modules/` are skipped) and writes the evidence map `REQ id -> [file:line test]`. `site/scripts/collect-evidence.mjs --out evidence.json` prints it. The status page and `/requirements.json` use the same map.

## Evidence and status

`just check-requirements` judges the status against the evidence (the tagged tests, and the attestations below):

| Rule | Result |
|---|---|
| A `done` record lacks evidence for any one of its verification kinds | error (L21). A test kind (`conformance-suite`, `test-vectors`, `integration-test`) needs a tagged test; `manual` needs an attestation. A record verified by `[integration-test, manual]` needs both. |
| A planned, open or withdrawn record has evidence | warning that names it: the status is behind the tests (L21). A `partial` record, and an `out-of-scope` one whose refusal is tested, may have evidence. |
| A tag names an id the catalogue lacks | error (L21) |
| A `partial` or `open` record has no `gap:` | error, as before (L15) |
| `milestone:` names a key `index.yaml` does not declare | error (L20) |
| A live record has no `milestone:` | warning while the switch is off, error once it is on (L20) |
| A record names a milestone and none of its issues is in it on the board | warning (L20); needs the board: `--board <file>` (JSON of `{options, issues: [{number, milestone}]}`), or `GH_TOKEN`/`GITHUB_TOKEN` to read the project as the status page does. Without either the check says so and skips this comparison. |

**The switch.** `MILESTONE_REQUIRED` at the top of `site/scripts/check-requirements.mjs` is `false`. The pull request that sets `milestone:` on every live record changes it to `true`, so that a missing milestone is an error from then on. `--require-milestone` turns it on for one run, to see what is left.

## Attestations

A requirement verified by manual review has no test to tag. It counts as evidenced when `attestations.yaml` holds an entry for it:

```yaml
schema: 1
attestations:
  - req: REQ-EXAMPLE-001
    by: <github login of the person who checked>
    on: "2026-11-04"
    checked: "The sign-in page was read against the record in the browser and in the text-only view."
```

`req` is a live record that has a `manual` verification; `by` is a GitHub login (in this public repository, the maintainer's or a reviewer's own); `on` is the UTC date; `checked` is one sentence on what was checked. An entry for a record without a manual verification, for an unknown record, or dated in the future is an error. An attestation is not renewed by itself: when the behaviour changes, the pull request that changes it adds a new entry or moves the record back.

## Adding a requirement

1. Pick the area and the next free number in it. Never reuse an id, not even of a withdrawn record.
2. Write one clause: one keyword, one behaviour, one sentence. If you want to write "and" between two behaviours, write two records.
3. Fill the traceability: the standards it implements (`section` when `depth` is `Full`), the issues that deliver it (`issues`; `features: [design]`
   when there is none yet), and how it is verified. A MUST needs a verification.
4. Set the `milestone`. Set the status honestly. A new record is never `done`: that status is set later, by the pull request that adds the passing test (see "Marking a requirement done" in the [contributing page](../contributing/decisions.md#marking-a-requirement-done)). An `open` or `partial` record names a `gap` key; an undecided point it waits for is an issue in `issues`.
5. Keep it public. No names of people or companies, no tickets, no addresses, no mention of any private infrastructure; the lint scans for them.
6. Run `devbox run -- just check`. The pages and `requirements.json` are generated, never committed.

To add an area, declare it in `index.yaml` (`areas`), create `<area>.yaml` with `schema: 1`, `area` and `requirements`, and keep the file name equal to the lower-case code.
