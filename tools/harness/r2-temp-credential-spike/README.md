# Spike: does a new R2 temporary credential show the propagation delay?

This is the spike page in the shape of "The shape of a result" in `docs/contributing/decisions.md`. Post it as the body of the tracking issue and fill in the empty parts when the spike has run. The harness is `main.go` in this directory.

## Question

Cloudflare R2 refused the credential of a new API token in v1, with 401, for up to about 34 s. It sometimes did so after it had accepted the credential once. Do the R2 temporary credentials that the `cloud-cloudflare` driver of v2 mints ([ADR 0013](../../../docs/decisions/0013-release-train-packaging-and-distribution.md), [ADR 0009](../../../docs/decisions/0009-export.md)) show the same delay and the same later refusal?

Why it matters: it decides what the requirement rows for the driver, the exporter's destination credential and the operator's rotation of the parent token must say (REQ-AUDIT, REQ-EXPORT-028 with its 60 s revocation target, REQ-OPS).

## When

Not measured yet. Prepared 2026-11-06 (UTC). The measurement date and time go here, in UTC, with the dates of every further run.

## Verdict

Pending. Fill in after the run, in one or two sentences, and name the arm and the number of credentials.

## Decision rule

Fixed before the run, so the numbers cannot choose it. The maintainer decides; the summary of the harness prints the rule's outcome for each arm as advice.

- **No delay and no later refusal.** Over N of at least 30 credentials, every credential was accepted by its second attempt (at most one retry, 500 ms later), and no credential was refused after it had been accepted. Then the rows only need "retry once on 401", and the driver needs no hold-back.
- **Anything else.** One credential accepted on its third attempt or later, one never accepted within 120 s, or one refused after an accept. Then v2 needs the v1 shape ([a996be339](https://github.com/truvity/sluis/commit/a996be339), [4fa125fd9](https://github.com/truvity/sluis/commit/4fa125fd9), [386b3d535](https://github.com/truvity/sluis/commit/386b3d535) on `master`): keep the old credential valid, hold the new one back until the store has accepted it for a settle time, and bound the attempts.
- **Fewer than 30 credentials** give no verdict.

The harness reads "no delay" as "accepted by the second attempt", because that is what "retry once on 401" tolerates. It also reports how many credentials were refused on the very first attempt, so a reader who wants the strict reading has the number.

## Method

READ in v1 (the commits above; no harness of the v1 measurement is in the repository): R2 refused a token that Cloudflare had just created, with 401, for a few seconds and at times intermittently for up to about 34 s, measured over 59 rotations on 2026-11-04. The credential was the token's id and the SHA-256 of its value. A wait of 5 s failed in 4 of 29 rotations. Measured on 2026-10-08, such a credential worked about 5 s after the mint.

The harness (Go, standard library only; the S3 requests are signed by the harness itself with Signature Version 4, so that no SDK retry hides a first refusal; its signer is tested against the example in the AWS documentation):

1. Reads the account id, the parent token and the bucket from the environment. It never prints or writes them, nor any credential; its error texts are cleaned of them.
2. Mints N temporary credentials (default 30), one every `-spacing` (default 10 s), with `POST /accounts/{id}/r2/temp-access-credentials`: `object-read-write`, one bucket, one prefix, a time to live of `-ttl` (default 15 min).
3. Probes each credential in its own goroutine from the moment the mint answers: PutObject, GetObject and HeadObject of its own key under the prefix, each retried every 500 ms until it is accepted (2xx) or 120 s pass. Then it sends HeadObject every 500 ms until 40 s after the first accept (`-soak`; v1 saw refusals up to about 34 s), so that an "accept, then refuse" has a chance to show. Then DeleteObject, retried the same way.
4. Records for every request its offset from the mint, status, duration and S3 error code; and for every credential the time to the first accept, the refusals before it and after it (401 or 403), and the time to the first accept of each operation.
5. Writes `credentials.csv` (one row for each credential), `attempts.csv` (one row for each request) and `summary.txt` (p50, p95 and max of the time to the first accept, the credentials with a later refusal and the count of later refusals, the status and error-code counts, and the rule's outcome) to `.cache/r2-spike/<UTC time>/`. It prints the summary too.
6. Cleans up. A credential deletes its own object. For an object that is still there (a run stopped with Ctrl-C, a refused delete), the harness mints one more credential at the end and deletes it with that.

With `-arm token` or `-arm both` it also creates an API token for each credential that can read and write the objects of the bucket, derives the credential as R2 documents it (access key id = token id, secret = SHA-256 of the token value, no session token), probes it the same way, and deletes the token. `-arm both` alternates the two arms, one of each every spacing, so the time of day does not favour one. This is the v1 mechanism, run beside the new one as a control: if the token arm shows no delay today, the run cannot say anything about the temporary credentials.

Versions: the summary names the Go version and platform. The Cloudflare API has no version to pin; the date of the run stands for it.

### The command for the owner

The test bucket is dedicated, empty and holds nothing else; delete it and the parent token afterwards. Nothing real is typed on the command line, so the shell history holds no secret:

```sh
# 1. The inputs. Read the token without echo; put real values only in your terminal.
export SLUIS_SPIKE_R2_ACCOUNT_ID='<account-id>'
export SLUIS_SPIKE_R2_BUCKET='<test-bucket>'
read -rs SLUIS_SPIKE_R2_PARENT_TOKEN && export SLUIS_SPIKE_R2_PARENT_TOKEN
# optional: the parent token's id, when the tool cannot verify it by itself
# export SLUIS_SPIKE_R2_PARENT_KEY_ID='<parent-token-id>'

# 2. The plan, with no request sent.
devbox run -- go run ./tools/harness/r2-temp-credential-spike -dry-run

# 3. A smoke run: two credentials and a short soak. It answers the UNVERIFIED parts below in about a minute.
devbox run -- go run ./tools/harness/r2-temp-credential-spike -n 2 -spacing 5s -soak 5s

# 4. The spike: 30 temporary credentials, one every 10 s (about 7 minutes).
devbox run -- go run ./tools/harness/r2-temp-credential-spike -n 30 -spacing 10s

# 5. With the control (the v1 mechanism); needs one more token, see the permissions.
read -rs SLUIS_SPIKE_R2_TOKEN_CREATOR && export SLUIS_SPIKE_R2_TOKEN_CREATOR
devbox run -- go run ./tools/harness/r2-temp-credential-spike -arm both -n 30 -spacing 10s
```

`SLUIS_SPIKE_R2_PREFIX` (default `sluis-spike/`) changes the prefix the credentials are scoped to. `-help` lists the other flags (`-interval`, `-deadline`, `-soak`, `-ttl`, `-out`). The harness refuses a `-ttl` that is shorter than one credential's longest probe, because a credential that expires in the middle would look like a refusal.

### Permissions

READ from Cloudflare's published API reference (2026-09-26); UNVERIFIED until the smoke run, and the names must be taken from the account's own list. A refusal at the first mint names the missing one.

| Token | Permission | Why |
|---|---|---|
| Parent token (`SLUIS_SPIKE_R2_PARENT_TOKEN`) | Account, **Workers R2 Storage: Edit** (Write) | The bearer of `POST /accounts/{id}/r2/temp-access-credentials`. This permission is account-wide and cannot be narrowed to one bucket, so use a token made only for the spike and delete it afterwards. |
| The same token | **Workers R2 Storage Bucket Item Write** on the test bucket only | The temporary credential never exceeds its parent's permissions, so the parent has to be able to read, write and delete objects in the test bucket. The id of this token is the `parentAccessKeyId`; the harness finds it with the token verify call, or take `SLUIS_SPIKE_R2_PARENT_KEY_ID`. |
| Token creator (`SLUIS_SPIKE_R2_TOKEN_CREATOR`, only for `-arm token` or `both`) | Account, **Account API Tokens: Edit** (Write) | Creates and deletes the control arm's tokens. A token with this right can mint children with any right its creating user holds (MEASURED 2026-10-08, in the v1 work), so make it for the run and delete it afterwards. The permission group of the control tokens is found by the name `-token-permission-group` (default `Workers R2 Storage Bucket Item Write`); take the exact spelling from the account's own list. |

The run sends about 90 requests to R2 for each credential (most of them the soak) and one call to the Cloudflare API. That is far below R2's free tier and below the API limit of 1,200 requests in 5 minutes.

## What the setup over- and under-counts

- **Where it runs.** The probes run from the owner's workstation, and v1 measured from AWS. R2's acceptance may depend on the data centre that serves the request. A different place can move the numbers either way. UNVERIFIED.
- **Local signing is not measured.** [ADR 0013](../../../docs/decisions/0013-release-train-packaging-and-distribution.md) says the credentials are "signed locally" with the parent token. Cloudflare's reference describes two ways to make a temporary credential: the API call and a token signed with the parent's secret, with no call (READ 2026-09-26; read it again before the `local` arm is written). The harness measures the call. If the local form is what v2 uses, the result is about its neighbour. See the open questions.
- **Probe rate.** About two requests a second for each credential, with about a dozen credentials in flight at the default spacing. A real driver sends one request after it mints. A burst of requests might keep a refusal alive that a single one would not, or the reverse. UNVERIFIED.
- **N of 30 is a small sample.** If the true rate of a delay is 10 %, 30 credentials miss it 4 times in 100; if it is 5 %, 21 times in 100. v1 saw 4 refusals in 29 rotations (about 14 %), which 30 credentials would catch about 99 times in 100. A clean run therefore excludes a v1-sized effect, not a rarer one.
- **Time of day.** v1 measured over a day. One run of 7 minutes sees one moment. See the open questions.
- **Time to live.** A short-lived credential could be handled differently from a long one. The harness uses 15 minutes; the production value is not chosen yet.
- **One bucket, default jurisdiction, no Object Lock.** The spike bucket is a plain one. The audit bucket of a real installation has other settings.
- **The clock.** Times are measured on the workstation from the moment the mint call returns. They include the round trips, about 100 to 300 ms each. The offset of a request is its start.

## Numbers

Empty until the run. Tables, with units, for each arm:

| Figure | temp | token (control) |
|---|---|---|
| Credentials (N) | | |
| Never accepted within 120 s | | |
| First attempt refused | | |
| Most attempts to the first accept | | |
| Time to first accept, p50 (s) | | |
| Time to first accept, p95 (s) | | |
| Time to first accept, max (s) | | |
| Credentials refused after an accept | | |
| Refusals after an accept, total | | |
| Refusals by status: 401 / 403 | | |
| S3 error codes seen | | |
| Objects left behind after cleanup | | |
| Outcome of the decision rule | | |

Also fill in the time to the first accept of each operation (put, get, head, delete), and the mint time of each arm.

## Roads not taken

- **The AWS SDK for Go.** It retries a 401 or 403 itself and would hide the first refusals, which are what is measured. It also adds a large dependency to a module that has none of it, and R2 refuses its default checksum on some objects ([the v1 note](https://github.com/truvity/sluis/blob/master/docs/guides/audit/operate/archive-on-r2.md)). Signing by hand costs about 80 lines and a test against the AWS example.
- **Probing from a Lambda function in an AWS region, like v1.** It is closer to v1 but needs an account, a role and a deployment. The first run from the workstation is cheaper; a second, from the place where the boards will run, is an open question.
- **Wrangler or an R2 binding.** Neither makes or uses a temporary credential.
- **Reading the object back from the public bucket address.** It would not use the credential.
- **A statistical test.** With N = 30 and a rare event, the rule on p100 is easier to read than a confidence interval. The sample-size note above says what it can exclude.

## Open questions

1. **Which mint is the production one: the call, or local signing?** [ADR 0013](../../../docs/decisions/0013-release-train-packaging-and-distribution.md) says "signed locally"; the owner's brief names the call.
   - *Measure the call only.* Pro: nothing more to build; it is what the harness does. Con: it may not be what v2 runs.
   - *Add a `local` arm* once the signing format is read from Cloudflare's reference and pinned. Pro: measures what the ADR says; also tells whether a credential the edge never saw minted is accepted at once. Con: more code, and a second UNVERIFIED format.
   - Recommendation: run the call now; add the `local` arm in the same pull request that fixes the ADR's wording, before the rows are written.
2. **How many runs?**
   - *One run of 30.* Pro: matches the rule. Con: one moment, see above.
   - *Three runs of 30 at different hours.* Pro: v1's delay came out over a day; three runs cover that. Con: a few more minutes of the owner's time.
   - Recommendation: three runs, with `-arm both` at least once, because a control that shows a delay proves the setup can see one.
3. **Where to run from.** *Workstation* (cheap, differs from v1) or *a board or a function in the target region* (closer to production, needs setup). Recommendation: the workstation first; repeat from a board when the first exporter exists.
4. **The permission of the parent token in production.** The brief asks for the least permission. If the mint needs the account-wide R2 right, the rotation runbook has to say so. Recommendation: let the smoke run settle it, and state the permission on the page that owns the driver.

## Changes made

By the pull request that prepares the spike: none to any machine, account or device. The harness was built, linted and tested against local fakes only; it was not run, and nothing called Cloudflare.

By the run, to fill in: the temporary credentials (they expire by themselves), the objects under the prefix (deleted by the harness, the count of leftovers is in the summary), and for `-arm token` the API tokens (deleted by the harness; a failure names `sluis-spike-<run id>-*` for deletion by hand). Undone at the end: the test bucket, the parent token and the creator token, by the owner.

## Raw logs

`credentials.csv`, `attempts.csv` and `summary.txt` of every run, from `.cache/r2-spike/<UTC time>/`. They hold the arm, the credential's number, times, statuses and S3 error codes, and no account, bucket, key, token or credential. Attach them to the issue.
