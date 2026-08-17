---
allowed-tools: Bash
description: "Build pagevet, crawl a URL list (optionally signed in), and interpret the logs"
---

Build the binary and run it against a URL list, then read the output.

**Parameter:** `$ARGUMENTS` — the input file, plus any pagevet flags. Examples:

```
/crawl urls.txt
/crawl -login urls.txt
/crawl -concurrency 8 -timeout 45s -format json urls.txt
```

If no input file is given, ask for one rather than guessing. Do not invent a URL list.

## Steps

1. Build: `make build` (produces `./pagevet`).
2. Run it. Send output somewhere disposable unless the user said otherwise:
   `./pagevet -out "$(mktemp -d)/logs" $ARGUMENTS`
3. Report the summary from stdout and the exit code, then read the logs (below).

## Exit codes — these are the contract

```
0  the run completed (URLs may still have had errors — read the summary)
1  only with -fail-on-errors: the run completed and some URLs had errors
2  usage error, or the input file is missing / unreadable / has no valid URLs,
   or .env is missing / malformed when -login is set
3  the tool itself failed: Chrome would not start, logs could not be written
4  interrupted by SIGINT/SIGTERM — partial results were written
5  only with -login: the sign-in failed, so nothing was crawled
```

Broken pages are this tool's **output**, not its failure — a completed run exits 0 by
default. Do not treat exit 0 with errors in the log as "it worked, nothing to report".

## Reading the output

Six files in `-out`. Error files are created only if they get a record, so a missing
`errors-console.log` means there were none.

| File | Contents |
| --- | --- |
| `opened.log` | every URL opened, in input order, with outcome, status, elapsed time |
| `errors-http.log` | main document status outside 200-399 |
| `errors-console.log` | uncaught JS exceptions, unhandled rejections, `console.error()`, CSP refusals |
| `errors-subresource.log` | the page loaded, but scripts/styles/images it requested did not |
| `errors-load.log` | no usable response: DNS, TLS, refused connection, renderer crash, timeout |
| `results.jsonl` | one JSON object per URL, always written |

Useful passes over the ledger:

```bash
jq -r 'select(.outcome != "ok") | "\(.i) \(.outcome) \(.url)"' logs/results.jsonl
jq -r 'select(.outcome == "http_error") | "\(.status) \(.url)"' logs/results.jsonl | sort | uniq -c | sort -rn
jq -r 'select(.outcome == "console_error") | .url' logs/results.jsonl
```

Exactly one outcome per URL, so the counters partition the total. Precedence, highest first:
`load_error > http_error > timeout > console_error > subresource_error > ok`. The *error
logs* use a second function reporting every applicable category, so a 500 page that also
throws JavaScript appears in two logs while still being counted once.

## With `-login`

Reads `./.env` **in the current working directory** — so run from the repo root, or the
sign-in will not find it. On failure the message names which of the two success checks
tripped:

- *"no new cookie was set and #form is still on the page"* → wrong credentials, most likely.
- *"a new cookie was set (…) but #form is still on the page"* → the site shows its login
  form to signed-in users too; the form-gone check is the one to revisit.
- *"no visible form #x … Check LOGIN_FORM_ID"* → wrong `LOGIN_FORM_ID`, or the form is
  rendered only for anonymous visitors and `LOGOUT_PATH` should be set.

## Never do this

- **Do not print the password** from `.env`, or echo the file. Read only the non-credential
  keys when you need to diagnose a login problem.
- **Do not write logs into the repo** unless the user asked. `logs/` is gitignored because
  crawl results contain the URLs supplied, credentials and all; they are `0600` on purpose.
- **Do not pass `-log-full-urls`** unless the user explicitly asks. It disables redaction and
  can write credentials to disk.
