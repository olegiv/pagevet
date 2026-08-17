# pagevet

Open a list of URLs in headless Chrome and report what broke.

`pagevet` reads a plain-text file of URLs, loads each one in a **real Chrome that executes JavaScript**,
and separates the failures into four logs: HTTP status errors, browser console errors, subresource
failures, and load failures.

## Why a browser and not `curl`

An HTTP fetch tells you the status code and nothing else. It cannot see:

- a JavaScript exception that leaves the page blank while still returning `200 OK`
- a `console.error()` from an API call that failed after the page loaded
- a `<script>` tag whose bundle 404s

Those are the failures this tool exists to catch, so the page is actually rendered and its scripts actually
run. The tradeoff is speed: a real render costs about a second per URL, against milliseconds for a HEAD
request. If all you need is "is the link dead", use a link checker.

## Install

Requires **Go 1.26.6 or newer** and **Google Chrome or Chromium**.

```sh
go build -o pagevet ./cmd/pagevet
```

The `go 1.26.6` directive is deliberate and load-bearing: Go 1.26.5 ships two vulnerabilities that are
*reachable* through the TLS path this program uses to talk to Chrome (`GO-2026-6090` in `crypto/tls`,
`GO-2026-5972` in `encoding/asn1`). Both are fixed in 1.26.6, and `govulncheck` is clean there. There is
no `toolchain` directive, so a `GOTOOLCHAIN=local` user on 1.26.5 gets a loud build failure instead of a
silently vulnerable binary.

## Use

```sh
pagevet urls.txt
```

`urls.txt` is one full `http://` or `https://` URL per line. Blank lines and `#` comments are ignored,
duplicates are skipped, and any other scheme is rejected with its line number.

```
# staging smoke list
https://example.com/
https://example.com/checkout
https://example.com/account
```

Common variations:

```sh
pagevet -concurrency 8 -timeout 45s urls.txt   # faster, heavier
pagevet -headed urls.txt                       # watch it happen, for debugging
pagevet -out reports/2026-08-14 urls.txt       # somewhere other than ./logs
pagevet -fail-on-errors urls.txt || alert      # non-zero exit for CI
pagevet -format json urls.txt                  # JSON Lines logs instead of text
```

## What it produces

Six files in `-out` (default `logs/`), plus a summary on stdout. Error files are created only if they get
a record, so an empty `errors-console.log` never appears.

| File | Contents |
| --- | --- |
| `opened.log` | every URL opened, in input order, with outcome, status and elapsed time |
| `errors-http.log` | the main document's final status was outside 200-399 |
| `errors-console.log` | uncaught JS exceptions, unhandled promise rejections, `console.error()`, CSP refusals |
| `errors-subresource.log` | the page loaded, but scripts, stylesheets or images it requested did not |
| `errors-load.log` | no usable response at all: DNS, TLS, refused connection, renderer crash, timeout |
| `results.jsonl` | one JSON object per URL, always written |

A URL that fails two ways appears in both logs, cross-referenced. The summary on stdout counts each URL
exactly once:

```
pagevet summary
──────────────────────────────────────────────────────────
input                  urls.txt
lines read                  5
  blank / comment / dup     1
attempted                   4

ok                          1
errored                     3
  http errors               2
  load errors               1

1 + 2 + 0 + 0 + 1 + 0 = 4   ✓ every URL counted exactly once
```

`results.jsonl` is written one unbuffered line at a time, so `kill -9` mid-run still leaves a complete,
`jq`-able ledger and `tail -f` works live:

```sh
tail -f logs/results.jsonl | jq -r 'select(.outcome != "ok") | "\(.i) \(.outcome) \(.url)"'
jq -r 'select(.outcome == "http_error") | "\(.status) \(.url)"' logs/results.jsonl | sort | uniq -c
```

## How a URL is classified

Exactly one outcome per URL, so the counters always partition the total. Precedence, highest first:

```
load_error > http_error > timeout > console_error > subresource_error > ok
```

Two of those orderings are deliberate and worth knowing:

- **`http_error` beats `timeout`.** A page that answers 500 and then hangs is reported as a 500. The status
  is definite and actionable; the hang is still recorded in `timed_out` and `settled_by`.
- **`console_error` beats `subresource_error`.** A page whose own JavaScript threw is more broken than one
  that merely failed to fetch an asset.

The error *logs* use a second function that reports **every** applicable category, so a 500 page that also
throws JavaScript shows up in both `errors-http.log` and `errors-console.log` while still being counted
once.

### What counts as a console error

| Source | Counted |
| --- | --- |
| Uncaught exceptions, unhandled promise rejections | yes |
| `console.error()`, `console.assert()` | yes |
| CSP refusals, parse-time `SyntaxError` | yes |
| `console.warn()` | only with `-console-warnings` |
| `console.log/info/debug` | never |
| A failed subresource | never — it is its own category |

That last row is the rule that makes the numbers trustworthy. Chrome reports a failed asset on the console
as `Failed to load resource: the server responded with a status of 404`. Routing that to the console bucket
would make every site with one dead tracking pixel a "console error" and collapse two of the three
categories into one.

Favicon failures, sourcemap requests and `chrome-extension:` URLs are ignored throughout.

## Flags

Run `pagevet -help` for the full list. The ones that change results:

| Flag | Default | Effect |
| --- | --- | --- |
| `-concurrency N` | 4 | URLs loaded in parallel on one shared Chrome (1–16) |
| `-timeout D` | 30s | hard per-URL deadline |
| `-settle D` | 1.5s | quiet window held open after load, to catch late JS errors |
| `-ok-status MIN-MAX` | 200-399 | statuses treated as OK |
| `-fail-on-console` | true | count console errors as failures |
| `-fail-on-resource` | true | count failed subresources as failures |
| `-console-warnings` | false | also count `console.warn` |
| `-headed` | false | visible window, for debugging |
| `-log-full-urls` | false | disable URL redaction (**unsafe**, see below) |
| `-fail-on-errors` | false | exit 1 when any URL had an error |

`-settle` is the flag most worth tuning. Modern SPAs throw during hydration, well after `load` fires; at
`0` you will only catch errors thrown before `window.onload`, which for a React or Vue app is a minority of
them. At `-concurrency 4`, the default 1.5s adds roughly six minutes to a 1000-URL run.

## Exit codes

```
0  the run completed (URLs may still have had errors — read the summary)
1  only with -fail-on-errors: the run completed and some URLs had errors
2  usage error, or the input file is missing / unreadable / has no valid URLs
3  the tool itself failed: Chrome would not start, logs could not be written
4  interrupted by SIGINT/SIGTERM — partial results were written and the summary printed
```

Broken pages are this tool's **output**, not its failure, so a completed run exits 0 by default. Exit 1 is
opt-in via `-fail-on-errors`. Keeping that separate from exit 3 is what makes the tool usable in CI: a red
build should mean "your pages are broken", not "the crawler could not find Chrome".

## Security

- **URLs are redacted by default.** Userinfo is stripped, the fragment is dropped (OAuth implicit flows put
  `#access_token=` there), and the *values* of about twenty credential-like query parameters are replaced
  with `REDACTED` while the key is kept so logs stay diagnosable. Redaction is applied inside error messages
  too, because Chrome embeds full URLs in exception text. `-log-full-urls` opts out and says so in `-help`.
- **Log files are `0600` in a `0700` directory**, and are opened through `os.Root` so a symlink or `..` in
  `-out` cannot escape it.
- **Only `http` and `https` are accepted.** `javascript:`, `file:`, `data:`, `chrome://`, `view-source:` and
  `blob:` are rejected by a positive allowlist, not a denylist.
- **Link-local addresses are blocked by default**, including the cloud metadata endpoint `169.254.169.254`
  and its IPv4-mapped IPv6 form. Loopback and RFC1918 remain allowed, because crawling your own staging site
  is the main use case. This is a pre-flight DNS check and is therefore vulnerable to TOCTOU and DNS
  rebinding — Chrome resolves independently. Treat it as defence in depth, not a boundary.
- **Chrome keeps its OS sandbox.** `pagevet` refuses to run as root, because Chrome would then be launched
  with `--no-sandbox`.
- **A fresh, empty, auto-deleted temporary profile** is used for every run. Your real cookies, logins and
  extensions are never exposed to a crawled page.
- **There is no generic `--chrome-flag` passthrough**, on purpose. That flag, not the binary path, is the
  dangerous one: it would let a copy-pasted command line inject `--no-sandbox`, `--disable-web-security` or
  `--user-data-dir=<your real profile>`.

## Development

```sh
make check     # every gate, in order
make test      # fast tests, no Chrome, ~seconds
make test-e2e  # includes the tests that drive real Chrome
```

### Claude Code support tools

`.claude/shared` is a git submodule of [claude-code-support-tools][ccst], carrying agents,
slash commands and Go hooks shared across projects. Several files under `.claude/` are
symlinks into it; the rest are pagevet-specific. See `.claude/README.md` for which is which.

Clone with submodules, or the symlinks dangle:

```sh
git clone --recurse-submodules https://github.com/olegiv/pagevet.git
make claude-init                      # fixes an existing clone
```

Refresh the shared tools with `/update-submodule`, or `git submodule update --remote --merge`.
That leaves an uncommitted change to the `.claude/shared` gitlink; commit it to keep the
update. None of this is required to build or test pagevet.

[ccst]: https://github.com/olegiv/claude-code-support-tools

Browser-dependent tests are gated by the `PAGEVET_E2E=1` environment variable rather than a build tag.
Files behind `//go:build e2e` are invisible to `go test ./...`, `go vet` and `golangci-lint`, so they rot
silently; with an env var they always type-check and only the body skips.

`make arch` enforces the two rules that keep the codebase testable:

- `chromedp` is imported by exactly one package, `internal/loader`
- `internal/verdict` — the classification core — imports nothing outside the standard library

That is why almost everything can be tested without a browser: the pool, the classifier, the reporter and
the exit-code logic all run against a fake `PageLoader`.

`.golangci.yml` uses the **v1 config schema** for golangci-lint v1.64.8. Do not migrate it to v2 syntax
without bumping the binary — v1 silently rejects the v2 keys, which would leave the project effectively
unlinted.

## Known limitations

1. **Cross-origin iframe errors are missed when `-site-isolation` is on.** Those frames get their own
   renderer process, whose console we do not attach to. It is off by default for exactly this reason;
   the OS sandbox, not site isolation, is what protects your machine here.
2. **Subresource failures are not console errors**, by design. If you want a broken asset to fail the page
   as an HTTP error instead, that is a policy change, not a flag.
3. **Cookies and storage are shared across URLs within a run**, since all tabs share one browser. Logging
   in on URL 3 affects URL 4. Use separate runs if that matters.
4. **Logs contain the URLs you supplied**, redaction notwithstanding. They are `0600`; treat them as
   sensitive.
5. **While a run is in flight, any local process running as your user can attach to Chrome's ephemeral
   DevTools socket.** This is inherent to driving Chrome over CDP.
6. **Go 1.26 tightened `url.Parse`** — `http://::1/` and `http://a:80:80/` are now rejected. An input file
   that worked with an older toolchain may now report parse errors. `GODEBUG=urlstrictcolons=0` restores
   the old behaviour if you need it.
7. **This is not a spider.** It reads a fixed list and renders each page once. It never follows links,
   honours `robots.txt`, or discovers URLs.
