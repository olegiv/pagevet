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
pagevet -login urls.txt                        # sign in first, see below
```

## Logging in

Pages behind a login are the ones most worth checking and the ones a crawler is
worst at: without a session they all come back as a redirect or a 403, which looks
like a wall of real failures. `-login` signs in once, before the crawl starts, and
every URL after that is fetched as that user.

```sh
cp .env.example .env && chmod 600 .env   # then fill it in
pagevet -login urls.txt
```

The flag is the whole command-line surface. Everything else lives in `.env`, read
from **the directory you run `pagevet` from**:

| Key | What it is |
| --- | --- |
| `LOGIN_PATH` | the login page: a path resolved against the first URL in your list, or a full `http(s)://` URL |
| `LOGOUT_PATH` | *optional* — a sign-out page loaded **before** the login page |
| `LOGIN_FORM_ID` | `id` of the `<form>` element |
| `USERNAME_NAME` | `name=` of the username input |
| `PASSWORD_NAME` | `name=` of the password input |
| `USER_ADMIN_NAME` | the account to sign in as |
| `USER_ADMIN_PASS` | its password |

Everything but `LOGOUT_PATH` is required, and a missing or malformed `.env` exits **2**
before Chrome is ever launched. See `.env.example` for the full annotated file.

**`LOGOUT_PATH` signs out first.** When set, pagevet loads it immediately before the
login page, so the sign-in always starts from a signed-out state. The run's Chrome
profile is empty to begin with, so most of the time there is nothing to sign out of —
but "most of the time" is doing real work in that sentence. Set it when your login page
behaves differently for a visitor who already has a session; the usual case is a login
block rendered only to anonymous users, which would otherwise fail with `no visible
form` on a run that picked up a session somewhere. Omit it and pagevet goes straight to
the login page, which is what every `.env` written before this key existed does.

It takes the same two forms as `LOGIN_PATH`, gets the same scheme and address checks,
and may point at a different host. If the page cannot be reached the run exits **5** and
names the key. Note that some sites require a one-time token on their logout route
(Drupal 10 does), in which case a bare `/user/logout` will not work and the key is
better left unset.

**How it knows the login worked.** Two independent signals, both required: the session
state changed, *and* the `LOGIN_FORM_ID` element is gone from the page. Either alone
lies in a common case — a site that sets a CSRF cookie on a *failed* login satisfies
the first, and a redirect that dropped the session can satisfy the second.

"Session state" means anything a later tab can actually reuse: the cookie jar, and the
page's `localStorage`. Three things follow from that, each of which was a real site
before it was a rule.

- It compares **values**, not just names. PHP and Express commonly hand anonymous
  visitors a session cookie and then authenticate that same session in place; nothing
  new appears, only the value moves.
- It counts **`localStorage`**, because a token-backed SPA may set no cookie at all and
  still be genuinely signed in for every tab on that origin.
- It does **not** count `sessionStorage`, which belongs to the tab that wrote it. The
  login tab is closed as soon as the sign-in finishes, so a token kept only there is a
  session the crawl would never have.

Storage is compared only while the origin stays put, since it is scoped per origin and
comparing one origin's storage against another's would call every key new.

If the sign-in fails, pagevet exits **5** and crawls nothing,
because a wall of 403s that look like page errors is worse than no data at all. The
message says which of the two checks tripped:

```
pagevet: login failed: submitted https://example.com/login but nothing happened:
no cookie or stored session changed, and #user-login-form is still on the page.
usual cause is wrong credentials
```

> If your site keeps rendering its login block to signed-in users, the second check
> will fail on a sign-in that actually worked. The error says so explicitly —
> `the session state changed (SSESS…) but #… is still on the page` — so you can tell the
> two apart.

**It works because all tabs share one browser.** There is no cookie copying and no
change to the worker pool: every URL is loaded in a tab of the one Chrome the run
started, so a session established before the pool starts applies to all of them.
That is the same property listed under "known limitations" below, used on purpose.

**`-timeout` bounds the sign-in too**, not just each crawled page. The whole sequence —
the optional logout, the login page, filling the form, submitting it and waiting for the
answer — shares that budget, and each individual step gets a fraction of it so one wrong
key in `.env` fails in seconds rather than consuming the lot. A slow authentication that
never navigates, as a single-page login does not, is waited out; one that answers with a
redirect is judged as soon as that lands. If a sign-in reports running out of time, the
message says which step did and `-timeout` is the knob.

Two things worth knowing before you point this at anything:

- **Use the lowest-privilege account that can see the pages you are checking.**
  pagevet renders every URL in your list with this session, and a page that deletes
  something on `GET` will be just as deleted.
- **The session is established once, at the start.** One that expires mid-run is not
  re-established.

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
| `-login` | false | sign in once from `./.env` before crawling ([above](#logging-in)) |
| `-log-full-urls` | false | disable URL redaction (**unsafe**, see below) |
| `-fail-on-errors` | false | exit 1 when any URL had an error |

`-settle` is the flag most worth tuning. Modern SPAs throw during hydration, well after `load` fires; at
`0` you will only catch errors thrown before `window.onload`, which for a React or Vue app is a minority of
them. At `-concurrency 4`, the default 1.5s adds roughly six minutes to a 1000-URL run.

## Exit codes

```
0  the run completed (URLs may still have had errors — read the summary)
1  only with -fail-on-errors: the run completed and some URLs had errors
2  usage error, or the input file is missing / unreadable / has no valid URLs,
   or .env is missing / malformed when -login is set
3  the tool itself failed: Chrome would not start, logs could not be written
4  interrupted by SIGINT/SIGTERM — partial results were written and the summary printed
5  only with -login: the sign-in failed, so nothing was crawled
```

Broken pages are this tool's **output**, not its failure, so a completed run exits 0 by default. Exit 1 is
opt-in via `-fail-on-errors`. Keeping that separate from exit 3 is what makes the tool usable in CI: a red
build should mean "your pages are broken", not "the crawler could not find Chrome".

Exit 5 exists for the same reason. "Your credentials are wrong" and "Chrome would not start" want different
responses from whoever reads the alert, so they get different codes. The split between 2 and 5 follows the
same rule: a `.env` you fix in an editor is a usage error, like a missing input file, whereas 5 means the
sign-in was actually attempted and did not take.

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
  rebinding — Chrome resolves independently. Treat it as defense in depth, not a boundary.
- **Chrome keeps its OS sandbox.** `pagevet` refuses to run as root, because Chrome would then be launched
  with `--no-sandbox`.
- **A fresh, empty, auto-deleted temporary profile** is used for every run. Your real cookies, logins and
  extensions are never exposed to a crawled page. `-login` does not weaken this: it signs in *inside* that
  throwaway profile, so the only session that ever exists is one this run created, and it is destroyed with
  the profile when the run ends.
- **The password is never written anywhere.** Not to a log file, not into an error message, not into the
  JavaScript pagevet evaluates — it reaches the browser only as an argument to a keystroke. The log header
  records the account name, the login URL and the form id, so you can tell which session produced a set of
  results, and nothing else. `.env` is read only when `-login` is passed, and pagevet warns if it is
  group- or world-readable.
- **`LOGIN_FORM_ID` and the two field names never become code.** Every expression pagevet evaluates is a
  constant JavaScript function applied to a JSON argument array, so a configured value is data the engine
  binds rather than program text — there is no quoted context for `x"] , [name="pass` to close. CSS
  selectors, which must be strings, are escaped instead and tested against the same hostile corpus. Both,
  rather than an allowlist, because `user[email]` is an ordinary Rails or PHP field name.
- **A credential is never typed into a control that could turn it into a file upload.** `chromedp.SendKeys`
  special-cases `<input type="file">` and treats the value as a local path, so a path-shaped password would
  upload that file to the site. pagevet inserts text through a path that has no such branch, and separately
  refuses any control that is not text-capable.
- **The login and logout URLs go through the same scheme allowlist and link-local check as every URL in your
  input file** — separately, since `LOGOUT_PATH` may name another origin. The page that *actually commits* is
  re-checked too: a login page is allowed to redirect, so the pre-flight check alone would not cover where
  the password finally gets typed. A redirect somewhere the policy rejects aborts before anything is entered.
- **There is no generic `--chrome-flag` passthrough**, on purpose. That flag, not the binary path, is the
  dangerous one: it would let a copy-pasted command line inject `--no-sandbox`, `--disable-web-security` or
  `--user-data-dir=<your real profile>`.

## Development

```sh
make check     # every gate, in order
make test      # fast tests, no Chrome, ~seconds
make test-e2e  # includes the tests that drive real Chrome
```

Browser-dependent tests are gated by the `PAGEVET_E2E=1` environment variable rather than a build tag.
Files behind `//go:build e2e` are invisible to `go test ./...`, `go vet` and `golangci-lint`, so they rot
silently; with an env var they always type-check and only the body skips.

`make arch` enforces the rules that keep the codebase testable:

- `chromedp` is imported by exactly one package, `internal/loader`
- `internal/verdict` — the classification core — imports nothing outside the standard library
- `internal/login` — which holds the only password in the program — likewise imports nothing outside the
  standard library. Same gate, different reason: the cheapest way to keep a credential out of a
  dependency's logging, telemetry or error formatting is for there to be no dependency at all.

That is why almost everything can be tested without a browser: the pool, the classifier, the reporter, the
exit-code logic and the sign-in ordering all run against a fake `PageLoader`.

`.golangci.yml` uses the **v2 config schema**, for golangci-lint v2.11.4 or newer. Do not hand-edit it back
to v1 keys (`linters.disable-all`, `linters-settings`, `run.timeout`); v2 rejects them, and while that is at
least a loud failure, it leaves the project unlinted until somebody notices.

Two things changed meaning when this moved off the v1 schema. `gosimple` and `stylecheck` no longer exist
separately — both are folded into `staticcheck`, so the enable list is shorter without checking any less.
And v1's default exclusions, which it applied invisibly, are now spelled out under
`linters.exclusions.presets`; deleting them makes an otherwise-identical config report dozens of findings
about unchecked `fmt.Fprintf` and `gosec` in test files.

## Known limitations

1. **Cross-origin iframe errors are missed when `-site-isolation` is on.** Those frames get their own
   renderer process, whose console we do not attach to. It is off by default for exactly this reason;
   the OS sandbox, not site isolation, is what protects your machine here.
2. **Subresource failures are not console errors**, by design. If you want a broken asset to fail the page
   as an HTTP error instead, that is a policy change, not a flag.
3. **Cookies and storage are shared across URLs within a run**, since all tabs share one browser. Logging
   in on URL 3 affects URL 4. This is what [`-login`](#logging-in) is built on, but it applies whether or
   not you use the flag — a page that logs you in, or out, changes the ones after it. Use separate runs if
   that matters. A session established by `-login` is set up once, before the crawl starts, and is not
   re-established if it expires mid-run.
4. **Logs contain the URLs you supplied**, redaction notwithstanding. They are `0600`; treat them as
   sensitive.
5. **While a run is in flight, any local process running as your user can attach to Chrome's ephemeral
   DevTools socket.** This is inherent to driving Chrome over CDP.
6. **Go 1.26 tightened `url.Parse`** — `http://::1/` and `http://a:80:80/` are now rejected. An input file
   that worked with an older toolchain may now report parse errors. `GODEBUG=urlstrictcolons=0` restores
   the old behaviour if you need it.
7. **This is not a spider.** It reads a fixed list and renders each page once. It never follows links,
   honours `robots.txt`, or discovers URLs.
8. **`-login` cannot stop a hostile login page from redirecting your credentials away.** pagevet checks the
   login page, the page it redirects to, the form's `action`, and the target again after the fields are
   filled — but a 307 or 308 answer to the POST itself preserves the method and body, and Chrome follows it
   before pagevet regains control. The run then fails loudly and says the credentials may have travelled,
   which is detection, not prevention. Preventing it needs CDP request interception, vetting every request
   before Chrome sends it. As with the address guard generally: this is defence in depth against an accident
   in your own `.env`, not a boundary against a login page written by an attacker. Point `-login` at sites
   you control.
9. **A failed login can satisfy both success signals.** The common post/redirect/get failure — wrong
   credentials, the server rotates a flash or session cookie and redirects to a dedicated error page that
   carries no login form — changes the session state *and* removes the form, which is everything `-login`
   checks. pagevet then reports success and crawls anonymously. The two signals are strong evidence that
   *something happened*, not proof of *who you are*; proving that needs a request whose answer depends on
   the account, which pagevet has no way to know for your site. Read the first few results of a `-login`
   run before trusting a long one: a page you expect to be private coming back 403 is the tell.
