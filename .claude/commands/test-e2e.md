---
allowed-tools: Bash
description: "Run the tests that drive a real Chrome, and triage failures that are environmental rather than code"
---

Run the browser-dependent suite.

```bash
make test-e2e
```

That is `PAGEVET_E2E=1 go test ./... -race -covermode=atomic -count=1 -timeout=10m -parallel=4`.
The fast suite (`make test`) skips these; only this target exercises Chrome.

**Parameter:** `$ARGUMENTS` — optional `-run` pattern to narrow the suite, e.g.
`/test-e2e TestLogin` runs only the login tests. Pass it through as
`PAGEVET_E2E=1 go test ./... -race -count=1 -timeout=10m -run '<pattern>'`.

## How the gating works

Browser tests are gated by the `PAGEVET_E2E=1` **environment variable**, not a build tag.
That is deliberate: files behind `//go:build e2e` are invisible to `go test ./...`, `go vet`
and `golangci-lint`, so they rot silently. With an env var they always type-check and only
the body skips. `internal/loader/browsertest.Guard(t)` is what performs the skip.

`PAGEVET_CHROME_PATH` overrides browser discovery. The guard accepts a browser that
pagevet's own autodetection does not probe for (Edge, a beta channel), which is why
`TestE2E_Binary` passes the discovered path to the binary explicitly with `-chrome`.

## Triage a failure here before blaming the code

Several failure modes are environmental. Check these first:

1. **Is Chrome present at all?** If every e2e test skips, the guard found no browser. Set
   `PAGEVET_CHROME_PATH` to an absolute path.
2. **`net::ERR_CONNECTION_REFUSED`, intermittently.** FLAKE RULE 1 in
   `internal/testfixtures/server.go`: use `srv.URL` exactly as returned, never rewrite
   `127.0.0.1` to `localhost`. On macOS `localhost` resolves to `::1` first while httptest
   binds IPv4 only.
3. **A test passes alone but fails after its neighbour.** FLAKE RULE 4: every fixture
   response must be `no-store`-wrapped, or Chrome serves the second visit from its own
   cache — no network events, no console output.
4. **A "clean page" assertion gained a phantom subresource failure.** FLAKE RULE 2: Chrome
   requests `/favicon.ico` for every page; the fixture answers it 204 on purpose.
5. **The whole binary times out with no attribution.** Tests use a caller-side deadline
   (`loadDeadline`) so a regression fails with a named test rather than hanging. If you see
   a bare 10m timeout, something is blocking outside a deadline.
6. **A stray Chrome is left running.** On macOS chromedp's process-group cleanup is a no-op,
   so an aborted run can leak a browser. Check with `pgrep -fl 'Chrome.*--headless'`.

## Cost

The suite shares one browser across tests (`sync.OnceValues` + a `TestMain` teardown that
closes the browser *before* the fixture server). It takes roughly a minute. Do not add a
browser-per-test.

## Reporting

Say which tests failed and quote their output. Distinguish clearly between "the code is
wrong" and "the environment is wrong" — they need different responses from the user.
