---
allowed-tools: Bash
description: "Run every pagevet gate (make check) and explain any failure"
---

Run the full gate ladder and report the result.

```bash
make check
```

`check` runs `fmt vet tidy build arch test test-e2e lint sec vuln vuln-module` in that
order — cheapest and most fundamental first, so a broken build fails in seconds rather than
after a five-minute lint. A green run ends with `all gates green`.

**Do not paper over a failing gate.** Each one exists for a reason, and the reason is
usually not obvious from the error text alone. Diagnose using the table below, fix the
cause, and re-run.

## What each gate means when it fails

| Gate | A failure means |
| --- | --- |
| `fmt` | Something is ungofmt'd. `gofmt -w` the listed files. |
| `vet` | A real correctness smell from the Go 1.26 analyzer set (lostcancel, copylocks, waitgroup...). Fix it; do not silence it. |
| `tidy` | `go.mod`/`go.sum` drifted. Run `go mod tidy`. **Never** lower the `go` directive to make something build — see below. |
| `arch` | The architecture invariant broke. Either `chromedp` is now imported outside `internal/loader`, or `internal/verdict` / `internal/login` gained a non-stdlib import. Both are load-bearing; move the code rather than relaxing the rule. |
| `test` | A fast test failed. No Chrome involved, so this is logic. |
| `test-e2e` | A browser test failed. See `/test-e2e` before assuming the code is wrong — several failures here are environmental. |
| `lint` | golangci-lint. Needs **v2.11.4 or newer**: `.golangci.yml` uses the v2 schema and a v1 binary rejects every key with a config error that reads like "lint is broken". The target checks the major version first and says so. |
| `sec` | Standalone gosec, authoritative over the copy bundled in golangci-lint. The repo currently reports `Issues: 0` and `Nosec: 0` — keep it that way. Prefer restructuring (e.g. `os.Root` instead of `os.Open` on a computed path) over a `#nosec` suppression. |
| `vuln` | `govulncheck` symbol-reachability scan. **The** security gate. A hit here is reachable, not theoretical. |
| `vuln-module` | Coarse module-level scan. Informational and over-reports by design. |

## Two things that are never the fix

- **Never lower the `go` directive in `go.mod`.** `go 1.26.6` is deliberate: 1.26.5 ships two
  vulnerabilities reachable through the TLS path this program uses to talk to Chrome
  (`GO-2026-6090`, `GO-2026-5972`). There is no `toolchain` directive on purpose, so a
  `GOTOOLCHAIN=local` user on 1.26.5 gets a loud build failure instead of a silently
  vulnerable binary.
- **Never relax `make arch` to make an import legal.** That rule is why almost everything in
  this codebase can be tested without a browser.

## Reporting

State plainly which gates passed and which failed. If a gate failed, quote the actual output
rather than summarizing it, then say what you changed and re-run `make check` to confirm.
