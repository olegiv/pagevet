# pagevet — working notes for Claude Code

`pagevet` opens a list of URLs in headless Chrome and reports what broke. `README.md` covers
what it does and why; this file covers the things that will bite you while changing it.

## The gate

```sh
make check     # every gate, in order — must end with "all gates green"
make test      # fast tests, no Chrome, seconds
make test-e2e  # includes the tests that drive real Chrome
```

`make check` is the definition of done. Run it before saying a change works. `/check`
explains what each gate means when it fails.

## Invariants that are enforced, and why

`make arch` fails the build on either of these, so they are not style preferences:

- **`chromedp` is imported by exactly one package, `internal/loader`.** This is why the
  worker pool, the classifier, the reporter and the exit-code logic can all be tested
  against `loader/fake.FakeLoader` with no browser anywhere.
- **`internal/verdict` and `internal/login` import nothing outside the standard library.**
  `verdict` is the classification core. `login` holds the only password in the program, and
  the cheapest way to keep a credential out of a dependency's logging or error formatting is
  for there to be no dependency at all.

Move the code rather than relaxing either rule.

## Things that are never the fix

- **Never lower the `go` directive in `go.mod`.** `go 1.26.6` is load-bearing: 1.26.5 ships
  two vulnerabilities reachable through the TLS path this program uses to talk to Chrome
  (`GO-2026-6090`, `GO-2026-5972`). There is deliberately no `toolchain` directive, so a
  `GOTOOLCHAIN=local` user on 1.26.5 gets a loud failure instead of a silent vulnerability.
- **Never add a `#nosec` or `//nolint` to make a gate pass** without exhausting the
  restructuring first. The repo currently reports `Nosec: 0` and lints clean with zero
  suppressions. `nolintlint` requires any suppression that survives to name its rule and
  justify itself.
- **Never commit `.env`.** It holds a real password and is gitignored. `.env.example` is the
  committed template.

## Adding a flag

Two places, always: the `fs.*Var` registration **and** the hand-written `usageText` block,
both in `internal/app/config.go`. `TestParseFlags_Defaults` catches a missed default;
nothing catches a missed help entry except reading it.

## Tests

- Standard library only — no testify, no gomock. Table-driven, `t.Parallel()`, `-race`.
- Browser tests are gated by the **`PAGEVET_E2E=1` environment variable**, never a build tag:
  files behind `//go:build e2e` are invisible to `go vet` and the linter, so they rot.
- `internal/report/testdata/*.golden` are asserted against a **fixed injected clock**, so the
  real timestamp layout is under test. Regenerate with `go test ./internal/report -update`
  only after confirming the new output is actually correct.
- `internal/testfixtures/server.go` carries numbered **FLAKE RULES** in comments. Read them
  before touching a fixture; each one records a specific way the suite has already broken.

## Linting

`.golangci.yml` uses the **v2 schema** and needs golangci-lint **2.11.4 or newer**. A v1
binary rejects every key with a config error that reads like "lint is broken" — `make lint`
checks the major version first and says so. `make sec` runs a standalone gosec and is
authoritative over the older copy bundled in golangci-lint.

## Claude Code setup

`.claude/shared` is a git submodule of shared tooling; several files under `.claude/` are
symlinks into it. See `.claude/README.md` for what is shared versus project-specific, and
run `make claude-init` if a clone left the submodule empty.
