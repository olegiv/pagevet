---
allowed-tools: ""
description: "Run a fresh review of the branch diff before opening a PR"
---

Review this branch's diff with fresh eyes, before `gh pr create`.

This is deliberately run with no prior conversation context. A session that just wrote the
code is primed to miss exactly the things that matter here: a fix whose invariant does not
generalize, a helper whose contract changed without every call site following, a doc that
now describes behaviour the code no longer has.

**When to use:** before opening a PR on any non-trivial branch. A typo or a README tweak
does not need this gate.

## Step 1 — establish the diff range

```bash
git fetch origin
git merge-base --fork-point origin/main HEAD || git merge-base origin/main HEAD
git diff --stat <base>...HEAD
```

Review `<base>...HEAD`, not the working tree. State the range you used.

## Step 2 — confirm the gates are green

```bash
make check
```

Do not review a branch that does not build. If `check` fails, stop and report that instead.

## Step 3 — read the diff for the things tests do not catch

Work through the actual hunks, not the summary. Look for:

- **Contract drift.** A changed function signature or error-wrapping behaviour where only
  some call sites were updated. Grep for every caller.
- **Invariants that only hold for the case at hand.** A fix keyed to one input shape that
  the next input will walk straight past.
- **Doc/runtime mismatch.** This repo documents heavily and the docs are load-bearing:
  `README.md` flag table and exit codes, the `usageText` block in `internal/app/config.go`,
  and package doc comments. A behaviour change that leaves any of them stale is a real
  finding. Note that adding a flag touches **two** places — `fs.*Var` and `usageText`.
- **The architecture rules.** `chromedp` only in `internal/loader`; `internal/verdict` and
  `internal/login` stdlib-pure. `make arch` catches the import, but not a design drifting
  toward needing to break it.
- **Test quality, not test count.** Does a new test fail if the fix is reverted? Is there a
  control case proving the assertion is not vacuous?
- **Anything that could write a credential to disk.** Log files, error messages, JavaScript
  interpolation. The password must never appear in any of them.
- **Golden files.** If `internal/report/testdata/*.golden` changed, is the new output
  actually correct, or was the golden regenerated to match a bug?

## Step 4 — report

List findings most-severe first, each with file:line and a concrete failure scenario — the
input or state that produces the wrong result. Separate "must fix before merge" from
"worth considering". If the branch is clean, say so plainly rather than manufacturing
findings.

Do **not** commit, push, or run `gh pr create` from this command. It reviews; the user
decides what happens next.
