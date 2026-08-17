# Claude Code configuration for pagevet

Two kinds of thing live here: content **shared** across projects, pulled in as a git
submodule and surfaced by symlink, and content **specific to pagevet**, written as ordinary
files. Knowing which is which tells you where to edit.

```
.claude/
├── shared/                       git submodule -> olegiv/claude-code-support-tools
├── agents/
│   ├── code-quality-auditor.md   -> ../shared/stacks/go/agents/
│   └── security-auditor.md       -> ../shared/agents/
├── commands/
│   ├── code-quality.md           -> ../shared/stacks/go/commands/
│   ├── commit-prepare.md         -> ../shared/stacks/go/commands/
│   ├── finalize.md               -> ../shared/global/commands/
│   ├── security-audit.md         -> ../shared/commands/
│   ├── update-submodule.md       -> ../shared/commands/
│   ├── check.md                  pagevet
│   ├── crawl.md                  pagevet
│   ├── pr-prepare.md             pagevet
│   └── test-e2e.md               pagevet
├── hooks/
│   ├── validate-go-test.sh       -> ../shared/stacks/go/hooks/
│   └── validate-go-toolchain.sh  -> ../shared/stacks/go/hooks/
├── skills/                       empty; see below
├── settings.json                 committed, team-wide
└── settings.local.json           personal, gitignored, never committed
```

Everything above is committed **except `settings.local.json`**. The symlinks are stored as
symlinks (git mode `120000`) with relative targets, so they resolve on any clone.

`crawl.md` is named that, and not `run.md`, because Claude Code ships a built-in `run`
skill: a command of that name here is shadowed by it and never appears. Anything added to
this directory needs a name no built-in already claims — check `/help` after adding one.

## After cloning

A plain `git clone` leaves `.claude/shared` empty and every symlink dangling. Either clone
with submodules, or fix it after the fact:

```sh
git clone --recurse-submodules https://github.com/olegiv/pagevet.git
# or, in an existing clone:
make claude-init
```

## Updating the shared tools

```sh
/update-submodule          # or: git submodule update --remote --merge
```

The submodule reference is pinned in this repo's history. Pulling a newer one leaves an
uncommitted change to the `.claude/shared` gitlink; `git add .claude/shared && git commit`
to keep it, `git submodule update` to discard it.

## Editing

- To change something under a **symlink**, you are editing the shared repo. Do that in
  `claude-code-support-tools` and open a PR there — a change made through the symlink is a
  change to the submodule's working tree and will not travel with this project.
- To change something **pagevet-specific**, edit the file here directly.
- To stop using a shared file, `rm` the symlink. To diverge from one, replace the symlink
  with a real file (`rm` it, then write your own).

## Hooks

`settings.json` wires two `PreToolUse` hooks on `Bash`. Both need `jq` on `PATH`.

- `validate-go-toolchain.sh` **blocks** (`exit 2`) a `go build/test/run/install` whose
  compiler does not match `go.mod`. That is not fussiness here: `go 1.26.6` is deliberate,
  because 1.26.5 ships two vulnerabilities reachable through the TLS path pagevet uses to
  talk to Chrome.
- `validate-go-test.sh` warns, never blocks, when `go test` omits `-race`. Every Makefile
  test target already passes it; this catches the ad-hoc invocation.

## Skills

Empty on purpose. The shared repo ships skills only for the Drupal and PHP stacks — the Go
stack has agents, commands and hooks but no skills — so there is nothing to symlink here.
Project-specific skills for pagevet can be added as `skills/<name>/SKILL.md`.
