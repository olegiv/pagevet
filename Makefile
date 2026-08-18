# pagevet — build, test, quality and security gates.
#
# `make check` runs every gate in order, cheapest and most fundamental first,
# so a broken build fails in seconds rather than after a five-minute lint.

BIN     := pagevet
PKG     := github.com/olegiv/pagevet
LOADER  := $(PKG)/internal/loader
DIST    := dist

# Release stamping, consumed by the -X flags below.
#
# `:=`, not `?=`. A `?=` variable is recursively expanded, so its $(shell) re-runs
# at every reference: eight subprocesses across build-all-platforms, and a `date`
# that can straddle a second boundary and stamp two binaries from the same run
# differently. `make build-prod COMMIT=deadbee` still overrides either way,
# because a command-line variable beats any assignment in this file.
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# -s -w drop the symbol table and DWARF: roughly a third off the binary, and
# nothing here reads either at runtime. -X patches internal/app's Version block,
# which is why those three are `var` and not `const` - the linker silently
# ignores an -X aimed at a constant, and a stamp that fails quietly is worse
# than no stamp at all.
LDFLAGS_PROD := -s -w \
    -X $(PKG)/internal/app.Commit=$(COMMIT) \
    -X $(PKG)/internal/app.BuildTime=$(DATE)

# CGO_ENABLED=0 is stated rather than assumed. Every dependency here is pure Go,
# so it changes nothing about what gets built; it makes the static result a
# property of this file instead of an accident of whether the cross-compile
# happened to disable cgo for us.
define cross_build
@mkdir -p $(DIST)
CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build -trimpath -ldflags="$(LDFLAGS_PROD)" -o $(DIST)/$(BIN)-$(1)-$(2) ./cmd/pagevet
endef

.PHONY: all build build-prod build-linux-amd64 build-linux-arm64 build-darwin-amd64 \
        build-darwin-arm64 build-all-platforms clean claude-init fmt vet tidy arch test \
        test-e2e lint sec vuln vuln-module check help

all: build

## build: compile the binary into ./pagevet
##
## Unoptimised on purpose - this is the binary `make check` builds, and a
## debugger needs the symbol table and DWARF that build-prod strips.
build:
	go build -o $(BIN) ./cmd/pagevet

## build-prod: optimised, version-stamped ./pagevet
build-prod:
	go build -trimpath -ldflags="$(LDFLAGS_PROD)" -o $(BIN) ./cmd/pagevet

## build-linux-amd64: release binary into dist/
build-linux-amd64:
	$(call cross_build,linux,amd64)

## build-linux-arm64: release binary into dist/
build-linux-arm64:
	$(call cross_build,linux,arm64)

## build-darwin-amd64: release binary into dist/
build-darwin-amd64:
	$(call cross_build,darwin,amd64)

## build-darwin-arm64: release binary into dist/
build-darwin-arm64:
	$(call cross_build,darwin,arm64)

## build-all-platforms: every release binary above, into dist/
##
## No Windows target. It would compile, but ResolveChromePath probes only the
## macOS app bundles and the Linux $PATH names, so the binary could never find
## a browser without -chrome on every single run.
build-all-platforms: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64
	@ls -lh $(DIST)/$(BIN)-*

## clean: remove build and coverage artifacts
clean:
	rm -f $(BIN) coverage.out coverage.e2e.out cover.html
	rm -rf $(DIST)

## claude-init: populate .claude/shared after a clone without --recurse-submodules
##
## Nothing in the build depends on .claude, so this is deliberately not part of
## `check`. It exists because the failure it fixes is silent: a plain git clone
## leaves the submodule empty and every symlink under .claude dangling, which
## looks like "the slash commands vanished" rather than like a missing checkout.
claude-init:
	git submodule update --init --recursive

## fmt: fail if anything is unformatted (gofmt exits 0 even when it lists files)
fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

## vet: the Go 1.26 analyzer set (slog, waitgroup, lostcancel, copylocks, ...)
vet:
	go vet ./...

## tidy: fail if go.mod/go.sum are untidy; writes nothing
tidy:
	go mod tidy -diff

## arch: enforce the dependency direction that keeps this codebase testable
##
## Only OUR packages are listed (./... , not -deps): -deps would also print
## chromedp's own package line and its transitive imports, which match the
## pattern for the wrong reason. The trailing-space alternation stops
## chromedp/kb and chromedp/device from counting as the driver itself.
##
## internal/login is held to the same stdlib-only rule as internal/verdict for a
## different reason: it holds the only password in the program, and the cheapest
## way to keep a credential out of a dependency's logging, telemetry or error
## formatting is for there to be no dependency at all.
arch:
	@leak=$$(go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}}' ./... \
	    | grep -E ' github\.com/chromedp/chromedp( |$$)' \
	    | grep -v '^$(LOADER) ' | cut -d' ' -f1); \
	if [ -n "$$leak" ]; then \
	  echo "FAIL: chromedp is imported outside $(LOADER):"; echo "$$leak"; exit 1; \
	fi
	@for pkg in ./internal/verdict ./internal/login; do \
	  if go list -f '{{join .Imports "\n"}}' $$pkg \
	      | grep -qE '^[a-z0-9.-]+\.[a-z]{2,}/'; then \
	    echo "FAIL: $$pkg is no longer stdlib-pure"; \
	    go list -f '{{join .Imports "\n"}}' $$pkg \
	      | grep -E '^[a-z0-9.-]+\.[a-z]{2,}/'; \
	    exit 1; \
	  fi; \
	done
	@echo "arch: chromedp confined to $(LOADER); internal/verdict and internal/login are stdlib-pure"

## test: fast tests, no Chrome required
test:
	go test ./... -short -race -covermode=atomic -coverprofile=coverage.out -count=1
	@go tool cover -func=coverage.out | tail -1

## test-e2e: full suite including tests that drive real Chrome
test-e2e:
	PAGEVET_E2E=1 go test ./... -race -covermode=atomic \
	    -coverprofile=coverage.e2e.out -count=1 -timeout=10m -parallel=4
	@go tool cover -func=coverage.e2e.out | tail -1

## lint: golangci-lint v2 (see the header note in .golangci.yml)
##
## The version check is not fussiness: a v1 binary rejects every v2 key in
## .golangci.yml and exits non-zero with a config error, which is easy to read
## as "lint is broken" and skip past. Saying which binary is wanted turns that
## into one actionable line.
##
## It compares all three components, not just the major. Checking only "is it 2"
## would wave through v2.0 while the message says v2.11.4, and a check that
## disagrees with its own error text is worse than no check. `sort -t. -k1,1n
## -k2,2n -k3,3n` orders the two versions numerically per component; if the
## required one does not sort first, the installed one is older.
lint:
	@need=2.11.4; \
	got=$$(golangci-lint version 2>/dev/null \
	    | grep -oE 'version v?[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
	if [ -z "$$got" ]; then \
	  echo "golangci-lint not found (or its version is unreadable); install v$$need or newer"; exit 1; \
	fi; \
	if [ "$$(printf '%s\n%s\n' "$$need" "$$got" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" != "$$need" ]; then \
	  echo "golangci-lint v$$got found, but this project needs v$$need or newer:"; \
	  echo "  .golangci.yml uses the v2 schema, which v1 rejects outright."; \
	  exit 1; \
	fi
	golangci-lint run ./...

## sec: standalone gosec; authoritative over the older copy bundled in golangci-lint
##
## gosec.json cannot carry comments, so the rationale lives here:
##   G301 0700 - the output directory
##   G302 0700 - the ONLY chmod in this codebase is on that directory, where
##               0700 is correct. No file is ever chmod'ed, and every log file
##               is created through (*os.Root).OpenFile at 0600.
##   G306 0600 - log files contain the URLs you supplied, tokens and all
sec:
	gosec -severity low -confidence low -exclude-generated \
	      -track-suppressions -conf gosec.json ./...

## vuln: symbol-reachability scan. THE security gate.
vuln:
	govulncheck ./...

## vuln-module: coarse module-level scan. Informational; over-reports by design.
##
## Two quirks of govulncheck v1.1.4, both of which cost time to rediscover:
## it REJECTS package patterns in this mode (no "./...", no "."), and it still
## has to load a package - so run it from a directory that contains Go files.
## This module's root has none, hence -C.
vuln-module:
	govulncheck -C cmd/pagevet -scan=module

## check: every gate, in order
check: fmt vet tidy build arch test test-e2e lint sec vuln vuln-module
	@echo
	@echo "all gates green"

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
