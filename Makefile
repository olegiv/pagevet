# pagevet — build, test, quality and security gates.
#
# `make check` runs every gate in order, cheapest and most fundamental first,
# so a broken build fails in seconds rather than after a five-minute lint.

BIN     := pagevet
PKG     := github.com/olegiv/pagevet
LOADER  := $(PKG)/internal/loader

.PHONY: all build clean fmt vet tidy arch test test-e2e lint sec vuln vuln-module check help

all: build

## build: compile the binary into ./pagevet
build:
	go build -o $(BIN) ./cmd/pagevet

## clean: remove build and coverage artifacts
clean:
	rm -f $(BIN) coverage.out coverage.e2e.out cover.html

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
