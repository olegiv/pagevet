// Package browsertest gates the tests that need a real Chrome.
//
// The gate is an ENVIRONMENT VARIABLE, not a build tag, and that choice is the
// whole point of the package. Code behind `//go:build e2e` is invisible to
// `go test ./...`, `go vet ./...` and golangci-lint, so it rots quietly until
// somebody remembers to run it — usually the day it is needed most. Guarded by
// an env var, the e2e tests are compiled and type-checked on every ordinary
// run, and only their bodies skip.
//
// Skips are LOUD and always name the switch that would have run the test. A
// silent skip is how a suite ends up green with nothing behind it.
//
// This package deliberately does NOT import internal/loader. The loader's own
// e2e tests live in package loader, and an import from here back to there would
// close a cycle in the test binary. The handful of Chrome paths below are
// duplicated for that reason; they are stable enough that the duplication costs
// less than the coupling would.
package browsertest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// EnvEnable must be "1" for any browser test to run.
	EnvEnable = "PAGEVET_E2E"

	// EnvChromePath overrides binary discovery with an explicit path.
	EnvChromePath = "PAGEVET_CHROME_PATH"
)

// macChromePaths are the standard install locations on macOS, which is the
// platform this project is developed on. They are absolute app-bundle paths, so
// exec.LookPath will never find them — they have to be probed directly.
var macChromePaths = []string{
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta",
	"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
}

// lookupNames are the PATH-resolvable binary names used on Linux and by
// Homebrew-style installs.
var lookupNames = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"chrome",
}

// errNoChrome is returned by find when no usable binary turned up.
var errNoChrome = errors.New("no Chrome or Chromium binary found")

// Guard skips the calling test unless a real browser run was asked for.
//
// It skips when -short is set, when PAGEVET_E2E is not "1", or when no Chrome
// binary can be found. Every skip message names the variable that would have
// changed the answer.
func Guard(t testing.TB) {
	t.Helper()

	// -short comes first: a developer who asked for the fast suite means it,
	// even with the env var exported in their shell profile.
	if testing.Short() {
		t.Skipf("browser test skipped: -short is set (needs %s=1 and a Chrome binary)", EnvEnable)
	}
	if os.Getenv(EnvEnable) != "1" {
		t.Skipf("browser test skipped: set %s=1 to run it (optionally %s=/path/to/chrome)", EnvEnable, EnvChromePath)
	}
	if _, err := find(); err != nil {
		t.Skipf("browser test skipped: %v (set %s to point at a binary)", err, EnvChromePath)
	}
}

// ChromePath returns the browser binary the test should launch, applying Guard
// first — so a browser test needs this one call and nothing else.
func ChromePath(t testing.TB) string {
	t.Helper()

	Guard(t)

	path, err := find()
	if err != nil {
		// Unreachable after Guard unless the binary vanished mid-run, which is
		// still a skip rather than a failure: it says nothing about the code.
		t.Skipf("browser test skipped: %v", err)
	}
	return path
}

// find locates a browser binary: the explicit override first, then the macOS
// bundles, then PATH.
func find() (string, error) {
	if override := strings.TrimSpace(os.Getenv(EnvChromePath)); override != "" {
		// The override is returned unexamined, on purpose. Everything else in
		// find() stats a path this file chose, so the only paths reaching the
		// filesystem here are constants; an environment-supplied one would make
		// this a taint sink for no benefit, since loader.NewChrome validates
		// the binary properly anyway. Requiring it to be absolute is enough to
		// catch the realistic mistake - a relative path that would silently
		// resolve against whatever directory the test happens to run in.
		if !filepath.IsAbs(override) {
			return "", errors.New(EnvChromePath + "=" + override + " must be an absolute path")
		}
		return filepath.Clean(override), nil
	}

	for _, p := range macChromePaths {
		if executable(p) {
			return p, nil
		}
	}

	for _, name := range lookupNames {
		if p, err := exec.LookPath(name); err == nil {
			return filepath.Clean(p), nil
		}
	}

	return "", errNoChrome
}

// executable reports whether path is a regular file with an execute bit. The
// mode check matters on macOS, where an app bundle directory sits at a path
// that looks very much like the binary inside it.
func executable(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}
