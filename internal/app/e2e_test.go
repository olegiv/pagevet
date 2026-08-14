package app_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/loader/browsertest"
	"github.com/olegiv/pagevet/internal/report"
	"github.com/olegiv/pagevet/internal/testfixtures"
)

// buildTimeout covers a cold `go build` on a machine with an empty cache.
const buildTimeout = 5 * time.Minute

// TestE2E_Binary is the ONLY test in this package that starts a real browser,
// and it is deliberately boring: it proves the WIRING - flags reach the loader,
// the loader reaches the reporter, the reporter reaches the exit code - over a
// list containing one URL of each shape. What each shape classifies AS is
// pinned by the classifier's own tests, from hand-built results, without Chrome.
//
// It runs the compiled binary as a subprocess rather than calling app.Main in
// process, because the exit code is part of the contract and cmd/pagevet is the
// only thing that produces one.
func TestE2E_Binary(t *testing.T) {
	browsertest.Guard(t)

	// The same discovery the guard used, handed to the binary explicitly: the
	// guard accepts a browser (Edge, a beta channel) that pagevet's own
	// autodetection does not probe for, and a skipped test that would have
	// passed is worse than no test.
	chrome := browsertest.ChromePath(t)

	ctx, cancel := context.WithTimeout(t.Context(), buildTimeout)
	defer cancel()

	bin := buildBinary(ctx, t)
	srv := testfixtures.New(t)

	// srv.URL VERBATIM. Rewriting 127.0.0.1 to "localhost" makes macOS resolve
	// ::1 first while httptest listens on IPv4 only, and Chrome then reports an
	// intermittent net::ERR_CONNECTION_REFUSED.
	urls := writeLines(t,
		srv.URL+"/ok",              // ok
		srv.URL+"/status/404",      // http_error
		srv.URL+"/throw",           // console_error
		srv.URL+"/subresource-404", // subresource_error
		// RFC 6761 reserves .invalid, so this can only ever be NXDOMAIN.
		"http://pagevet-does-not-exist.invalid/", // load_error
	)

	t.Run("a completed run exits 0", func(t *testing.T) {
		logs := filepath.Join(t.TempDir(), "logs")
		code, stdout, stderr := runBinary(ctx, t, bin,
			"-chrome", chrome, "-out", logs, "-concurrency", "2", "-timeout", "20s", urls)

		// Broken pages are this tool's DATA, not its failure. Without
		// -fail-on-errors a run that reached the summary exits 0.
		if code != 0 {
			t.Fatalf("exit code = %d, want 0\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}
		for _, want := range []string{
			"pagevet summary",
			// The arithmetic self-check. A run that printed a summary without
			// this line has counters that do not add up.
			"✓ every URL counted exactly once",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout is missing %q:\n%s", want, stdout)
			}
		}

		// One file per category the list was built to produce.
		for _, name := range []string{
			report.FileOpened,
			report.FileResults,
			report.FileHTTP,
			report.FileConsole,
			report.FileSubresource,
			report.FileLoad,
		} {
			if _, err := os.Stat(filepath.Join(logs, name)); err != nil {
				t.Errorf("%s was not written: %v\n--- stdout ---\n%s", name, err, stdout)
			}
		}
	})

	t.Run("-fail-on-errors exits 1", func(t *testing.T) {
		logs := filepath.Join(t.TempDir(), "logs")
		code, stdout, stderr := runBinary(ctx, t, bin,
			"-chrome", chrome, "-out", logs, "-concurrency", "2", "-timeout", "20s",
			"-fail-on-errors", urls)

		if code != 1 {
			t.Fatalf("exit code = %d, want 1\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "-fail-on-errors set") {
			t.Errorf("the summary does not say why the code is 1:\n%s", stdout)
		}
	})
}

// buildBinary compiles cmd/pagevet into the test's temp directory.
func buildBinary(ctx context.Context, t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving the module root: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "pagevet")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/pagevet")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/pagevet: %v\n%s", err, out)
	}
	return bin
}

// runBinary runs pagevet to completion and reports its exit code and streams.
func runBinary(ctx context.Context, t *testing.T, bin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()

	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	err := cmd.Run()
	switch {
	case err == nil:
		return 0, out.String(), errOut.String()
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), out.String(), errOut.String()
		}
		// Not an exit status: the binary could not be started at all.
		t.Fatalf("running %s: %v\n--- stderr ---\n%s", bin, err, errOut.String())
		return -1, "", ""
	}
}
