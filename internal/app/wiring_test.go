package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/loader"
	"github.com/olegiv/pagevet/internal/loader/fake"
	"github.com/olegiv/pagevet/internal/verdict"
)

// These tests drive run() end to end through the newBrowser seam, which is the
// only reason the reporter wiring, the injected exit-code policy, the summary
// and all five exit codes can be exercised without launching Chrome. Everything
// here would otherwise need a subprocess and a real browser.

// fakeBrowser adapts a fake.FakeLoader to the browser interface run expects.
type fakeBrowser struct {
	*fake.FakeLoader
	closed bool
}

func (f *fakeBrowser) Describe() string { return "FakeChrome/0.0 (headless, JavaScript enabled)" }
func (f *fakeBrowser) Close()           { f.closed = true }

// factoryFor returns a newBrowser that always yields fb, and records the
// loader.Options run assembled from the Config - which is the only place that
// translation is observable.
func factoryFor(fb *fakeBrowser, got *loader.Options) newBrowser {
	return func(o loader.Options) (browser, error) {
		if got != nil {
			*got = o
		}
		return fb, nil
	}
}

// deadline bounds every wiring test. A regression in the pool or the drain
// should fail the suite, not hang it - and these tests are in the internal test
// package, so they cannot borrow the helper of the same name from app_test.
func deadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// writeURLs puts a URL list in a temp dir and returns its path.
func writeURLs(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	return path
}

// runCfg is a Config with the defaults ParseFlags would have produced, pointed
// at the given input and output directory.
func runCfg(t *testing.T, input string) Config {
	t.Helper()
	return Config{
		Input:          input,
		Out:            filepath.Join(t.TempDir(), "logs"),
		Format:         "text",
		Concurrency:    2,
		Timeout:        30 * time.Second,
		Settle:         0,
		OKStatusMin:    200,
		OKStatusMax:    399,
		FailOnConsole:  true,
		FailOnResource: true,
		MaxConsole:     20,
		Quiet:          true,
	}
}

func TestRunWiring_CleanRunExitsZeroAndWritesSummary(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://a.test/", "https://b.test/")
	cfg := runCfg(t, in)

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 200, SettledBy: "load"}, nil)

	var stdout, stderr bytes.Buffer
	code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

	if code != ExitOK {
		t.Errorf("exit = %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}
	if !fb.closed {
		t.Error("the browser was never closed; on macOS that leaks a Chrome process")
	}

	out := stdout.String()
	for _, want := range []string{
		"pagevet summary",
		"attempted                   2",
		"every URL counted exactly once",
		"FakeChrome/0.0",
		"run completed; no errors",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestRunWiring_ErroredRunStillExitsZero(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://ok.test/", "https://gone.test/")
	cfg := runCfg(t, in)

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 200, SettledBy: "load"}, nil)
	fb.SetResult("https://gone.test/", verdict.Result{Status: 404, SettledBy: "load"}, nil)

	var stdout, stderr bytes.Buffer
	code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

	// Broken pages are this tool's OUTPUT, not its failure.
	if code != ExitOK {
		t.Errorf("exit = %d, want %d: a completed run reports page errors as data", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "run completed; 1 URLs had errors") {
		t.Errorf("summary did not report the error count:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.Out, "errors-http.log")); err != nil {
		t.Errorf("errors-http.log was not written: %v", err)
	}
}

func TestRunWiring_FailOnErrorsExitsOne(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://gone.test/")
	cfg := runCfg(t, in)
	cfg.FailOnErrors = true

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 500, SettledBy: "load"}, nil)

	var stdout, stderr bytes.Buffer
	code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

	if code != ExitPageErrors {
		t.Errorf("exit = %d, want %d", code, ExitPageErrors)
	}
	if !strings.Contains(stdout.String(), "-fail-on-errors set") {
		t.Errorf("summary did not explain the non-zero code:\n%s", stdout.String())
	}
}

func TestRunWiring_BrowserFailureExitsInternal(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://a.test/")
	cfg := runCfg(t, in)

	boom := errors.New("chrome would not start")
	factory := func(loader.Options) (browser, error) {
		return nil, boom
	}

	var stdout, stderr bytes.Buffer
	code := run(deadline(t), cfg, factory, &stdout, &stderr)

	// A browser that will not start is a TOOL failure, which must not look the
	// same as "your pages are broken".
	if code != ExitInternal {
		t.Errorf("exit = %d, want %d", code, ExitInternal)
	}
	if !strings.Contains(stderr.String(), boom.Error()) {
		t.Errorf("stderr did not name the cause: %s", stderr.String())
	}
}

func TestRunWiring_FatalLoaderErrorExitsInternal(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://a.test/")
	cfg := runCfg(t, in)

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{}, loader.ErrBrowserUnavailable)

	var stdout, stderr bytes.Buffer
	code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

	if code != ExitInternal {
		t.Errorf("exit = %d, want %d", code, ExitInternal)
	}
	// The summary still prints: a run that died halfway is exactly when the
	// partial counts matter most.
	if !strings.Contains(stdout.String(), "pagevet summary") {
		t.Errorf("no summary after a fatal loader error:\n%s", stdout.String())
	}
}

func TestRunWiring_CanceledContextExitsInterrupted(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://a.test/", "https://b.test/")
	cfg := runCfg(t, in)

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 200, SettledBy: "load"}, nil)

	ctx, cancel := context.WithCancel(deadline(t))
	cancel()

	var stdout, stderr bytes.Buffer
	code := run(ctx, cfg, factoryFor(fb, nil), &stdout, &stderr)

	if code != ExitInterrupted {
		t.Errorf("exit = %d, want %d", code, ExitInterrupted)
	}
}

func TestRunWiring_UnwritableOutputDirExitsInternal(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://a.test/")
	cfg := runCfg(t, in)

	// A regular file where the output directory should be: MkdirAll fails, and
	// that is a tool failure rather than a usage error.
	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	cfg.Out = blocker

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 200, SettledBy: "load"}, nil)

	var stdout, stderr bytes.Buffer
	code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

	if code != ExitInternal {
		t.Errorf("exit = %d, want %d (stderr: %s)", code, ExitInternal, stderr.String())
	}
}

// TestRunWiring_ConfigReachesLoaderOptions pins the Config-to-Options
// translation, including the two fields that inverate: -headed means NOT
// headless, and -log-full-urls means NOT redacting.
func TestRunWiring_ConfigReachesLoaderOptions(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://a.test/")
	cfg := runCfg(t, in)
	cfg.Timeout = 12 * time.Second
	cfg.Settle = 3 * time.Second
	cfg.Headed = true
	cfg.SiteIsolation = true
	cfg.UserAgent = "pagevet-test/1.0"
	cfg.MaxConsole = 7
	cfg.ConsoleWarnings = true
	cfg.LogFullURLs = true

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 200, SettledBy: "load"}, nil)

	var got loader.Options
	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, &got), &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"Timeout", got.Timeout, 12 * time.Second},
		{"Settle", got.Settle, 3 * time.Second},
		{"Headless", got.Headless, false},
		{"SiteIsolation", got.SiteIsolation, true},
		{"UserAgent", got.UserAgent, "pagevet-test/1.0"},
		{"MaxConsolePerPage", got.MaxConsolePerPage, 7},
		{"ConsoleWarnings", got.ConsoleWarnings, true},
		{"RedactURLs", got.RedactURLs, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("Options.%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestRunWiring_CombinedErrorLog checks the one output-shape flag that changes
// which files exist rather than what is in them.
func TestRunWiring_CombinedErrorLog(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://gone.test/")
	cfg := runCfg(t, in)
	cfg.Combined = true

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 404, SettledBy: "load"}, nil)

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}

	if _, err := os.Stat(filepath.Join(cfg.Out, "errors.log")); err != nil {
		t.Errorf("combined errors.log missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Out, "errors-http.log")); !os.IsNotExist(err) {
		t.Errorf("per-category file written despite -combined-error-log (err = %v)", err)
	}
}

// TestRunWiring_ProgressGoesToStderr keeps stdout clean enough to redirect:
// `pagevet urls.txt > report.txt` must yield only the summary.
func TestRunWiring_ProgressGoesToStderr(t *testing.T) {
	t.Parallel()

	in := writeURLs(t, "https://gone.test/")
	cfg := runCfg(t, in)
	cfg.Quiet = false

	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetDefault(verdict.Result{Status: 500, SettledBy: "load"}, nil)

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}

	if !strings.Contains(stderr.String(), "http_error") {
		t.Errorf("progress line not on stderr: %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "[  1/1]") {
		t.Errorf("progress leaked into stdout:\n%s", stdout.String())
	}
}
