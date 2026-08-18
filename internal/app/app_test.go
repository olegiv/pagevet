package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/app"
	"github.com/olegiv/pagevet/internal/input"
	"github.com/olegiv/pagevet/internal/loader"
	"github.com/olegiv/pagevet/internal/loader/fake"
	"github.com/olegiv/pagevet/internal/report"
	"github.com/olegiv/pagevet/internal/verdict"
)

// baseTime fixes the reporter's clock. Nothing in this file asserts on elapsed
// time, but a frozen clock keeps the log files byte-stable so a failure message
// is worth reading.
var baseTime = time.Date(2026, 8, 14, 11, 2, 30, 0, time.UTC)

// hardDeadline bounds every test that starts Run on another goroutine. It exists
// so a deadlock regression FAILS in seconds instead of hanging the suite until
// go test's own timeout kills the whole binary and takes every other result
// with it.
const hardDeadline = 30 * time.Second

// harness is one run's worth of wiring: an output directory, a reporter writing
// into it, and the config the pool runs under. Everything a test varies is the
// loader and the URL list.
type harness struct {
	dir      string
	cfg      app.Config
	policy   verdict.Policy
	rep      *report.Reporter
	progress *bytes.Buffer
}

func newHarness(t *testing.T, concurrency int) *harness {
	t.Helper()

	// A subdirectory of the temp dir, so the reporter has to create it rather
	// than inheriting one go test already made.
	dir := filepath.Join(t.TempDir(), "logs")
	policy := verdict.DefaultPolicy()

	rep, err := report.New(report.Options{
		Dir:    dir,
		Format: report.FormatText,
		Policy: policy,
		Now:    func() time.Time { return baseTime },
		Header: report.Header{
			Version:     app.Version,
			Input:       "urls.txt",
			Concurrency: concurrency,
			Timeout:     30 * time.Second,
			Settle:      1500 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("report.New(%s): %v", dir, err)
	}
	// Close is idempotent, so a test that closes early to read its own files
	// does not fight this cleanup.
	t.Cleanup(func() {
		if err := rep.Close(); err != nil {
			t.Errorf("closing the reporter: %v", err)
		}
	})

	return &harness{
		dir:      dir,
		policy:   policy,
		rep:      rep,
		progress: &bytes.Buffer{},
		cfg: app.Config{
			Input:          "urls.txt",
			Out:            dir,
			Format:         "text",
			Concurrency:    concurrency,
			Timeout:        30 * time.Second,
			Settle:         1500 * time.Millisecond,
			OKStatusMin:    200,
			OKStatusMax:    399,
			FailOnConsole:  true,
			FailOnResource: true,
			MaxConsole:     20,
		},
	}
}

func (h *harness) run(ctx context.Context, urls []string, pl loader.PageLoader) (verdict.Counts, error) {
	return app.Run(ctx, h.cfg, h.policy, parsedFrom(urls), pl, h.rep, h.progress)
}

// finish flushes the logs so the test can read them. The cleanup registered by
// newHarness closes again and gets nil.
func (h *harness) finish(t *testing.T) {
	t.Helper()
	if err := h.rep.Close(); err != nil {
		t.Fatalf("closing the reporter: %v", err)
	}
}

// read returns the contents of one log file, through an *os.Root for the same
// reason the package under test writes through one: it keeps a computed
// directory out of os.Open, and the repo free of gosec suppressions.
func (h *harness) read(t *testing.T, name string) string {
	t.Helper()

	root, err := os.OpenRoot(h.dir)
	if err != nil {
		t.Fatalf("open %s: %v", h.dir, err)
	}
	defer root.Close()

	f, err := root.Open(name)
	if err != nil {
		t.Fatalf("open %s/%s: %v", h.dir, name, err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s/%s: %v", h.dir, name, err)
	}
	return string(b)
}

func (h *harness) exists(t *testing.T, name string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(h.dir, name))
	return err == nil
}

// parsedFrom builds the input.Parsed a real read would have produced for these
// URLs: 1-based indices, one line each, nothing skipped and nothing rejected.
func parsedFrom(urls []string) input.Parsed {
	entries := make([]input.Entry, len(urls))
	for i, u := range urls {
		entries[i] = input.Entry{Index: i + 1, Line: i + 1, URL: u}
	}
	return input.Parsed{Entries: entries, Total: len(urls)}
}

func urlList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "https://example.test/page/" + strconv.Itoa(i+1)
	}
	return out
}

// deadline derives a context that fails the test loudly rather than letting a
// regression hang the run.
func deadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), hardDeadline)
	t.Cleanup(cancel)
	return ctx
}

// waitFor polls cond until it holds or ctx expires, and reports which. Polling
// a CONDITION is the only synchronization used in this file: a sleep long
// enough to "usually" work is how a real race turns into a green build.
func waitFor(ctx context.Context, cond func() bool) bool {
	for {
		if cond() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
		}
	}
}

// okResult is the answer a healthy page gives.
func okResult() verdict.Result {
	return verdict.Result{Status: 200, StatusText: "OK", SettledBy: "load", Started: baseTime, DurationMS: 120}
}

func TestRun_LogsEveryURLExactlyOnce(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 4)
	list := urlList(10)
	f := fake.New()

	counts, err := h.run(deadline(t), list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	if counts.Attempted != len(list) {
		t.Errorf("Attempted = %d, want %d", counts.Attempted, len(list))
	}
	if got := f.CallCount(); got != len(list) {
		t.Errorf("loader was called %d times, want %d", got, len(list))
	}

	// A URL missing here is a dropped page; a URL twice is a double fetch, which
	// doubles that page's weight in every counter downstream.
	seen := make(map[string]int, len(list))
	for _, u := range f.Calls() {
		seen[u]++
	}
	for _, u := range list {
		if seen[u] != 1 {
			t.Errorf("loader saw %s %d times, want exactly 1", u, seen[u])
		}
	}
	if len(seen) != len(list) {
		t.Errorf("loader saw %d distinct URLs, want %d", len(seen), len(list))
	}

	if got := len(openedIndices(t, h.read(t, report.FileOpened))); got != len(list) {
		t.Errorf("%s has %d rows, want %d", report.FileOpened, got, len(list))
	}
}

// TestRun_EmitsInInputOrderUnderConcurrency is the test that protects the
// reorder buffer. The per-URL delays are chosen so completion order cannot
// match input order, and the logs must read top-to-bottom in input order
// anyway: "the third URL" only means something if position is preserved.
func TestRun_EmitsInInputOrderUnderConcurrency(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 4)
	list := urlList(20)
	f := fake.New()
	for i, u := range list {
		f.SetDelay(u, stagger(i+1))
	}

	counts, err := h.run(deadline(t), list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	if counts.Attempted != len(list) {
		t.Fatalf("Attempted = %d, want %d", counts.Attempted, len(list))
	}

	got := openedIndices(t, h.read(t, report.FileOpened))
	if len(got) != len(list) {
		t.Fatalf("%s has %d rows, want %d", report.FileOpened, len(got), len(list))
	}
	for i, n := range got {
		if n != i+1 {
			t.Fatalf("%s row %d has index %d, want %d; emitted order was %v",
				report.FileOpened, i, n, i+1, got)
		}
	}
}

// stagger is a deterministic per-URL delay. Index 1 is made the slowest so the
// head of the line is guaranteed to finish after the URLs behind it, which is
// the case the reorder buffer exists for. The rest is derived from the index by
// arithmetic rather than drawn from math/rand, so a failure reproduces exactly
// instead of "sometimes, on CI".
func stagger(index int) time.Duration {
	if index == 1 {
		return 80 * time.Millisecond
	}
	return time.Duration((index*7)%13+1) * time.Millisecond
}

// TestRun_PendingBoundedByConcurrency proves the non-obvious half of the
// concurrency model: the semaphore slot is released when a result is EMITTED,
// not when its load finishes. A stuck head-of-line URL therefore stops dispatch
// entirely instead of letting the 100 fast URLs behind it pile up in the
// reorder buffer.
func TestRun_PendingBoundedByConcurrency(t *testing.T) {
	t.Parallel()

	const (
		concurrency = 4
		total       = 101
	)
	h := newHarness(t, concurrency)
	list := urlList(total)
	f := fake.New()
	ctx := deadline(t)

	// How many loads had STARTED while the head of the line was still blocked.
	// Releasing on emit pins this at exactly Concurrency; releasing on
	// completion would let it climb towards total.
	var startedWhileBlocked atomic.Int64

	f.SetFunc(func(fnCtx context.Context, _ int, rawURL string) (verdict.Result, error) {
		if rawURL != list[0] {
			return okResult(), nil
		}
		// The head blocks until the pool has dispatched everything it is
		// allowed to, then records what that was. If the condition never holds
		// the poll gives up and the assertion below fails - it never hangs.
		waitFor(fnCtx, func() bool { return f.CallCount() >= concurrency })
		startedWhileBlocked.Store(int64(f.CallCount()))
		return okResult(), nil
	})

	counts, err := h.run(ctx, list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	if counts.Attempted != total {
		t.Errorf("Attempted = %d, want %d", counts.Attempted, total)
	}
	if got := f.MaxConcurrent(); got > concurrency {
		t.Errorf("MaxConcurrent = %d, want at most %d", got, concurrency)
	}
	if got := startedWhileBlocked.Load(); got != concurrency {
		t.Errorf("%d loads had started while URL 1 was blocked, want exactly %d: "+
			"the pool dispatched past a head-of-line stall, so the reorder buffer is unbounded",
			got, concurrency)
	}
}

// TestRun_CountsPartitionAttempted feeds one result of every shape and checks
// the counters still partition Attempted. That partition is what lets the
// summary claim every URL was counted exactly once.
func TestRun_CountsPartitionAttempted(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 3)
	list := urlList(6)
	f := fake.New()

	f.SetResult(list[0], okResult(), nil)
	f.SetResult(list[1], verdict.Result{Status: 500, StatusText: "Internal Server Error", SettledBy: "load"}, nil)
	f.SetResult(list[2], verdict.Result{
		Status:    200,
		SettledBy: "load",
		Console: []verdict.ConsoleError{
			{Kind: verdict.KindException, Text: "TypeError: Cannot read properties of null (reading 'total')", Count: 2},
		},
	}, nil)
	f.SetResult(list[3], verdict.Result{
		Status:    200,
		SettledBy: "load",
		Resources: []verdict.ResourceError{
			{URL: "https://example.test/missing-bundle.js", Type: "Script", Status: 404, Count: 1},
		},
	}, nil)
	f.SetResult(list[4], verdict.Result{TimedOut: true, SettledBy: "deadline"}, nil)
	f.SetResult(list[5], verdict.Result{
		NetError: "net::ERR_NAME_NOT_RESOLVED", NetErrorClass: "DNS", SettledBy: "netfail",
	}, nil)

	counts, err := h.run(deadline(t), list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	if !counts.Invariant() {
		t.Error("Counts.Invariant() = false: a result was counted under no outcome, or under two")
	}
	if counts.Attempted != len(list) {
		t.Errorf("Attempted = %d, want %d", counts.Attempted, len(list))
	}
	if got := counts.OK() + counts.Errored(); got != counts.Attempted {
		t.Errorf("OK()+Errored() = %d, want Attempted = %d", got, counts.Attempted)
	}

	for _, tc := range []struct {
		outcome verdict.Outcome
		want    int
	}{
		{verdict.OutcomeOK, 1},
		{verdict.OutcomeHTTPError, 1},
		{verdict.OutcomeConsoleError, 1},
		{verdict.OutcomeSubresourceError, 1},
		{verdict.OutcomeTimeout, 1},
		{verdict.OutcomeLoadError, 1},
	} {
		if got := counts.Get(tc.outcome); got != tc.want {
			t.Errorf("Get(%s) = %d, want %d", tc.outcome, got, tc.want)
		}
	}

	// The overlapping tallies deliberately do not partition anything, but they
	// still have to count what actually happened.
	if counts.PagesWithConsoleErrors != 1 || counts.ConsoleEvents != 2 {
		t.Errorf("console tallies = %d pages / %d events, want 1 / 2",
			counts.PagesWithConsoleErrors, counts.ConsoleEvents)
	}
	if counts.PagesWithResourceErrors != 1 || counts.ResourceEvents != 1 {
		t.Errorf("subresource tallies = %d pages / %d events, want 1 / 1",
			counts.PagesWithResourceErrors, counts.ResourceEvents)
	}

	// Only errored URLs go to stderr, and every one of them does.
	if got := strings.Count(strings.TrimSpace(h.progress.String()), "\n") + 1; got != counts.Errored() {
		t.Errorf("progress printed %d lines, want %d (one per errored URL):\n%s",
			got, counts.Errored(), h.progress.String())
	}
}

// TestRun_BothErrorCategoriesWriteToBothFiles pins the deliberate duplication:
// a page that is both a 500 and a JS error is classified once, but appears in
// both error logs. Someone triaging console errors must not have to know the
// page was also a 500 to find it.
func TestRun_BothErrorCategoriesWriteToBothFiles(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 1)
	list := urlList(1)
	f := fake.New()
	f.SetResult(list[0], verdict.Result{
		Status: 500, StatusText: "Internal Server Error", SettledBy: "load",
		Console: []verdict.ConsoleError{
			{Kind: verdict.KindConsoleAPI, Text: "boom 42", Count: 1},
		},
	}, nil)

	counts, err := h.run(deadline(t), list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	// Classification stays single-valued: http_error outranks console_error.
	if got := counts.Get(verdict.OutcomeHTTPError); got != 1 {
		t.Errorf("http_error count = %d, want 1", got)
	}
	if got := counts.Get(verdict.OutcomeConsoleError); got != 0 {
		t.Errorf("console_error count = %d, want 0: the counters must not double-count", got)
	}

	httpLog := h.read(t, report.FileHTTP)
	consoleLog := h.read(t, report.FileConsole)
	for name, body := range map[string]string{
		report.FileHTTP:    httpLog,
		report.FileConsole: consoleLog,
	} {
		if !strings.Contains(body, list[0]) {
			t.Errorf("%s does not mention %s:\n%s", name, list[0], body)
		}
	}
	// Each block states the outcome of the file it lives in, and cross-refers
	// to the other.
	if !strings.Contains(httpLog, "outcome=http_error") {
		t.Errorf("%s does not carry outcome=http_error:\n%s", report.FileHTTP, httpLog)
	}
	if !strings.Contains(consoleLog, "outcome=console_error") {
		t.Errorf("%s does not carry outcome=console_error:\n%s", report.FileConsole, consoleLog)
	}
	if !strings.Contains(httpLog, report.FileConsole) || !strings.Contains(consoleLog, report.FileHTTP) {
		t.Error("the two blocks do not cross-reference each other")
	}
}

// TestRun_LogsURLEvenWhenPageFails: opened.log is the record of what was
// touched, not of what worked. A URL that never produced a response still
// belongs in it.
func TestRun_LogsURLEvenWhenPageFails(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 1)
	list := urlList(1)
	f := fake.New()
	f.SetResult(list[0], verdict.Result{
		NetError: "net::ERR_NAME_NOT_RESOLVED", NetErrorClass: "DNS", SettledBy: "netfail",
	}, nil)

	counts, err := h.run(deadline(t), list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	if got := counts.Get(verdict.OutcomeLoadError); got != 1 {
		t.Fatalf("load_error count = %d, want 1", got)
	}
	opened := h.read(t, report.FileOpened)
	for _, want := range []string{list[0], "load_error", "net::ERR_NAME_NOT_RESOLVED"} {
		if !strings.Contains(opened, want) {
			t.Errorf("%s is missing %q:\n%s", report.FileOpened, want, opened)
		}
	}
}

// TestRun_FatalLoaderErrorIsReported: a non-nil loader error means the browser
// is gone, which is a TOOL failure. Run has to hand it back so Main can exit 3
// rather than reporting a clean run over pages it never opened.
func TestRun_FatalLoaderErrorIsReported(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 2)
	list := urlList(5)
	f := fake.New()
	f.SetDefault(verdict.Result{}, loader.ErrBrowserUnavailable)

	counts, err := h.run(deadline(t), list, f)
	h.finish(t)

	if !errors.Is(err, loader.ErrBrowserUnavailable) {
		t.Fatalf("Run error = %v, want one wrapping loader.ErrBrowserUnavailable", err)
	}
	if counts.Attempted != 0 {
		t.Errorf("Attempted = %d, want 0: nothing was successfully loaded", counts.Attempted)
	}
	if counts.NotRun != len(list) {
		t.Errorf("NotRun = %d, want %d", counts.NotRun, len(list))
	}
}

// TestRun_HonorsCancellation: Ctrl-C has to end the run promptly, account for
// the URLs that never ran, and say why. The hard deadline is failure detection,
// not synchronization - a regression that deadlocks fails here instead of
// hanging the suite.
func TestRun_HonorsCancellation(t *testing.T) {
	t.Parallel()

	const concurrency = 2
	h := newHarness(t, concurrency)
	list := urlList(50)
	f := fake.New()
	for _, u := range list {
		// Long enough that nothing finishes on its own; the fake returns
		// ctx.Err() the moment the context dies.
		f.SetDelay(u, time.Hour)
	}

	hard := deadline(t)
	runCtx, cancel := context.WithCancel(hard)
	defer cancel()

	type outcome struct {
		counts verdict.Counts
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		c, err := h.run(runCtx, list, f)
		done <- outcome{counts: c, err: err}
	}()

	if !waitFor(hard, func() bool { return f.CallCount() >= concurrency }) {
		t.Fatal("the pool never dispatched anything")
	}
	cancel()

	var got outcome
	select {
	case got = <-done:
	case <-hard.Done():
		t.Fatal("Run did not return after its context was canceled")
	}
	h.finish(t)

	if !errors.Is(got.err, context.Canceled) {
		t.Errorf("Run error = %v, want one wrapping context.Canceled", got.err)
	}
	if got.counts.NotRun == 0 {
		t.Error("NotRun = 0, want the URLs the interrupt cost us to be accounted for")
	}
	// Every input line ends up in exactly one of the two buckets. A line in
	// neither is a URL that silently disappeared from the report.
	if total := got.counts.Attempted + got.counts.NotRun; total != len(list) {
		t.Errorf("Attempted+NotRun = %d, want %d", total, len(list))
	}
}

// TestRun_PreCanceledContextRunsNothing is the degenerate case of the same
// path: a run whose context is already dead must dispatch nothing, report every
// line as not-run, and return - rather than crawling a list the user has
// already given up on.
func TestRun_PreCanceledContextRunsNothing(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 4)
	list := urlList(50)
	f := fake.New()
	for _, u := range list {
		// The delay is never waited out: the fake abandons it the moment the
		// context is done, which is how a real loader answers too.
		f.SetDelay(u, time.Hour)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	counts, err := h.run(ctx, list, f)
	h.finish(t)

	// Whether a given entry loses the dispatch race or is dispatched and comes
	// straight back canceled is up to the scheduler; either way nothing loads.
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want nil or one wrapping context.Canceled", err)
	}
	if counts.Attempted != 0 {
		t.Errorf("Attempted = %d, want 0", counts.Attempted)
	}
	if counts.NotRun != len(list) {
		t.Errorf("NotRun = %d, want %d: every line has to be accounted for", counts.NotRun, len(list))
	}
	if h.exists(t, report.FileOpened) {
		t.Errorf("%s was created for a run that opened nothing", report.FileOpened)
	}
}

// TestRun_RecoversWorkerPanic: one page must not be able to end a 10,000-URL
// crawl. The panic becomes that URL's load error and the rest of the run
// continues.
func TestRun_RecoversWorkerPanic(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 2)
	list := urlList(5)
	f := fake.New()
	f.SetFunc(func(_ context.Context, _ int, rawURL string) (verdict.Result, error) {
		if rawURL == list[2] {
			panic("collector fell over")
		}
		return okResult(), nil
	})

	counts, err := h.run(deadline(t), list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	if counts.Attempted != len(list) {
		t.Errorf("Attempted = %d, want %d: the surviving URLs must still be reported", counts.Attempted, len(list))
	}
	if got := counts.Get(verdict.OutcomeLoadError); got != 1 {
		t.Errorf("load_error count = %d, want 1", got)
	}
	if got := counts.OK(); got != len(list)-1 {
		t.Errorf("ok count = %d, want %d", got, len(list)-1)
	}

	// The panic is recorded honestly rather than as a mystery empty result.
	opened := h.read(t, report.FileOpened)
	if !strings.Contains(opened, "internal panic: collector fell over") {
		t.Errorf("%s does not carry the panic:\n%s", report.FileOpened, opened)
	}
	loadLog := h.read(t, report.FileLoad)
	if !strings.Contains(loadLog, list[2]) {
		t.Errorf("%s does not mention the panicking URL:\n%s", report.FileLoad, loadLog)
	}
}

// TestRun_WritesAllExpectedFiles: opened.log and results.jsonl are always
// there, and an error log exists only when that category actually occurred. An
// empty errors-console.log reads as "checked and clean" to some people and as
// "the tool broke" to others; the absence of the file is unambiguous.
func TestRun_WritesAllExpectedFiles(t *testing.T) {
	t.Parallel()

	errorLogs := []string{
		report.FileErrors,
		report.FileHTTP,
		report.FileConsole,
		report.FileSubresource,
		report.FileLoad,
	}

	t.Run("a clean run leaves no error logs at all", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, 2)
		list := urlList(4)
		if _, err := h.run(deadline(t), list, fake.New()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		h.finish(t)

		for _, name := range []string{report.FileOpened, report.FileResults} {
			if !h.exists(t, name) {
				t.Errorf("%s is missing", name)
			}
		}
		for _, name := range errorLogs {
			if h.exists(t, name) {
				t.Errorf("%s exists after a run with no errors", name)
			}
		}
	})

	t.Run("only the categories that occurred get a file", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, 2)
		list := urlList(3)
		f := fake.New()
		f.SetResult(list[1], verdict.Result{
			Status: 200, SettledBy: "load",
			Console: []verdict.ConsoleError{{Kind: verdict.KindConsoleAPI, Text: "boom 42", Count: 1}},
		}, nil)
		f.SetResult(list[2], verdict.Result{
			NetError: "net::ERR_CONNECTION_REFUSED", NetErrorClass: "CONNECT", SettledBy: "netfail",
		}, nil)

		if _, err := h.run(deadline(t), list, f); err != nil {
			t.Fatalf("Run: %v", err)
		}
		h.finish(t)

		want := map[string]bool{
			report.FileOpened:      true,
			report.FileResults:     true,
			report.FileConsole:     true,
			report.FileLoad:        true,
			report.FileErrors:      false, // -combined-error-log is off
			report.FileHTTP:        false,
			report.FileSubresource: false,
		}
		for name, shouldExist := range want {
			if got := h.exists(t, name); got != shouldExist {
				t.Errorf("exists(%s) = %v, want %v", name, got, shouldExist)
			}
		}
	})
}

// TestRun_ResultsJSONLIsOneObjectPerLine: results.jsonl is the machine-readable
// ledger, so every line has to stand alone as a complete object - that is what
// makes `tail -f | jq` work on a run that is still going.
func TestRun_ResultsJSONLIsOneObjectPerLine(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 4)
	list := urlList(12)
	f := fake.New()
	f.SetResult(list[3], verdict.Result{Status: 404, StatusText: "Not Found", SettledBy: "load"}, nil)
	f.SetResult(list[7], verdict.Result{
		Status: 200, SettledBy: "load",
		Console: []verdict.ConsoleError{{Kind: verdict.KindException, Text: "TypeError: x is not a function", Count: 1}},
	}, nil)

	counts, err := h.run(deadline(t), list, f)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	lines := strings.Split(strings.TrimSuffix(h.read(t, report.FileResults), "\n"), "\n")
	if len(lines) != counts.Attempted {
		t.Fatalf("%s has %d lines, want %d (one per attempted URL)", report.FileResults, len(lines), counts.Attempted)
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%s line %d is not a JSON object: %v\n%s", report.FileResults, i+1, err, line)
		}
		if _, ok := rec["outcome"]; !ok {
			t.Errorf("%s line %d has no \"outcome\" key: %s", report.FileResults, i+1, line)
		}
		if got, ok := rec["i"].(float64); !ok || int(got) != i+1 {
			t.Errorf("%s line %d has index %v, want %d", report.FileResults, i+1, rec["i"], i+1)
		}
	}
}

// TestRun_EmitFailureIsFatal: a log file that cannot be written makes the run's
// output incomplete, and the exit code has to say so rather than reporting a
// tidy summary over records that never reached the disk. A reporter closed
// before the run is the cheapest way to make every Emit fail.
func TestRun_EmitFailureIsFatal(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 2)
	list := urlList(4)
	h.finish(t)

	counts, err := h.run(deadline(t), list, fake.New())
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Run error = %v, want one wrapping os.ErrClosed", err)
	}
	// The counters are updated before the write is attempted, so the summary
	// still describes what was loaded.
	if counts.Attempted != len(list) {
		t.Errorf("Attempted = %d, want %d", counts.Attempted, len(list))
	}
}

// TestRun_FlushesResultsStrandedByAGap: when the head of the line is lost - a
// dead browser, a Ctrl-C - the index it would have occupied never arrives, and
// everything behind it sits in the reorder buffer waiting for it. Those results
// completed, so they still have to reach the logs instead of being dropped
// along with the gap. That is the whole reason OrderedSink has a Flush.
func TestRun_FlushesResultsStrandedByAGap(t *testing.T) {
	t.Parallel()

	// Concurrency equal to the list length, so every URL is dispatched before
	// the drain can see the first one fail. That makes the gap deterministic.
	const total = 4

	newLoader := func(list []string) *fake.FakeLoader {
		f := fake.New()
		f.SetResult(list[0], verdict.Result{}, loader.ErrBrowserUnavailable)
		return f
	}

	t.Run("the results behind the gap still reach the logs", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, total)
		list := urlList(total)

		counts, err := h.run(deadline(t), list, newLoader(list))
		h.finish(t)

		if !errors.Is(err, loader.ErrBrowserUnavailable) {
			t.Fatalf("Run error = %v, want one wrapping loader.ErrBrowserUnavailable", err)
		}
		if counts.NotRun != 1 || counts.Attempted != total-1 {
			t.Errorf("Attempted/NotRun = %d/%d, want %d/1", counts.Attempted, counts.NotRun, total-1)
		}

		// Still in index order, and still missing exactly the lost one.
		got := openedIndices(t, h.read(t, report.FileOpened))
		want := []int{2, 3, 4}
		if len(got) != len(want) {
			t.Fatalf("%s has rows %v, want %v", report.FileOpened, got, want)
		}
		for i, n := range got {
			if n != want[i] {
				t.Fatalf("%s has rows %v, want %v", report.FileOpened, got, want)
			}
		}
	})

	t.Run("a flush that cannot write is still a run failure", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, total)
		list := urlList(total)
		h.finish(t)

		counts, err := h.run(deadline(t), list, newLoader(list))
		if err == nil {
			t.Fatal("Run succeeded with a reporter that cannot be written to, want an error")
		}
		if counts.Attempted != total-1 {
			t.Errorf("Attempted = %d, want %d", counts.Attempted, total-1)
		}
	})
}

// TestRun_DuplicateIndexIsReported: Run trusts its caller for the entry
// indices, and the ordered sink is the thing that notices when that trust was
// misplaced. Emitting the same position twice would silently duplicate a log
// record, so it becomes a run error instead.
func TestRun_DuplicateIndexIsReported(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 1)
	parsed := input.Parsed{
		Entries: []input.Entry{
			{Index: 1, Line: 1, URL: "https://example.test/a"},
			{Index: 1, Line: 2, URL: "https://example.test/b"},
		},
		Total: 2,
	}

	_, err := app.Run(deadline(t), h.cfg, h.policy, parsed, fake.New(), h.rep, h.progress)
	h.finish(t)

	if err == nil {
		t.Fatal("Run succeeded on entries that share an index, want an error")
	}
	if !strings.Contains(err.Error(), "already emitted") {
		t.Errorf("Run error = %v, want it to name the duplicate position", err)
	}
}

// TestRun_ProgressIsQuietOnSuccess: the per-URL progress stream is for failures.
// A clean run of 10,000 URLs must not print 10,000 lines nobody reads.
func TestRun_ProgressIsQuietOnSuccess(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 2)
	list := urlList(5)

	if _, err := h.run(deadline(t), list, fake.New()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	if h.progress.Len() != 0 {
		t.Errorf("a clean run wrote progress output:\n%s", h.progress.String())
	}
}

// TestRun_ProgressLines pins the shape of the one stream a user actually
// watches: index, outcome, status, URL, and a detail that says which of the
// three error categories it was.
func TestRun_ProgressLines(t *testing.T) {
	t.Parallel()

	h := newHarness(t, 1)
	list := urlList(4)
	f := fake.New()
	f.SetResult(list[0], verdict.Result{Status: 500, StatusText: "Internal Server Error", SettledBy: "load"}, nil)
	f.SetResult(list[1], verdict.Result{
		Status: 200, SettledBy: "load",
		Console: []verdict.ConsoleError{{Kind: verdict.KindConsoleAPI, Text: "boom 42", Count: 1}},
	}, nil)
	f.SetResult(list[2], verdict.Result{
		Status: 200, SettledBy: "load",
		Resources: []verdict.ResourceError{{URL: "https://example.test/missing-bundle.js", Type: "Script", Status: 404, Count: 1}},
	}, nil)
	f.SetResult(list[3], verdict.Result{
		NetError: "net::ERR_NAME_NOT_RESOLVED", NetErrorClass: "DNS", SettledBy: "netfail",
	}, nil)

	if _, err := h.run(deadline(t), list, f); err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.finish(t)

	got := h.progress.String()
	for _, want := range []string{
		"[  1/4] http_error",
		"500",
		"console error(s)",
		"failed subresource(s)",
		"load_error",
		// A result with no status prints a dash, because zero is not a status.
		"net::ERR_NAME_NOT_RESOLVED",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("progress output is missing %q:\n%s", want, got)
		}
	}
}

// openedIndices returns the input ordinals of opened.log's data rows, in file
// order. Header lines are the ones starting with '#'; a data row starts with
// its timestamp.
func openedIndices(t *testing.T, body string) []int {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(body), "\n")
	out := make([]int, 0, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("unparseable %s row %q", report.FileOpened, line)
		}
		n, err := strconv.Atoi(strings.TrimPrefix(fields[1], "#"))
		if err != nil {
			t.Fatalf("%s row %q carries no index tag: %v", report.FileOpened, line, err)
		}
		out = append(out, n)
	}
	return out
}

// --- Main: the paths that need no browser ------------------------------------

// runMain calls Main with its two streams captured, which is the whole reason
// Main returns a code instead of calling os.Exit.
func runMain(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = app.Main(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// The expectation is deliberately the UNSTAMPED rendering. A `go test` binary
// is linked without -X, so app.Commit and app.BuildTime are empty and -version
// prints the same single line it printed before stamping existed. The stamped
// forms are covered by TestVersionLine.
func TestMain_Version(t *testing.T) {
	t.Parallel()

	code, stdout, _ := runMain(t, "-version")
	if code != app.ExitOK {
		t.Errorf("exit code = %d, want %d", code, app.ExitOK)
	}
	if want := "pagevet " + app.Version + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if app.Version != "0.1.0" {
		t.Errorf("Version = %q, want 0.1.0", app.Version)
	}
}

func TestMain_Help(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runMain(t, "-help")
	if code != app.ExitOK {
		t.Errorf("exit code = %d, want %d: asking for help is not an error", code, app.ExitOK)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing: the usage text goes to stderr", stdout)
	}
	if !strings.Contains(stderr, "usage: pagevet") {
		t.Errorf("stderr does not carry the usage text:\n%s", stderr)
	}
}

func TestMain_UsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		wantText []string
	}{
		{
			name:     "a rejected flag value",
			args:     []string{"-concurrency", "0", "urls.txt"},
			wantText: []string{"-concurrency", "Run 'pagevet -help' for usage."},
		},
		{
			name:     "an unknown flag",
			args:     []string{"-not-a-flag", "urls.txt"},
			wantText: []string{"not-a-flag"},
		},
		{
			name:     "no input file",
			args:     nil,
			wantText: []string{"no input file"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, _, stderr := runMain(t, tc.args...)
			if code != app.ExitUsage {
				t.Errorf("exit code = %d, want %d", code, app.ExitUsage)
			}
			for _, want := range tc.wantText {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr is missing %q:\n%s", want, stderr)
				}
			}
		})
	}
}

func TestMain_UnreadableInput(t *testing.T) {
	t.Parallel()

	t.Run("a missing file in a directory that exists", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "does-not-exist.txt")
		code, _, stderr := runMain(t, path)
		if code != app.ExitUsage {
			t.Errorf("exit code = %d, want %d", code, app.ExitUsage)
		}
		if !strings.Contains(stderr, path) {
			t.Errorf("stderr does not name the file it could not read:\n%s", stderr)
		}
	})

	t.Run("a path whose directory does not exist", func(t *testing.T) {
		t.Parallel()

		const path = "/nonexistent/file.txt"
		code, _, stderr := runMain(t, path)
		if code != app.ExitUsage {
			t.Errorf("exit code = %d, want %d", code, app.ExitUsage)
		}
		if !strings.Contains(stderr, path) {
			t.Errorf("stderr does not name the file it could not read:\n%s", stderr)
		}
	})
}

// TestMain_NoUsableURLs: a list that parses fine but yields nothing to crawl is
// a usage problem, not a clean run of zero URLs. Exiting 0 there would let a CI
// job go green on an empty input.
func TestMain_NoUsableURLs(t *testing.T) {
	t.Parallel()

	path := writeLines(t,
		"# every line here is a comment or blank",
		"",
		"   ",
		"# https://example.test/ (commented out)",
	)

	code, _, stderr := runMain(t, path)
	if code != app.ExitUsage {
		t.Errorf("exit code = %d, want %d", code, app.ExitUsage)
	}
	if !strings.Contains(stderr, "contains no valid http/https URLs") {
		t.Errorf("stderr does not explain the empty list:\n%s", stderr)
	}
}

// TestMain_RejectedSchemesAreReportedWithLineNumbers: the scheme allowlist is
// the program's primary security control, and a rejection is only actionable if
// the user can find the line it came from.
func TestMain_RejectedSchemesAreReportedWithLineNumbers(t *testing.T) {
	t.Parallel()

	path := writeLines(t,
		"javascript:alert(1)",
		"file:///etc/passwd",
		"data:text/html,<h1>x</h1>",
	)

	code, _, stderr := runMain(t, path)
	if code != app.ExitUsage {
		t.Errorf("exit code = %d, want %d", code, app.ExitUsage)
	}
	for _, want := range []string{
		path + ":1: skipping",
		path + ":2: skipping",
		path + ":3: skipping",
		"javascript",
		"file",
		"data",
		"unsupported URL scheme",
		"contains no valid http/https URLs",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}
}

// TestMain_BrowserFailureIsInternal: a Chrome that cannot be started is a TOOL
// failure, not a page failure. The split between exit 2 and exit 3 is what
// makes the alert unambiguous in CI, so it is asserted rather than assumed.
//
// The path below never launches anything: ResolveChromePath rejects it before
// any process is created, which is what keeps this test browser-free.
func TestMain_BrowserFailureIsInternal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		extra []string
	}{
		{name: "plain"},
		// -debug-chrome only forwards Chrome's own output to stderr. It must
		// not change which exit code a failed start produces.
		{name: "with -debug-chrome", extra: []string{"-debug-chrome"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := writeLines(t, "https://example.test/")
			missingChrome := filepath.Join(t.TempDir(), "no-such-chrome")

			args := append([]string{"-chrome", missingChrome}, tc.extra...)
			code, _, stderr := runMain(t, append(args, path)...)
			if code != app.ExitInternal {
				t.Errorf("exit code = %d, want %d", code, app.ExitInternal)
			}
			if !strings.Contains(stderr, missingChrome) {
				t.Errorf("stderr does not name the browser path that failed:\n%s", stderr)
			}
		})
	}
}

// writeLines writes a URL list into the test's own temp directory and returns
// its path.
func writeLines(t *testing.T, lines ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "urls.txt")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}
