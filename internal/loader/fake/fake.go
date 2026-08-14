// Package fake provides a scriptable loader.PageLoader that never launches a
// browser.
//
// It is what makes the worker pool, the reporter, the exit-code logic and the
// whole app package testable in milliseconds and without Chrome: a test states
// what each URL should "load" as, and the code under test cannot tell the
// difference.
//
// Every method is safe for concurrent use. That is not decoration — the pool
// calls Load from N goroutines and the app tests run under -race, so an
// unguarded map here would show up as a flaky data race in somebody else's
// package.
package fake

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/olegiv/pagevet/internal/loader"
	"github.com/olegiv/pagevet/internal/verdict"
)

// Compile-time proof that the fake is substitutable for the real browser
// loader. If the interface ever changes, this line breaks before any test does.
var _ loader.PageLoader = (*FakeLoader)(nil)

// LoadFunc is a full manual override of Load's answer, installed by SetFunc.
// It receives exactly what Load received.
type LoadFunc func(ctx context.Context, index int, rawURL string) (verdict.Result, error)

// scripted is one canned answer: the Result to hand back and the loader-level
// error to return alongside it.
type scripted struct {
	res verdict.Result
	err error
}

// FakeLoader is a PageLoader whose every answer is dictated by the test.
//
// Resolution order for one call, highest first:
//
//	SetFunc > SetResult (exact URL match) > SetDefault
//
// An unconfigured FakeLoader answers every URL with a plain 200, so a test that
// only cares about plumbing (ordering, concurrency, exit codes) does not have
// to script anything at all.
//
//nolint:revive // fake.FakeLoader stutters, but the plan fixes the name and every other package's tests are written against it.
type FakeLoader struct {
	mu       sync.Mutex
	fn       LoadFunc
	byURL    map[string]scripted
	fallback scripted
	delays   map[string]time.Duration

	calls    []string
	inFlight int
	peak     int
}

// New returns a FakeLoader whose default answer is a clean 200 page.
func New() *FakeLoader {
	return &FakeLoader{
		byURL:  make(map[string]scripted, 8),
		delays: make(map[string]time.Duration, 4),
		fallback: scripted{res: verdict.Result{
			Status:    200,
			SettledBy: "load",
		}},
	}
}

// SetResult scripts the answer for one exact URL. The URL is matched byte for
// byte — no normalization — because the whole point is to catch a caller that
// rewrote the URL on its way to the loader.
func (f *FakeLoader) SetResult(rawURL string, res verdict.Result, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byURL[rawURL] = scripted{res: res, err: err}
}

// SetDefault scripts the answer for every URL with no SetResult entry.
func (f *FakeLoader) SetDefault(res verdict.Result, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fallback = scripted{res: res, err: err}
}

// SetDelay makes Load block for d before answering rawURL.
//
// This is how a test forces a deterministic completion order out of a pool that
// dispatches in input order: make the first URL slow and assert the reporter
// still emits results in input order.
func (f *FakeLoader) SetDelay(rawURL string, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delays[rawURL] = d
}

// SetFunc installs a callback that answers every Load, overriding SetResult and
// SetDefault. Any configured delay is still honored first, so a callback can
// assume it runs at the same point in time a scripted answer would.
//
// Use it for answers that depend on the call itself — deriving a status from
// the index, blocking on a barrier to prove the semaphore bounds concurrency,
// or failing only the third call.
func (f *FakeLoader) SetFunc(fn LoadFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fn = fn
}

// Load implements loader.PageLoader.
//
// Per the PageLoader contract a page-level failure belongs inside the Result
// with a nil error, and a non-nil error means the loader itself is finished.
// The fake enforces neither: whatever the test scripted is what the caller
// gets, because testing the caller's handling of a contract violation is a
// legitimate thing to want.
func (f *FakeLoader) Load(ctx context.Context, index int, rawURL string) (verdict.Result, error) {
	fn, delay := f.begin(rawURL)
	defer f.end()

	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			// Cancellation during a load is a loader-level failure, so it comes
			// back as an error rather than as a timeout Result. A real Chrome
			// loader behaves the same way: a dead context means we can no
			// longer speak to the browser at all.
			return stamp(verdict.Result{}, index, rawURL), ctx.Err()
		case <-timer.C:
		}
	}

	if fn != nil {
		res, err := fn(ctx, index, rawURL)
		return stamp(res, index, rawURL), err
	}
	res, err := f.scriptFor(rawURL)
	return stamp(res, index, rawURL), err
}

// Calls returns the URLs passed to Load, in dispatch order.
//
// The URL is recorded on entry, before any delay, so this is the order work was
// started in rather than the order it finished. A duplicate entry here is the
// signature of a double-fetch bug: it is the reason this method exists.
func (f *FakeLoader) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// CallCount returns how many times Load was entered.
func (f *FakeLoader) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// MaxConcurrent returns the peak number of Load calls in flight at once.
//
// This is the assertion that proves the pool's semaphore actually bounds
// parallelism: with -conc=4 over 20 URLs it must come back as 4, not 20.
func (f *FakeLoader) MaxConcurrent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peak
}

// begin records the call and snapshots the configuration it needs, so that the
// (possibly long) delay and the callback both run with the mutex released.
func (f *FakeLoader) begin(rawURL string) (LoadFunc, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, rawURL)
	f.inFlight++
	if f.inFlight > f.peak {
		f.peak = f.inFlight
	}
	return f.fn, f.delays[rawURL]
}

// end closes the concurrency window opened by begin. It runs from a defer so
// the count stays honest on the cancellation path too.
func (f *FakeLoader) end() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inFlight--
}

// scriptFor returns the canned answer for rawURL, falling back to the default.
func (f *FakeLoader) scriptFor(rawURL string) (verdict.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.byURL[rawURL]; ok {
		return s.res, s.err
	}
	return f.fallback.res, f.fallback.err
}

// stamp fills in the two bookkeeping fields tests never bother to script.
//
// Downstream code keys on Index for output ordering and prints URL in every log
// line, so a Result missing them is not merely incomplete — it makes the code
// under test look broken. A scripted value always wins, which is what lets a
// test deliberately hand back a mismatched Index to check the caller notices.
func stamp(r verdict.Result, index int, rawURL string) verdict.Result {
	if r.Index == 0 {
		r.Index = index
	}
	if r.URL == "" {
		r.URL = rawURL
	}
	return r
}
