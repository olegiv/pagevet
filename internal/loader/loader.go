// Package loader is pagevet's browser layer. It is the only package allowed to
// import chromedp, and within it only chrome.go does so — `make arch` enforces
// both rules.
//
// The PageLoader interface below is the seam that keeps the rest of the program
// testable: the worker pool, the classifier, the reporter and the exit-code
// logic all run against loader/fake.FakeLoader with no browser anywhere.
package loader

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/olegiv/pagevet/internal/verdict"
)

// ErrBrowserUnavailable means Chrome could not be started, or has died. It is a
// run-fatal condition, never a per-URL result.
var ErrBrowserUnavailable = errors.New("browser unavailable")

// PageLoader loads exactly one URL and reports what the browser observed.
//
// The contract — and the entire point of this interface:
//
//	A PAGE-level failure (404, 500, a JS exception, a navigation timeout, a DNS
//	failure) is reported INSIDE the returned Result, with a nil error.
//
//	A NON-NIL error means the LOADER itself is unusable — the browser died, or
//	the caller's context was canceled — and the run must stop.
//
// Callers rely on that split: a non-nil error aborts the run with exit code 3,
// whereas a Result carrying an error outcome is ordinary data.
type PageLoader interface {
	Load(ctx context.Context, index int, rawURL string) (verdict.Result, error)
}

// Options configures the Chrome-backed PageLoader. The zero value is not
// usable; see DefaultOptions.
type Options struct {
	// ExecPath is the absolute path to the Chrome or Chromium binary. Empty
	// means autodetect.
	ExecPath string

	// Timeout is the hard per-URL deadline, covering navigation plus settle.
	Timeout time.Duration

	// Settle is the quiet window held open after the load event, to catch JS
	// errors thrown from setTimeout handlers, fetch callbacks and SPA
	// hydration. It is spent inside Timeout, not in addition to it.
	Settle time.Duration

	// Headless runs Chrome without a visible window. JavaScript executes
	// either way.
	Headless bool

	// SiteIsolation re-enables Chrome's per-site process isolation. It is off
	// by default because cross-origin iframes then run in separate renderer
	// processes whose console errors become invisible to us — a regression in
	// this tool's core job. The OS sandbox, which is the real boundary, stays
	// on regardless.
	SiteIsolation bool

	// UserAgent overrides Chrome's User-Agent. Chrome's headless default
	// contains "HeadlessChrome", which some sites answer with 403.
	UserAgent string

	// ChromeStderr receives Chrome's own stdout and stderr. Nil discards them.
	ChromeStderr io.Writer

	// MaxConsolePerPage caps distinct console-error records retained per page.
	// Overflow increments Result.ConsoleSuppressed and sets Truncated.
	MaxConsolePerPage int

	// MaxMessageBytes caps a single console message, truncated on a rune
	// boundary.
	MaxMessageBytes int

	// MaxResourcesPerPage caps distinct subresource-failure records per page.
	MaxResourcesPerPage int

	// MaxRedirectHops caps recorded redirect hops per page.
	MaxRedirectHops int

	// ConsoleWarnings also counts console.warn as an error.
	ConsoleWarnings bool

	// IgnoreFavicon drops favicon fetch failures, which are near-universal and
	// carry no signal about the page.
	IgnoreFavicon bool

	// RedactURLs strips credentials from URLs before they reach any Result
	// field. See verdict.RedactURL.
	RedactURLs bool
}

// DefaultOptions returns the shipped defaults. The caller still has to set
// ExecPath (or leave it empty for autodetect).
func DefaultOptions() Options {
	return Options{
		Timeout:             30 * time.Second,
		Settle:              1500 * time.Millisecond,
		Headless:            true,
		SiteIsolation:       false,
		MaxConsolePerPage:   20,
		MaxMessageBytes:     2048,
		MaxResourcesPerPage: 20,
		MaxRedirectHops:     25,
		ConsoleWarnings:     false,
		IgnoreFavicon:       true,
		RedactURLs:          true,
	}
}
