// Package verdict is the pure, dependency-free core of pagevet: the per-URL
// observation record, the classification rules and the run counters.
//
// It imports nothing outside the standard library, and must never import
// chromedp, cdproto, os or log/slog. That restriction is enforced by `make
// arch`, and it is what makes the whole classification layer testable without
// launching a browser: every value in this package is constructible by hand in
// a test.
package verdict

// Outcome is the single primary classification of one attempted URL.
//
// Exactly one Outcome applies to any given attempt. That is the invariant
// behind Counts.Invariant, and behind the summary arithmetic that lets the
// report state "every URL counted exactly once".
type Outcome uint8

// The outcomes, in no particular order — see Classify for the precedence that
// actually decides between them when several could apply.
const (
	// OutcomeOK: acceptable status, no console errors, no failed subresources,
	// finished loading within the deadline.
	OutcomeOK Outcome = iota

	// OutcomeConsoleError: the page loaded with an acceptable status, but its
	// JavaScript reported errors.
	OutcomeConsoleError

	// OutcomeSubresourceError: the page itself loaded, but assets it requested
	// (scripts, stylesheets, images, XHR) failed to load.
	OutcomeSubresourceError

	// OutcomeTimeout: the per-URL deadline expired before the page finished.
	OutcomeTimeout

	// OutcomeHTTPError: the main document's final status is outside the OK band.
	OutcomeHTTPError

	// OutcomeLoadError: no HTTP response arrived at all — DNS, TLS, connection
	// failure, blocked request, or a renderer crash.
	OutcomeLoadError

	// numOutcomes bounds the Counts array. Keep it last.
	numOutcomes
)

// String returns the stable, machine-readable name of the outcome. These
// strings appear in the logs and in results.jsonl, so they are frozen API.
func (o Outcome) String() string {
	switch o {
	case OutcomeOK:
		return "ok"
	case OutcomeConsoleError:
		return "console_error"
	case OutcomeSubresourceError:
		return "subresource_error"
	case OutcomeTimeout:
		return "timeout"
	case OutcomeHTTPError:
		return "http_error"
	case OutcomeLoadError:
		return "load_error"
	case numOutcomes:
		// Not a real outcome; only ever an array bound.
		return "unknown"
	}
	return "unknown"
}

// IsError reports whether this outcome counts against the run.
func (o Outcome) IsError() bool { return o != OutcomeOK }

// MarshalText makes Outcome encode as its name in JSON rather than as a number.
func (o Outcome) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// Category is the error-log bucket an outcome belongs to. It is deliberately
// coarser than Outcome: timeouts share the "load" log with DNS and TLS
// failures, because both mean "we never got a usable page".
type Category uint8

// The error-log categories. CategoryNone means the URL was fine and belongs in
// no error log at all.
const (
	CategoryNone Category = iota
	CategoryHTTP
	CategoryConsole
	CategorySubresource
	CategoryLoad
)

// String returns the category's name, which is also the infix of its log file
// (errors-http.log, errors-console.log, ...).
func (c Category) String() string {
	switch c {
	case CategoryNone:
		return "none"
	case CategoryHTTP:
		return "http"
	case CategoryConsole:
		return "console"
	case CategorySubresource:
		return "subresource"
	case CategoryLoad:
		return "load"
	}
	return "unknown"
}

// MarshalText makes Category encode as its name in JSON.
func (c Category) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Category maps an outcome to the error log it is written to.
func (o Outcome) Category() Category {
	switch o {
	case OutcomeOK:
		return CategoryNone
	case OutcomeHTTPError:
		return CategoryHTTP
	case OutcomeConsoleError:
		return CategoryConsole
	case OutcomeSubresourceError:
		return CategorySubresource
	case OutcomeTimeout, OutcomeLoadError:
		return CategoryLoad
	case numOutcomes:
		return CategoryNone
	}
	return CategoryNone
}

// ErrorCategories is every category that has its own log file, in the order
// they are reported in the summary.
var ErrorCategories = [...]Category{CategoryHTTP, CategoryConsole, CategorySubresource, CategoryLoad}
