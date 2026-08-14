package verdict

import "time"

// ConsoleKind distinguishes the three DevTools-protocol channels that carry
// page-side errors. They do not overlap the way people assume:
// Runtime.consoleAPICalled never carries uncaught exceptions, and
// Log.entryAdded carries browser-side errors (CSP refusals, parse-time
// SyntaxErrors) that page JavaScript never printed.
type ConsoleKind uint8

// The console-error channels.
const (
	// KindException: Runtime.exceptionThrown — uncaught JS exceptions and
	// unhandled promise rejections.
	KindException ConsoleKind = iota

	// KindConsoleAPI: Runtime.consoleAPICalled with type "error" or "assert"
	// (and "warning" when console warnings are enabled).
	KindConsoleAPI

	// KindBrowserLog: Log.entryAdded with source "javascript" and level
	// "error" — CSP refusals and parse-time SyntaxErrors.
	//
	// Log entries with source "network" are NOT console errors; they are
	// subresource failures and are routed to Result.Resources instead.
	KindBrowserLog
)

// String returns the stable name used in logs and results.jsonl.
func (k ConsoleKind) String() string {
	switch k {
	case KindException:
		return "exception"
	case KindConsoleAPI:
		return "console.error"
	case KindBrowserLog:
		return "browser.log"
	}
	return "unknown"
}

// MarshalText makes ConsoleKind encode as its name in JSON.
func (k ConsoleKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// ConsoleError is one deduplicated browser-console error for a single page.
// Text is already normalized and truncated to the configured cap on a rune
// boundary by the time it reaches here.
type ConsoleError struct {
	Kind   ConsoleKind `json:"kind"`
	Text   string      `json:"text"`
	Frame  string      `json:"frame,omitempty"`  // first stack frame, "fn (url:line:col)"
	Source string      `json:"source,omitempty"` // script URL, already redacted
	Line   int64       `json:"line,omitempty"`   // 1-based (CDP is 0-based; the collector adds 1)
	Col    int64       `json:"col,omitempty"`    // 1-based
	Count  int         `json:"count"`            // occurrences collapsed into this record; always >= 1
}

// ResourceError is a subresource that failed to load. Per the project's
// decision these are their own error category, distinct from both HTTP errors
// (which concern the main document's status) and console errors.
type ResourceError struct {
	URL      string `json:"url"`
	Type     string `json:"type"`                // CDP ResourceType: Script, Stylesheet, Image, XHR, ...
	Status   int    `json:"status,omitempty"`    // HTTP status if one arrived, else 0
	NetError string `json:"net_error,omitempty"` // net::ERR_* if the transport failed
	Count    int    `json:"count"`
}

// Hop is one entry of a server-side 3xx chain. Status is what that URL
// returned, not what it redirected to.
type Hop struct {
	Status int    `json:"status"`
	URL    string `json:"url"`
}

// Result is everything observed for exactly one input line.
//
// It holds no browser handles, no contexts and no file descriptors, so tests
// construct it as a plain literal — which is the entire reason classification
// can be tested without Chrome.
//
// This is also the results.jsonl schema. The JSON field names are frozen API.
type Result struct {
	Index      int    `json:"i"`   // 1-based input ordinal; drives output ordering
	URL        string `json:"url"` // normalized input URL, redacted unless -log-full-urls
	FinalURL   string `json:"final_url,omitempty"`
	Status     int    `json:"status"` // main-document FINAL status; 0 means no response arrived
	StatusText string `json:"status_text,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	Protocol   string `json:"protocol,omitempty"`

	NetError      string `json:"net_error,omitempty"`       // net::ERR_* for the MAIN document only
	NetErrorClass string `json:"net_error_class,omitempty"` // DNS|CONNECT|TLS|PROTOCOL|TIMEOUT|BLOCKED|ABORTED|OTHER
	BlockReason   string `json:"block_reason,omitempty"`    // CDP BlockedReason, if the request was blocked

	TimedOut  bool   `json:"timed_out,omitempty"`
	Crashed   bool   `json:"crashed,omitempty"`
	Download  bool   `json:"download,omitempty"`
	Truncated bool   `json:"truncated,omitempty"` // a per-page cap was hit
	SettledBy string `json:"settled_by"`          // load | deadline | netfail | crash | no-content | download

	Redirects []Hop `json:"redirects,omitempty"`

	Console           []ConsoleError  `json:"console,omitempty"`
	ConsoleSuppressed int             `json:"console_suppressed,omitempty"`
	Resources         []ResourceError `json:"resources,omitempty"`

	Started    time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
}

// ConsoleEvents is the raw occurrence count across all deduplicated records,
// i.e. how many times the page actually errored, not how many distinct errors
// it had.
func (r Result) ConsoleEvents() int {
	n := 0
	for _, c := range r.Console {
		n += c.Count
	}
	return n
}

// ResourceEvents is the raw occurrence count across all deduplicated
// subresource failure records.
func (r Result) ResourceEvents() int {
	n := 0
	for _, e := range r.Resources {
		n += e.Count
	}
	return n
}
