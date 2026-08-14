package loader

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/inspector"
	cdplog "github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"

	"github.com/olegiv/pagevet/internal/verdict"
)

// The point of every test in this file: the collector is driven entirely by
// hand-built cdproto structs. No browser is launched, nothing is mocked, and
// the protocol quirks the collector exists to survive are reproduced literally.

const (
	mainFrame = cdp.FrameID("FRAME-MAIN")
	subFrame  = cdp.FrameID("FRAME-SUB")

	pageURL   = "https://ex.test/"
	frameURL  = "https://ex.test/embed"
	scriptURL = "https://ex.test/app.js"
)

// testOptions keeps redaction off so assertions read the literal URLs; the
// tests that care about redaction turn it on themselves.
func testOptions() Options {
	o := DefaultOptions()
	o.RedactURLs = false
	return o
}

func feed(c *collector, events ...any) {
	for _, e := range events {
		c.handle(e)
	}
}

func docRequest(id network.RequestID, frame cdp.FrameID, u string) *network.EventRequestWillBeSent {
	return &network.EventRequestWillBeSent{
		RequestID: id,
		FrameID:   frame,
		Type:      network.ResourceTypeDocument,
		Request:   &network.Request{URL: u},
	}
}

// redirected is the re-emitted requestWillBeSent Chrome sends for hop N+1,
// carrying hop N's response. Same request id throughout — that is the quirk.
func redirected(id network.RequestID, frame cdp.FrameID, nextURL string, prevStatus int64, prevURL string) *network.EventRequestWillBeSent {
	e := docRequest(id, frame, nextURL)
	e.RedirectResponse = &network.Response{Status: prevStatus, URL: prevURL}
	return e
}

func subRequest(id network.RequestID, frame cdp.FrameID, typ network.ResourceType, u string) *network.EventRequestWillBeSent {
	return &network.EventRequestWillBeSent{
		RequestID: id,
		FrameID:   frame,
		Type:      typ,
		Request:   &network.Request{URL: u},
	}
}

func responded(id network.RequestID, frame cdp.FrameID, typ network.ResourceType, u string, status int64) *network.EventResponseReceived {
	return &network.EventResponseReceived{
		RequestID: id,
		FrameID:   frame,
		Type:      typ,
		Response:  &network.Response{URL: u, Status: status},
	}
}

func failed(id network.RequestID, typ network.ResourceType, errText string) *network.EventLoadingFailed {
	return &network.EventLoadingFailed{RequestID: id, Type: typ, ErrorText: errText}
}

func thrown(description, url string, line, col int64) *runtime.EventExceptionThrown {
	return &runtime.EventExceptionThrown{
		ExceptionDetails: &runtime.ExceptionDetails{
			Text:         "Uncaught",
			URL:          url,
			LineNumber:   line,
			ColumnNumber: col,
			Exception: &runtime.RemoteObject{
				Type:        runtime.TypeObject,
				Subtype:     runtime.SubtypeError,
				Description: description,
			},
		},
	}
}

func consoleCall(t runtime.APIType, msg, url string) *runtime.EventConsoleAPICalled {
	return &runtime.EventConsoleAPICalled{
		Type: t,
		Args: []*runtime.RemoteObject{str(msg)},
		StackTrace: &runtime.StackTrace{CallFrames: []*runtime.CallFrame{
			{FunctionName: "handler", URL: url, LineNumber: 2, ColumnNumber: 5},
		}},
	}
}

func logEntry(source cdplog.Source, level cdplog.Level, text, u string) *cdplog.EventEntryAdded {
	return &cdplog.EventEntryAdded{
		Entry: &cdplog.Entry{Source: source, Level: level, Text: text, URL: u},
	}
}

// -- main-document identification ---------------------------------------------

func TestCollector_RedirectChains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		events     []any
		wantStatus int
		wantHops   []verdict.Hop
	}{
		{
			name: "301 then 302 then 200 keeps the final status and both hops in order",
			events: []any{
				docRequest("1", mainFrame, "https://ex.test/a"),
				redirected("1", mainFrame, "https://ex.test/b", 301, "https://ex.test/a"),
				redirected("1", mainFrame, "https://ex.test/c", 302, "https://ex.test/b"),
				responded("1", mainFrame, network.ResourceTypeDocument, "https://ex.test/c", 200),
			},
			wantStatus: 200,
			wantHops: []verdict.Hop{
				{Status: 301, URL: "https://ex.test/a"},
				{Status: 302, URL: "https://ex.test/b"},
			},
		},
		{
			name: "301 then 404 reports the 404 and the single hop that led to it",
			events: []any{
				docRequest("1", mainFrame, "https://ex.test/a"),
				redirected("1", mainFrame, "https://ex.test/b", 301, "https://ex.test/a"),
				responded("1", mainFrame, network.ResourceTypeDocument, "https://ex.test/b", 404),
			},
			wantStatus: 404,
			wantHops:   []verdict.Hop{{Status: 301, URL: "https://ex.test/a"}},
		},
		{
			name: "no redirect, no hops",
			events: []any{
				docRequest("1", mainFrame, pageURL),
				responded("1", mainFrame, network.ResourceTypeDocument, pageURL, 200),
			},
			wantStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newCollector(testOptions())
			feed(c, tt.events...)
			s := c.snapshot()

			if s.DocStatus != tt.wantStatus {
				t.Errorf("DocStatus = %d, want %d", s.DocStatus, tt.wantStatus)
			}
			if len(s.Redirects) != len(tt.wantHops) {
				t.Fatalf("got %d hops %v, want %d", len(s.Redirects), s.Redirects, len(tt.wantHops))
			}
			for i, want := range tt.wantHops {
				if s.Redirects[i] != want {
					t.Errorf("hop %d = %+v, want %+v", i, s.Redirects[i], want)
				}
			}
		})
	}
}

// TestCollector_SubframeDocumentDoesNotOverwriteDocStatus is the anti-regression
// test for the entire main-document guard: an iframe that 404s must not become
// the page's HTTP status.
func TestCollector_SubframeDocumentDoesNotOverwriteDocStatus(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		&page.EventFrameAttached{FrameID: subFrame, ParentFrameID: mainFrame},
		docRequest("main", mainFrame, pageURL),
		responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
		docRequest("sub", subFrame, frameURL),
		responded("sub", subFrame, network.ResourceTypeDocument, frameURL, 404),
	)
	s := c.snapshot()

	if s.DocStatus != 200 {
		t.Errorf("DocStatus = %d, want 200 (the iframe's 404 leaked into the page status)", s.DocStatus)
	}
	if s.FinalURL != pageURL {
		t.Errorf("FinalURL = %q, want %q", s.FinalURL, pageURL)
	}
	if len(s.Resources) != 1 || s.Resources[0].URL != frameURL || s.Resources[0].Status != 404 {
		t.Errorf("Resources = %+v, want one 404 for %q", s.Resources, frameURL)
	}
}

// TestCollector_SubframeDocumentIsNotTakenAsMain covers the other half of the
// guard: an iframe whose document request arrives BEFORE the page's own.
func TestCollector_SubframeDocumentIsNotTakenAsMain(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		&page.EventFrameAttached{FrameID: subFrame, ParentFrameID: mainFrame},
		docRequest("sub", subFrame, frameURL),
		docRequest("main", mainFrame, pageURL),
		responded("sub", subFrame, network.ResourceTypeDocument, frameURL, 500),
		responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
	)
	s := c.snapshot()

	if s.DocStatus != 200 {
		t.Errorf("DocStatus = %d, want 200", s.DocStatus)
	}
	if len(s.Resources) != 1 || s.Resources[0].Status != 500 {
		t.Errorf("Resources = %+v, want the iframe's 500", s.Resources)
	}
}

func TestCollector_FrameNavigatedRegistersSubframe(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		// No frameAttached: a bfcache restore only announces the frame here.
		&page.EventFrameNavigated{Frame: &cdp.Frame{ID: subFrame, ParentID: mainFrame, URL: frameURL}},
		docRequest("sub", subFrame, frameURL),
		docRequest("main", mainFrame, pageURL),
		responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 204),
	)

	if s := c.snapshot(); s.DocStatus != 204 {
		t.Errorf("DocStatus = %d, want 204", s.DocStatus)
	}
}

func TestCollector_AboutBlankIsNotTheMainDocument(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		docRequest("blank", mainFrame, aboutBlank),
		docRequest("main", mainFrame, pageURL),
		responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
	)

	if s := c.snapshot(); s.DocStatus != 200 {
		t.Errorf("DocStatus = %d, want 200", s.DocStatus)
	}
}

func TestCollector_MainDocumentFieldsAreCaptured(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	c.handle(docRequest("1", mainFrame, pageURL))
	c.handle(&network.EventResponseReceived{
		RequestID: "1",
		FrameID:   mainFrame,
		Type:      network.ResourceTypeDocument,
		Response: &network.Response{
			URL: pageURL, Status: 503, StatusText: "Service Unavailable",
			MimeType: "text/html", RemoteIPAddress: "203.0.113.7", Protocol: "h2",
		},
	})
	s := c.snapshot()

	if s.DocStatus != 503 || s.DocStatusText != "Service Unavailable" {
		t.Errorf("status = %d %q", s.DocStatus, s.DocStatusText)
	}
	if s.DocMime != "text/html" || s.DocIP != "203.0.113.7" || s.DocProtocol != "h2" {
		t.Errorf("mime=%q ip=%q proto=%q", s.DocMime, s.DocIP, s.DocProtocol)
	}
}

// -- subresource failures ------------------------------------------------------

func TestCollector_SubresourceResponseError(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		docRequest("main", mainFrame, pageURL),
		responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
		subRequest("img", mainFrame, network.ResourceTypeImage, "https://ex.test/logo.png"),
		responded("img", mainFrame, network.ResourceTypeImage, "https://ex.test/logo.png", 404),
		// A 304 is not a failure, and neither is a 200.
		responded("css", mainFrame, network.ResourceTypeStylesheet, "https://ex.test/a.css", 304),
	)
	s := c.snapshot()

	if s.DocStatus != 200 {
		t.Errorf("DocStatus = %d, want 200", s.DocStatus)
	}
	if len(s.Resources) != 1 {
		t.Fatalf("Resources = %+v, want exactly one", s.Resources)
	}
	got := s.Resources[0]
	if got.URL != "https://ex.test/logo.png" || got.Status != 404 || got.Type != "Image" || got.Count != 1 {
		t.Errorf("Resources[0] = %+v", got)
	}
}

func TestCollector_LoadingFailed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		events       []any
		wantNetError string
		wantBlocked  string
		wantResource int
	}{
		{
			name: "the main request's failure is the page's failure",
			events: []any{
				docRequest("main", mainFrame, pageURL),
				failed("main", network.ResourceTypeDocument, "net::ERR_NAME_NOT_RESOLVED"),
			},
			wantNetError: "net::ERR_NAME_NOT_RESOLVED",
		},
		{
			name: "a blocked main request also records why",
			events: []any{
				docRequest("main", mainFrame, pageURL),
				&network.EventLoadingFailed{
					RequestID: "main", Type: network.ResourceTypeDocument,
					ErrorText: "net::ERR_BLOCKED_BY_CLIENT", BlockedReason: network.BlockedReasonCsp,
				},
			},
			wantNetError: "net::ERR_BLOCKED_BY_CLIENT",
			wantBlocked:  "csp",
		},
		{
			name: "a subresource failure never touches the main net error",
			events: []any{
				docRequest("main", mainFrame, pageURL),
				responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
				subRequest("js", mainFrame, network.ResourceTypeScript, scriptURL),
				failed("js", network.ResourceTypeScript, "net::ERR_CONNECTION_REFUSED"),
			},
			wantResource: 1,
		},
		{
			name: "a canceled subresource is navigation noise, not breakage",
			events: []any{
				docRequest("main", mainFrame, pageURL),
				subRequest("js", mainFrame, network.ResourceTypeScript, scriptURL),
				&network.EventLoadingFailed{
					RequestID: "js", Type: network.ResourceTypeScript,
					ErrorText: "net::ERR_FAILED", Canceled: true,
				},
			},
		},
		{
			name: "ERR_ABORTED on a subresource is ignored even without the Canceled flag",
			events: []any{
				docRequest("main", mainFrame, pageURL),
				subRequest("js", mainFrame, network.ResourceTypeScript, scriptURL),
				failed("js", network.ResourceTypeScript, errAborted),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newCollector(testOptions())
			feed(c, tt.events...)
			s := c.snapshot()

			if s.MainNetError != tt.wantNetError {
				t.Errorf("MainNetError = %q, want %q", s.MainNetError, tt.wantNetError)
			}
			if s.BlockedReason != tt.wantBlocked {
				t.Errorf("BlockedReason = %q, want %q", s.BlockedReason, tt.wantBlocked)
			}
			if len(s.Resources) != tt.wantResource {
				t.Errorf("Resources = %+v, want %d", s.Resources, tt.wantResource)
			}
		})
	}
}

// TestCollector_LoadingFailedRecoversTheURL proves the request-id to URL map
// earns its keep: Network.loadingFailed carries no URL of its own.
func TestCollector_LoadingFailedRecoversTheURL(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		docRequest("main", mainFrame, pageURL),
		subRequest("js", mainFrame, network.ResourceTypeScript, scriptURL),
		failed("js", network.ResourceTypeScript, "net::ERR_TIMED_OUT"),
	)
	s := c.snapshot()

	if len(s.Resources) != 1 {
		t.Fatalf("Resources = %+v", s.Resources)
	}
	if s.Resources[0].URL != scriptURL || s.Resources[0].NetError != "net::ERR_TIMED_OUT" {
		t.Errorf("Resources[0] = %+v", s.Resources[0])
	}
}

// -- console-source routing ----------------------------------------------------

// TestCollector_LogEntryRouting asserts the single highest-value routing rule in
// the design, from both sides: a source=network entry must land in Resources and
// must NOT land in Console.
func TestCollector_LogEntryRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		entry         *cdplog.EventEntryAdded
		wantConsole   int
		wantResources int
	}{
		{
			name:          "source=network is a subresource failure, never a console error",
			entry:         logEntry(cdplog.SourceNetwork, cdplog.LevelError, "Failed to load resource: the server responded with a status of 404", "https://ex.test/pixel.gif"),
			wantResources: 1,
		},
		{
			name:  "source=network at warning level is a cookie notice, not a failed load",
			entry: logEntry(cdplog.SourceNetwork, cdplog.LevelWarning, "Cookie will be rejected soon", "https://ex.test/x.gif"),
		},
		{
			name:        "source=javascript at error level is a console error",
			entry:       logEntry(cdplog.SourceJavascript, cdplog.LevelError, "Refused to execute inline script: CSP", pageURL),
			wantConsole: 1,
		},
		{
			name:  "source=javascript below error level is not",
			entry: logEntry(cdplog.SourceJavascript, cdplog.LevelWarning, "slow script", pageURL),
		},
		{name: "deprecation is advisory", entry: logEntry(cdplog.SourceDeprecation, cdplog.LevelError, "d", pageURL)},
		{name: "intervention is advisory", entry: logEntry(cdplog.SourceIntervention, cdplog.LevelError, "i", pageURL)},
		{name: "recommendation is advisory", entry: logEntry(cdplog.SourceRecommendation, cdplog.LevelError, "r", pageURL)},
		{
			// Chrome 151 reports a CSP-blocked inline script here and nowhere
			// else - no exceptionThrown, no consoleAPICalled. Dropping it would
			// let a page whose every script was refused classify as ok.
			name: "source=security at error level is a blocked-by-policy console error",
			entry: logEntry(cdplog.SourceSecurity, cdplog.LevelError,
				"Executing inline script violates the following Content Security Policy directive", pageURL),
			wantConsole: 1,
		},
		{
			name:  "source=security below error level is advisory",
			entry: logEntry(cdplog.SourceSecurity, cdplog.LevelWarning, "certificate transparency note", pageURL),
		},
		{name: "rendering is advisory", entry: logEntry(cdplog.SourceRendering, cdplog.LevelError, "g", pageURL)},
		{name: "violation is advisory", entry: logEntry(cdplog.SourceViolation, cdplog.LevelError, "v", pageURL)},
		{name: "other is advisory", entry: logEntry(cdplog.SourceOther, cdplog.LevelError, "o", pageURL)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newCollector(testOptions())
			feed(c,
				docRequest("main", mainFrame, pageURL),
				responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
				tt.entry,
			)
			s := c.snapshot()

			if len(s.Console) != tt.wantConsole {
				t.Errorf("Console = %+v, want %d entries", s.Console, tt.wantConsole)
			}
			if len(s.Resources) != tt.wantResources {
				t.Errorf("Resources = %+v, want %d entries", s.Resources, tt.wantResources)
			}
		})
	}
}

func TestCollector_JavascriptLogEntryIsABrowserLogKind(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	c.handle(&cdplog.EventEntryAdded{Entry: &cdplog.Entry{
		Source:     cdplog.SourceJavascript,
		Level:      cdplog.LevelError,
		Text:       "Refused to load the script 'https://cdn.test/x.js' because it violates CSP",
		URL:        pageURL,
		LineNumber: 12,
	}})
	s := c.snapshot()

	if len(s.Console) != 1 {
		t.Fatalf("Console = %+v", s.Console)
	}
	got := s.Console[0]
	if got.Kind != verdict.KindBrowserLog {
		t.Errorf("Kind = %v, want %v", got.Kind, verdict.KindBrowserLog)
	}
	// Log entries come from Blink's SourceLocation, which is already 1-based —
	// unlike Runtime's script offsets, this one must NOT be incremented.
	if got.Line != 12 {
		t.Errorf("Line = %d, want 12 (log entries are already 1-based)", got.Line)
	}
	if got.Source != pageURL {
		t.Errorf("Source = %q, want %q", got.Source, pageURL)
	}
}

// TestCollector_ConsoleAPITypes walks every console API type CDP defines, so a
// future protocol addition cannot quietly start counting as an error.
func TestCollector_ConsoleAPITypes(t *testing.T) {
	t.Parallel()

	all := []runtime.APIType{
		runtime.APITypeLog, runtime.APITypeDebug, runtime.APITypeInfo,
		runtime.APITypeError, runtime.APITypeWarning, runtime.APITypeDir,
		runtime.APITypeDirxml, runtime.APITypeTable, runtime.APITypeTrace,
		runtime.APITypeClear, runtime.APITypeStartGroup,
		runtime.APITypeStartGroupCollapsed, runtime.APITypeEndGroup,
		runtime.APITypeAssert, runtime.APITypeProfile, runtime.APITypeProfileEnd,
		runtime.APITypeCount, runtime.APITypeTimeEnd,
	}

	for _, warnings := range []bool{false, true} {
		name := "warnings=" + strconv.FormatBool(warnings)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, apiType := range all {
				t.Run(string(apiType), func(t *testing.T) {
					t.Parallel()
					want := apiType == runtime.APITypeError || apiType == runtime.APITypeAssert ||
						(warnings && apiType == runtime.APITypeWarning)

					o := testOptions()
					o.ConsoleWarnings = warnings
					c := newCollector(o)
					c.handle(consoleCall(apiType, "message", scriptURL))
					s := c.snapshot()

					if got := len(s.Console) == 1; got != want {
						t.Errorf("kept = %v, want %v (Console = %+v)", got, want, s.Console)
					}
					if want && s.Console[0].Kind != verdict.KindConsoleAPI {
						t.Errorf("Kind = %v, want %v", s.Console[0].Kind, verdict.KindConsoleAPI)
					}
				})
			}
		})
	}
}

func TestCollector_BrowserInternalSourcesAreDropped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event any
	}{
		{
			name:  "exception from an extension content script",
			event: thrown("TypeError: adblock broke", "chrome-extension://abcdef/inject.js", 1, 1),
		},
		{
			name:  "exception from the devtools front end",
			event: thrown("TypeError: devtools", "devtools://devtools/bundled/x.js", 1, 1),
		},
		{
			name:  "exception from a chrome:// page",
			event: thrown("TypeError: internal", "chrome://newtab/x.js", 1, 1),
		},
		{
			name: "exception whose only location is an extension stack frame",
			event: &runtime.EventExceptionThrown{ExceptionDetails: &runtime.ExceptionDetails{
				Text: "Uncaught",
				StackTrace: &runtime.StackTrace{CallFrames: []*runtime.CallFrame{
					{FunctionName: "inject", URL: "chrome-extension://abcdef/inject.js"},
				}},
				Exception: &runtime.RemoteObject{
					Type: runtime.TypeObject, Subtype: runtime.SubtypeError,
					Description: "Error: extension",
				},
			}},
		},
		{
			name:  "console.error called from an extension",
			event: consoleCall(runtime.APITypeError, "boom", "chrome-extension://abcdef/inject.js"),
		},
		{
			name:  "CSP log entry attributed to an extension page",
			event: logEntry(cdplog.SourceJavascript, cdplog.LevelError, "csp", "chrome-extension://abcdef/page.html"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newCollector(testOptions())
			c.handle(tt.event)
			if s := c.snapshot(); len(s.Console) != 0 {
				t.Errorf("Console = %+v, want empty", s.Console)
			}
		})
	}
}

func TestCollector_ExceptionPositionsAreOneBased(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	// CDP reports 0-based script offsets; DevTools and every editor show 1-based.
	c.handle(thrown("TypeError: nope", scriptURL, 0, 0))
	c.handle(consoleCall(runtime.APITypeError, "bad", scriptURL))
	s := c.snapshot()

	if len(s.Console) != 2 {
		t.Fatalf("Console = %+v", s.Console)
	}
	if s.Console[0].Line != 1 || s.Console[0].Col != 1 {
		t.Errorf("exception position = %d:%d, want 1:1", s.Console[0].Line, s.Console[0].Col)
	}
	// consoleCall's frame is line 2, column 5 in CDP's numbering.
	if s.Console[1].Line != 3 || s.Console[1].Col != 6 {
		t.Errorf("console.error position = %d:%d, want 3:6", s.Console[1].Line, s.Console[1].Col)
	}
	if want := "handler (" + scriptURL + ":3:6)"; s.Console[1].Frame != want {
		t.Errorf("Frame = %q, want %q", s.Console[1].Frame, want)
	}
}

// -- ignored requests ----------------------------------------------------------

func TestIgnoredResourceURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		url           string
		ignoreFavicon bool
		want          bool
	}{
		{name: "empty URL is kept, since we cannot judge it", url: ""},
		{name: "ordinary asset", url: "https://ex.test/a.js"},
		{name: "favicon dropped when configured", url: "https://ex.test/favicon.ico", ignoreFavicon: true, want: true},
		{name: "favicon kept when not configured", url: "https://ex.test/favicon.ico"},
		{name: "favicon with a cache buster still matches", url: "https://ex.test/favicon.ico?v=3", ignoreFavicon: true, want: true},
		{name: "sourcemap always dropped", url: "https://ex.test/a.js.map", want: true},
		{name: "sourcemap with a query", url: "https://ex.test/a.js.map?x=1", want: true},
		{name: "extension URL always dropped", url: "chrome-extension://abcdef/x.js", want: true},
		{name: "a path merely containing favicon.ico is kept", url: "https://ex.test/favicon.ico.html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ignoredResourceURL(tt.url, tt.ignoreFavicon); got != tt.want {
				t.Errorf("ignoredResourceURL(%q, %v) = %v, want %v", tt.url, tt.ignoreFavicon, got, tt.want)
			}
		})
	}
}

func TestCollector_IgnoredRequestsNeverReachResources(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions()) // IgnoreFavicon defaults to true
	feed(c,
		docRequest("main", mainFrame, pageURL),
		responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
		responded("fav", mainFrame, network.ResourceTypeOther, "https://ex.test/favicon.ico", 404),
		responded("map", mainFrame, network.ResourceTypeOther, "https://ex.test/app.js.map", 404),
		subRequest("ext", mainFrame, network.ResourceTypeScript, "chrome-extension://abcdef/x.js"),
		failed("ext", network.ResourceTypeScript, "net::ERR_FAILED"),
		logEntry(cdplog.SourceNetwork, cdplog.LevelError, "404", "https://ex.test/favicon.ico"),
	)

	if s := c.snapshot(); len(s.Resources) != 0 {
		t.Errorf("Resources = %+v, want empty", s.Resources)
	}
}

// -- double-reporting reconciliation -------------------------------------------

// TestCollector_LogCopyOfANetworkFailureIsNotDoubleCounted pins the fix for the
// most likely source of inflated numbers: Chrome describes one dead asset twice,
// once on the Network domain and once as a Log entry.
func TestCollector_LogCopyOfANetworkFailureIsNotDoubleCounted(t *testing.T) {
	t.Parallel()

	const asset = "https://ex.test/pixel.gif"

	tests := []struct {
		name  string
		entry *cdplog.EventEntryAdded
	}{
		{
			name: "matched by request id",
			entry: &cdplog.EventEntryAdded{Entry: &cdplog.Entry{
				Source: cdplog.SourceNetwork, Level: cdplog.LevelError,
				Text: "Failed to load resource", URL: asset, NetworkRequestID: "img",
			}},
		},
		{
			name: "matched by URL when Chrome omits the request id",
			entry: logEntry(cdplog.SourceNetwork, cdplog.LevelError,
				"Failed to load resource", asset+"?cb=9"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newCollector(testOptions())
			feed(c,
				docRequest("main", mainFrame, pageURL),
				responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
				subRequest("img", mainFrame, network.ResourceTypeImage, asset),
				responded("img", mainFrame, network.ResourceTypeImage, asset, 404),
				tt.entry,
			)
			s := c.snapshot()

			if len(s.Resources) != 1 {
				t.Fatalf("Resources = %+v, want exactly one", s.Resources)
			}
			if s.Resources[0].Status != 404 || s.Resources[0].Type != "Image" {
				t.Errorf("the precise Network-domain record was not the one kept: %+v", s.Resources[0])
			}
		})
	}
}

// TestCollector_UnmatchedNetworkLogEntryIsKept: reconciliation must only drop
// duplicates. A log entry describing a request the Network domain never
// reported is the only evidence that asset failed.
func TestCollector_UnmatchedNetworkLogEntryIsKept(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		docRequest("main", mainFrame, pageURL),
		responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200),
		subRequest("img", mainFrame, network.ResourceTypeImage, "https://ex.test/p.gif"),
		responded("img", mainFrame, network.ResourceTypeImage, "https://ex.test/p.gif", 404),
		&cdplog.EventEntryAdded{Entry: &cdplog.Entry{
			Source: cdplog.SourceNetwork, Level: cdplog.LevelError,
			Text: "Failed to load resource", URL: "https://cdn.test/font.woff2",
			NetworkRequestID: "unrelated",
		}},
	)
	s := c.snapshot()

	if len(s.Resources) != 2 {
		t.Fatalf("Resources = %+v, want both the pixel and the font", s.Resources)
	}
	if s.Resources[1].URL != "https://cdn.test/font.woff2" {
		t.Errorf("Resources[1] = %+v, want the font", s.Resources[1])
	}
}

// TestCollector_MainDocumentLogCopyIsNotASubresourceError stops an http_error
// page from also being reported as a subresource_error page.
func TestCollector_MainDocumentLogCopyIsNotASubresourceError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *cdplog.EventEntryAdded
	}{
		{
			name: "matched by the main request id",
			entry: &cdplog.EventEntryAdded{Entry: &cdplog.Entry{
				Source: cdplog.SourceNetwork, Level: cdplog.LevelError,
				Text: "Failed to load resource: the server responded with a status of 404",
				URL:  pageURL, NetworkRequestID: "main",
			}},
		},
		{
			name: "matched by the final URL when Chrome omits the request id",
			entry: logEntry(cdplog.SourceNetwork, cdplog.LevelError,
				"Failed to load resource: the server responded with a status of 404", pageURL),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newCollector(testOptions())
			feed(c,
				docRequest("main", mainFrame, pageURL),
				responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 404),
				tt.entry,
			)
			s := c.snapshot()

			if s.DocStatus != 404 {
				t.Errorf("DocStatus = %d, want 404", s.DocStatus)
			}
			if len(s.Resources) != 0 {
				t.Errorf("Resources = %+v, want empty", s.Resources)
			}
		})
	}
}

// -- lifecycle flags -----------------------------------------------------------

func TestCollector_TargetCrashed(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	if s := c.snapshot(); s.Crashed {
		t.Fatal("Crashed set before any event")
	}
	c.handle(&inspector.EventTargetCrashed{})
	if s := c.snapshot(); !s.Crashed {
		t.Error("Crashed not set after inspector.targetCrashed")
	}
}

func TestCollector_DownloadWillBegin(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	c.handle(&browser.EventDownloadWillBegin{GUID: "g", URL: "https://ex.test/report.pdf"})
	if s := c.snapshot(); !s.Download {
		t.Error("Download not set after browser.downloadWillBegin")
	}
}

// TestCollector_DialogsSignalsWithoutBlocking proves the event path never waits
// on anyone: with no pump goroutine draining the channel, a burst of dialogs
// must still return immediately.
func TestCollector_DialogsSignalsWithoutBlocking(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	for range 100 {
		c.handle(&page.EventJavascriptDialogOpening{
			URL: pageURL, Message: "hi", Type: page.DialogTypeAlert,
		})
	}

	select {
	case <-c.Dialogs():
	default:
		t.Fatal("no dialog signal delivered")
	}
	select {
	case <-c.Dialogs():
		t.Fatal("the size-1 buffer coalesced nothing")
	default:
	}
}

// -- dedupe, caps and redaction ------------------------------------------------

func TestCollector_DedupeCollapsesRepeats(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	for range 3 {
		c.handle(thrown("TypeError: x is not a function", scriptURL, 4, 2))
	}
	s := c.snapshot()

	if len(s.Console) != 1 {
		t.Fatalf("Console = %+v, want one collapsed record", s.Console)
	}
	if s.Console[0].Count != 3 {
		t.Errorf("Count = %d, want 3", s.Console[0].Count)
	}
	if s.ConsoleSuppressed != 0 || s.Truncated {
		t.Errorf("suppressed=%d truncated=%v, want 0/false", s.ConsoleSuppressed, s.Truncated)
	}
}

func TestCollector_ConsoleCapSuppressesAndMarksTruncated(t *testing.T) {
	t.Parallel()

	o := testOptions()
	o.MaxConsolePerPage = 2
	c := newCollector(o)
	for i := range 5 {
		c.handle(thrown("Error: distinct "+strconv.Itoa(i), scriptURL, int64(i), 0))
	}
	s := c.snapshot()

	if len(s.Console) != 2 {
		t.Fatalf("Console = %+v, want 2 records", s.Console)
	}
	if s.ConsoleSuppressed != 3 {
		t.Errorf("ConsoleSuppressed = %d, want 3", s.ConsoleSuppressed)
	}
	if !s.Truncated {
		t.Error("Truncated not set although the cap fired")
	}
}

// TestCollector_RawBufferCapIsAccountedFor covers the second, coarser cap: the
// one on UN-deduplicated events, which exists because dedupe cannot run on the
// event goroutine. Every occurrence must still be accounted for.
func TestCollector_RawBufferCapIsAccountedFor(t *testing.T) {
	t.Parallel()

	o := testOptions()
	o.MaxConsolePerPage = 1
	c := newCollector(o)

	const events = rawRetentionFactor + 36
	for i := range events {
		c.handle(thrown("Error: distinct "+strconv.Itoa(i), scriptURL, int64(i), 0))
	}
	s := c.snapshot()

	if len(s.Console) != 1 {
		t.Fatalf("Console = %+v, want 1 record", s.Console)
	}
	if got := len(s.Console) + s.ConsoleSuppressed; got != events {
		t.Errorf("records+suppressed = %d, want %d (occurrences went missing)", got, events)
	}
	if !s.Truncated {
		t.Error("Truncated not set although the raw buffer overflowed")
	}
}

func TestCollector_ResourceRawBufferCapIsMarked(t *testing.T) {
	t.Parallel()

	o := testOptions()
	o.MaxResourcesPerPage = 1
	c := newCollector(o)
	c.handle(docRequest("main", mainFrame, pageURL))
	for i := range rawRetentionFactor + 6 {
		u := "https://ex.test/a" + strconv.Itoa(i) + ".png"
		c.handle(responded(network.RequestID("r"+strconv.Itoa(i)), mainFrame, network.ResourceTypeImage, u, 404))
	}
	s := c.snapshot()

	if len(s.Resources) != 1 {
		t.Fatalf("Resources = %+v, want 1", s.Resources)
	}
	if !s.Truncated {
		t.Error("Truncated not set although the resource buffer overflowed")
	}
}

// TestCollector_UncappedOptionsRetainEverything covers the "0 means unlimited"
// path shared by the raw buffer and the dedupers.
func TestCollector_UncappedOptionsRetainEverything(t *testing.T) {
	t.Parallel()

	o := testOptions()
	o.MaxConsolePerPage = 0
	o.MaxResourcesPerPage = 0
	o.MaxRedirectHops = 0
	c := newCollector(o)

	const n = rawRetentionFactor + 40
	for i := range n {
		c.handle(thrown("Error: distinct "+strconv.Itoa(i), scriptURL, int64(i), 0))
	}
	s := c.snapshot()

	if len(s.Console) != n {
		t.Errorf("Console holds %d records, want %d", len(s.Console), n)
	}
	if s.ConsoleSuppressed != 0 || s.Truncated {
		t.Errorf("suppressed=%d truncated=%v, want 0/false", s.ConsoleSuppressed, s.Truncated)
	}
}

func TestCollector_NetworkLogEntryWithoutAURLIsDropped(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	c.handle(logEntry(cdplog.SourceNetwork, cdplog.LevelError, "Failed to load resource", ""))

	if s := c.snapshot(); len(s.Resources) != 0 {
		t.Errorf("Resources = %+v, want empty: a URL-less record says nothing", s.Resources)
	}
}

func TestCollector_RedirectHopCapMarksTruncated(t *testing.T) {
	t.Parallel()

	o := testOptions()
	o.MaxRedirectHops = 2
	c := newCollector(o)
	c.handle(docRequest("1", mainFrame, "https://ex.test/0"))
	for i := range 5 {
		from := "https://ex.test/" + strconv.Itoa(i)
		to := "https://ex.test/" + strconv.Itoa(i+1)
		c.handle(redirected("1", mainFrame, to, 302, from))
	}
	s := c.snapshot()

	if len(s.Redirects) != 2 {
		t.Errorf("Redirects = %+v, want 2", s.Redirects)
	}
	if !s.Truncated {
		t.Error("Truncated not set although the hop cap fired")
	}
}

func TestCollector_RedactionAppliesToEveryURLBearingField(t *testing.T) {
	t.Parallel()

	o := testOptions()
	o.RedactURLs = true
	c := newCollector(o)
	feed(c,
		docRequest("1", mainFrame, "https://ex.test/a?token=hunter2"),
		redirected("1", mainFrame, "https://ex.test/b", 302, "https://ex.test/a?token=hunter2"),
		responded("1", mainFrame, network.ResourceTypeDocument, "https://ex.test/b?api_key=abc", 200),
		subRequest("img", mainFrame, network.ResourceTypeImage, "https://ex.test/p.gif?secret=s3cr3t"),
		responded("img", mainFrame, network.ResourceTypeImage, "https://ex.test/p.gif?secret=s3cr3t", 404),
		thrown("Error: fetch https://ex.test/x?password=letmein failed", "https://ex.test/app.js?key=k", 1, 1),
	)
	s := c.snapshot()

	for _, got := range []string{
		s.FinalURL,
		s.Redirects[0].URL,
		s.Resources[0].URL,
		s.Console[0].Text,
		s.Console[0].Source,
	} {
		if !strings.Contains(got, verdict.RedactedValue) {
			t.Errorf("%q was not redacted", got)
		}
	}
}

// -- concurrency ---------------------------------------------------------------

// TestCollector_SnapshotReturnsClonedSlices: chrome.go hands the Snapshot on to
// the reporter, which sorts and rewrites it. That must not reach back into a
// collector whose event goroutine is still running.
func TestCollector_SnapshotReturnsClonedSlices(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		docRequest("1", mainFrame, "https://ex.test/a"),
		redirected("1", mainFrame, pageURL, 301, "https://ex.test/a"),
		responded("1", mainFrame, network.ResourceTypeDocument, pageURL, 200),
		subRequest("img", mainFrame, network.ResourceTypeImage, "https://ex.test/p.gif"),
		responded("img", mainFrame, network.ResourceTypeImage, "https://ex.test/p.gif", 404),
		thrown("TypeError: nope", scriptURL, 1, 1),
	)

	first := c.snapshot()
	first.Redirects[0].URL = "MUTATED"
	first.Redirects[0].Status = 999
	first.Resources[0].URL = "MUTATED"
	first.Console[0].Text = "MUTATED"

	second := c.snapshot()
	if second.Redirects[0].URL == "MUTATED" || second.Redirects[0].Status == 999 {
		t.Errorf("Redirects aliased the collector: %+v", second.Redirects)
	}
	if second.Resources[0].URL == "MUTATED" {
		t.Errorf("Resources aliased the collector: %+v", second.Resources)
	}
	if second.Console[0].Text == "MUTATED" {
		t.Errorf("Console aliased the collector: %+v", second.Console)
	}
}

// TestCollector_ConcurrentHandleAndSnapshot is the test that proves the "never
// block, always lock" rule: several goroutines push events while others read
// snapshots. It must be clean under -race.
func TestCollector_ConcurrentHandleAndSnapshot(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	c.handle(docRequest("main", mainFrame, pageURL))

	const (
		writers    = 8
		readers    = 4
		iterations = 300
	)

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range iterations {
				switch (w + i) % 8 {
				case 0:
					c.handle(responded("main", mainFrame, network.ResourceTypeDocument, pageURL, 200))
				case 1:
					c.handle(responded("img", mainFrame, network.ResourceTypeImage, "https://ex.test/p.gif", 404))
				case 2:
					c.handle(thrown("TypeError: nope", scriptURL, int64(i), 3))
				case 3:
					c.handle(consoleCall(runtime.APITypeError, "boom "+strconv.Itoa(i), scriptURL))
				case 4:
					c.handle(logEntry(cdplog.SourceNetwork, cdplog.LevelError, "failed", "https://ex.test/x"+strconv.Itoa(i)))
				case 5:
					c.handle(&page.EventFrameAttached{FrameID: cdp.FrameID("F" + strconv.Itoa(i)), ParentFrameID: mainFrame})
				case 6:
					c.handle(subRequest(network.RequestID("r"+strconv.Itoa(i)), mainFrame, network.ResourceTypeScript, scriptURL))
				case 7:
					c.handle(&page.EventJavascriptDialogOpening{URL: pageURL, Type: page.DialogTypeAlert})
				}
			}
		}()
	}
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				if s := c.snapshot(); s.DocStatus != 0 && s.DocStatus != 200 {
					t.Errorf("DocStatus = %d, want 0 or 200", s.DocStatus)
				}
			}
		}()
	}
	wg.Wait()

	final := c.snapshot()
	if final.DocStatus != 200 {
		t.Errorf("DocStatus = %d, want 200", final.DocStatus)
	}
	if len(final.Console) == 0 {
		t.Error("no console errors survived the hammering")
	}
}

// -- degenerate input ----------------------------------------------------------

func TestCollector_MalformedEventsAreIgnored(t *testing.T) {
	t.Parallel()

	c := newCollector(testOptions())
	feed(c,
		&network.EventRequestWillBeSent{RequestID: "x", Type: network.ResourceTypeDocument}, // nil Request
		&network.EventResponseReceived{RequestID: "x"},                                      // nil Response
		&runtime.EventExceptionThrown{},                                                     // nil ExceptionDetails
		&cdplog.EventEntryAdded{},                                                           // nil Entry
		&page.EventFrameNavigated{},                                                         // nil Frame
		&page.EventFrameAttached{},                                                          // empty FrameID
		"not a cdp event",
		nil,
	)

	s := c.snapshot()
	if s.DocStatus != 0 || len(s.Console) != 0 || len(s.Resources) != 0 {
		t.Errorf("degenerate events produced state: %+v", s)
	}
}
