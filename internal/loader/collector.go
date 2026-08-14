package loader

import (
	"strings"
	"sync"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/inspector"
	cdplog "github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"

	"github.com/olegiv/pagevet/internal/verdict"
)

// Snapshot is everything one page's event stream produced, read out once the
// page has settled.
//
// It is deliberately a plain value with no CDP types in it: chrome.go turns a
// Snapshot into a verdict.Result, and the verdict package must never see the
// protocol. Every slice in it is freshly allocated by snapshot(), so the caller
// may keep it, sort it or mutate it while the collector is still running.
type Snapshot struct {
	// The main document, and only the main document. A 404 favicon must never
	// reach these fields; see the request-id guard in onResponseReceived.
	DocStatus     int
	DocStatusText string
	FinalURL      string
	DocMime       string
	DocIP         string
	DocProtocol   string

	// MainNetError is net::ERR_* for the main document only. BlockedReason is
	// set when Chrome refused the request outright (CSP, mixed content).
	MainNetError  string
	BlockedReason string

	Redirects []verdict.Hop

	Console           []verdict.ConsoleError
	ConsoleSuppressed int
	Resources         []verdict.ResourceError

	Crashed   bool
	Download  bool
	Truncated bool
}

const (
	// aboutBlank is the URL of the tab Chrome opens before we navigate
	// anywhere. Its document request would otherwise be mistaken for the page's.
	aboutBlank = "about:blank"

	// errAborted is the net error Chrome reports for in-flight subresource
	// loads it cancels itself — on navigation away, on element removal, on a
	// fetch() whose AbortController fired. None of those is breakage.
	errAborted = "net::ERR_ABORTED"

	// rawRetentionFactor bounds how many UN-deduplicated events are retained
	// per page, as a multiple of the configured record cap.
	//
	// Deduplication is what normally keeps this bounded, but it cannot run on
	// the event goroutine (see handle), so a page throwing once per animation
	// frame would grow the pending slice for the whole page deadline. Overflow
	// is reported as suppression rather than silently dropped.
	rawRetentionFactor = 64

	// maxTrackedRequests bounds the request-id to URL map. Network.loadingFailed
	// carries no URL, so the URL has to come from the earlier
	// requestWillBeSent — but an infinite-scroll page can issue tens of
	// thousands of requests, and we are not a proxy log.
	maxTrackedRequests = 4096
)

// pendingConsole is one console event captured verbatim on the event goroutine.
//
// It holds the CDP structs by pointer and renders nothing: chromedp allocates a
// fresh event value per message and never reuses it, so retaining the pointer
// is both safe and free, and rendering is deferred to snapshot().
type pendingConsole struct {
	kind      verdict.ConsoleKind
	exception *runtime.ExceptionDetails // KindException
	args      []*runtime.RemoteObject   // KindConsoleAPI
	stack     *runtime.StackTrace       // KindConsoleAPI, KindBrowserLog
	text      string                    // KindBrowserLog
	source    string                    // KindBrowserLog
	line      int64                     // KindBrowserLog, already 1-based
}

// pendingResource is one subresource failure, before dedupe and redaction.
//
// reqID and fromLog exist for reconciliation: Chrome reports the same dead
// asset on both the Network domain and the Log domain, and counting it twice
// would inflate every subresource total. See snapshot().
type pendingResource struct {
	reqID    network.RequestID
	url      string
	typ      string
	status   int
	netError string
	fromLog  bool
}

// collector turns one page's CDP event stream into a Snapshot.
//
// It is a pure state machine: it makes no CDP calls, performs no I/O and never
// blocks. That is not a stylistic preference. handle() runs synchronously on
// chromedp's single event-reading goroutine, while that goroutine holds an
// internal lock, and the same goroutine is what delivers the replies to
// outgoing CDP commands. Any command issued from inside handle() therefore
// waits on a reply that cannot arrive until handle() returns: a hard deadlock.
type collector struct {
	// opts is written once, by newCollector, and only read afterwards — so the
	// event path may consult it without taking mu.
	opts Options

	// dialogs is the escape hatch for the one event that DOES need a CDP call
	// in response. See onDialog.
	dialogs chan struct{}

	// consoleRawCap and resourceRawCap are derived from opts; see rawCap.
	consoleRawCap  int
	resourceRawCap int

	mu sync.Mutex

	// subFrames is every frame known to have a parent. A document response
	// belonging to one of these is an iframe's status, not the page's.
	subFrames map[cdp.FrameID]struct{}

	// mainReqID is the request id of the main document. Chrome reuses ONE
	// request id for an entire redirect chain, so this stays valid across hops.
	mainReqID network.RequestID
	mainSeen  bool

	docStatus     int64
	docStatusText string
	finalURL      string
	docMime       string
	docIP         string
	docProtocol   string
	mainNetError  string
	blockedReason string

	redirects        []verdict.Hop
	redirectsDropped bool

	reqURL map[network.RequestID]string

	pendingConsole   []pendingConsole
	consoleDropped   int
	pendingResources []pendingResource
	resourceDropped  bool

	crashed  bool
	download bool
}

// newCollector returns a collector configured for one page load. A collector is
// never reused across pages: the caps, the dedupe state and the main-request id
// are all per-page.
func newCollector(o Options) *collector {
	return &collector{
		opts:           o,
		dialogs:        make(chan struct{}, 1),
		consoleRawCap:  rawCap(o.MaxConsolePerPage),
		resourceRawCap: rawCap(o.MaxResourcesPerPage),
		subFrames:      make(map[cdp.FrameID]struct{}, 4),
		reqURL:         make(map[network.RequestID]string, 64),
	}
}

// rawCap converts a cap on distinct RECORDS into a cap on raw events. Zero
// means unlimited, matching the deduper the events eventually feed.
func rawCap(recordCap int) int {
	if recordCap <= 0 {
		return 0
	}
	return recordCap * rawRetentionFactor
}

// Dialogs fires once per javascript dialog the page opens.
//
// Page.javascriptDialogOpening must be answered with
// Page.handleJavaScriptDialog or the renderer stalls until the deadline — but
// answering it is a CDP call, and a CDP call from inside handle() deadlocks the
// event goroutine. So the event path only signals, and chrome.go runs a pump
// goroutine that does the dismissing off the event path.
//
// The channel is buffered to one and sent to without blocking: if a dismissal
// is already pending, a second dialog cannot appear until the first is
// answered, so a dropped signal is not a lost dialog.
func (c *collector) Dialogs() <-chan struct{} { return c.dialogs }

// handle consumes one CDP event. It is called from chromedp's event goroutine
// and must stay allocation-light and lock-short; see the type doc for why.
func (c *collector) handle(ev any) {
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		c.onRequestWillBeSent(e)
	case *network.EventResponseReceived:
		c.onResponseReceived(e)
	case *network.EventLoadingFailed:
		c.onLoadingFailed(e)

	case *page.EventFrameAttached:
		c.addSubFrame(e.FrameID)
	case *page.EventFrameNavigated:
		// A frame with a parent is an iframe. frameAttached usually arrives
		// first, but a frame restored from the back-forward cache or created
		// before we attached is only ever announced this way.
		if e.Frame != nil && e.Frame.ParentID != "" {
			c.addSubFrame(e.Frame.ID)
		}
	case *page.EventJavascriptDialogOpening:
		c.onDialog()

	case *runtime.EventExceptionThrown:
		c.onExceptionThrown(e)
	case *runtime.EventConsoleAPICalled:
		c.onConsoleAPICalled(e)
	case *cdplog.EventEntryAdded:
		c.onLogEntryAdded(e)

	case *inspector.EventTargetCrashed:
		c.mu.Lock()
		c.crashed = true
		c.mu.Unlock()

	case *browser.EventDownloadWillBegin:
		// Best effort only: whether this arrives on the target listener or the
		// browser listener depends on whether Chrome stamps a SessionID on it,
		// which has changed between releases. The real defense against a
		// download hanging the load is SetDownloadBehavior(Deny) in chrome.go;
		// this flag just labels the Result when we do see it.
		c.mu.Lock()
		c.download = true
		c.mu.Unlock()
	}
}

func (c *collector) addSubFrame(id cdp.FrameID) {
	if id == "" {
		return
	}
	c.mu.Lock()
	c.subFrames[id] = struct{}{}
	c.mu.Unlock()
}

func (c *collector) onDialog() {
	select {
	case c.dialogs <- struct{}{}:
	default:
		// A dismissal is already queued. Chrome will not open a second dialog
		// before the first is answered, so nothing is lost.
	}
}

// onRequestWillBeSent identifies the main document and records redirect hops.
//
// Both jobs live here because of one protocol quirk: Chrome reuses a single
// request id for an entire 3xx chain and re-emits requestWillBeSent for each
// hop, carrying the PREVIOUS hop's response in RedirectResponse. There is no
// responseReceived for an intermediate hop, so this event is the only place a
// redirect is ever observable.
func (c *collector) onRequestWillBeSent(e *network.EventRequestWillBeSent) {
	u := ""
	if e.Request != nil {
		u = e.Request.URL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// loadingFailed carries no URL, only a request id.
	if len(c.reqURL) < maxTrackedRequests {
		c.reqURL[e.RequestID] = u
	}

	if !c.mainSeen && e.Type == network.ResourceTypeDocument && u != "" && u != aboutBlank {
		if _, sub := c.subFrames[e.FrameID]; !sub {
			c.mainReqID = e.RequestID
			c.mainSeen = true
		}
	}

	if !c.mainSeen || e.RequestID != c.mainReqID || e.RedirectResponse == nil {
		return
	}
	if c.opts.MaxRedirectHops > 0 && len(c.redirects) >= c.opts.MaxRedirectHops {
		// A redirect loop is capped rather than followed forever; the cap
		// firing is itself reportable, hence the flag.
		c.redirectsDropped = true
		return
	}
	// Status and URL are those of the hop that redirected, not of its target.
	c.redirects = append(c.redirects, verdict.Hop{
		Status: int(e.RedirectResponse.Status),
		URL:    e.RedirectResponse.URL,
	})
}

// onResponseReceived records the main document's status, or a failed
// subresource.
//
// The request-id match is the load-bearing line of the whole collector: this
// event fires for every image, script and beacon on the page, and reading
// Status off any of them would make a dead tracking pixel the page's HTTP
// status. Last write wins, so the final hop of a redirect chain — the only hop
// that produces a responseReceived — is what survives.
func (c *collector) onResponseReceived(e *network.EventResponseReceived) {
	if e.Response == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mainSeen && e.RequestID == c.mainReqID {
		if _, sub := c.subFrames[e.FrameID]; !sub {
			c.docStatus = e.Response.Status
			c.docStatusText = e.Response.StatusText
			c.finalURL = e.Response.URL
			c.docMime = e.Response.MimeType
			c.docIP = e.Response.RemoteIPAddress
			c.docProtocol = e.Response.Protocol

			// A main document served as an attachment is a file, not a page:
			// Chrome answers 200, then aborts the navigation without ever
			// rendering anything. Browser.downloadWillBegin would tell us the
			// same thing, but it is delivered to the browser-level listener
			// rather than the tab's, so this header is the signal we can
			// actually see from here. Without it the URL reports a clean 200
			// and classifies as ok, having never been a page at all.
			if isAttachment(e.Response.Headers) {
				c.download = true
			}
			return
		}
	}

	if e.Response.Status < 400 {
		return
	}
	if ignoredResourceURL(e.Response.URL, c.opts.IgnoreFavicon) {
		return
	}
	c.addResourceLocked(pendingResource{
		reqID:  e.RequestID,
		url:    e.Response.URL,
		typ:    e.Type.String(),
		status: int(e.Response.Status),
	})
}

// onLoadingFailed splits transport failures into "the page never loaded" and
// "one of the page's assets never loaded" — two different error categories, and
// the split is decided purely by the request id.
func (c *collector) onLoadingFailed(e *network.EventLoadingFailed) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mainSeen && e.RequestID == c.mainReqID {
		c.mainNetError = e.ErrorText
		if e.BlockedReason != "" {
			c.blockedReason = e.BlockedReason.String()
		}
		return
	}

	// Navigation noise, not breakage: Chrome cancels in-flight subresource
	// loads whenever the page navigates away or a script drops the element.
	if e.Canceled || e.ErrorText == errAborted {
		return
	}

	u := c.reqURL[e.RequestID]
	if ignoredResourceURL(u, c.opts.IgnoreFavicon) {
		return
	}
	c.addResourceLocked(pendingResource{
		reqID:    e.RequestID,
		url:      u,
		typ:      e.Type.String(),
		netError: e.ErrorText,
	})
}

// onExceptionThrown records uncaught exceptions and unhandled promise
// rejections. This channel never carries anything else, so everything on it is
// a console error.
func (c *collector) onExceptionThrown(e *runtime.EventExceptionThrown) {
	d := e.ExceptionDetails
	if d == nil {
		return
	}

	// The script's origin decides whether this is the page's fault. An ad
	// blocker throwing inside its own content script says nothing about the
	// site under test, and would otherwise fail every page on the machine.
	src := d.URL
	if src == "" {
		if fr := firstCallFrame(d.StackTrace); fr != nil {
			src = fr.URL
		}
	}
	if isBrowserInternalURL(src) {
		return
	}

	c.mu.Lock()
	c.addConsoleLocked(pendingConsole{kind: verdict.KindException, exception: d})
	c.mu.Unlock()
}

// onConsoleAPICalled records console.error and console.assert — and
// console.warn only when the run asked for it.
//
// Runtime.consoleAPICalled covers about eighteen call types, of which
// console.log, .info, .debug, .table, .time* and the grouping calls are
// ordinary page instrumentation. Counting them would make every well-logged
// site an error.
func (c *collector) onConsoleAPICalled(e *runtime.EventConsoleAPICalled) {
	if !c.wantsAPIType(e.Type) {
		return
	}
	if fr := firstCallFrame(e.StackTrace); fr != nil && isBrowserInternalURL(fr.URL) {
		return
	}

	c.mu.Lock()
	c.addConsoleLocked(pendingConsole{
		kind:  verdict.KindConsoleAPI,
		args:  e.Args,
		stack: e.StackTrace,
	})
	c.mu.Unlock()
}

// wantsAPIType reports whether a console API call counts as an error. opts is
// immutable after construction, so this needs no lock.
func (c *collector) wantsAPIType(t runtime.APIType) bool {
	switch t {
	case runtime.APITypeError, runtime.APITypeAssert:
		return true
	case runtime.APITypeWarning:
		return c.opts.ConsoleWarnings
	}
	return false
}

// onLogEntryAdded routes Log.entryAdded, which is where the two most confusable
// classes of message arrive on the SAME channel.
//
// source=network carries "Failed to load resource: the server responded with a
// status of 404" — a SUBRESOURCE failure. Routing it to the console bucket
// would make every site with one dead tracking pixel a "console error" and
// would collapse two of this tool's three error categories into one. It goes to
// Resources, never to Console.
//
// source=javascript at level=error carries what page JavaScript never printed
// and Runtime never reported: CSP refusals and parse-time SyntaxErrors. Those
// are genuine console errors.
//
// Everything else on this channel — deprecations, interventions,
// recommendations, security notices, rendering and violation reports — is
// advisory. It describes how the page is written, not whether it works.
func (c *collector) onLogEntryAdded(e *cdplog.EventEntryAdded) {
	en := e.Entry
	if en == nil {
		return
	}

	switch {
	case en.Source == cdplog.SourceNetwork:
		// Level matters even here: Chrome emits a steady stream of
		// source=network WARNINGS about SameSite cookies and deprecated
		// headers, none of which is a failed load.
		if en.Level != cdplog.LevelError {
			return
		}
		// A ResourceError carries only a URL, a type, a status and a net error,
		// and this channel supplies none of the last three. Without a URL the
		// record would be entirely blank, so there is nothing to report.
		if en.URL == "" || ignoredResourceURL(en.URL, c.opts.IgnoreFavicon) {
			return
		}
		c.mu.Lock()
		c.addResourceLocked(pendingResource{
			reqID:   en.NetworkRequestID,
			url:     en.URL,
			fromLog: true,
		})
		c.mu.Unlock()

	// SourceSecurity at error level is where Chrome 151 actually reports a
	// blocked inline script: "Executing inline script violates the following
	// Content Security Policy directive ... The action has been blocked."
	// It arrives on no other channel — there is no exceptionThrown and no
	// consoleAPICalled — so dropping it means a page whose scripts were all
	// refused by CSP classifies as ok, which is exactly backwards. DevTools
	// prints these in red in the console, and so do we.
	//
	// The level guard is what keeps this quiet: source=security also carries
	// informational notes about certificate transparency and mixed content
	// that get downgraded rather than blocked, and those are warnings.
	case en.Source == cdplog.SourceJavascript && en.Level == cdplog.LevelError,
		en.Source == cdplog.SourceSecurity && en.Level == cdplog.LevelError:
		if isBrowserInternalURL(en.URL) {
			return
		}
		c.mu.Lock()
		c.addConsoleLocked(pendingConsole{
			kind:   verdict.KindBrowserLog,
			text:   en.Text,
			source: en.URL,
			// Unlike Runtime's script offsets, Log entries come from Blink's
			// SourceLocation, which is already 1-based — and Chrome omits the
			// field entirely (leaving 0) when the position is unknown. So this
			// one is passed through rather than incremented.
			line:  en.LineNumber,
			stack: en.StackTrace,
		})
		c.mu.Unlock()
	}
}

// addConsoleLocked buffers a console event. Callers must hold c.mu.
func (c *collector) addConsoleLocked(p pendingConsole) {
	if c.consoleRawCap > 0 && len(c.pendingConsole) >= c.consoleRawCap {
		c.consoleDropped++
		return
	}
	c.pendingConsole = append(c.pendingConsole, p)
}

// addResourceLocked buffers a subresource failure. Callers must hold c.mu.
func (c *collector) addResourceLocked(p pendingResource) {
	if c.resourceRawCap > 0 && len(c.pendingResources) >= c.resourceRawCap {
		c.resourceDropped = true
		return
	}
	c.pendingResources = append(c.pendingResources, p)
}

// snapshot renders, deduplicates and redacts everything collected so far.
//
// All the expensive work lives here rather than in handle(): string building,
// the dedupe regexes and URL redaction are each cheap on their own, but they
// run on chromedp's event goroutine if done on the event path, where they delay
// every other event and every command reply for the whole browser.
//
// It rebuilds from the raw buffer on every call, which makes it idempotent and
// makes the returned slices unaliased by construction — the caller can mutate
// them freely.
func (c *collector) snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	redact := c.opts.RedactURLs

	s := Snapshot{
		DocStatus:     int(c.docStatus),
		DocStatusText: c.docStatusText,
		FinalURL:      c.finalURL,
		DocMime:       c.docMime,
		DocIP:         c.docIP,
		DocProtocol:   c.docProtocol,
		MainNetError:  c.mainNetError,
		BlockedReason: c.blockedReason,
		Crashed:       c.crashed,
		Download:      c.download,
	}
	if redact {
		s.FinalURL = verdict.RedactURL(s.FinalURL)
	}

	if len(c.redirects) > 0 {
		s.Redirects = make([]verdict.Hop, len(c.redirects))
		copy(s.Redirects, c.redirects)
		if redact {
			for i := range s.Redirects {
				s.Redirects[i].URL = verdict.RedactURL(s.Redirects[i].URL)
			}
		}
	}

	console := verdict.NewConsoleDeduper(c.opts.MaxConsolePerPage, c.opts.MaxMessageBytes)
	for i := range c.pendingConsole {
		console.Add(c.pendingConsole[i].render(redact))
	}
	s.Console = console.Records()
	s.ConsoleSuppressed = console.Suppressed() + c.consoleDropped

	resources := verdict.NewResourceDeduper(c.opts.MaxResourcesPerPage)
	netReqs, netURLs := c.networkReportedLocked()
	for i := range c.pendingResources {
		p := &c.pendingResources[i]
		if p.fromLog && c.logCopyIsRedundantLocked(p, netReqs, netURLs) {
			continue
		}
		u := p.url
		if redact {
			u = verdict.RedactURL(u)
		}
		resources.Add(verdict.ResourceError{
			URL:      u,
			Type:     p.typ,
			Status:   p.status,
			NetError: p.netError,
		})
	}
	s.Resources = resources.Records()

	s.Truncated = console.Truncated() || resources.Truncated() ||
		c.consoleDropped > 0 || c.resourceDropped || c.redirectsDropped

	return s
}

// networkReportedLocked indexes the subresource failures the Network domain
// described, by request id and by query-stripped URL. Callers must hold c.mu.
func (c *collector) networkReportedLocked() (map[network.RequestID]struct{}, map[string]struct{}) {
	reqs := make(map[network.RequestID]struct{}, len(c.pendingResources))
	urls := make(map[string]struct{}, len(c.pendingResources))
	for i := range c.pendingResources {
		p := &c.pendingResources[i]
		if p.fromLog {
			continue
		}
		if p.reqID != "" {
			reqs[p.reqID] = struct{}{}
		}
		if p.url != "" {
			urls[verdict.StripQuery(p.url)] = struct{}{}
		}
	}
	return reqs, urls
}

// logCopyIsRedundantLocked reports whether a source=network log entry merely
// restates something already recorded.
//
// Chrome describes one dead asset twice: once precisely, on the Network domain
// (with a status, a resource type and a net error), and once as free text on
// the Log domain. Keeping both would double every subresource count. It also
// logs the MAIN document's own bad status this way, which would turn a plain
// http_error page into a subresource_error page as well.
//
// Matching is by request id, falling back to the query-stripped URL for the
// entries Chrome emits without one. Callers must hold c.mu.
func (c *collector) logCopyIsRedundantLocked(
	p *pendingResource,
	reqs map[network.RequestID]struct{},
	urls map[string]struct{},
) bool {
	if p.reqID != "" {
		if c.mainSeen && p.reqID == c.mainReqID {
			return true
		}
		if _, ok := reqs[p.reqID]; ok {
			return true
		}
	}
	stripped := verdict.StripQuery(p.url)
	if c.finalURL != "" && stripped == verdict.StripQuery(c.finalURL) {
		return true
	}
	_, ok := urls[stripped]
	return ok
}

// render turns one buffered event into the ConsoleError that reaches the logs.
func (p pendingConsole) render(redact bool) verdict.ConsoleError {
	ce := verdict.ConsoleError{Kind: p.kind, Count: 1}

	switch p.kind {
	case verdict.KindException:
		text, frame, source, line, col := renderException(p.exception)
		ce.Text, ce.Frame, ce.Source = text, frame, source
		// V8 reports script positions 0-based over CDP; DevTools displays them
		// 1-based, and so does every editor the reader will jump to.
		ce.Line, ce.Col = line+1, col+1

	case verdict.KindConsoleAPI:
		ce.Text = renderArgs(p.args)
		ce.Frame = firstFrame(p.stack)
		if fr := firstCallFrame(p.stack); fr != nil {
			ce.Source = fr.URL
			ce.Line, ce.Col = fr.LineNumber+1, fr.ColumnNumber+1
		}

	case verdict.KindBrowserLog:
		ce.Text = p.text
		ce.Source = p.source
		ce.Line = p.line // already 1-based; see onLogEntryAdded
		ce.Frame = firstFrame(p.stack)
	}

	if redact {
		// Chrome embeds full URLs inside exception messages and log text, so
		// redacting only the Source field would leak the credentials that
		// redaction exists to protect.
		ce.Text = verdict.RedactText(ce.Text)
		ce.Frame = verdict.RedactText(ce.Frame)
		ce.Source = verdict.RedactURL(ce.Source)
	}
	return ce
}

// ignoredResourceURL reports whether a subresource URL carries no signal about
// the page under test.
//
// Sourcemaps are fetched only because a debugger is attached — which is exactly
// what this tool is — so a missing .map is an artifact of the measurement, not a
// property of the page. Extension URLs belong to the user's browser profile.
// Favicons are optional by specification and missing on a large fraction of
// otherwise perfect sites.
func ignoredResourceURL(raw string, ignoreFavicon bool) bool {
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "chrome-extension:") {
		return true
	}
	path := verdict.StripQuery(raw)
	if strings.HasSuffix(path, ".map") {
		return true
	}
	return ignoreFavicon && strings.HasSuffix(path, "/favicon.ico")
}

// isBrowserInternalURL reports whether a script URL belongs to the browser
// rather than to the page: extensions, the DevTools front end, and Chrome's own
// internal pages. Errors from those are the user's environment, not the site.
func isBrowserInternalURL(raw string) bool {
	return strings.HasPrefix(raw, "chrome-extension:") ||
		strings.HasPrefix(raw, "devtools:") ||
		strings.HasPrefix(raw, "chrome:")
}

// isAttachment reports whether response headers mark the body as a download.
//
// CDP delivers headers as a map with whatever casing the server sent, so the
// lookup has to be case-insensitive on the key as well as on the value.
func isAttachment(h network.Headers) bool {
	for k, v := range h {
		if !strings.EqualFold(k, "content-disposition") {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		return strings.Contains(strings.ToLower(s), "attachment")
	}
	return false
}
