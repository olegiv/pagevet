package loader

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/olegiv/pagevet/internal/verdict"
)

// browserStartTimeout bounds Chrome's launch. Without it a machine that pops a
// firewall dialog on the loopback bind hangs forever instead of failing.
const browserStartTimeout = 30 * time.Second

// errPageTimeout is the cause attached to a per-URL deadline. Using a cause
// rather than a bare context.DeadlineExceeded is what lets us tell "this page
// hung" apart from "the user pressed Ctrl-C", which are the same error value
// but very different findings.
var errPageTimeout = errors.New("page deadline exceeded")

// Browser is a single Chrome process that serves every URL in a run, one tab
// at a time. It implements PageLoader.
type Browser struct {
	allocCtx    context.Context
	browserCtx  context.Context
	allocCancel context.CancelFunc
	browserCtxC context.CancelFunc

	opts     Options
	product  string // e.g. "Chrome/151.0.7922.138"
	closeOne sync.Once

	// hostChecked memoizes Options.CheckHost per hostname.
	//
	// A sign-in validates up to five addresses — the logout page, the login
	// page, the form's target before and after the fields are filled, and where
	// the submission landed — and they are usually all the same host. Each
	// check is a DNS lookup, and an mDNS ".local" name costs five seconds a
	// time, which was enough to spend the entire per-URL budget on resolving
	// one host over and over.
	//
	// Caching adds no weakness: the answer for a host cannot change within a
	// run in any way this program could act on, and input.CheckHost is already
	// documented as a pre-flight check vulnerable to TOCTOU and DNS rebinding.
	hostMu      sync.Mutex
	hostChecked map[string]error
}

var _ PageLoader = (*Browser)(nil)

// NewChrome starts one Chrome process for the whole run.
//
// The allocator is rooted in context.Background rather than in the caller's
// context ON PURPOSE. Shutdown has to stay under our control even when the
// caller's context has already been canceled by the very signal that
// triggered shutdown — otherwise Ctrl-C would cancel the cleanup that is
// supposed to kill Chrome. Per-URL cancellation is propagated explicitly in
// Load instead.
//
// This matters more on macOS than elsewhere: chromedp's process-group cleanup
// is a no-op on non-Linux, so a Chrome that outlives an aborted cleanup simply
// keeps running.
func NewChrome(o Options) (*Browser, error) {
	execPath, err := ResolveChromePath(o.ExecPath)
	if err != nil {
		return nil, err
	}

	// Start from chromedp's defaults, which already include a fresh temporary
	// user-data-dir. That temp profile is a security property, not an
	// implementation detail: it means no cookies, no logins and no extensions
	// from the user's REAL profile are ever exposed to a crawled page.
	//
	// -login does not weaken this. It signs in inside this throwaway profile,
	// so the session it creates is one this run established and one that dies
	// with the profile when allocCancel removes the directory. See Login.
	allocOpts := make([]chromedp.ExecAllocatorOption, 0, len(chromedp.DefaultExecAllocatorOptions)+8)
	allocOpts = append(allocOpts, chromedp.DefaultExecAllocatorOptions[:]...)
	allocOpts = append(allocOpts,
		chromedp.ExecPath(execPath),
		// Deterministic geometry keeps lazy-loading and responsive layouts
		// consistent between runs, so a page's console output does not depend
		// on whatever window size Chrome felt like.
		chromedp.WindowSize(1366, 900),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		// We never want a page to prompt, translate, or phone home.
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("disable-background-networking", true),
	)

	if !o.Headless {
		// Flag(name, false) omits the flag entirely rather than passing
		// --headless=false, which is what actually produces a visible window.
		allocOpts = append(allocOpts, chromedp.Flag("headless", false))
	}
	if o.SiteIsolation {
		// chromedp's defaults disable site-per-process. Re-enabling it is more
		// defensive against a hostile page, at the cost of cross-origin iframe
		// console errors becoming invisible to us.
		allocOpts = append(allocOpts, chromedp.Flag("site-per-process", true))
	}
	if o.UserAgent != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(o.UserAgent))
	}
	if o.ChromeStderr != nil {
		allocOpts = append(allocOpts, chromedp.CombinedOutput(o.ChromeStderr))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	b := &Browser{
		allocCtx:    allocCtx,
		browserCtx:  browserCtx,
		allocCancel: allocCancel,
		browserCtxC: browserCancel,
		opts:        o,
	}

	// The first chromedp.Run is what actually launches Chrome, and the
	// allocator binds the browser process's lifetime to the context it is
	// handed. That context MUST be browserCtx.
	//
	// Passing a derived context.WithTimeout here instead looks harmless and is
	// not: canceling that timeout - which a defer would do the moment this
	// function returned - tears down the whole browser, and every subsequent
	// Load then fails with "context canceled" against a Chrome that is already
	// gone. So the start deadline is enforced with a select below rather than
	// with a context we would have to cancel.
	started := make(chan startResult, 1)
	go func() {
		var product string
		err := chromedp.Run(browserCtx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				_, p, _, _, _, err := cdpbrowser.GetVersion().Do(ctx)
				product = p
				return err
			}),
			// A Content-Disposition download never commits a navigation, so
			// without this a download URL would silently burn the whole
			// per-URL deadline. Denying it turns the same URL into an honest
			// net::ERR_ABORTED instead.
			cdpbrowser.SetDownloadBehavior(cdpbrowser.SetDownloadBehaviorBehaviorDeny),
		)
		started <- startResult{product: product, err: err}
	}()

	select {
	case r := <-started:
		if r.err != nil {
			b.Close()
			return nil, fmt.Errorf("%w: starting %s: %w", ErrBrowserUnavailable, execPath, r.err)
		}
		b.product = r.product
	case <-time.After(browserStartTimeout):
		b.Close()
		return nil, fmt.Errorf("%w: %s did not become ready within %s",
			ErrBrowserUnavailable, execPath, browserStartTimeout)
	}

	return b, nil
}

// startResult carries the browser's self-reported version out of the startup
// goroutine. It travels by channel rather than by shared variable so that the
// timeout path cannot race the goroutine still writing to it.
type startResult struct {
	product string
	err     error
}

// Describe returns a human-readable identification of the browser for the log
// headers, e.g. "Chrome/151.0.7922.138 (headless, JavaScript enabled)".
func (b *Browser) Describe() string {
	mode := "headed"
	if b.opts.Headless {
		mode = "headless"
	}
	product := b.product
	if product == "" {
		product = "Chrome (version unknown)"
	}
	return fmt.Sprintf("%s (%s, JavaScript enabled)", product, mode)
}

// Close shuts Chrome down and removes its temporary profile. It is safe to
// call more than once.
func (b *Browser) Close() {
	b.closeOne.Do(func() {
		// Graceful first: Browser.close lets Chrome tear down its renderers and
		// delete the profile itself. It is given its own fresh context so a
		// canceled parent cannot abort the shutdown.
		if b.browserCtx.Err() == nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = chromedp.Cancel(b.browserCtx)
			}()
			select {
			case <-done:
			case <-shutdownCtx.Done():
				// Chrome ignored the polite request; the cancels below kill it.
			}
			cancel()
		}
		b.browserCtxC()
		// allocCancel waits on the exec.Cmd and removes the temp user-data-dir.
		b.allocCancel()
	})
}

// Load opens one URL in its own tab and reports what the browser observed.
//
// Per the PageLoader contract, page-level failures come back inside the Result
// with a nil error; a non-nil error means the browser itself is unusable.
//
// rather than from ctx: chromedp requires a tab to be a child of the browser it
// belongs to, and rooting it in the caller's context instead would make Ctrl-C
// tear the browser down mid-shutdown. The caller's cancellation is not dropped -
// it is forwarded explicitly by the context.AfterFunc below, and checked again
// before returning.
//
//nolint:contextcheck // The tab context deliberately descends from browserCtx
func (b *Browser) Load(ctx context.Context, index int, rawURL string) (verdict.Result, error) {
	start := time.Now()

	displayURL := rawURL
	if b.opts.RedactURLs {
		displayURL = verdict.RedactURL(rawURL)
	}
	res := verdict.Result{Index: index, URL: displayURL, Started: start}

	if err := ctx.Err(); err != nil {
		return res, err
	}
	if err := b.browserCtx.Err(); err != nil {
		return res, fmt.Errorf("%w: %w", ErrBrowserUnavailable, err)
	}

	// A fresh tab per URL. Tabs share the browser (and therefore its cookie
	// jar) but not each other's console, which is what keeps concurrent loads
	// from attributing one page's errors to another.
	tabCtx, cancelTab := chromedp.NewContext(b.browserCtx)
	defer cancelTab()

	// The tab hangs off the browser, not off the caller, so the caller's
	// cancellation has to be forwarded explicitly.
	stopForward := context.AfterFunc(ctx, cancelTab)
	defer stopForward()

	runCtx, cancelRun := context.WithTimeoutCause(tabCtx, b.opts.Timeout, errPageTimeout)
	defer cancelRun()

	col := newCollector(b.opts)
	// Listeners must be registered before the first action, or the events of
	// the navigation we are about to start are simply missed.
	chromedp.ListenTarget(runCtx, col.handle)

	pumpDone := b.startDialogPump(runCtx, col)

	resp, navErr := chromedp.RunResponse(runCtx, chromedp.Navigate(rawURL))
	if navErr == nil && b.opts.Settle > 0 {
		// Late errors are the common case in SPAs: hydration, deferred module
		// scripts and fetch handlers all throw after the load event. Ignore the
		// error here — a deadline during settle is not a navigation failure,
		// and the timeout is recorded from the context cause below.
		_ = chromedp.Run(runCtx, chromedp.Sleep(b.opts.Settle))
	}

	timedOut := errors.Is(context.Cause(runCtx), errPageTimeout)
	cancelRun()
	<-pumpDone

	snap := col.snapshot()
	b.assemble(&res, snap, resp, timedOut, start)

	// Only the CALLER's cancellation, or a dead browser, is a loader error.
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if b.browserCtx.Err() != nil {
		return res, fmt.Errorf("%w: browser exited during %s", ErrBrowserUnavailable, displayURL)
	}
	return res, nil
}

// startDialogPump dismisses JavaScript dialogs off the event path.
//
// The collector cannot answer a dialog itself: its handler runs on chromedp's
// single event-reader goroutine, and issuing a CDP call from there deadlocks
// against the response it is waiting to deliver. So the collector only signals,
// and this goroutine does the talking. Without it, one alert() on a page stalls
// the renderer until the per-URL deadline expires.
func (b *Browser) startDialogPump(ctx context.Context, col *collector) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-col.Dialogs():
				// Dismiss rather than accept: accepting a confirm() can commit
				// a navigation the page was asking permission for.
				_ = chromedp.Run(ctx, page.HandleJavaScriptDialog(false))
			case <-ctx.Done():
				return
			}
		}
	}()
	return done
}

// assemble folds the collector's observations, and whatever RunResponse
// managed to return, into the final Result.
func (b *Browser) assemble(
	res *verdict.Result,
	snap Snapshot,
	resp *network.Response,
	timedOut bool,
	start time.Time,
) {
	res.DurationMS = time.Since(start).Milliseconds()

	res.Status, res.StatusText = snap.DocStatus, snap.DocStatusText
	res.FinalURL, res.MimeType = snap.FinalURL, snap.DocMime
	res.RemoteIP, res.Protocol = snap.DocIP, snap.DocProtocol
	res.Redirects = snap.Redirects
	res.Console, res.ConsoleSuppressed = snap.Console, snap.ConsoleSuppressed
	res.Resources, res.Truncated = snap.Resources, snap.Truncated
	res.Crashed, res.Download = snap.Crashed, snap.Download
	res.NetError, res.BlockReason = snap.MainNetError, snap.BlockedReason

	// RunResponse only ENRICHES. It returns nil on every error path — including
	// a timeout — so a page that answered 500 and then hung would lose its
	// status entirely if this were the only source. The collector is the
	// source of truth; this fills gaps.
	if resp != nil {
		if res.Status == 0 {
			res.Status, res.StatusText = int(resp.Status), resp.StatusText
		}
		if res.FinalURL == "" {
			res.FinalURL = resp.URL
		}
		if res.MimeType == "" {
			res.MimeType = resp.MimeType
		}
		if res.RemoteIP == "" {
			res.RemoteIP = resp.RemoteIPAddress
		}
		if res.Protocol == "" {
			res.Protocol = resp.Protocol
		}
	}

	if b.opts.RedactURLs {
		res.FinalURL = verdict.RedactURL(res.FinalURL)
		for i := range res.Redirects {
			res.Redirects[i].URL = verdict.RedactURL(res.Redirects[i].URL)
		}
	}

	switch {
	case res.Crashed:
		res.NetError, res.NetErrorClass, res.SettledBy = "net::ERR_RENDERER_CRASHED", "OTHER", "crash"
	case res.NetError != "":
		res.NetErrorClass, res.SettledBy = ClassifyNetError(res.NetError), "netfail"
	case timedOut:
		res.TimedOut, res.SettledBy = true, "deadline"
	default:
		res.SettledBy = "load"
	}

	// 204 and 205 do not commit a navigation: Chrome leaves the previous page
	// up, never fires a load event, and RunResponse burns the whole deadline.
	// The collector still saw the response, so we have a real status — report
	// it instead of a bogus timeout.
	if res.Status == 204 || res.Status == 205 {
		res.TimedOut, res.SettledBy = false, "no-content"
	}

	// A download is not a page. With SetDownloadBehavior(Deny), Chrome answers
	// the request - so a bare net::ERR_ABORTED alongside a perfectly healthy
	// 200 is all a reader would otherwise see. Name the real reason instead;
	// verdict.Classify turns Download into a load error regardless of status.
	if res.Download {
		res.NetError, res.NetErrorClass, res.SettledBy = "download_not_a_page", "OTHER", "download"
	}
}

// netErrorClasses maps net:: error prefixes to the coarse class reported in
// results.jsonl. The raw string is always kept verbatim alongside it — the
// class is additive, never a replacement, because the exact error is what a
// user needs to act on.
var netErrorClasses = []struct {
	prefix string
	class  string
}{
	{"net::ERR_NAME_", "DNS"},
	{"net::ERR_DNS_", "DNS"},
	{"net::ERR_ICANN_", "DNS"},
	{"net::ERR_CERT_", "TLS"},
	{"net::ERR_SSL_", "TLS"},
	{"net::ERR_BAD_SSL_", "TLS"},
	{"net::ERR_TIMED_OUT", "TIMEOUT"},
	{"net::ERR_CONNECTION_TIMED_OUT", "TIMEOUT"},
	{"net::ERR_CONNECTION_", "CONNECT"},
	{"net::ERR_ADDRESS_", "CONNECT"},
	{"net::ERR_INTERNET_DISCONNECTED", "CONNECT"},
	{"net::ERR_SOCKET_", "CONNECT"},
	{"net::ERR_PROXY_", "CONNECT"},
	{"net::ERR_TUNNEL_", "CONNECT"},
	{"net::ERR_BLOCKED_", "BLOCKED"},
	{"net::ERR_UNSAFE_", "BLOCKED"},
	{"net::ERR_UNKNOWN_URL_SCHEME", "BLOCKED"},
	{"net::ERR_DISALLOWED_URL_SCHEME", "BLOCKED"},
	{"net::ERR_ABORTED", "ABORTED"},
	{"net::ERR_EMPTY_RESPONSE", "PROTOCOL"},
	{"net::ERR_INVALID_", "PROTOCOL"},
	{"net::ERR_RESPONSE_", "PROTOCOL"},
	{"net::ERR_CONTENT_DECODING_", "PROTOCOL"},
	{"net::ERR_TOO_MANY_REDIRECTS", "PROTOCOL"},
	{"net::ERR_HTTP2_", "PROTOCOL"},
	{"net::ERR_QUIC_", "PROTOCOL"},
	{"net::ERR_HTTP_", "PROTOCOL"},
}

// ClassifyNetError buckets a raw net:: error string. An unrecognized error
// returns "OTHER" rather than an empty string, so the field is never
// ambiguous between "not classified" and "not present".
func ClassifyNetError(netErr string) string {
	if netErr == "" {
		return ""
	}
	// Longest prefix wins, so ERR_CONNECTION_TIMED_OUT is a TIMEOUT rather
	// than being swallowed by the shorter ERR_CONNECTION_ CONNECT rule.
	best, bestLen := "OTHER", 0
	for _, c := range netErrorClasses {
		if len(c.prefix) > bestLen && strings.HasPrefix(netErr, c.prefix) {
			best, bestLen = c.class, len(c.prefix)
		}
	}
	return best
}
