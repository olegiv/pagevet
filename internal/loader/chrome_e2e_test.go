package loader

// The real-Chrome half of the loader's tests.
//
// Every test here is gated on browsertest.Guard, so an ordinary `go test ./...`
// stays hermetic and fast: without PAGEVET_E2E=1 the bodies skip loudly and no
// browser is ever launched, while the file itself is still compiled, vetted and
// linted on every run.
//
// What these tests buy is the only evidence that matters for this program's
// central claim — that pages are RENDERED rather than fetched — plus the one
// place where the collector's CDP state machine meets a browser that actually
// emits the events it was written against. collector_test.go proves the state
// machine is right about the protocol; this file proves the protocol is what we
// think it is.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/loader/browsertest"
	"github.com/olegiv/pagevet/internal/testfixtures"
	"github.com/olegiv/pagevet/internal/verdict"
)

const (
	// e2eTimeout is the shared browser's per-URL deadline. It sits far below the
	// suite timeout, so a page that hangs fails its own test instead of killing
	// the binary with no attribution, and far above a normal fixture load
	// (~1.6s, nearly all of it the settle window) so a loaded machine cannot
	// turn a healthy page into a timeout.
	e2eTimeout = 15 * time.Second

	// quickLoad bounds every "this must not burn the deadline" assertion:
	// 204s, alerts and downloads. It is deliberately between a normal load and
	// e2eTimeout — nothing can exceed it except something genuinely waiting on
	// the per-URL deadline.
	quickLoad = 8 * time.Second

	// loadDeadline is the caller-side deadline every Load in this file runs
	// under. It must exceed e2eTimeout: a page hitting its OWN deadline has to
	// come back as a timeout Result, whereas this deadline expiring is a loader
	// error and would mask it.
	loadDeadline = 45 * time.Second
)

// sharedEnv is the one fixture server and the one Chrome the whole file uses.
//
// Chrome costs about a second to start and rather more to stop, so a browser
// per test would dominate the runtime; on macOS a failed teardown also leaves a
// stray process behind, and there is no reason to have twenty chances at that.
// Each test still gets its own TAB, which is the isolation boundary that
// actually matters — see TestChrome_ConcurrentLoads.
type sharedEnv struct {
	srv *httptest.Server
	br  *Browser
}

// live publishes the started environment for TestMain to tear down. A test
// helper cannot own this: t.Cleanup runs when its own test ends, and the shared
// browser has to outlive every test that borrows it.
var live atomic.Pointer[sharedEnv]

// sharedChrome starts the environment on first use and hands the same one to
// everybody afterwards. Starting lazily is what keeps a guarded-off run from
// launching a browser it will never use.
var sharedChrome = sync.OnceValues(startShared)

func startShared() (*sharedEnv, error) {
	// The server comes up FIRST so that it can go down LAST: Chrome must be
	// dead before the pages it might still be fetching disappear underneath it.
	// TestMain enforces the reverse order explicitly.
	//
	// log.Printf rather than a t.Logf: there is no test to attach to from here.
	// Two routes log by design when a test abandons them (/slow and /hangup),
	// so a "testfixtures:" line is not on its own a failure.
	srv := httptest.NewServer(testfixtures.Handler(log.Printf))

	o := DefaultOptions()
	o.Timeout = e2eTimeout
	o.ExecPath = chromeExecPath()

	br, err := NewChrome(o)
	if err != nil {
		srv.Close()
		return nil, err
	}

	env := &sharedEnv{srv: srv, br: br}
	live.Store(env)
	return env, nil
}

func TestMain(m *testing.M) {
	code := m.Run()
	// Browser first, server second — the reverse of startup. os.Exit skips
	// defers, so the teardown runs before it rather than in one.
	if env := live.Load(); env != nil {
		env.br.Close()
		env.srv.Close()
	}
	os.Exit(code)
}

// chromeExecPath is the explicit override browsertest.Guard honors, or "" for
// autodetect — the same two-step ResolveChromePath performs for -chrome.
func chromeExecPath() string {
	return strings.TrimSpace(os.Getenv(browsertest.EnvChromePath))
}

// e2e guards the calling test and returns the shared environment.
func e2e(t *testing.T) *sharedEnv {
	t.Helper()

	browsertest.Guard(t)

	env, err := sharedChrome()
	if err != nil {
		// Guard already established that a browser binary exists, so failing to
		// start it is a defect rather than a missing dependency: fail, do not
		// skip.
		t.Fatalf("starting the shared browser: %v", err)
	}
	return env
}

// url builds an absolute fixture URL. srv.URL is used exactly as given — see
// FLAKE RULE 1 in internal/testfixtures for why rewriting the host is a trap.
func (e *sharedEnv) url(path string) string { return e.srv.URL + path }

// load runs one fixture page on the shared browser and reports how long it took.
func (e *sharedEnv) load(t *testing.T, path string) (verdict.Result, time.Duration) {
	t.Helper()
	return loadURL(t, e.br, e.url(path))
}

// loadURL is load for the tests that need a browser or a URL of their own.
//
// The caller-side deadline is what makes a regression FAIL rather than hang
// until the go test timeout kills the whole binary with no attribution.
func loadURL(t *testing.T, br *Browser, rawURL string) (verdict.Result, time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), loadDeadline)
	defer cancel()

	start := time.Now()
	res, err := br.Load(ctx, 1, rawURL)
	elapsed := time.Since(start)
	if err != nil {
		// Per the PageLoader contract a non-nil error means the LOADER is
		// unusable; every page-level failure arrives inside the Result.
		t.Fatalf("Load(%q) returned a loader error after %s: %v", rawURL, elapsed, err)
	}
	return res, elapsed
}

// newBrowser starts a Chrome of its own, for the tests whose Options differ
// from the shared one's. Its cleanup closes it; the shared fixture server
// outlives every test, so nothing here can be torn down out of order.
func newBrowser(t *testing.T, o Options) *Browser {
	t.Helper()

	o.ExecPath = chromeExecPath()
	br, err := NewChrome(o)
	if err != nil {
		t.Fatalf("NewChrome: %v", err)
	}
	t.Cleanup(br.Close)
	return br
}

// outcomeOf classifies under the shipped policy, which is the one the CLI uses.
func outcomeOf(r verdict.Result) verdict.Outcome {
	return verdict.Classify(r, verdict.DefaultPolicy())
}

// -- proof of the core requirement ---------------------------------------------

// TestChrome_ExecutesJavaScript is the test that separates pagevet from an HTTP
// GET. /ok's only distinguishing feature is an inline <script> that assigns
// document.title, and it must come back as a clean 200 with nothing else
// attached — no phantom console error from the script having run, no phantom
// subresource failure from the favicon.
//
// The Result carries no title field, so the engine leaves its fingerprint in
// the sibling tests instead: the TypeError in TestChrome_CapturesUncaughtTypeError
// and the rendered "boom 42" in TestChrome_CapturesConsoleError can only exist
// if a JavaScript engine executed the page. This test pins the other half of
// that claim — running script cleanly must produce no findings at all.
func TestChrome_ExecutesJavaScript(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, elapsed := env.load(t, "/ok")

	if res.Status != 200 {
		t.Errorf("Status = %d, want 200 (result: %+v)", res.Status, res)
	}
	if got := outcomeOf(res); got != verdict.OutcomeOK {
		t.Errorf("outcome = %s, want ok (console=%+v resources=%+v)", got, res.Console, res.Resources)
	}
	if res.SettledBy != "load" {
		t.Errorf("SettledBy = %q, want %q", res.SettledBy, "load")
	}
	if elapsed > quickLoad {
		t.Errorf("a clean page took %s, want well under %s", elapsed, quickLoad)
	}
}

// -- HTTP status ----------------------------------------------------------------

func TestChrome_HTTP404(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/status/404")

	if res.Status != 404 {
		t.Errorf("Status = %d, want 404", res.Status)
	}
	if got := outcomeOf(res); got != verdict.OutcomeHTTPError {
		t.Errorf("outcome = %s, want http_error (result: %+v)", got, res)
	}
	// Chrome also logs the main document's bad status on the Log domain as
	// "Failed to load resource". An http_error page must not also be reported
	// as a subresource_error because of it.
	if len(res.Resources) != 0 {
		t.Errorf("Resources = %+v, want empty: the main document is not a subresource", res.Resources)
	}
}

func TestChrome_HTTP500(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/status/500")

	if res.Status != 500 {
		t.Errorf("Status = %d, want 500", res.Status)
	}
	if got := outcomeOf(res); got != verdict.OutcomeHTTPError {
		t.Errorf("outcome = %s, want http_error (result: %+v)", got, res)
	}
}

// TestChrome_HTTP500EmptyBody is the regression test for chromedp.RunResponse
// discarding its *network.Response on every error path. A bodyless error
// response is the cheapest way to reach that path, and the status still has to
// arrive — because the collector captures it independently of RunResponse.
func TestChrome_HTTP500EmptyBody(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, elapsed := env.load(t, "/status/500?empty=1")

	if res.Status != 500 {
		t.Errorf("Status = %d, want 500 (the collector lost the status: %+v)", res.Status, res)
	}
	if res.TimedOut {
		t.Errorf("TimedOut = true, want false: an empty body is a completed load (SettledBy=%q)", res.SettledBy)
	}
	if elapsed > quickLoad {
		t.Errorf("took %s, want well under %s: an empty 500 must not wait on the deadline", elapsed, quickLoad)
	}
	if got := outcomeOf(res); got != verdict.OutcomeHTTPError {
		t.Errorf("outcome = %s, want http_error", got)
	}
}

// TestChrome_HTTP204DoesNotTimeOut covers the status that commits no
// navigation: Chrome leaves the previous page up and never fires a load event,
// so a naive implementation waits out the whole per-URL deadline and then
// reports a timeout it invented. The collector saw the response, so the honest
// answer is 204, settled by "no-content", promptly.
func TestChrome_HTTP204DoesNotTimeOut(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, elapsed := env.load(t, "/status/204")

	if res.Status != 204 {
		t.Errorf("Status = %d, want 204 (result: %+v)", res.Status, res)
	}
	if res.SettledBy != "no-content" {
		t.Errorf("SettledBy = %q, want %q", res.SettledBy, "no-content")
	}
	if res.TimedOut {
		t.Error("TimedOut = true: a 204 is an answer, not a hang")
	}
	if elapsed > quickLoad {
		t.Errorf("took %s, want well under %s (the per-URL deadline is %s)", elapsed, quickLoad, e2eTimeout)
	}
}

func TestChrome_RedirectChainEndingIn200(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/redirect/2/ok")

	if res.Status != 200 {
		t.Errorf("Status = %d, want 200", res.Status)
	}
	if len(res.Redirects) != 2 {
		t.Fatalf("Redirects = %+v, want 2 hops", res.Redirects)
	}
	// A hop records the status and URL of the page that redirected, not of its
	// target — so hop 0 is the URL the crawl was pointed at.
	want := []verdict.Hop{
		{Status: 302, URL: env.url("/redirect/2/ok")},
		{Status: 302, URL: env.url("/redirect/1/ok")},
	}
	for i, w := range want {
		if res.Redirects[i] != w {
			t.Errorf("hop %d = %+v, want %+v", i, res.Redirects[i], w)
		}
	}
	if res.FinalURL != env.url("/ok") {
		t.Errorf("FinalURL = %q, want %q", res.FinalURL, env.url("/ok"))
	}
	if got := outcomeOf(res); got != verdict.OutcomeOK {
		t.Errorf("outcome = %s, want ok", got)
	}
}

// TestChrome_RedirectChainEndingIn404 pins which hop decides the verdict: the
// FINAL one. Reporting the first 302 would make every broken redirect look fine.
func TestChrome_RedirectChainEndingIn404(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/redirect/2/status/404")

	if res.Status != 404 {
		t.Errorf("Status = %d, want 404 (an intermediate 302 won: %+v)", res.Status, res.Redirects)
	}
	if len(res.Redirects) != 2 {
		t.Errorf("Redirects = %+v, want 2 hops", res.Redirects)
	}
	if got := outcomeOf(res); got != verdict.OutcomeHTTPError {
		t.Errorf("outcome = %s, want http_error", got)
	}
}

// -- console errors --------------------------------------------------------------

func TestChrome_CapturesUncaughtTypeError(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/throw")

	if len(res.Console) != 1 {
		t.Fatalf("Console = %+v, want exactly one record", res.Console)
	}
	got := res.Console[0]
	if got.Kind != verdict.KindException {
		t.Errorf("Kind = %s, want %s: an uncaught throw arrives on Runtime.exceptionThrown", got.Kind, verdict.KindException)
	}
	if !strings.Contains(got.Text, "TypeError") {
		t.Errorf("Text = %q, want it to name the TypeError", got.Text)
	}
	// CDP reports script positions 0-based; every editor the reader will jump
	// to is 1-based, so a 0 here means the conversion was lost.
	if got.Line < 1 || got.Col < 1 {
		t.Errorf("position = %d:%d, want both >= 1 (1-based)", got.Line, got.Col)
	}
	if got.Count != 1 {
		t.Errorf("Count = %d, want 1", got.Count)
	}
	if o := outcomeOf(res); o != verdict.OutcomeConsoleError {
		t.Errorf("outcome = %s, want console_error", o)
	}
}

// TestChrome_CapturesConsoleError proves the RemoteObject rendering works from
// the event payload alone: console.error("boom", 42) has to come out as
// "boom 42" without a CDP round-trip, because a round-trip from the event
// goroutine would deadlock the browser.
func TestChrome_CapturesConsoleError(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/console-error")

	if len(res.Console) != 1 {
		t.Fatalf("Console = %+v, want exactly one record", res.Console)
	}
	got := res.Console[0]
	if got.Kind != verdict.KindConsoleAPI {
		t.Errorf("Kind = %s, want %s", got.Kind, verdict.KindConsoleAPI)
	}
	if !strings.Contains(got.Text, "boom") || !strings.Contains(got.Text, "42") {
		t.Errorf("Text = %q, want both arguments rendered", got.Text)
	}
	if o := outcomeOf(res); o != verdict.OutcomeConsoleError {
		t.Errorf("outcome = %s, want console_error", o)
	}
}

// TestChrome_IgnoresConsoleNoise is the negative control for the whole console
// category: log, info, warn and debug are ordinary page instrumentation.
// Counting them would make nearly every real site fail, which would make the
// tool useless rather than strict.
func TestChrome_IgnoresConsoleNoise(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/console-noise")

	if len(res.Console) != 0 {
		t.Errorf("Console = %+v, want empty", res.Console)
	}
	if got := outcomeOf(res); got != verdict.OutcomeOK {
		t.Errorf("outcome = %s, want ok", got)
	}
}

// TestChrome_DedupesRepeatedErrors: the fixture throws from the same source
// position three times, out of three separate tasks. One record, count three —
// a page erroring once per animation frame must not fill the log.
func TestChrome_DedupesRepeatedErrors(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/console-dup")

	if len(res.Console) != 1 {
		t.Fatalf("Console = %+v, want one collapsed record", res.Console)
	}
	if res.Console[0].Count != 3 {
		t.Errorf("Count = %d, want 3 (text %q)", res.Console[0].Count, res.Console[0].Text)
	}
	if res.ConsoleEvents() != 3 {
		t.Errorf("ConsoleEvents() = %d, want 3", res.ConsoleEvents())
	}
	if res.ConsoleSuppressed != 0 || res.Truncated {
		t.Errorf("suppressed=%d truncated=%v, want 0/false", res.ConsoleSuppressed, res.Truncated)
	}
}

// TestChrome_CapturesUnhandledRejection covers the other half of
// Runtime.exceptionThrown: a promise nobody handled.
//
// No polling and no sleeping happen here. V8 reports the rejection at the end
// of the microtask checkpoint — long before the load event — and Load holds the
// tab open for the settle window on top of that, so the record is already in
// the Snapshot by the time Load returns. (The fixture's window.__rejectionSeen
// listener is there for a caller that can reach into the page; Load owns and
// closes the tab, so this test asserts on the record instead.)
func TestChrome_CapturesUnhandledRejection(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/reject")

	if len(res.Console) != 1 {
		t.Fatalf("Console = %+v, want exactly one record", res.Console)
	}
	got := res.Console[0]
	if got.Kind != verdict.KindException {
		t.Errorf("Kind = %s, want %s", got.Kind, verdict.KindException)
	}
	if !strings.Contains(got.Text, "pagevet unhandled rejection") {
		t.Errorf("Text = %q, want the rejection reason", got.Text)
	}
	if o := outcomeOf(res); o != verdict.OutcomeConsoleError {
		t.Errorf("outcome = %s, want console_error", o)
	}
}

// TestChrome_CapturesCSPViolation covers the third console channel: a refusal
// the BROWSER reports, which page JavaScript never printed and Runtime never
// saw. It arrives as Log.entryAdded, which is the entire reason KindBrowserLog
// exists.
//
// WHICH Log entry it arrives as depends on the Chrome version, and the
// difference decides whether the refusal is reported at all:
//
//   - source="javascript", level="error" is routed to Console as
//     KindBrowserLog, which is what onLogEntryAdded documents and expects;
//   - source="security" is treated as advisory and dropped, because a security
//     notice normally describes how a page is written rather than something
//     that failed.
//
// Chrome 151 uses the second one. Verified on 151.0.7922.138 (2026-08-14), the
// only event this page produces is:
//
//	Log.entryAdded source="security" level="error" line=3
//	  "Executing inline script violates the following Content Security Policy
//	   directive 'script-src 'self''. ... The action has been blocked."
//
// No Runtime.exceptionThrown and no Runtime.consoleAPICalled accompany it, so
// on this Chrome a CSP refusal produces NO console error and the page
// classifies as ok — even though the policy really was enforced (the fixture's
// document.title assignment never ran). That is a genuine gap, reported rather
// than asserted away: the skip below fires on exactly the versions that have
// it, and the assertions run on the versions that do not.
func TestChrome_CapturesCSPViolation(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/csp")

	// The page itself is fine; only its inline script was refused.
	if res.Status != 200 {
		t.Errorf("Status = %d, want 200", res.Status)
	}
	// Chrome 151 reports a CSP-blocked inline script as a Log entry with
	// source="security", level="error" — there is no exceptionThrown and no
	// consoleAPICalled for it. onLogEntryAdded routes that source at error
	// level to the console bucket precisely so this case is not silently ok.
	if len(res.Console) != 1 {
		t.Fatalf("Console = %+v, want exactly one record", res.Console)
	}
	got := res.Console[0]
	if got.Kind != verdict.KindBrowserLog {
		t.Errorf("Kind = %s, want %s (record: %+v)", got.Kind, verdict.KindBrowserLog, got)
	}
	if !strings.Contains(got.Text, "Content Security Policy") {
		t.Errorf("Text = %q, want Chrome's CSP refusal", got.Text)
	}
	if o := outcomeOf(res); o != verdict.OutcomeConsoleError {
		t.Errorf("outcome = %s, want console_error", o)
	}
}

// -- subresource failures ---------------------------------------------------------

// TestChrome_SubresourceFailureIsItsOwnCategory is the single most important
// classification rule in the program: a dead asset on a page that itself loaded
// fine is a SUBRESOURCE error, never a console error and never an HTTP error.
//
// It is also the de-duplication test. Chrome describes the same dead script
// twice — precisely on the Network domain, and as free text on the Log domain —
// and the Log copy is the one that would otherwise land in Console and collapse
// two of this tool's three error categories into one.
func TestChrome_SubresourceFailureIsItsOwnCategory(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := env.load(t, "/subresource-404")

	if res.Status != 200 {
		t.Errorf("Status = %d, want 200: the PAGE loaded, only its script did not", res.Status)
	}
	if len(res.Console) != 0 {
		t.Errorf("Console = %+v, want empty: a failed subresource is not a console error", res.Console)
	}
	if len(res.Resources) != 1 {
		t.Fatalf("Resources = %+v, want exactly one (Chrome reports it on two domains)", res.Resources)
	}
	got := res.Resources[0]
	if !strings.Contains(got.URL, "/status/404") {
		t.Errorf("Resources[0].URL = %q, want the dead script", got.URL)
	}
	if got.Status != 404 {
		t.Errorf("Resources[0].Status = %d, want 404 (the precise Network-domain record was not the one kept: %+v)", got.Status, got)
	}
	if o := outcomeOf(res); o != verdict.OutcomeSubresourceError {
		t.Errorf("outcome = %s, want subresource_error", o)
	}
}

// TestChrome_IgnoresFaviconFailures: a missing favicon is near-universal and
// says nothing about the page. Since failed subresources are their own error
// category, counting it would fail a large fraction of otherwise perfect sites.
//
// The failing request is an <img> rather than Chrome's own favicon fetch on
// purpose: the img is requested as part of the document load, so the assertion
// is deterministic, while the browser's favicon fetch is asynchronous and may
// land after the settle window. The rule under test is the URL suffix either way.
func TestChrome_IgnoresFaviconFailures(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	var requested atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasSuffix(r.URL.Path, "/favicon.ico") {
			requested.Add(1)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write([]byte(faviconOnlyHTML)); err != nil {
			t.Logf("writing the favicon fixture page: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	res, _ := loadURL(t, env.br, srv.URL+"/")

	if n := requested.Load(); n == 0 {
		t.Fatal("the page never requested the favicon, so nothing was ignored")
	}
	if res.Status != 200 {
		t.Errorf("Status = %d, want 200", res.Status)
	}
	if len(res.Resources) != 0 {
		t.Errorf("Resources = %+v, want empty: a missing favicon is not a finding", res.Resources)
	}
	if got := outcomeOf(res); got != verdict.OutcomeOK {
		t.Errorf("outcome = %s, want ok (console=%+v)", got, res.Console)
	}
}

// faviconOnlyHTML is a page whose only failing request is a favicon.
const faviconOnlyHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>favicon-only</title>
<link rel="icon" href="/favicon.ico"></head>
<body><h1>favicon-only</h1><img src="/favicon.ico" alt=""></body></html>
`

// -- failure modes ----------------------------------------------------------------

// TestChrome_ConnectionRefused uses a port a listener has just vacated rather
// than a hardcoded low one. The obvious candidate, 127.0.0.1:1, is the wrong
// one: ports 1 and 21 are both on Chrome's restricted-port list and come back
// as net::ERR_UNSAFE_PORT with class BLOCKED (verified on Chrome 151), which is
// a different failure from the refused connection this test is about. An
// ephemeral port whose listener has just closed is refused for the right reason.
func TestChrome_ConnectionRefused(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL + "/"
	dead.Close()

	res, _ := loadURL(t, env.br, deadURL)

	if res.Status != 0 {
		t.Errorf("Status = %d, want 0: nothing answered", res.Status)
	}
	if !strings.Contains(res.NetError, "ERR_CONNECTION_REFUSED") {
		t.Errorf("NetError = %q, want ERR_CONNECTION_REFUSED", res.NetError)
	}
	if got := ClassifyNetError(res.NetError); got != "CONNECT" {
		t.Errorf("ClassifyNetError(%q) = %q, want CONNECT", res.NetError, got)
	}
	if res.NetErrorClass != "CONNECT" {
		t.Errorf("NetErrorClass = %q, want CONNECT", res.NetErrorClass)
	}
	if got := outcomeOf(res); got != verdict.OutcomeLoadError {
		t.Errorf("outcome = %s, want load_error", got)
	}
}

// TestChrome_UnresolvableHost uses the reserved .invalid TLD, which no resolver
// is permitted to answer.
func TestChrome_UnresolvableHost(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, _ := loadURL(t, env.br, "http://pagevet-no-such-host.invalid/")

	if res.Status != 0 {
		t.Errorf("Status = %d, want 0", res.Status)
	}
	if !strings.Contains(res.NetError, "ERR_NAME_NOT_RESOLVED") {
		t.Errorf("NetError = %q, want ERR_NAME_NOT_RESOLVED", res.NetError)
	}
	if res.NetErrorClass != "DNS" {
		t.Errorf("NetErrorClass = %q, want DNS", res.NetErrorClass)
	}
	if got := outcomeOf(res); got != verdict.OutcomeLoadError {
		t.Errorf("outcome = %s, want load_error", got)
	}
}

// TestChrome_EmptyResponse covers the transport failure that has no HTTP status
// to report: the server accepted the connection and then dropped it.
func TestChrome_EmptyResponse(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, elapsed := env.load(t, "/hangup")

	if res.Status != 0 {
		t.Errorf("Status = %d, want 0", res.Status)
	}
	if !strings.Contains(res.NetError, "ERR_EMPTY_RESPONSE") {
		t.Errorf("NetError = %q, want ERR_EMPTY_RESPONSE", res.NetError)
	}
	if res.SettledBy != "netfail" {
		t.Errorf("SettledBy = %q, want %q", res.SettledBy, "netfail")
	}
	if elapsed > quickLoad {
		t.Errorf("took %s, want well under %s: a dropped connection is immediate", elapsed, quickLoad)
	}
	if got := outcomeOf(res); got != verdict.OutcomeLoadError {
		t.Errorf("outcome = %s, want load_error", got)
	}
}

// TestChrome_RespectsTimeout asserts the ELAPSED time, not just the flag: a
// TimedOut set by a deadline that never fired would still read as green.
func TestChrome_RespectsTimeout(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	const pageTimeout = 3 * time.Second
	o := DefaultOptions()
	o.Timeout = pageTimeout
	br := newBrowser(t, o)

	res, elapsed := loadURL(t, br, env.url("/slow?d=30s"))

	if elapsed > 10*time.Second {
		t.Errorf("took %s with a %s deadline: the deadline is not being enforced", elapsed, pageTimeout)
	}
	if elapsed < pageTimeout {
		t.Errorf("took %s, less than the %s deadline: the page gave up early, so this proves nothing", elapsed, pageTimeout)
	}
	if !res.TimedOut {
		t.Errorf("TimedOut = false after %s (result: %+v)", elapsed, res)
	}
	if res.SettledBy != "deadline" {
		t.Errorf("SettledBy = %q, want %q", res.SettledBy, "deadline")
	}
	if got := outcomeOf(res); got != verdict.OutcomeTimeout {
		t.Errorf("outcome = %s, want timeout", got)
	}
}

// TestChrome_DismissesAlertDialog is the regression test for the dialog pump.
// A modal dialog stops the renderer until somebody answers it, and the
// collector cannot answer one itself — a CDP call from the event goroutine
// deadlocks against the reply it is waiting for. Without the pump goroutine a
// single alert() burns the entire per-URL deadline.
func TestChrome_DismissesAlertDialog(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, elapsed := env.load(t, "/alert")

	if elapsed > quickLoad {
		t.Errorf("took %s of the %s deadline: the dialog was never dismissed", elapsed, e2eTimeout)
	}
	if res.Status != 200 {
		t.Errorf("Status = %d, want 200", res.Status)
	}
	if res.TimedOut {
		t.Error("TimedOut = true: the alert stalled the renderer")
	}
	if got := outcomeOf(res); got != verdict.OutcomeOK {
		t.Errorf("outcome = %s, want ok (console=%+v)", got, res.Console)
	}
}

// TestChrome_DownloadDoesNotHang: a Content-Disposition attachment never
// commits a navigation and never fires a load event. SetDownloadBehavior(Deny)
// turns it into an honest net::ERR_ABORTED instead of a page that waits out the
// deadline for a document that was never going to arrive.
//
// On Chrome 151 the response header arrives before the abort, so the Result
// carries BOTH a 200 and net::ERR_ABORTED, and settles by "netfail" in about
// 70ms. Which of the two settlements shows up depends on where Chrome delivers
// browser.downloadWillBegin — the target listener or the browser listener,
// which has changed between releases — so the assertion accepts either. What
// must never appear is "deadline".
func TestChrome_DownloadDoesNotHang(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	res, elapsed := env.load(t, "/download")

	if elapsed > quickLoad {
		t.Errorf("took %s of the %s deadline: the download was never refused", elapsed, e2eTimeout)
	}
	if res.TimedOut {
		t.Errorf("TimedOut = true (result: %+v)", res)
	}

	// Chrome answers a denied download with a perfectly healthy 200 and then
	// aborts the navigation, so without the Content-Disposition check in the
	// collector this URL would report as a clean page it never was.
	if !res.Download {
		t.Errorf("Download = false: the Content-Disposition attachment was not detected (result: %+v)", res)
	}
	if res.SettledBy != "download" {
		t.Errorf("SettledBy = %q, want download (result: %+v)", res.SettledBy, res)
	}
	if o := outcomeOf(res); o != verdict.OutcomeLoadError {
		t.Errorf("outcome = %s, want load_error: a file transfer is not a page", o)
	}
}

// TestChrome_BrowserUnavailable needs no Chrome and is deliberately NOT behind
// the guard: the sentinel it checks is what turns a bad -chrome path into a
// run-fatal exit rather than a per-URL result, and that has to hold on a
// machine with no browser at all.
func TestChrome_BrowserUnavailable(t *testing.T) {
	t.Parallel()

	o := DefaultOptions()
	o.ExecPath = "/nonexistent/chrome"

	br, err := NewChrome(o)
	if err == nil {
		br.Close()
		t.Fatal("NewChrome accepted a path with no binary at it")
	}
	if !errors.Is(err, ErrBrowserUnavailable) {
		t.Errorf("error %v does not wrap ErrBrowserUnavailable", err)
	}
}

// -- concurrency -------------------------------------------------------------------

// TestChrome_ConcurrentLoads is the highest-value test in the file: eight pages
// loaded at once on one browser, each of which must carry ONLY its own errors.
//
// Tabs share a browser and therefore a CDP connection, so every page's events
// arrive interleaved on one goroutine. If the per-tab listener or the
// collector's locking were wrong, /ok would come back carrying /throw's
// TypeError — and a crawl would report errors against pages that never had
// them. The "want exactly" assertions below are what catch that; a bleed shows
// up as an EXTRA record, not a missing one.
func TestChrome_ConcurrentLoads(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	type page struct {
		path      string
		console   int
		resources int
		contains  string
	}
	// Each page twice: two tabs on the same URL are still two tabs, and a
	// collector shared between them would show up as doubled counts.
	pages := []page{
		{path: "/ok"},
		{path: "/throw", console: 1, contains: "TypeError"},
		{path: "/console-error", console: 1, contains: "boom"},
		{path: "/subresource-404", resources: 1},
		{path: "/ok"},
		{path: "/throw", console: 1, contains: "TypeError"},
		{path: "/console-error", console: 1, contains: "boom"},
		{path: "/subresource-404", resources: 1},
	}

	ctx, cancel := context.WithTimeout(t.Context(), loadDeadline)
	defer cancel()

	results := make([]verdict.Result, len(pages))
	errs := make([]error, len(pages))

	var wg sync.WaitGroup
	for i, p := range pages {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Distinct slots, one writer each: the only shared state is the
			// browser, which is the thing under test.
			results[i], errs[i] = env.br.Load(ctx, i+1, env.url(p.path))
		}()
	}
	wg.Wait()

	for i, p := range pages {
		t.Run(strconv.Itoa(i)+p.path, func(t *testing.T) {
			if errs[i] != nil {
				t.Fatalf("Load(%s) returned a loader error: %v", p.path, errs[i])
			}
			res := results[i]
			if res.Index != i+1 {
				t.Errorf("Index = %d, want %d: results were crossed", res.Index, i+1)
			}
			if res.Status != 200 {
				t.Errorf("Status = %d, want 200", res.Status)
			}
			if len(res.Console) != p.console {
				t.Errorf("Console = %+v, want exactly %d record(s)", res.Console, p.console)
			}
			if len(res.Resources) != p.resources {
				t.Errorf("Resources = %+v, want exactly %d record(s)", res.Resources, p.resources)
			}
			if p.contains != "" && (len(res.Console) == 0 || !strings.Contains(res.Console[0].Text, p.contains)) {
				t.Errorf("Console = %+v, want a record containing %q", res.Console, p.contains)
			}
		})
	}
}

// -- identification ------------------------------------------------------------------

// chromeVersionRe matches the product string Browser.getVersion reports, e.g.
// "Chrome/151.0.7922.138".
var chromeVersionRe = regexp.MustCompile(`/\d+\.\d+`)

func TestBrowser_Describe(t *testing.T) {
	t.Parallel()
	env := e2e(t)

	got := env.br.Describe()

	if !strings.Contains(got, "headless") {
		t.Errorf("Describe() = %q, want it to name the headless mode", got)
	}
	if !chromeVersionRe.MatchString(got) {
		t.Errorf("Describe() = %q, want a browser version in it", got)
	}
	if strings.Contains(got, "version unknown") {
		t.Errorf("Describe() = %q: the startup handshake did not report a product", got)
	}
}
