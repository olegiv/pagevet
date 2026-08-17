// Package testfixtures serves a local site that deterministically produces
// every outcome pagevet must classify: clean pages, HTTP errors, uncaught
// exceptions, unhandled rejections, console.error calls, CSP refusals, dead
// subresources, redirect chains, hangs, dropped connections, dialogs and
// downloads.
//
// It exists so the browser-facing tests assert against a page whose behavior is
// written down in this file, rather than against example.com and whatever the
// internet is doing today.
//
// The package imports "testing" from a non-test file on purpose: it is an
// internal, test-only package, and taking a testing.TB is what lets New wire the
// server's lifetime to the test's.
package testfixtures

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strconv"
	"testing"
	"time"
)

// maxHops bounds /redirect/{n}/... so a typo cannot spin the server into a
// thousand-hop chain that Chrome will refuse anyway.
const maxHops = 20

// New starts a fixture server and shuts it down when the test finishes.
//
// FLAKE RULE 1: use srv.URL exactly as returned. Never rewrite 127.0.0.1 to
// "localhost". On macOS "localhost" resolves to ::1 first, httptest binds IPv4
// only, and Chrome then fails the navigation with net::ERR_CONNECTION_REFUSED —
// intermittently, depending on the machine's resolver order.
func New(t testing.TB) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(Handler(t.Logf))
	t.Cleanup(srv.Close)
	return srv
}

// Handler returns the fixture routes.
//
// logf receives the errors that have no other home — a write to a client that
// already hung up, a failed hijack. It may be nil, which discards them; New
// passes t.Logf so a genuinely broken fixture says so instead of producing a
// mystery test failure elsewhere.
func Handler(logf func(format string, args ...any)) http.Handler {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	f := &fixture{logf: logf}

	mux := http.NewServeMux()
	mux.HandleFunc("/", f.index)
	mux.HandleFunc("/ok", f.page(okHTML))
	mux.HandleFunc("/throw", f.page(throwHTML))
	mux.HandleFunc("/reject", f.page(rejectHTML))
	mux.HandleFunc("/console-error", f.page(consoleErrorHTML))
	mux.HandleFunc("/console-noise", f.page(consoleNoiseHTML))
	mux.HandleFunc("/console-dup", f.page(consoleDupHTML))
	mux.HandleFunc("/csp", f.csp)
	mux.HandleFunc("/subresource-404", f.page(subresourceHTML))
	mux.HandleFunc("/status/{code}", f.status)
	mux.HandleFunc("/redirect/{n}/{rest...}", f.redirect)
	mux.HandleFunc("/slow", f.slow)
	mux.HandleFunc("/hangup", f.hangup)
	mux.HandleFunc("/alert", f.page(alertHTML))
	mux.HandleFunc("/download", f.download)
	mux.HandleFunc("/favicon.ico", f.favicon)
	// The -login flow; see login.go.
	mux.HandleFunc("/login", f.loginPage)
	mux.HandleFunc("/login-sticky", f.loginSticky)
	mux.HandleFunc("/login-anon", f.loginAnon)
	mux.HandleFunc("/login-hidden", f.loginHidden)
	mux.HandleFunc("/login-nobutton", f.loginNoButton)
	mux.HandleFunc("/login-samecookie", f.loginSameCookie)
	mux.HandleFunc("/login-prefilled", f.loginPrefilled)
	mux.HandleFunc("/login-redirect", f.loginRedirect)
	mux.HandleFunc("/logout", f.logout)
	mux.HandleFunc("/grant", f.grant)
	mux.HandleFunc("/private", f.private)

	return noStore(mux)
}

// fixture carries the one piece of state the handlers share.
type fixture struct {
	logf func(format string, args ...any)
}

// noStore stamps every response as uncacheable.
//
// FLAKE RULE 4: without this, Chrome serves the second visit to a fixture URL
// from its own cache — no network events, no subresource failures, no console
// output — and a test that passed alone fails when run after its neighbor.
func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// write sends a body, routing the one error a handler cannot otherwise report
// to the test log.
func (f *fixture) write(w http.ResponseWriter, s string) {
	if _, err := io.WriteString(w, s); err != nil {
		f.logf("testfixtures: write failed: %v", err)
	}
}

// html sends a 200 HTML response. The Content-Type is explicit rather than
// sniffed, because sniffing decides on the first 512 bytes and these pages are
// deliberately short.
func (f *fixture) html(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	f.write(w, body)
}

// page adapts a constant body into a handler.
func (f *fixture) page(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { f.html(w, body) }
}

// index doubles as the 404 route: http.ServeMux gives "/" everything no other
// pattern claimed, so anything unknown must be rejected here rather than
// silently answered with a 200.
func (f *fixture) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		f.write(w, indexHTML(true))
		return
	}
	f.html(w, indexHTML(false))
}

// csp serves a page whose inline script is refused by Content-Security-Policy.
//
// The refusal is reported by the browser itself, not by page JavaScript, so it
// arrives as Log.entryAdded rather than Runtime.exceptionThrown — which is the
// entire reason KindBrowserLog exists. Note that Chrome has labeled the source
// of these entries "security" in some versions and "javascript" in others; a
// test asserting on the source should accept either.
func (f *fixture) csp(w http.ResponseWriter, _ *http.Request) {
	// script-src 'self' with no 'unsafe-inline' and no nonce: same-origin
	// script files would still load, only the inline block is blocked.
	w.Header().Set("Content-Security-Policy", "script-src 'self'; object-src 'none'")
	f.html(w, cspHTML)
}

// status serves an arbitrary status code: /status/500, /status/404. With
// ?empty=1 it sends no body at all, which is how a test distinguishes "an error
// page" from "no content to render".
func (f *fixture) status(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("code")
	code, err := strconv.Atoi(raw)
	if err != nil || code < 200 || code > 599 {
		// 1xx is excluded deliberately: net/http treats WriteHeader(1xx) as an
		// informational response and keeps the handler on the hook for a real
		// one, which is not what a fixture caller means by /status/100.
		http.Error(w, "bad status code "+raw, http.StatusBadRequest)
		return
	}

	// 204 and 304 are defined to have no body; writing one makes net/http log a
	// "superfluous" complaint and confuses the client.
	if r.URL.Query().Get("empty") == "1" || code == http.StatusNoContent || code == http.StatusNotModified {
		w.WriteHeader(code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	f.write(w, statusHTML(code))
}

// redirect emits an n-hop 302 chain that lands on /{rest}, preserving the query
// string so /redirect/2/status/204?empty=1 does what it looks like it does.
func (f *fixture) redirect(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 || n > maxHops {
		http.Error(w, "hop count must be 1.."+strconv.Itoa(maxHops), http.StatusBadRequest)
		return
	}

	// path.Join cleans the wildcard before it can become a destination. A
	// "rest" of "/evil.example" would otherwise produce "//evil.example",
	// which browsers read as a protocol-relative URL and follow off-origin -
	// a real open redirect, even in a test fixture. Joining under a fixed
	// root, and emitting only Path and RawQuery, makes an off-origin target
	// unrepresentable rather than merely unlikely.
	rest := r.PathValue("rest")
	target := &url.URL{RawQuery: r.URL.RawQuery}
	if n > 1 {
		target.Path = path.Join("/redirect", strconv.Itoa(n-1), rest)
	} else {
		target.Path = path.Join("/", rest)
	}
	next := target.String()

	// 302 rather than 301: a permanent redirect is cacheable by Chrome even
	// across the no-store hint on the destination, which would make the second
	// crawl of a chain record a different number of hops than the first.
	http.Redirect(w, r, next, http.StatusFound)
}

// slow sleeps for ?d= before answering: /slow?d=30s outlives any sane per-URL
// deadline and is how the timeout outcome gets exercised.
//
// d is required. A default would be a trap either way — long enough to be
// useful means long enough to stall an unrelated test that hit /slow by
// accident.
func (f *fixture) slow(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("d")
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		http.Error(w, "slow requires ?d=<duration>, e.g. /slow?d=30s", http.StatusBadRequest)
		return
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		f.html(w, slowHTML)
	case <-r.Context().Done():
		// FLAKE RULE 3: bail out the instant the client goes away. Without this
		// arm, httptest.Server.Close blocks until the sleep finishes, so the
		// t.Cleanup that closes the server deadlocks the whole test binary
		// until the go test timeout kills it.
		f.logf("testfixtures: /slow?d=%s abandoned by the client", raw)
	}
}

// hangup accepts the request and drops the connection without writing a byte,
// which Chrome surfaces as net::ERR_EMPTY_RESPONSE — the load-error path that
// has no HTTP status to report.
func (f *fixture) hangup(w http.ResponseWriter, _ *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		f.logf("testfixtures: hijack failed: %v", err)
		return
	}
	if err := conn.Close(); err != nil {
		f.logf("testfixtures: closing hijacked conn: %v", err)
	}
}

// download serves an attachment. Chrome never fires a load event for one, so
// the collector has to settle it some other way — see Result.SettledBy.
func (f *fixture) download(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="pagevet-fixture.bin"`)
	w.WriteHeader(http.StatusOK)
	f.write(w, "pagevet fixture download payload\n")
}

// favicon answers 204.
//
// FLAKE RULE 2: Chrome requests /favicon.ico for every page it renders. Left to
// the 404 route, every single fixture page would silently gain one phantom
// subresource failure — and since failed subresources are now their own error
// category, that would turn every "clean page" assertion in the suite into a
// false failure.
func (f *fixture) favicon(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// The fixture pages. Each one is minimal on purpose: the less markup there is,
// the fewer ways a browser has to surprise the assertion.

const okHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ok</title></head>
<body><h1>ok</h1>
<script>
// The title only changes if a real JavaScript engine ran, which is what
// separates this crawler from an HTTP GET. Assert on it in the e2e tests.
document.title = "js-ran";
</script>
</body></html>
`

const throwHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>throw</title></head>
<body><h1>throw</h1>
<script>
// Uncaught TypeError -> Runtime.exceptionThrown -> verdict.KindException.
(function () { var o = null; o.boom(); })();
</script>
</body></html>
`

const rejectHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>reject</title></head>
<body><h1>reject</h1>
<script>
window.__rejectionSeen = false;
// The listener gives a test a CONDITION to poll on. Polling for
// window.__rejectionSeen === true is deterministic; sleeping 200ms and hoping
// the microtask queue drained is how flaky suites are born.
window.addEventListener("unhandledrejection", function () {
  window.__rejectionSeen = true;
});
Promise.reject(new Error("pagevet unhandled rejection"));
</script>
</body></html>
`

const consoleErrorHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>console-error</title></head>
<body><h1>console-error</h1>
<script>
// Multiple arguments on purpose: the collector has to join them, and a page
// that logs only strings would not catch a formatter that drops numbers.
console.error("boom", 42);
</script>
</body></html>
`

const consoleNoiseHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>console-noise</title></head>
<body><h1>console-noise</h1>
<script>
// Everything here is below the error threshold, so this page must classify as
// ok. It is the negative control for the console category.
console.log("log");
console.info("info");
console.warn("warn");
console.debug("debug");
</script>
</body></html>
`

const consoleDupHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>console-dup</title></head>
<body><h1>console-dup</h1>
<script>
// Three separate tasks throw from the SAME source position, so all three
// exceptions share a fingerprint and must collapse into one record with
// Count 3. Throwing inline three times would not work: the first uncaught
// exception ends the enclosing script.
function pagevetBoom() { throw new TypeError("pagevet duplicate boom"); }
setTimeout(pagevetBoom, 0);
setTimeout(pagevetBoom, 0);
setTimeout(pagevetBoom, 0);
</script>
</body></html>
`

const cspHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>csp</title></head>
<body><h1>csp</h1>
<script>
// Refused by the Content-Security-Policy header. If a test ever sees the title
// change to "csp-ran", the policy stopped being enforced and the fixture is
// no longer testing anything.
document.title = "csp-ran";
</script>
</body></html>
`

const subresourceHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>subresource-404</title></head>
<body><h1>subresource-404</h1>
<!--
  ?empty=1 keeps the 404 body out of the response. Chrome does not execute the
  body of a non-2xx script, but an empty body removes any doubt about whether a
  stray parse error crept into the console counts.
-->
<script src="/status/404?empty=1"></script>
<script>
document.title = "js-ran";
</script>
</body></html>
`

const alertHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>alert</title></head>
<body><h1>alert</h1>
<script>
// A modal dialog stops the renderer until someone answers it. Unless the
// collector handles Page.javascriptDialogOpening, this page hangs the crawl
// until the per-URL deadline — which is precisely the regression this route
// guards against. The assignment below only runs once the dialog is dismissed.
alert("pagevet alert");
document.title = "after-alert";
</script>
</body></html>
`

const slowHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>slow</title></head>
<body><h1>slow</h1></body></html>
`

// statusHTML is the body served with an arbitrary status code.
func statusHTML(code int) string {
	s := strconv.Itoa(code)
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>status ` + s + `</title></head>
<body><h1>status ` + s + `</h1></body></html>
`
}

// indexHTML lists the routes. Serving it for unknown paths as well means a
// mistyped fixture URL produces a page that says what the right ones are. The
// requested path is deliberately not echoed back: reflecting it would make this
// fixture an XSS sink, and gosec would be right to say so.
func indexHTML(notFound bool) string {
	body := "<h1>pagevet fixtures</h1>"
	if notFound {
		body = "<h1>no such fixture</h1><p>no route for this path</p>"
	}
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>fixtures</title></head>
<body>` + body + `
<ul>
<li>/ok</li><li>/throw</li><li>/reject</li><li>/console-error</li>
<li>/console-noise</li><li>/console-dup</li><li>/csp</li>
<li>/subresource-404</li><li>/status/{code}?empty=1</li>
<li>/redirect/{n}/{rest}</li><li>/slow?d=30s</li><li>/hangup</li>
<li>/alert</li><li>/download</li><li>/favicon.ico</li>
</ul>
</body></html>
`
}
