package report

import (
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/verdict"
)

var update = flag.Bool("update", false, "rewrite the goldens in testdata instead of comparing against them")

const goldenDir = "testdata"

// baseTime is the run's start instant. Everything time-shaped in these tests is
// derived from it, so the goldens assert the real layout of a real timestamp
// rather than the shape of a regex that scrubbed one away.
var baseTime = time.Date(2026, 8, 14, 11, 2, 30, 0, time.UTC)

func at(ms int) time.Time { return baseTime.Add(time.Duration(ms) * time.Millisecond) }

// stepClock returns the given instants in order, repeating the last one
// forever. New consumes the first (the run's start) and Summary the second,
// which is what puts a plausible elapsed time in the summary golden without
// making it depend on how fast the test machine is.
func stepClock(times ...time.Time) func() time.Time {
	i := 0
	return func() time.Time {
		t := times[i]
		if i < len(times)-1 {
			i++
		}
		return t
	}
}

func testHeader() Header {
	return Header{
		Version:     "0.1.0",
		Input:       "urls.txt",
		Concurrency: 4,
		Timeout:     30 * time.Second,
		Settle:      1500 * time.Millisecond,
		Chrome:      "Google Chrome 151.0.7922.138 (headless, JavaScript enabled)",
	}
}

func newReporter(t *testing.T, dir, format string, combined bool) *Reporter {
	t.Helper()
	r, err := New(Options{
		Dir:      dir,
		Format:   format,
		Combined: combined,
		Policy:   verdict.DefaultPolicy(),
		Now:      stepClock(baseTime, baseTime.Add(41300*time.Millisecond)),
		Header:   testHeader(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close in cleanup: %v", err)
		}
	})
	return r
}

func outDir(t *testing.T) string {
	t.Helper()
	// A subdirectory of the temp dir, so New has to create it and the 0700
	// assertion is about our code rather than about t.TempDir's mode.
	return filepath.Join(t.TempDir(), "logs")
}

// fixtures is the corpus every golden is rendered from: one result per shape
// the reporter has to render, in input order.
func fixtures() []verdict.Result {
	return []verdict.Result{
		{
			Index: 1, URL: "https://example.com/", Status: 200, StatusText: "OK",
			MimeType: "text/html", RemoteIP: "93.184.216.34", Protocol: "h2",
			SettledBy: "load", Started: at(200), DurationMS: 840,
		},
		{
			Index: 2, URL: "https://example.com/missing",
			FinalURL: "https://www.example.com/missing",
			Status:   404, StatusText: "Not Found", MimeType: "text/html",
			// A loopback address with an ephemeral port is what the
			// integration tests see; scrubGot normalizes the port so a golden
			// recorded against httptest stays stable.
			RemoteIP: "127.0.0.1:51234", Protocol: "http/1.1",
			Redirects: []verdict.Hop{
				{Status: 301, URL: "https://example.com/missing"},
				{Status: 302, URL: "https://example.com/moved"},
			},
			SettledBy: "load", Started: at(250), DurationMS: 420,
		},
		{
			Index: 3, URL: "https://shop.example.com/cart", Status: 200, StatusText: "OK",
			Console: []verdict.ConsoleError{
				{
					Kind:   verdict.KindException,
					Text:   "TypeError: Cannot read properties of null (reading 'total')",
					Frame:  "updateTotal (https://shop.example.com/static/cart.js:118:24)",
					Source: "https://shop.example.com/static/cart.js", Line: 118, Col: 24, Count: 3,
				},
				{Kind: verdict.KindConsoleAPI, Text: "checkout: price sync failed 503", Count: 1},
			},
			ConsoleSuppressed: 3, Truncated: true,
			SettledBy: "load", Started: at(1100), DurationMS: 1920,
		},
		{
			Index: 4, URL: "https://example.com/gallery", Status: 200, StatusText: "OK",
			Resources: []verdict.ResourceError{
				{URL: "https://cdn.example.com/img/hero.png", Type: "Image", Status: 404, Count: 2},
				{URL: "https://a.example.net/track.js", Type: "Script", NetError: "net::ERR_CONNECTION_REFUSED", Count: 1},
				{URL: "https://cdn.example.com/style/print.css", Type: "Stylesheet", Count: 2},
			},
			SettledBy: "load", Started: at(900), DurationMS: 1310,
		},
		{
			Index: 5, URL: "https://nope.invalid/",
			NetError: "net::ERR_NAME_NOT_RESOLVED", NetErrorClass: "DNS",
			SettledBy: "netfail", Started: at(3900), DurationMS: 120,
		},
		{
			// Responded, then hung: classified as a timeout, but its console
			// errors still belong in errors-console.log.
			Index: 6, URL: "https://slow.example.com/hang", Status: 200, StatusText: "OK",
			TimedOut: true, SettledBy: "deadline",
			Console: []verdict.ConsoleError{
				{
					Kind:   verdict.KindBrowserLog,
					Text:   "Refused to connect to 'wss://live.example.com/socket' because it violates the Content Security Policy directive",
					Source: "https://slow.example.com/hang", Line: 1, Col: 1, Count: 2,
				},
			},
			Started: at(2000), DurationMS: 30000,
		},
		{
			Index: 7, URL: "https://shop.example.com/checkout?step=2&ref=nav",
			Status: 500, StatusText: "Internal Server Error", MimeType: "text/html",
			RemoteIP: "203.0.113.9", Protocol: "h2",
			Console: []verdict.ConsoleError{
				{
					Kind:   verdict.KindException,
					Text:   "TypeError: Cannot read properties of null (reading 'total')",
					Frame:  "updateTotal (https://shop.example.com/static/cart.js:118:24)",
					Source: "https://shop.example.com/static/cart.js", Line: 118, Col: 24, Count: 9,
				},
			},
			SettledBy: "load", Started: at(4100), DurationMS: 760,
		},
		{
			Index: 8, URL: "https://slow.example.com/never",
			TimedOut: true, SettledBy: "deadline", Started: at(5000), DurationMS: 30000,
		},
		{
			Index: 9, URL: "https://ads.example.net/pixel",
			NetError: "net::ERR_BLOCKED_BY_CLIENT", NetErrorClass: "BLOCKED",
			BlockReason: "inspector", SettledBy: "netfail", Started: at(5200), DurationMS: 90,
		},
		{
			Index: 10, URL: "https://heavy.example.com/render",
			Crashed: true, SettledBy: "crash", Started: at(5300), DurationMS: 4500,
		},
	}
}

func emitFixtures(t *testing.T, r *Reporter) {
	t.Helper()
	p := verdict.DefaultPolicy()
	for _, res := range fixtures() {
		if err := r.Emit(res, verdict.Classify(res, p)); err != nil {
			t.Fatalf("Emit %s: %v", res.URL, err)
		}
	}
}

// fixtureCounts is what the worker pool would have accumulated for the corpus,
// plus a handful of plain pages so the status breakdown has enough entries to
// wrap onto a second line.
func fixtureCounts() verdict.Counts {
	var c verdict.Counts
	p := verdict.DefaultPolicy()
	for _, res := range fixtures() {
		c.Add(res, verdict.Classify(res, p))
	}
	for _, st := range []int{200, 200, 204, 301, 301, 304} {
		c.Add(verdict.Result{Status: st, SettledBy: "load"}, verdict.OutcomeOK)
	}
	c.SkippedLines = 3
	c.InvalidLines = 1
	return c
}

// loopbackPort is the one genuinely nondeterministic thing a golden recorded
// against a local test server can contain. Durations and timestamps are
// injected, not measured, so they are asserted verbatim.
var loopbackPort = regexp.MustCompile(`127\.0\.0\.1:\d+`)

func scrubGot(got, dir string) string {
	got = strings.ReplaceAll(got, dir, "logs")
	return loopbackPort.ReplaceAllString(got, "127.0.0.1:PORT")
}

// readFile reads through an *os.Root for the same reason the package under
// test writes through one: it keeps a computed directory out of os.Open, and
// the repo free of gosec suppressions.
func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open dir %s: %v", dir, err)
	}
	defer root.Close()

	f, err := root.Open(name)
	if err != nil {
		t.Fatalf("open %s/%s: %v", dir, name, err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s/%s: %v", dir, name, err)
	}
	return string(b)
}

func exists(t *testing.T, dir, name string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	root, err := os.OpenRoot(goldenDir)
	if err != nil {
		t.Fatalf("open %s: %v", goldenDir, err)
	}
	defer root.Close()

	file := name + ".golden"
	if *update {
		w, wErr := root.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if wErr != nil {
			t.Fatalf("create golden %s: %v", file, wErr)
		}
		if _, wErr := io.WriteString(w, got); wErr != nil {
			t.Fatalf("write golden %s: %v", file, wErr)
		}
		if wErr := w.Close(); wErr != nil {
			t.Fatalf("close golden %s: %v", file, wErr)
		}
		return
	}

	f, fErr := root.Open(file)
	if fErr != nil {
		t.Fatalf("open golden %s: %v (regenerate with: go test ./internal/report -update)", file, fErr)
	}
	defer f.Close()
	want, rErr := io.ReadAll(f)
	if rErr != nil {
		t.Fatalf("read golden %s: %v", file, rErr)
	}
	if got != string(want) {
		t.Errorf("%s does not match the golden.\n--- got ---\n%s\n--- want ---\n%s", file, got, want)
	}
}

func TestGolden_TextOutputs(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)
	emitFixtures(t, r)

	var summary strings.Builder
	if err := r.Summary(fixtureCounts(), &summary); err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, tc := range []struct{ golden, file string }{
		{"opened_text", FileOpened},
		{"errors_http", FileHTTP},
		{"errors_console", FileConsole},
		{"errors_subresource", FileSubresource},
		{"errors_load", FileLoad},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			checkGolden(t, tc.golden, scrubGot(readFile(t, dir, tc.file), dir))
		})
	}
	t.Run("summary_text", func(t *testing.T) {
		checkGolden(t, "summary_text", scrubGot(summary.String(), dir))
	})
}

func TestGolden_OpenedJSON(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatJSON, false)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	checkGolden(t, "opened_json", scrubGot(readFile(t, dir, FileOpened), dir))

	// Every line of every JSON-format log must be a standalone object,
	// including the header line.
	for _, name := range []string{FileOpened, FileHTTP, FileConsole, FileSubresource, FileLoad} {
		for i, line := range splitLines(readFile(t, dir, name)) {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("%s line %d is not JSON: %v\n%s", name, i+1, err, line)
			}
		}
	}
}

func TestGolden_ErrorsBothCategories(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	res := fixtures()[6] // 500 whose JavaScript also threw
	if err := r.Emit(res, verdict.Classify(res, verdict.DefaultPolicy())); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var b strings.Builder
	for _, name := range []string{FileHTTP, FileConsole} {
		b.WriteString("==> " + name + " <==\n")
		b.WriteString(readFile(t, dir, name))
	}
	checkGolden(t, "errors_both_categories", scrubGot(b.String(), dir))
}

func TestGolden_SummaryEmpty(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	var b strings.Builder
	if err := r.Summary(verdict.Counts{}, &b); err != nil {
		t.Fatalf("Summary: %v", err)
	}
	checkGolden(t, "summary_empty", scrubGot(b.String(), dir))
}

func TestGolden_SummaryInvariantViolated(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	c := fixtureCounts()
	// A counting bug looks exactly like this from the reporter's side: more
	// URLs attempted than the outcome buckets account for.
	c.Attempted += 2

	var b strings.Builder
	if err := r.Summary(c, &b); err != nil {
		t.Fatalf("Summary: %v", err)
	}
	got := scrubGot(b.String(), dir)
	if strings.Contains(got, "✓") {
		t.Error("a violated invariant must not be reported with a tick")
	}
	checkGolden(t, "summary_invariant_violated", got)
}

func TestEmit_BothCategories_WritesToBothFiles(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	res := fixtures()[6]
	if err := r.Emit(res, verdict.Classify(res, verdict.DefaultPolicy())); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	httpLog := readFile(t, dir, FileHTTP)
	consoleLog := readFile(t, dir, FileConsole)

	for _, tc := range []struct{ name, body, want string }{
		{FileHTTP, httpLog, "outcome=http_error"},
		{FileHTTP, httpLog, "also     console_error 1 error(s)   (see " + FileConsole + " #0007)"},
		{FileConsole, consoleLog, "outcome=console_error"},
		{FileConsole, consoleLog, "also     http_error 500   (see " + FileHTTP + " #0007)"},
	} {
		if !strings.Contains(tc.body, tc.want) {
			t.Errorf("%s does not contain %q\n%s", tc.name, tc.want, tc.body)
		}
	}
	if exists(t, dir, FileSubresource) || exists(t, dir, FileLoad) {
		t.Error("categories that do not apply must not create a log file")
	}
}

func TestEmit_OKURLCreatesNoErrorFile(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	res := fixtures()[0]
	if err := r.Emit(res, verdict.OutcomeOK); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	want := []string{filepath.Join(dir, FileOpened), filepath.Join(dir, FileResults)}
	if got := r.Files(); !equalStrings(got, want) {
		t.Errorf("Files() = %v, want %v", got, want)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, name := range []string{FileErrors, FileHTTP, FileConsole, FileSubresource, FileLoad} {
		if exists(t, dir, name) {
			t.Errorf("a clean run must not create %s", name)
		}
	}
}

func TestFiles_Created0600In0700Dir(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if got := di.Mode().Perm(); got != fs.FileMode(0o700) {
		t.Errorf("output dir mode = %04o, want 0700", got)
	}

	files := r.Files()
	if len(files) != 6 {
		t.Fatalf("Files() = %v, want all six logs", files)
	}
	for _, p := range files {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := fi.Mode().Perm(); got != fs.FileMode(0o600) {
			t.Errorf("%s mode = %04o, want 0600", p, got)
		}
	}
}

func TestResultsJSONL_OneObjectPerLine(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := splitLines(readFile(t, dir, FileResults))
	all := fixtures()
	if len(lines) != len(all) {
		t.Fatalf("results.jsonl has %d lines, want %d", len(lines), len(all))
	}
	p := verdict.DefaultPolicy()
	for i, line := range lines {
		var rec struct {
			Index   int      `json:"i"`
			URL     string   `json:"url"`
			Status  int      `json:"status"`
			Outcome string   `json:"outcome"`
			Flags   []string `json:"flags"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not a JSON object: %v\n%s", i+1, err, line)
		}
		want := all[i]
		if rec.Index != want.Index || rec.URL != want.URL || rec.Status != want.Status {
			t.Errorf("line %d = %+v, want index/url/status from %+v", i+1, rec, want)
		}
		if rec.Outcome != verdict.Classify(want, p).String() {
			t.Errorf("line %d outcome = %q, want %q", i+1, rec.Outcome, verdict.Classify(want, p))
		}
		if len(rec.Flags) != len(verdict.Flags(want, p)) {
			t.Errorf("line %d flags = %v, want %v", i+1, rec.Flags, verdict.Flags(want, p))
		}
	}

	// The ledger must survive a query string intact: no HTML escaping.
	if body := readFile(t, dir, FileResults); !strings.Contains(body, "checkout?step=2&ref=nav") {
		t.Error("results.jsonl escaped a query string that jq consumers read verbatim")
	}
}

func TestEmit_ConcurrentIsSafe(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	all := fixtures()
	p := verdict.DefaultPolicy()
	const rounds = 20

	var wg sync.WaitGroup
	for i := range rounds {
		wg.Add(1)
		go func(round int) {
			defer wg.Done()
			for _, res := range all {
				res.Index = round*len(all) + res.Index
				if err := r.Emit(res, verdict.Classify(res, p)); err != nil {
					t.Errorf("Emit: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := rounds * len(all)
	if got := len(splitLines(readFile(t, dir, FileResults))); got != want {
		t.Errorf("results.jsonl has %d records, want %d", got, want)
	}
	// Three header comment lines, then one row per attempt.
	if got := len(splitLines(readFile(t, dir, FileOpened))) - 3; got != want {
		t.Errorf("opened.log has %d rows, want %d", got, want)
	}
}

func TestCombined_OneFileWithTypeField(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, true)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, name := range []string{FileHTTP, FileConsole, FileSubresource, FileLoad} {
		if exists(t, dir, name) {
			t.Errorf("combined mode must not create %s", name)
		}
	}
	body := readFile(t, dir, FileErrors)
	for _, want := range []string{
		"type=http", "type=console", "type=subresource", "type=load",
		"(see " + FileErrors + " #0007 type=console)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s does not contain %q", FileErrors, want)
		}
	}
}

func TestNew_RejectsBadOptions(t *testing.T) {
	t.Parallel()

	t.Run("unknown format", func(t *testing.T) {
		t.Parallel()
		if _, err := New(Options{Dir: outDir(t), Format: "yaml"}); err == nil {
			t.Fatal("want an error for an unsupported format")
		}
	})

	t.Run("output path is a file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := New(Options{Dir: path}); err == nil {
			t.Fatal("want an error when the output path is not a directory")
		}
	})

	t.Run("defaults are filled in", func(t *testing.T) {
		t.Parallel()
		dir := outDir(t)
		r, err := New(Options{Dir: dir})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
		if r.opts.Format != FormatText || r.opts.Now == nil {
			t.Errorf("defaults not applied: format=%q now=%v", r.opts.Format, r.opts.Now != nil)
		}
	})
}

func TestClose_IsIdempotentAndBlocksEmit(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)
	emitFixtures(t, r)

	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
	if err := r.Emit(fixtures()[0], verdict.OutcomeOK); err == nil {
		t.Error("Emit after Close must fail rather than write to a closed file")
	}
}

func TestLayoutHelpers(t *testing.T) {
	t.Parallel()

	t.Run("padCol always separates", func(t *testing.T) {
		t.Parallel()
		if got := padCol("500 Internal Server Error", blockStatus); !strings.HasSuffix(got, " ") {
			t.Errorf("padCol(%q) = %q, want a trailing space", "500 Internal Server Error", got)
		}
		if got := padCol("status", blockLabel); got != "status   " {
			t.Errorf("padCol = %q", got)
		}
	})

	t.Run("index tag", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			in   int
			want string
		}{{1, "#0001"}, {42, "#0042"}, {12345, "#12345"}} {
			if got := indexTag(tc.in); got != tc.want {
				t.Errorf("indexTag(%d) = %q, want %q", tc.in, got, tc.want)
			}
		}
	})

	t.Run("status phrase", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			res  verdict.Result
			want string
		}{
			{verdict.Result{Status: 0}, "-"},
			{verdict.Result{Status: 404}, "404 Not Found"},
			{verdict.Result{Status: 404, StatusText: "Nope"}, "404 Nope"},
			{verdict.Result{Status: 599}, "599"},
		} {
			if got := statusPhrase(tc.res); got != tc.want {
				t.Errorf("statusPhrase(%d/%q) = %q, want %q", tc.res.Status, tc.res.StatusText, got, tc.want)
			}
		}
	})

	t.Run("elapsed", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			in   time.Duration
			want string
		}{
			{-time.Second, "0.0s"},
			{1500 * time.Millisecond, "1.5s"},
			{41300 * time.Millisecond, "41.3s"},
			{125 * time.Second, "2m5.0s"},
		} {
			if got := humanDur(tc.in); got != tc.want {
				t.Errorf("humanDur(%s) = %q, want %q", tc.in, got, tc.want)
			}
		}
	})

	t.Run("frame falls back to source coordinates", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			in   verdict.ConsoleError
			want string
		}{
			{verdict.ConsoleError{Frame: "f (a.js:1:2)"}, "at f (a.js:1:2)"},
			{verdict.ConsoleError{Source: "a.js", Line: 9, Col: 4}, "at a.js:9:4"},
			{verdict.ConsoleError{Source: "a.js", Line: 9}, "at a.js:9"},
			{verdict.ConsoleError{Source: "a.js"}, "at a.js"},
			{verdict.ConsoleError{}, ""},
		} {
			if got := frameLine(tc.in); got != tc.want {
				t.Errorf("frameLine(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		}
	})

	t.Run("resource detail", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			in   verdict.ResourceError
			want string
		}{
			{verdict.ResourceError{Status: 404}, "404"},
			{verdict.ResourceError{NetError: "net::ERR_FAILED"}, "net::ERR_FAILED"},
			{verdict.ResourceError{}, "-"},
		} {
			if got := resourceDetail(tc.in); got != tc.want {
				t.Errorf("resourceDetail(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		}
	})
}

func TestSummary_ExitCodeOverride(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r, err := New(Options{
		Dir:    dir,
		Policy: verdict.DefaultPolicy(),
		Now:    stepClock(baseTime),
		Header: testHeader(),
		ExitCode: func(verdict.Counts) (int, string) {
			return 1, "failing because -fail-on-error is set and " + verdict.OutcomeHTTPError.String() + " occurred"
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	var b strings.Builder
	if err := r.Summary(fixtureCounts(), &b); err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if !strings.Contains(b.String(), "exit code              1  (failing because") {
		t.Errorf("injected exit code not rendered:\n%s", b.String())
	}
}

func TestSummary_TopConsoleErrorsRanksAndTruncates(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	// Eight distinct messages; the block shows five. "shared" is the same
	// exception on three pages, which must outrank a noisier single page.
	var c verdict.Counts
	p := verdict.DefaultPolicy()
	emit := func(i int, text string, count int) {
		res := verdict.Result{
			Index: i, URL: "https://example.com/p" + strconv.Itoa(i), Status: 200,
			Console:   []verdict.ConsoleError{{Kind: verdict.KindException, Text: text, Count: count}},
			SettledBy: "load", Started: at(0), DurationMS: 10,
		}
		if err := r.Emit(res, verdict.Classify(res, p)); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		c.Add(res, verdict.Classify(res, p))
	}
	for i := 1; i <= 3; i++ {
		emit(i, "shared boom", 4)
	}
	for i := 4; i <= 9; i++ {
		emit(i, "noise "+strconv.Itoa(i), 11-i)
	}

	var b strings.Builder
	if err := r.Summary(c, &b); err != nil {
		t.Fatalf("Summary: %v", err)
	}
	block, _, _ := strings.Cut(strings.SplitN(b.String(), "top console errors\n", 2)[1], "\nbrowser")
	rows := splitLines(block)
	if len(rows) != topConsoleN {
		t.Fatalf("top console errors has %d rows, want %d:\n%s", len(rows), topConsoleN, block)
	}
	if want := "  12x  3 urls  shared boom"; rows[0] != want {
		t.Errorf("first row = %q, want %q", rows[0], want)
	}
	if !strings.Contains(rows[1], "noise 4") {
		t.Errorf("second row = %q, want the next-noisiest message", rows[1])
	}
	if strings.Contains(block, "noise 9") {
		t.Errorf("the quietest message must not survive the top-%d cut:\n%s", topConsoleN, block)
	}
}

func TestEmit_LoadFailureWithConsoleErrorsCrossReferences(t *testing.T) {
	t.Parallel()
	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)

	// The document never arrived, but the page had already run JavaScript
	// against a previous document and thrown.
	res := verdict.Result{
		Index: 11, URL: "https://flaky.example.com/", NetError: "net::ERR_CONNECTION_RESET",
		NetErrorClass: "CONNECT", SettledBy: "netfail", Started: at(0), DurationMS: 300,
		Console: []verdict.ConsoleError{{Kind: verdict.KindException, Text: "Error: aborted", Count: 1}},
	}
	if err := r.Emit(res, verdict.Classify(res, verdict.DefaultPolicy())); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := "also     load_error net::ERR_CONNECTION_RESET   (see " + FileLoad + " #0011)"
	if got := readFile(t, dir, FileConsole); !strings.Contains(got, want) {
		t.Errorf("%s does not contain %q\n%s", FileConsole, want, got)
	}
	if got := readFile(t, dir, FileLoad); !strings.Contains(got, "also     console_error 1 error(s)") {
		t.Errorf("%s is missing the console cross-reference\n%s", FileLoad, got)
	}
}

func TestSummary_WriteErrorIsWrapped(t *testing.T) {
	t.Parallel()
	r := newReporter(t, outDir(t), FormatText, false)
	if err := r.Summary(verdict.Counts{}, failingWriter{}); err == nil {
		t.Fatal("want the writer's error to propagate")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrPermission }

// splitLines drops the trailing empty element left by a final newline, so a
// line count is a record count.
func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
