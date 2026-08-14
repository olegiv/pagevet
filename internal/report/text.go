package report

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/olegiv/pagevet/internal/verdict"
)

// Column geometry. These are the whole layout: every text shape in this file
// is built from padCol/padRight/padLeft against these widths, never from
// hand-counted spaces in a format string, so a change here moves every column
// that depends on it at once.
const (
	colTS      = 20 // RFC3339 seconds in UTC is exactly 20 bytes
	colIndex   = 5  // "#0001"
	colOutcome = 17 // widest is "subresource_error"
	colStatus  = 9
	colElapsed = 9

	blockIndent = 7  // aligns block body under the URL on the "#NNNN  url" line
	blockLabel  = 9  // "status", "elapsed", "redirect", "also"
	blockStatus = 14 // "200 OK" plus separation before outcome=
	blockNum    = 3  // "1. "
	blockKind   = 17 // "[console.error]" plus separation
	blockCount  = 5  // "x12" plus separation
	blockType   = 16 // "[SignedExchange]" plus separation
	blockDetail = 28 // "net::ERR_BLOCKED_BY_RESPONSE"

	summaryLabel  = 23 // summary key column
	summaryNumber = 6  // summary value column, right-aligned
	detailLabel   = 31 // the detail section's longer labels
	detailNumber  = 2
	summaryRule   = 58
)

// padRight left-aligns s in a field of n bytes with no guaranteed separation:
// use it only when the NEXT column is right-aligned and therefore separates
// itself.
func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// padCol left-aligns s in a field of n bytes, always leaving at least one
// trailing space so an over-long value pushes the next column right instead of
// colliding with it. Every value passed here is ASCII, so byte width is column
// width.
func padCol(s string, n int) string {
	// An over-long value still needs visible separation from the next column,
	// or "404 Not Found" runs straight into "outcome=".
	if len(s) >= n {
		return s + "  "
	}
	return s + strings.Repeat(" ", n-len(s))
}

// padLeft right-aligns s in a field of n bytes.
func padLeft(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat(" ", n-len(s)) + s
}

// indexTag renders the input ordinal as "#0001". Four digits keeps the column
// stable for the runs people actually have; a larger index simply widens it
// rather than being truncated, because a wrong ordinal is worse than a ragged
// column.
func indexTag(i int) string {
	s := strconv.Itoa(i)
	if len(s) < 4 {
		s = strings.Repeat("0", 4-len(s)) + s
	}
	return "#" + s
}

// stamp renders a timestamp the way every log line in this package does: UTC,
// second resolution, RFC3339. UTC is not a preference — logs from a run that
// crossed a DST boundary have to remain sortable.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// completedAt is when the attempt finished, which is what a reader scanning
// opened.log wants next to a duration. It is derived from the Result rather
// than from the injected clock so the column stays meaningful even though
// results are emitted in input order, long after some of them finished.
func completedAt(res verdict.Result) time.Time {
	return res.Started.Add(time.Duration(res.DurationMS) * time.Millisecond)
}

// secs formats a duration in seconds with centisecond resolution, the
// resolution at which page loads are actually compared.
func secs(ms int64) string {
	return strconv.FormatFloat(float64(ms)/1000, 'f', 2, 64) + "s"
}

// humanDur formats the whole-run elapsed time for the summary.
func humanDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	}
	m := int64(d / time.Minute)
	rest := d - time.Duration(m)*time.Minute
	return strconv.FormatInt(m, 10) + "m" + strconv.FormatFloat(rest.Seconds(), 'f', 1, 64) + "s"
}

// statusCell renders the main-document status for the opened.log table. A dash
// rather than "0" because zero is not a status, it is the absence of one.
func statusCell(res verdict.Result) string {
	if res.Status == 0 {
		return "-"
	}
	return strconv.Itoa(res.Status)
}

// statusPhrase renders "404 Not Found" for the error blocks, preferring the
// reason phrase the server actually sent over net/http's canonical one.
func statusPhrase(res verdict.Result) string {
	if res.Status == 0 {
		return "-"
	}
	code := strconv.Itoa(res.Status)
	txt := res.StatusText
	if txt == "" {
		txt = http.StatusText(res.Status)
	}
	if txt == "" {
		return code
	}
	return code + " " + txt
}

// annotations are the trailing facts appended to an opened.log line, and only
// when they are non-zero: a clean run's opened.log must stay scannable, and
// "js=0/0 res=0" on every line defeats that.
func annotations(res verdict.Result) []string {
	out := make([]string, 0, 3)
	if n := len(res.Console); n > 0 {
		out = append(out, "js="+strconv.Itoa(n)+"/"+strconv.Itoa(res.ConsoleEvents()))
	}
	if n := len(res.Resources); n > 0 {
		out = append(out, "res="+strconv.Itoa(n))
	}
	if res.NetError != "" {
		out = append(out, res.NetError)
	}
	if res.BlockReason != "" {
		out = append(out, "blocked="+res.BlockReason)
	}
	return out
}

// openedLine renders one row of the opened.log table.
func openedLine(res verdict.Result, o verdict.Outcome) string {
	var b strings.Builder
	b.WriteString(padRight(stamp(completedAt(res)), colTS))
	b.WriteString("    ")
	b.WriteString(padRight(indexTag(res.Index), colIndex))
	b.WriteString("  ")
	b.WriteString(padRight(o.String(), colOutcome))
	b.WriteString(padLeft(statusCell(res), colStatus))
	b.WriteString(padLeft(secs(res.DurationMS), colElapsed))
	b.WriteString("  ")
	b.WriteString(res.URL)
	if ann := annotations(res); len(ann) > 0 {
		b.WriteString("   ")
		b.WriteString(strings.Join(ann, "  "))
	}
	return b.String()
}

// headerText stamps the provenance block at the top of a log file.
func (r *Reporter) headerText(name string) string {
	h := r.opts.Header
	var b strings.Builder

	b.WriteString("# pagevet ")
	b.WriteString(h.Version)
	if name == FileOpened {
		b.WriteString("  started ")
		b.WriteString(stamp(r.start))
		b.WriteString("  input=")
		b.WriteString(h.Input)
		b.WriteString("  concurrency=")
		b.WriteString(strconv.Itoa(h.Concurrency))
		b.WriteString("  timeout=")
		b.WriteString(h.Timeout.String())
		b.WriteString("  settle=")
		b.WriteString(h.Settle.String())
		b.WriteString("\n")
		if h.Chrome != "" {
			b.WriteString("# chrome ")
			b.WriteString(h.Chrome)
			b.WriteString("\n")
		}
		// The "# " marker eats the first two columns of the ts field, so the
		// column head still lands over the data below it.
		b.WriteString("# ")
		b.WriteString(padRight("ts", colTS-2))
		b.WriteString("    ")
		b.WriteString(padRight("n", colIndex))
		b.WriteString("  ")
		b.WriteString(padRight("outcome", colOutcome))
		b.WriteString(padLeft("status", colStatus))
		b.WriteString(padLeft("elapsed", colElapsed))
		b.WriteString("  url\n")
		return b.String()
	}

	b.WriteString("  ")
	b.WriteString(r.logTitle(name))
	b.WriteString("  started ")
	b.WriteString(stamp(r.start))
	b.WriteString("\n")
	b.WriteString(r.logPreamble(name))
	b.WriteString("\n")
	return b.String()
}

// logTitle is the one-phrase description on a log file's first line.
func (r *Reporter) logTitle(name string) string {
	switch name {
	case FileErrors:
		return "errors"
	case FileHTTP:
		return "HTTP status errors"
	case FileConsole:
		return "browser console errors"
	case FileSubresource:
		return "failed subresources"
	case FileLoad:
		return "load failures"
	}
	return "log"
}

// logPreamble explains what a reader is looking at, in the file itself.
// Someone hands this log to a colleague; the colleague should not need the
// README to know whether a missing stylesheet belongs in it.
func (r *Reporter) logPreamble(name string) string {
	switch name {
	case FileErrors:
		return "# Every failing URL, one block per category. The type= field on each\n" +
			"# block names the category it was recorded under.\n"
	case FileHTTP:
		return "# Main-document responses whose FINAL status is outside the acceptable\n" +
			"# band (" + strconv.Itoa(r.opts.Policy.OKStatusMin) + "-" + strconv.Itoa(r.opts.Policy.OKStatusMax) +
			"). Intermediate 3xx hops are listed, not counted as errors.\n"
	case FileConsole:
		return "# Uncaught JS exceptions, unhandled promise rejections, console.error(), and\n" +
			"# browser-side JS errors (CSP refusals, parse-time SyntaxError).\n"
	case FileSubresource:
		return "# Assets the page requested that never loaded: scripts, stylesheets, images,\n" +
			"# fonts, XHR/fetch. The page's own document status was acceptable.\n"
	case FileLoad:
		return "# No usable response arrived: DNS, TLS, refused connection, blocked request,\n" +
			"# renderer crash, or the per-URL deadline expiring.\n"
	}
	return ""
}

// errorBlockText renders one record of one error log.
func (r *Reporter) errorBlockText(c verdict.Category, cats []verdict.Category, flags []verdict.Outcome, res verdict.Result) string {
	ind := strings.Repeat(" ", blockIndent)
	var b strings.Builder

	b.WriteString(indexTag(res.Index))
	b.WriteString("  ")
	b.WriteString(res.URL)
	if r.opts.Combined {
		// Combined mode collapses four files into one, so the category has to
		// travel with the record or it is unrecoverable.
		b.WriteString("   type=")
		b.WriteString(c.String())
	}
	b.WriteString("\n")

	b.WriteString(ind)
	b.WriteString(padCol("status", blockLabel))
	b.WriteString(padCol(statusPhrase(res), blockStatus))
	b.WriteString("outcome=")
	b.WriteString(outcomeFor(c, flags).String())
	b.WriteString("\n")

	switch c {
	case verdict.CategoryHTTP:
		r.writeHTTPBody(&b, ind, res)
	case verdict.CategoryConsole:
		r.writeConsoleBody(&b, ind, res)
	case verdict.CategorySubresource:
		r.writeResourceBody(&b, ind, res)
	case verdict.CategoryLoad:
		r.writeLoadBody(&b, ind, res)
	case verdict.CategoryNone:
	}

	for _, other := range cats {
		if other == c {
			continue
		}
		b.WriteString(ind)
		b.WriteString(padCol("also", blockLabel))
		b.WriteString(alsoDetail(other, flags, res))
		b.WriteString("   (see ")
		b.WriteString(r.errorFileName(other))
		b.WriteString(" ")
		b.WriteString(indexTag(res.Index))
		if r.opts.Combined {
			b.WriteString(" type=")
			b.WriteString(other.String())
		}
		b.WriteString(")\n")
	}

	b.WriteString("\n")
	return b.String()
}

// outcomeFor picks the flag that put this result in category c. A block states
// the outcome of the file it lives in, not the run's primary classification: a
// 500 that also throws JS is "outcome=console_error" in errors-console.log and
// "outcome=http_error" in errors-http.log, and the "also" line carries the
// cross-reference.
func outcomeFor(c verdict.Category, flags []verdict.Outcome) verdict.Outcome {
	for _, o := range flags {
		if o.Category() == c {
			return o
		}
	}
	return verdict.OutcomeOK
}

// alsoDetail summarizes the record as the OTHER category sees it, so the
// cross-reference is worth reading on its own.
func alsoDetail(c verdict.Category, flags []verdict.Outcome, res verdict.Result) string {
	name := outcomeFor(c, flags).String()
	switch c {
	case verdict.CategoryHTTP:
		return name + " " + strconv.Itoa(res.Status)
	case verdict.CategoryConsole:
		return name + " " + strconv.Itoa(len(res.Console)) + " error(s)"
	case verdict.CategorySubresource:
		return name + " " + strconv.Itoa(len(res.Resources)) + " asset(s)"
	case verdict.CategoryLoad:
		if res.NetError != "" {
			return name + " " + res.NetError
		}
		return name
	case verdict.CategoryNone:
	}
	return name
}

func (r *Reporter) writeHTTPBody(b *strings.Builder, ind string, res verdict.Result) {
	if res.FinalURL != "" && res.FinalURL != res.URL {
		b.WriteString(ind)
		b.WriteString(padCol("final", blockLabel))
		b.WriteString(res.FinalURL)
		b.WriteString("\n")
	}
	if res.RemoteIP != "" || res.Protocol != "" {
		b.WriteString(ind)
		b.WriteString(padCol("remote", blockLabel))
		b.WriteString(strings.TrimSpace(res.RemoteIP + "  " + res.Protocol))
		b.WriteString("\n")
	}
	if len(res.Redirects) > 0 {
		b.WriteString(ind)
		b.WriteString(padCol("redirect", blockLabel))
		b.WriteString(strconv.Itoa(len(res.Redirects)))
		b.WriteString(" hop(s)\n")
		hopInd := ind + strings.Repeat(" ", blockLabel)
		for i, h := range res.Redirects {
			b.WriteString(hopInd)
			b.WriteString(padCol(strconv.Itoa(i+1)+".", blockNum))
			b.WriteString(padCol(strconv.Itoa(h.Status), blockNum+2))
			b.WriteString(h.URL)
			b.WriteString("\n")
		}
	}
}

func (r *Reporter) writeConsoleBody(b *strings.Builder, ind string, res verdict.Result) {
	b.WriteString(ind)
	b.WriteString(strconv.Itoa(len(res.Console)))
	b.WriteString(" distinct error(s), ")
	b.WriteString(strconv.Itoa(res.ConsoleEvents()))
	b.WriteString(" occurrence(s)\n")

	for i, ce := range res.Console {
		num := padCol(strconv.Itoa(i+1)+".", blockNum)
		b.WriteString(ind)
		b.WriteString(num)
		b.WriteString(padCol("["+ce.Kind.String()+"]", blockKind))
		b.WriteString(padCol("x"+strconv.Itoa(ce.Count), blockCount))
		b.WriteString(ce.Text)
		b.WriteString("\n")
		if fr := frameLine(ce); fr != "" {
			// The frame is a continuation of the message, so it hangs under
			// the message column rather than starting a new numbered item.
			b.WriteString(ind)
			b.WriteString(strings.Repeat(" ", len(num)+blockKind+blockCount))
			b.WriteString(fr)
			b.WriteString("\n")
		}
	}
	if res.ConsoleSuppressed > 0 {
		b.WriteString(ind)
		b.WriteString("+ ")
		b.WriteString(strconv.Itoa(res.ConsoleSuppressed))
		b.WriteString(" occurrence(s) suppressed by -max-console\n")
	}
}

// frameLine renders the origin of a console error, preferring the collector's
// pre-formatted first stack frame and falling back to the script coordinates
// when the exception carried no stack at all.
func frameLine(ce verdict.ConsoleError) string {
	if ce.Frame != "" {
		return "at " + ce.Frame
	}
	if ce.Source == "" {
		return ""
	}
	s := ce.Source
	if ce.Line > 0 {
		s += ":" + strconv.FormatInt(ce.Line, 10)
		if ce.Col > 0 {
			s += ":" + strconv.FormatInt(ce.Col, 10)
		}
	}
	return "at " + s
}

func (r *Reporter) writeResourceBody(b *strings.Builder, ind string, res verdict.Result) {
	b.WriteString(ind)
	b.WriteString(strconv.Itoa(len(res.Resources)))
	b.WriteString(" distinct failure(s), ")
	b.WriteString(strconv.Itoa(res.ResourceEvents()))
	b.WriteString(" occurrence(s)\n")

	for i, re := range res.Resources {
		b.WriteString(ind)
		b.WriteString(padCol(strconv.Itoa(i+1)+".", blockNum))
		b.WriteString(padCol("["+re.Type+"]", blockType))
		b.WriteString(padCol(resourceDetail(re), blockDetail))
		b.WriteString(padCol("x"+strconv.Itoa(re.Count), blockCount))
		b.WriteString(re.URL)
		b.WriteString("\n")
	}
}

// resourceDetail is the status if one arrived, otherwise the transport error.
// A subresource that got a 404 and one that never resolved fail for entirely
// different reasons, and the column has to say which.
func resourceDetail(re verdict.ResourceError) string {
	switch {
	case re.Status != 0:
		return strconv.Itoa(re.Status)
	case re.NetError != "":
		return re.NetError
	}
	return "-"
}

func (r *Reporter) writeLoadBody(b *strings.Builder, ind string, res verdict.Result) {
	if res.NetError != "" {
		b.WriteString(ind)
		b.WriteString(padCol("net", blockLabel))
		b.WriteString(res.NetError)
		if res.NetErrorClass != "" {
			b.WriteString("  class=")
			b.WriteString(res.NetErrorClass)
		}
		b.WriteString("\n")
	}
	if res.BlockReason != "" {
		b.WriteString(ind)
		b.WriteString(padCol("blocked", blockLabel))
		b.WriteString(res.BlockReason)
		b.WriteString("\n")
	}
	if res.Crashed {
		b.WriteString(ind)
		b.WriteString(padCol("crashed", blockLabel))
		b.WriteString("renderer process died before the page settled\n")
	}
	if res.TimedOut {
		b.WriteString(ind)
		b.WriteString(padCol("timeout", blockLabel))
		b.WriteString("deadline ")
		b.WriteString(r.opts.Header.Timeout.String())
		b.WriteString(" exceeded\n")
	}
	b.WriteString(ind)
	b.WriteString(padCol("elapsed", blockLabel))
	b.WriteString(secs(res.DurationMS))
	if res.SettledBy != "" {
		b.WriteString("  settled_by=")
		b.WriteString(res.SettledBy)
	}
	b.WriteString("\n")
}

// summaryText renders the whole run summary. Caller holds r.mu.
func (r *Reporter) summaryText(c verdict.Counts, elapsed time.Duration) string {
	var b strings.Builder

	kv := func(k, v string) {
		b.WriteString(padRight(k, summaryLabel))
		b.WriteString(v)
		b.WriteString("\n")
	}
	num := func(k string, n int) {
		b.WriteString(padRight(k, summaryLabel))
		b.WriteString(padLeft(strconv.Itoa(n), summaryNumber))
		b.WriteString("\n")
	}

	b.WriteString("pagevet summary\n")
	b.WriteString(strings.Repeat("─", summaryRule))
	b.WriteString("\n")

	if r.opts.Header.Input != "" {
		kv("input", r.opts.Header.Input)
	}
	num("lines read", c.Attempted+c.SkippedLines+c.InvalidLines+c.NotRun)
	if c.SkippedLines > 0 {
		num("  blank / comment / dup", c.SkippedLines)
	}
	if c.InvalidLines > 0 {
		b.WriteString(padRight("  invalid URLs", summaryLabel))
		b.WriteString(padLeft(strconv.Itoa(c.InvalidLines), summaryNumber))
		b.WriteString("   (see stderr)\n")
	}
	num("attempted", c.Attempted)
	if c.NotRun > 0 {
		num("  not run", c.NotRun)
	}

	b.WriteString("\n")
	num("ok", c.OK())
	num("errored", c.Errored())
	for _, o := range verdict.ErrorOutcomes {
		if n := c.Get(o); n > 0 {
			num("  "+errorLabel(o), n)
		}
	}

	b.WriteString("\n")
	b.WriteString(arithmeticLine(c))

	if s := detailSection(c); s != "" {
		b.WriteString("\n")
		b.WriteString(s)
	}
	if s := statusSection(c); s != "" {
		b.WriteString("\n")
		b.WriteString(s)
	}
	if s := r.topConsoleSection(); s != "" {
		b.WriteString("\n")
		b.WriteString(s)
	}

	b.WriteString("\n")
	if r.opts.Header.Chrome != "" {
		kv("browser", r.opts.Header.Chrome)
	}
	kv("elapsed", humanDur(elapsed))
	if files := r.filesLocked(); len(files) > 0 {
		kv("logs", strings.Join(files, "  "))
	}
	code, note := r.exitCode(c)
	kv("exit code", strconv.Itoa(code)+"  ("+note+")")

	return b.String()
}

// errorLabel is the summary's plural-English name for an error outcome.
func errorLabel(o verdict.Outcome) string {
	switch o {
	case verdict.OutcomeHTTPError:
		return "http errors"
	case verdict.OutcomeConsoleError:
		return "console errors"
	case verdict.OutcomeSubresourceError:
		return "subresource errors"
	case verdict.OutcomeLoadError:
		return "load errors"
	case verdict.OutcomeTimeout:
		return "timeouts"
	case verdict.OutcomeOK:
		return "ok"
	}
	return o.String()
}

// arithmeticLine renders the claim that every attempted URL was counted
// exactly once — and, when Counts says otherwise, refuses to print a tick.
//
// This line is the only self-check a user gets on the counters. Printing a
// reassuring "✓" next to arithmetic that does not add up would be worse than
// printing nothing, so a violated invariant produces a loud, unmissable
// warning instead.
func arithmeticLine(c verdict.Counts) string {
	terms := make([]string, 0, 1+len(verdict.ErrorOutcomes))
	sum := c.OK()
	terms = append(terms, strconv.Itoa(c.OK()))
	for _, o := range verdict.ErrorOutcomes {
		n := c.Get(o)
		sum += n
		terms = append(terms, strconv.Itoa(n))
	}
	eq := strings.Join(terms, " + ") + " = " + strconv.Itoa(sum)
	if c.Invariant() {
		return eq + "   ✓ every URL counted exactly once\n"
	}
	return eq + "\n!! MISCOUNT: " + strconv.Itoa(c.Attempted) +
		" URLs attempted but outcomes sum to " + strconv.Itoa(sum) +
		" — this is a bug in pagevet, not in the pages\n"
}

// detailSection reports the overlapping tallies, which deliberately do NOT
// partition anything: one page can appear on several of these lines.
func detailSection(c verdict.Counts) string {
	type row struct {
		label string
		n     int
		note  string
	}
	suppressed := ""
	if c.ConsoleSuppressed > 0 {
		suppressed = strconv.Itoa(c.ConsoleSuppressed) + " message(s) suppressed by -max-console"
	}
	rows := []row{
		{"pages with console errors", c.PagesWithConsoleErrors, ""},
		{"console error events", c.ConsoleEvents, suppressed},
		{"pages with failed subresources", c.PagesWithResourceErrors, ""},
		{"subresource failure events", c.ResourceEvents, ""},
		{"redirected pages", c.RedirectedPages, ""},
	}

	var b strings.Builder
	for _, rw := range rows {
		if rw.n == 0 {
			continue
		}
		b.WriteString(padRight("  "+rw.label, detailLabel))
		b.WriteString(padLeft(strconv.Itoa(rw.n), detailNumber))
		if rw.note != "" {
			b.WriteString("      ")
			b.WriteString(rw.note)
		}
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return ""
	}
	return "detail (a URL may appear in more than one line below)\n" + b.String()
}

// statusBreakdownPerLine keeps the breakdown inside the width of the rule above
// it, so a run against a hundred distinct statuses does not produce one line
// that wraps unpredictably in the reader's terminal.
const statusBreakdownPerLine = 5

func statusSection(c verdict.Counts) string {
	pairs := c.StatusBreakdown()
	if len(pairs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("http status breakdown\n")
	for i, p := range pairs {
		switch {
		case i%statusBreakdownPerLine == 0:
			b.WriteString("  ")
		default:
			b.WriteString("    ")
		}
		b.WriteString(padLeft(strconv.Itoa(p.Status), 3))
		b.WriteString(padLeft(strconv.Itoa(p.Count), 4))
		if i%statusBreakdownPerLine == statusBreakdownPerLine-1 || i == len(pairs)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// topConsoleN is how many distinct messages the summary shows. Five is enough
// to spot the pattern and short enough that nobody scrolls past the arithmetic
// line to find it.
const topConsoleN = 5

// topConsoleSection ranks messages across the whole run. Caller holds r.mu.
func (r *Reporter) topConsoleSection() string {
	top := r.topConsole(topConsoleN)
	if len(top) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("top console errors\n")
	for _, st := range top {
		b.WriteString("  ")
		b.WriteString(padLeft(strconv.Itoa(st.occ)+"x", blockNum))
		b.WriteString("  ")
		b.WriteString(strconv.Itoa(len(st.urls)))
		// Deliberately not pluralised: the count is a column, and "1 url"
		// would shift the message text by a byte on exactly the rows a reader
		// is least interested in.
		b.WriteString(" urls  ")
		b.WriteString(st.text)
		b.WriteString("\n")
	}
	return b.String()
}

// exitCode renders the last line of the summary.
//
// The default is 0 whenever Summary runs at all: reaching the summary means the
// run completed, and pages that were broken are the tool's OUTPUT, not its
// failure. Abnormal terminations (no browser, unreadable input) never get this
// far. Callers that want -fail-on-error semantics inject Options.ExitCode.
func (r *Reporter) exitCode(c verdict.Counts) (int, string) {
	if r.opts.ExitCode != nil {
		return r.opts.ExitCode(c)
	}
	if n := c.Errored(); n > 0 {
		return 0, "run completed; " + strconv.Itoa(n) + " URLs had errors"
	}
	return 0, "run completed; no errors"
}
