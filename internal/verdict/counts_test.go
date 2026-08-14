package verdict

import (
	"slices"
	"testing"
)

// addAll classifies each result under p and records it, the way the reporter
// does at the end of a run.
func addAll(c *Counts, p Policy, results ...Result) {
	for _, r := range results {
		c.Add(r, Classify(r, p))
	}
}

// TestCounts_SumsToAttempted is the arithmetic the summary line claims: every
// attempted URL lands in exactly one primary bucket.
func TestCounts_SumsToAttempted(t *testing.T) {
	t.Parallel()

	results := []Result{
		{Index: 1, Status: 200},
		{Index: 2, Status: 204},
		{Index: 3, Status: 404},
		{Index: 4, Status: 500, Console: consoleErrs(1)},
		{Index: 5, Status: 200, Console: consoleErrs(2)},
		{Index: 6, Status: 200, Resources: resourceErrs(1)},
		{Index: 7, Status: 200, TimedOut: true},
		{Index: 8, NetError: "net::ERR_NAME_NOT_RESOLVED"},
		{Index: 9, TimedOut: true},
		{Index: 10, Crashed: true, NetError: "net::ERR_RENDERER_CRASHED"},
	}

	var c Counts
	addAll(&c, DefaultPolicy(), results...)

	if c.Attempted != len(results) {
		t.Errorf("Attempted = %d, want %d", c.Attempted, len(results))
	}
	if !c.Invariant() {
		t.Error("Invariant() = false, want true")
	}

	sumErrors := 0
	for _, o := range ErrorOutcomes {
		sumErrors += c.Get(o)
	}
	if got := c.OK() + sumErrors; got != c.Attempted {
		t.Errorf("OK()+errors = %d, want Attempted = %d", got, c.Attempted)
	}

	want := map[Outcome]int{
		OutcomeOK:               2, // 200, 204
		OutcomeHTTPError:        2, // 404, 500-that-throws
		OutcomeConsoleError:     1,
		OutcomeSubresourceError: 1,
		OutcomeTimeout:          2, // 200-then-hang, and the deadline-only page
		OutcomeLoadError:        2, // DNS failure, renderer crash
	}
	for o, n := range want {
		if got := c.Get(o); got != n {
			t.Errorf("Get(%v) = %d, want %d", o, got, n)
		}
	}
}

func TestCounts_ErroredExcludesOK(t *testing.T) {
	t.Parallel()

	var c Counts
	addAll(&c, DefaultPolicy(),
		Result{Status: 200},
		Result{Status: 200},
		Result{Status: 404},
		Result{Status: 200, Console: consoleErrs(1)},
	)

	if c.OK() != 2 {
		t.Errorf("OK() = %d, want 2", c.OK())
	}
	if c.Errored() != 2 {
		t.Errorf("Errored() = %d, want 2", c.Errored())
	}
	if c.OK()+c.Errored() != c.Attempted {
		t.Errorf("OK()+Errored() = %d, want Attempted = %d", c.OK()+c.Errored(), c.Attempted)
	}
}

// TestCounts_BothErrorsCountedOnce pins the split between the partition and the
// overlap block: a 500 that also throws is ONE attempt under http_error, while
// the (deliberately overlapping) console counters still see it.
func TestCounts_BothErrorsCountedOnce(t *testing.T) {
	t.Parallel()

	r := Result{Status: 500, Console: []ConsoleError{{Kind: KindException, Text: "boom", Count: 1}}}

	var c Counts
	c.Add(r, Classify(r, DefaultPolicy()))

	if c.Attempted != 1 {
		t.Errorf("Attempted = %d, want 1", c.Attempted)
	}
	if got := c.Get(OutcomeHTTPError); got != 1 {
		t.Errorf("Get(http_error) = %d, want 1", got)
	}
	if got := c.Get(OutcomeConsoleError); got != 0 {
		t.Errorf("Get(console_error) = %d, want 0 (the partition must not double-count)", got)
	}
	if c.PagesWithConsoleErrors != 1 {
		t.Errorf("PagesWithConsoleErrors = %d, want 1", c.PagesWithConsoleErrors)
	}
	if c.ConsoleEvents != 1 {
		t.Errorf("ConsoleEvents = %d, want 1", c.ConsoleEvents)
	}
	if !c.Invariant() {
		t.Error("Invariant() = false, want true")
	}
}

// TestCounts_DuplicateURLsCountedTwice: dedupe of input lines is input's job,
// not the counters'. Whatever is attempted is counted.
func TestCounts_DuplicateURLsCountedTwice(t *testing.T) {
	t.Parallel()

	r := Result{URL: "https://example.test/", Status: 200}

	var c Counts
	addAll(&c, DefaultPolicy(), r, r)

	if c.Attempted != 2 {
		t.Errorf("Attempted = %d, want 2", c.Attempted)
	}
	if c.OK() != 2 {
		t.Errorf("OK() = %d, want 2", c.OK())
	}
	if got := c.ByStatus[200]; got != 2 {
		t.Errorf("ByStatus[200] = %d, want 2", got)
	}
	if !c.Invariant() {
		t.Error("Invariant() = false, want true")
	}
}

// TestCounts_EmptyInput: the zero value has to be usable, because a run that
// ends before dispatching anything still prints a summary.
func TestCounts_EmptyInput(t *testing.T) {
	t.Parallel()

	var c Counts

	if c.Attempted != 0 {
		t.Errorf("Attempted = %d, want 0", c.Attempted)
	}
	if c.OK() != 0 || c.Errored() != 0 {
		t.Errorf("OK() = %d, Errored() = %d, want 0 and 0", c.OK(), c.Errored())
	}
	if !c.Invariant() {
		t.Error("Invariant() = false, want true")
	}
	if got := c.StatusBreakdown(); got != nil {
		t.Errorf("StatusBreakdown() = %v, want nil", got)
	}
	for _, o := range ErrorOutcomes {
		if got := c.Get(o); got != 0 {
			t.Errorf("Get(%v) = %d, want 0", o, got)
		}
	}
}

// TestCounts_StatusBreakdownIsSorted: the summary must render identically on
// every run, which Go's randomized map iteration would otherwise prevent.
func TestCounts_StatusBreakdownIsSorted(t *testing.T) {
	t.Parallel()

	var c Counts
	addAll(&c, DefaultPolicy(),
		Result{Status: 500},
		Result{Status: 200},
		Result{Status: 404},
		Result{Status: 200},
		Result{Status: 301},
		Result{NetError: "net::ERR_CONNECTION_REFUSED"}, // status 0: no response to report
	)

	want := []StatusPair{{200, 2}, {301, 1}, {404, 1}, {500, 1}}
	got := c.StatusBreakdown()
	if !slices.Equal(got, want) {
		t.Fatalf("StatusBreakdown() = %v, want %v", got, want)
	}
	if _, ok := c.ByStatus[0]; ok {
		t.Error("ByStatus contains status 0; a missing response is not a status")
	}
	if c.Attempted != 6 {
		t.Errorf("Attempted = %d, want 6", c.Attempted)
	}
}

// TestCounts_ConsoleAndResourceEventCounts: the event counters sum occurrences,
// not deduplicated records — a loop that throws 500 times reports 500.
func TestCounts_ConsoleAndResourceEventCounts(t *testing.T) {
	t.Parallel()

	r := Result{
		Status: 200,
		Console: []ConsoleError{
			{Kind: KindException, Text: "raf loop", Count: 500},
			{Kind: KindConsoleAPI, Text: "warn", Count: 2},
		},
		ConsoleSuppressed: 7,
		Resources: []ResourceError{
			{URL: "https://example.test/a.js", Type: "Script", Status: 404, Count: 50},
		},
		Redirects: []Hop{{Status: 301, URL: "https://example.test/old"}},
	}

	if got := r.ConsoleEvents(); got != 502 {
		t.Errorf("ConsoleEvents() = %d, want 502", got)
	}
	if got := r.ResourceEvents(); got != 50 {
		t.Errorf("ResourceEvents() = %d, want 50", got)
	}

	var c Counts
	c.Add(r, Classify(r, DefaultPolicy()))

	if c.PagesWithConsoleErrors != 1 {
		t.Errorf("PagesWithConsoleErrors = %d, want 1 (records, not occurrences)", c.PagesWithConsoleErrors)
	}
	if c.ConsoleEvents != 502 {
		t.Errorf("ConsoleEvents = %d, want 502", c.ConsoleEvents)
	}
	if c.ConsoleSuppressed != 7 {
		t.Errorf("ConsoleSuppressed = %d, want 7", c.ConsoleSuppressed)
	}
	if c.PagesWithResourceErrors != 1 {
		t.Errorf("PagesWithResourceErrors = %d, want 1", c.PagesWithResourceErrors)
	}
	if c.ResourceEvents != 50 {
		t.Errorf("ResourceEvents = %d, want 50", c.ResourceEvents)
	}
	if c.RedirectedPages != 1 {
		t.Errorf("RedirectedPages = %d, want 1", c.RedirectedPages)
	}
}

// FuzzCountsInvariant hunts for a Result whose classification escapes the
// partition — either a bucket Add cannot reach or a combination of policy and
// observation that Classify leaves unaccounted for.
func FuzzCountsInvariant(f *testing.F) {
	// Seeds: clean page, plain 404, throwing 200, DNS failure, timeout,
	// blocked request, and an inverted status band.
	f.Add(200, "", "", false, false, uint8(0), uint8(0), true, true, 200, 399)
	f.Add(404, "", "", false, false, uint8(0), uint8(0), true, true, 200, 399)
	f.Add(200, "", "", false, false, uint8(3), uint8(0), true, true, 200, 399)
	f.Add(0, "net::ERR_NAME_NOT_RESOLVED", "", false, false, uint8(0), uint8(0), true, true, 200, 399)
	f.Add(0, "", "", true, false, uint8(0), uint8(0), true, true, 200, 399)
	f.Add(0, "", "csp", false, true, uint8(1), uint8(1), false, false, 200, 399)
	f.Add(500, "", "", true, false, uint8(2), uint8(2), true, true, 399, 200)

	f.Fuzz(func(t *testing.T,
		status int, netError, blockReason string,
		timedOut, crashed bool,
		nConsole, nResources uint8,
		failOnConsole, failOnResource bool,
		okMin, okMax int,
	) {
		r := Result{
			Status:      status,
			NetError:    netError,
			BlockReason: blockReason,
			TimedOut:    timedOut,
			Crashed:     crashed,
			// Capped: the fuzzer's job is to vary the shape, not to allocate.
			Console:   consoleErrs(int(nConsole % 8)),
			Resources: resourceErrs(int(nResources % 8)),
		}
		p := Policy{
			OKStatusMin:    okMin,
			OKStatusMax:    okMax,
			FailOnConsole:  failOnConsole,
			FailOnResource: failOnResource,
		}

		o := Classify(r, p)
		if o >= numOutcomes {
			t.Fatalf("Classify() = %d, outside the outcome range", o)
		}

		var c Counts
		for range 3 {
			c.Add(r, o)
			if !c.Invariant() {
				t.Fatalf("Invariant() = false after %d adds of %+v under %+v", c.Attempted, r, p)
			}
		}
		if c.Attempted != 3 {
			t.Fatalf("Attempted = %d, want 3", c.Attempted)
		}
		if c.OK()+c.Errored() != c.Attempted {
			t.Fatalf("OK()+Errored() = %d, want Attempted = %d", c.OK()+c.Errored(), c.Attempted)
		}

		// Flags must agree with the primary outcome, or a URL would be counted
		// under one heading and logged under another.
		flags := Flags(r, p)
		if len(flags) == 0 || flags[0] != o {
			t.Fatalf("Flags() = %v, want it to lead with Classify() = %v", flags, o)
		}
	})
}
