package verdict

import "sort"

// Counts is the run summary.
//
// byOutcome is a PARTITION of Attempted — every attempted URL lands in exactly
// one bucket, which Invariant checks and the reporter asserts before printing.
// That is what lets the summary claim "every URL counted exactly once".
//
// The second block of fields deliberately overlaps: a page can have both
// console errors and failed subresources. Those are reported separately and
// labeled as overlapping, and they never feed the primary arithmetic.
type Counts struct {
	Attempted int
	byOutcome [numOutcomes]int

	InvalidLines int // rejected by input.ReadURLs; never navigated, never Attempted
	SkippedLines int // blank, comment or duplicate
	NotRun       int // interrupted before dispatch

	PagesWithConsoleErrors  int
	ConsoleEvents           int
	ConsoleSuppressed       int
	PagesWithResourceErrors int
	ResourceEvents          int
	RedirectedPages         int

	// ByStatus counts main-document statuses actually observed.
	ByStatus map[int]int
}

// Add records one attempted URL under its primary outcome.
func (c *Counts) Add(r Result, o Outcome) {
	c.Attempted++
	c.byOutcome[o]++

	if len(r.Console) > 0 {
		c.PagesWithConsoleErrors++
		c.ConsoleEvents += r.ConsoleEvents()
	}
	c.ConsoleSuppressed += r.ConsoleSuppressed

	if len(r.Resources) > 0 {
		c.PagesWithResourceErrors++
		c.ResourceEvents += r.ResourceEvents()
	}

	if len(r.Redirects) > 0 {
		c.RedirectedPages++
	}

	if r.Status != 0 {
		if c.ByStatus == nil {
			c.ByStatus = make(map[int]int, 16)
		}
		c.ByStatus[r.Status]++
	}
}

// Get returns the number of URLs whose primary outcome was o.
func (c Counts) Get(o Outcome) int { return c.byOutcome[o] }

// OK returns the number of URLs that loaded cleanly.
func (c Counts) OK() int { return c.byOutcome[OutcomeOK] }

// Errored returns the number of attempted URLs that were not OK.
func (c Counts) Errored() int { return c.Attempted - c.OK() }

// Invariant reports whether the primary counters still partition Attempted.
// A false result means a Result was counted under no outcome or under two,
// which is a bug in the caller rather than a property of the crawl.
func (c Counts) Invariant() bool {
	sum := 0
	for _, n := range c.byOutcome {
		sum += n
	}
	return sum == c.Attempted
}

// ErrorOutcomes lists the non-OK outcomes in the order the summary reports
// them.
var ErrorOutcomes = [...]Outcome{
	OutcomeHTTPError,
	OutcomeConsoleError,
	OutcomeSubresourceError,
	OutcomeLoadError,
	OutcomeTimeout,
}

// StatusPair is one entry of the status breakdown.
type StatusPair struct {
	Status int
	Count  int
}

// StatusBreakdown returns the observed statuses in ascending order, so the
// summary renders deterministically rather than in Go's randomized map order.
func (c Counts) StatusBreakdown() []StatusPair {
	if len(c.ByStatus) == 0 {
		return nil
	}
	out := make([]StatusPair, 0, len(c.ByStatus))
	for s, n := range c.ByStatus {
		out = append(out, StatusPair{Status: s, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Status < out[j].Status })
	return out
}
