package verdict

// Classify reduces a Result to its single primary Outcome.
//
// It is total and deterministic: every Result maps to exactly one Outcome.
// That totality is the invariant behind Counts.Invariant, and behind the
// summary line asserting every URL was counted exactly once.
//
// Precedence, highest to lowest:
//
//	LoadError > HTTPError > Timeout > ConsoleError > SubresourceError > OK
//
// Three of those orderings are worth justifying, because they are the ones a
// reader will question:
//
//   - HTTPError above Timeout. A 500 that then hangs is a 500. The status is
//     definite and actionable; the hang is still recorded in TimedOut and
//     SettledBy for debugging. This ordering is only reachable because the
//     collector captures the main-document status INDEPENDENTLY of
//     chromedp.RunResponse, which discards its *network.Response on any error
//     path — including timeouts.
//
//   - Timeout above ConsoleError. A page that never finished loading is a
//     bigger problem than one that logged an error while finishing.
//
//   - ConsoleError above SubresourceError. A page whose own JavaScript threw is
//     more broken than one that merely failed to fetch an asset.
func Classify(r Result, p Policy) Outcome {
	if r.Status == 0 {
		// No main-document response ever arrived.
		if r.NetError != "" || r.Crashed || r.BlockReason != "" {
			return OutcomeLoadError
		}
		if r.TimedOut {
			return OutcomeTimeout
		}
		// No response, no network error, no deadline hit. We do not know what
		// happened, and "we don't know" must never read as OK.
		return OutcomeLoadError
	}
	// A download is not a page. Chrome answers the request, then aborts the
	// navigation without rendering anything, so the 200 on a
	// Content-Disposition: attachment response describes a file transfer that
	// was refused - reporting it as a healthy page would be a lie, and no
	// console or subresource observation for it means anything either.
	if r.Download {
		return OutcomeLoadError
	}
	if !p.StatusOK(r.Status) {
		return OutcomeHTTPError
	}
	if r.TimedOut {
		return OutcomeTimeout
	}
	if p.FailOnConsole && len(r.Console) > 0 {
		return OutcomeConsoleError
	}
	if p.FailOnResource && len(r.Resources) > 0 {
		return OutcomeSubresourceError
	}
	return OutcomeOK
}

// Flags reports EVERY error category that applies, independent of precedence.
//
// A 500 page whose own JavaScript also throws returns both OutcomeHTTPError and
// OutcomeConsoleError, so the human-facing error logs can list it under both.
//
// Flags is used ONLY for the error logs. The counters use Classify — if they
// used Flags the totals would double-count and the summary arithmetic would
// stop balancing.
//
// The returned slice is ordered by the same precedence Classify uses, and is
// never empty: a clean Result yields exactly [OutcomeOK].
func Flags(r Result, p Policy) []Outcome {
	out := make([]Outcome, 0, 3)

	switch {
	case r.Status == 0:
		if r.NetError != "" || r.Crashed || r.BlockReason != "" {
			out = append(out, OutcomeLoadError)
		}
		if r.TimedOut {
			out = append(out, OutcomeTimeout)
		}
		if len(out) == 0 {
			// Mirrors Classify's "we don't know" fallback.
			out = append(out, OutcomeLoadError)
		}

	case r.Download:
		// See Classify: a download never became a page, so it gets that one
		// honest flag and nothing else. Console and subresource observations
		// on a file transfer would be meaningless.
		return append(out, OutcomeLoadError)

	default:
		if !p.StatusOK(r.Status) {
			out = append(out, OutcomeHTTPError)
		}
		if r.TimedOut {
			out = append(out, OutcomeTimeout)
		}
	}

	if p.FailOnConsole && len(r.Console) > 0 {
		out = append(out, OutcomeConsoleError)
	}
	if p.FailOnResource && len(r.Resources) > 0 {
		out = append(out, OutcomeSubresourceError)
	}

	if len(out) == 0 {
		out = append(out, OutcomeOK)
	}
	return out
}

// Categories returns the distinct error-log buckets a Result belongs in,
// ordered as in ErrorCategories. A clean Result returns nil.
//
// This exists because Flags can yield two outcomes that share one log file —
// a page that both timed out and failed to resolve is one record in
// errors-load.log, not two.
func Categories(r Result, p Policy) []Category {
	flags := Flags(r, p)
	seen := make(map[Category]bool, len(flags))
	for _, o := range flags {
		if c := o.Category(); c != CategoryNone {
			seen[c] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]Category, 0, len(seen))
	for _, c := range ErrorCategories {
		if seen[c] {
			out = append(out, c)
		}
	}
	return out
}
