package verdict

// Policy is the tunable half of classification.
//
// It is injected rather than read from globals or from package flag, which is
// what lets classify_test.go cover every combination of settings without
// touching the CLI layer.
type Policy struct {
	// OKStatusMin and OKStatusMax bound the main-document statuses treated as
	// acceptable, inclusive. The default band is 200-399: a 3xx that is the
	// FINAL hop of a chain (rather than an intermediate redirect) is not an
	// error, and neither is a 304.
	OKStatusMin int
	OKStatusMax int

	// FailOnConsole makes browser console errors count as a failure.
	FailOnConsole bool

	// FailOnResource makes failed subresources count as a failure, reported
	// under their own OutcomeSubresourceError.
	FailOnResource bool
}

// DefaultPolicy is the shipped default: statuses 200-399 are OK, and both
// console errors and subresource failures count against a page.
func DefaultPolicy() Policy {
	return Policy{
		OKStatusMin:    200,
		OKStatusMax:    399,
		FailOnConsole:  true,
		FailOnResource: true,
	}
}

// StatusOK reports whether a main-document status falls inside the acceptable
// band. A zero status (no response arrived) is never OK.
func (p Policy) StatusOK(status int) bool {
	if status == 0 {
		return false
	}
	return status >= p.OKStatusMin && status <= p.OKStatusMax
}
