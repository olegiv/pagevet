package report

import (
	"fmt"
	"sort"
	"sync"

	"github.com/olegiv/pagevet/internal/verdict"
)

// OrderedSink restores input order to results that finished out of order.
//
// With N workers in flight, URL #7 routinely finishes before URL #3. The logs
// must still read top-to-bottom in input order, because that is the order the
// user's file is in and the only order in which "the third URL" means anything.
//
// The buffer is bounded in practice by the worker count: at most one unfinished
// result per in-flight worker can be blocking the drain, because a result only
// waits for indices that are still being fetched.
//
// Every method is safe for concurrent use.
type OrderedSink struct {
	mu      sync.Mutex
	next    func(verdict.Result, verdict.Outcome) error
	want    int
	pending map[int]pendingResult
}

type pendingResult struct {
	res verdict.Result
	out verdict.Outcome
}

// NewOrdered returns a sink that emits through next in index order.
//
// Indices are 0-BASED positions in the input, contiguous from zero — which is
// the dispatch index of the worker pool, not verdict.Result.Index (1-based).
// A caller that passes 1-based indices still gets correct output, but nothing
// drains until Flush, because index 0 never arrives.
func NewOrdered(next func(verdict.Result, verdict.Outcome) error) *OrderedSink {
	return &OrderedSink{next: next, pending: make(map[int]pendingResult, 16)}
}

// Push offers the result for position i, then drains as far as the buffer
// allows: nothing is emitted until every earlier index has been.
//
// If next fails, the index is still consumed and the sink moves on. Retrying
// would duplicate a record that may already be half-written to a log file, and
// stalling would deadlock the drain behind an error the caller is already being
// told about.
func (s *OrderedSink) Push(i int, res verdict.Result, o verdict.Outcome) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if i < s.want {
		return fmt.Errorf("report: ordered sink: index %d already emitted (next expected %d)", i, s.want)
	}
	if _, dup := s.pending[i]; dup {
		return fmt.Errorf("report: ordered sink: index %d pushed twice", i)
	}
	s.pending[i] = pendingResult{res: res, out: o}

	for {
		p, ok := s.pending[s.want]
		if !ok {
			return nil
		}
		delete(s.pending, s.want)
		s.want++
		if err := s.next(p.res, p.out); err != nil {
			return err
		}
	}
}

// Flush emits everything still buffered, in index order, and empties the sink.
//
// It exists for the interrupted run: when the user hits Ctrl-C, indices in the
// middle of the buffer will never arrive, and the results that DID complete
// must still reach the logs rather than being dropped along with the gap.
func (s *OrderedSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pending) == 0 {
		return nil
	}
	idx := make([]int, 0, len(s.pending))
	for i := range s.pending {
		idx = append(idx, i)
	}
	sort.Ints(idx)

	var firstErr error
	for _, i := range idx {
		p := s.pending[i]
		delete(s.pending, i)
		// Every remaining result is emitted even if one fails, because this is
		// the last chance any of them has to reach the log.
		if err := s.next(p.res, p.out); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.want = idx[len(idx)-1] + 1
	return firstErr
}
