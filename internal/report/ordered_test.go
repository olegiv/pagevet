package report

import (
	"errors"
	"testing"

	"github.com/olegiv/pagevet/internal/verdict"
)

// collector records the order Push/Flush actually emitted in.
type collector struct {
	got  []int
	fail map[int]error
}

func (c *collector) sink(res verdict.Result, _ verdict.Outcome) error {
	c.got = append(c.got, res.Index)
	return c.fail[res.Index]
}

func result(i int) verdict.Result {
	return verdict.Result{Index: i, URL: "https://example.com/" + string(rune('a'+i%26))}
}

func TestOrderedSink_ShuffledPushEmitsInIndexOrder(t *testing.T) {
	t.Parallel()

	// A stride coprime with n visits every index exactly once, so this is a
	// genuine permutation with no random source to seed — a failure here
	// reproduces byte for byte.
	const n, stride = 64, 37
	order := make([]int, n)
	for i := range order {
		order[i] = (i*stride + 11) % n
	}

	var c collector
	s := NewOrdered(c.sink)
	for _, i := range order {
		if err := s.Push(i, result(i), verdict.OutcomeOK); err != nil {
			t.Fatalf("Push(%d): %v", i, err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if len(c.got) != n {
		t.Fatalf("emitted %d results, want %d", len(c.got), n)
	}
	for i, got := range c.got {
		if got != i {
			t.Fatalf("emit %d was index %d, want %d (order: %v)", i, got, i, c.got)
		}
	}
}

func TestOrderedSink_HoldsUntilPredecessorArrives(t *testing.T) {
	t.Parallel()

	var c collector
	s := NewOrdered(c.sink)

	for _, i := range []int{3, 1, 2} {
		if err := s.Push(i, result(i), verdict.OutcomeOK); err != nil {
			t.Fatalf("Push(%d): %v", i, err)
		}
		if len(c.got) != 0 {
			t.Fatalf("nothing may be emitted while index 0 is outstanding, got %v", c.got)
		}
	}
	if err := s.Push(0, result(0), verdict.OutcomeOK); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	if want := []int{0, 1, 2, 3}; !equalInts(c.got, want) {
		t.Fatalf("after the gap closed, emitted %v, want %v", c.got, want)
	}
}

func TestOrderedSink_FlushEmitsRemainderInOrder(t *testing.T) {
	t.Parallel()

	var c collector
	s := NewOrdered(c.sink)

	// An interrupted run: indices 2 and 5 never arrive.
	for _, i := range []int{7, 3, 0, 6, 1, 4} {
		if err := s.Push(i, result(i), verdict.OutcomeOK); err != nil {
			t.Fatalf("Push(%d): %v", i, err)
		}
	}
	if want := []int{0, 1}; !equalInts(c.got, want) {
		t.Fatalf("streamed %v before the gap, want %v", c.got, want)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if want := []int{0, 1, 3, 4, 6, 7}; !equalInts(c.got, want) {
		t.Fatalf("after Flush emitted %v, want %v", c.got, want)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
}

func TestOrderedSink_EmptyIsNoop(t *testing.T) {
	t.Parallel()

	var c collector
	s := NewOrdered(c.sink)
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush on an empty sink: %v", err)
	}
	if len(c.got) != 0 {
		t.Fatalf("an empty sink emitted %v", c.got)
	}
}

func TestOrderedSink_RejectsRepeatedIndex(t *testing.T) {
	t.Parallel()

	var c collector
	s := NewOrdered(c.sink)

	if err := s.Push(1, result(1), verdict.OutcomeOK); err != nil {
		t.Fatalf("Push(1): %v", err)
	}
	if err := s.Push(1, result(1), verdict.OutcomeOK); err == nil {
		t.Error("pushing a buffered index twice must be an error, not a silent duplicate")
	}
	if err := s.Push(0, result(0), verdict.OutcomeOK); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	if err := s.Push(0, result(0), verdict.OutcomeOK); err == nil {
		t.Error("pushing an already-emitted index must be an error")
	}
}

func TestOrderedSink_PropagatesSinkErrors(t *testing.T) {
	t.Parallel()

	boom := errors.New("disk full")
	// Index 1 fails while streaming, index 4 fails during the final drain.
	c := collector{fail: map[int]error{1: boom, 4: boom}}
	s := NewOrdered(c.sink)

	if err := s.Push(0, result(0), verdict.OutcomeOK); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	if err := s.Push(1, result(1), verdict.OutcomeOK); !errors.Is(err, boom) {
		t.Fatalf("Push(1) error = %v, want %v", err, boom)
	}
	// The failed index is still consumed, so the drain keeps moving.
	if err := s.Push(2, result(2), verdict.OutcomeOK); err != nil {
		t.Fatalf("Push(2): %v", err)
	}
	if err := s.Push(4, result(4), verdict.OutcomeOK); err != nil {
		t.Fatalf("Push(4): %v", err)
	}
	if err := s.Flush(); !errors.Is(err, boom) {
		t.Fatalf("Flush error = %v, want %v", err, boom)
	}
	if want := []int{0, 1, 2, 4}; !equalInts(c.got, want) {
		t.Fatalf("emitted %v, want %v", c.got, want)
	}
}

func TestOrderedSink_ConcurrentPushIsSafe(t *testing.T) {
	t.Parallel()

	const n = 128
	var c collector
	s := NewOrdered(c.sink)

	done := make(chan struct{})
	for i := range n {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			if err := s.Push(i, result(i), verdict.OutcomeOK); err != nil {
				t.Errorf("Push(%d): %v", i, err)
			}
		}(i)
	}
	for range n {
		<-done
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(c.got) != n {
		t.Fatalf("emitted %d results, want %d", len(c.got), n)
	}
	for i, got := range c.got {
		if got != i {
			t.Fatalf("emit %d was index %d, want %d", i, got, i)
		}
	}
}

func equalInts(a, b []int) bool {
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
