package fake_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/loader"
	"github.com/olegiv/pagevet/internal/loader/fake"
	"github.com/olegiv/pagevet/internal/verdict"
)

func TestDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configure  func(f *fake.FakeLoader)
		url        string
		wantStatus int
		wantErr    error
	}{
		{
			name:       "unconfigured loader answers a clean 200",
			configure:  func(*fake.FakeLoader) {},
			url:        "https://example.test/",
			wantStatus: 200,
		},
		{
			name: "SetDefault covers unscripted URLs",
			configure: func(f *fake.FakeLoader) {
				f.SetDefault(verdict.Result{Status: 503}, nil)
			},
			url:        "https://example.test/anything",
			wantStatus: 503,
		},
		{
			name: "SetResult beats SetDefault for its own URL",
			configure: func(f *fake.FakeLoader) {
				f.SetDefault(verdict.Result{Status: 503}, nil)
				f.SetResult("https://example.test/a", verdict.Result{Status: 404}, nil)
			},
			url:        "https://example.test/a",
			wantStatus: 404,
		},
		{
			name: "SetResult is an exact match, not a prefix",
			configure: func(f *fake.FakeLoader) {
				f.SetDefault(verdict.Result{Status: 503}, nil)
				f.SetResult("https://example.test/a", verdict.Result{Status: 404}, nil)
			},
			url:        "https://example.test/a?q=1",
			wantStatus: 503,
		},
		{
			name: "SetFunc overrides both",
			configure: func(f *fake.FakeLoader) {
				f.SetDefault(verdict.Result{Status: 503}, nil)
				f.SetResult("https://example.test/a", verdict.Result{Status: 404}, nil)
				f.SetFunc(func(context.Context, int, string) (verdict.Result, error) {
					return verdict.Result{Status: 418}, nil
				})
			},
			url:        "https://example.test/a",
			wantStatus: 418,
		},
		{
			name: "a scripted loader error is returned verbatim",
			configure: func(f *fake.FakeLoader) {
				f.SetResult("https://example.test/dead", verdict.Result{}, loader.ErrBrowserUnavailable)
			},
			url:     "https://example.test/dead",
			wantErr: loader.ErrBrowserUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := fake.New()
			tc.configure(f)

			res, err := f.Load(t.Context(), 7, tc.url)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Load error = %v, want %v", err, tc.wantErr)
			}
			if res.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", res.Status, tc.wantStatus)
			}
		})
	}
}

func TestStamping(t *testing.T) {
	t.Parallel()

	t.Run("Index and URL are filled in when the script omits them", func(t *testing.T) {
		t.Parallel()

		f := fake.New()
		f.SetDefault(verdict.Result{Status: 200}, nil)

		res, err := f.Load(t.Context(), 42, "https://example.test/x")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if res.Index != 42 {
			t.Errorf("Index = %d, want 42", res.Index)
		}
		if res.URL != "https://example.test/x" {
			t.Errorf("URL = %q, want the requested URL", res.URL)
		}
	})

	t.Run("scripted Index and URL survive", func(t *testing.T) {
		t.Parallel()

		f := fake.New()
		f.SetDefault(verdict.Result{Index: 1, URL: "scripted", Status: 200}, nil)

		res, err := f.Load(t.Context(), 42, "https://example.test/x")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if res.Index != 1 || res.URL != "scripted" {
			t.Errorf("Index/URL = %d/%q, want 1/%q", res.Index, res.URL, "scripted")
		}
	})

	t.Run("SetFunc sees the real index and URL", func(t *testing.T) {
		t.Parallel()

		f := fake.New()
		var gotIndex int
		var gotURL string
		f.SetFunc(func(_ context.Context, index int, rawURL string) (verdict.Result, error) {
			gotIndex, gotURL = index, rawURL
			return verdict.Result{Status: 200}, nil
		})

		if _, err := f.Load(t.Context(), 3, "https://example.test/y"); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if gotIndex != 3 || gotURL != "https://example.test/y" {
			t.Errorf("callback saw %d/%q", gotIndex, gotURL)
		}
	})
}

func TestCallRecording(t *testing.T) {
	t.Parallel()

	f := fake.New()
	urls := []string{"https://example.test/a", "https://example.test/b", "https://example.test/a"}
	for i, u := range urls {
		if _, err := f.Load(t.Context(), i+1, u); err != nil {
			t.Fatalf("Load(%q): %v", u, err)
		}
	}

	if got := f.Calls(); !slices.Equal(got, urls) {
		t.Errorf("Calls() = %q, want %q", got, urls)
	}
	if got := f.CallCount(); got != len(urls) {
		t.Errorf("CallCount() = %d, want %d", got, len(urls))
	}

	// The returned slice is a copy: mutating it must not corrupt the recording.
	calls := f.Calls()
	calls[0] = "mutated"
	if f.Calls()[0] != urls[0] {
		t.Error("Calls() handed out its internal slice")
	}
}

func TestMaxConcurrent(t *testing.T) {
	t.Parallel()

	t.Run("peak is one when calls do not overlap", func(t *testing.T) {
		t.Parallel()

		f := fake.New()
		for i := range 5 {
			if _, err := f.Load(t.Context(), i+1, "https://example.test/"+strconv.Itoa(i)); err != nil {
				t.Fatalf("Load: %v", err)
			}
		}
		if got := f.MaxConcurrent(); got != 1 {
			t.Errorf("MaxConcurrent() = %d, want 1", got)
		}
	})

	t.Run("peak counts genuinely simultaneous loads", func(t *testing.T) {
		t.Parallel()

		const n = 8
		f := fake.New()

		// Every call parks in the callback until all n have arrived, so the
		// peak is forced to be exactly n rather than whatever the scheduler
		// happened to overlap.
		arrived := make(chan struct{}, n)
		release := make(chan struct{})
		f.SetFunc(func(context.Context, int, string) (verdict.Result, error) {
			arrived <- struct{}{}
			<-release
			return verdict.Result{Status: 200}, nil
		})

		ctx := t.Context()
		var wg sync.WaitGroup
		wg.Add(n)
		for i := range n {
			go func() {
				defer wg.Done()
				if _, err := f.Load(ctx, i+1, "https://example.test/"+strconv.Itoa(i)); err != nil {
					t.Errorf("Load: %v", err)
				}
			}()
		}
		for range n {
			<-arrived
		}
		close(release)
		wg.Wait()

		if got := f.MaxConcurrent(); got != n {
			t.Errorf("MaxConcurrent() = %d, want %d", got, n)
		}
		if got := f.CallCount(); got != n {
			t.Errorf("CallCount() = %d, want %d", got, n)
		}
	})
}

func TestDelay(t *testing.T) {
	t.Parallel()

	t.Run("the scripted result arrives after the delay", func(t *testing.T) {
		t.Parallel()

		const delay = 20 * time.Millisecond
		f := fake.New()
		f.SetDefault(verdict.Result{Status: 201}, nil)
		f.SetDelay("https://example.test/slow", delay)

		start := time.Now()
		res, err := f.Load(t.Context(), 1, "https://example.test/slow")
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if res.Status != 201 {
			t.Errorf("Status = %d, want 201", res.Status)
		}
		if elapsed < delay {
			t.Errorf("returned after %v, want at least %v", elapsed, delay)
		}
	})

	t.Run("cancellation during the delay returns the context error", func(t *testing.T) {
		t.Parallel()

		f := fake.New()
		f.SetDelay("https://example.test/hang", time.Hour)

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		res, err := f.Load(ctx, 9, "https://example.test/hang")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Load error = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("cancellation took %v; the delay was not interruptible", elapsed)
		}
		// Even the failure path carries enough identity to be logged usefully.
		if res.Index != 9 || res.URL != "https://example.test/hang" {
			t.Errorf("Index/URL = %d/%q, want 9/%q", res.Index, res.URL, "https://example.test/hang")
		}
	})

	t.Run("a deadline that expires mid-delay is reported too", func(t *testing.T) {
		t.Parallel()

		f := fake.New()
		f.SetDelay("https://example.test/hang", time.Hour)

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		if _, err := f.Load(ctx, 1, "https://example.test/hang"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Load error = %v, want context.DeadlineExceeded", err)
		}
	})
}

// TestConcurrentConfiguration is the -race canary: reconfiguring the fake while
// loads are in flight is exactly what an app-level test does, and it must not
// race.
func TestConcurrentConfiguration(t *testing.T) {
	t.Parallel()

	f := fake.New()
	ctx := t.Context()
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			f.SetResult("https://example.test/"+strconv.Itoa(i), verdict.Result{Status: 200}, nil)
			f.SetDelay("https://example.test/"+strconv.Itoa(i), 0)
		}()
		go func() {
			defer wg.Done()
			if _, err := f.Load(ctx, i+1, "https://example.test/"+strconv.Itoa(i)); err != nil {
				t.Errorf("Load: %v", err)
			}
			_ = f.Calls()
			_ = f.MaxConcurrent()
		}()
	}
	wg.Wait()

	if got := f.CallCount(); got != 16 {
		t.Errorf("CallCount() = %d, want 16", got)
	}
}
