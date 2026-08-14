package verdict

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// noTruncate keeps the message cap out of the way of the dedupe tests.
const noTruncate = 0

func TestConsoleDeduper_CollapsesIdenticalErrors(t *testing.T) {
	t.Parallel()

	d := NewConsoleDeduper(20, noTruncate)
	c := ConsoleError{Kind: KindException, Text: "TypeError: x is not a function", Source: "https://example.test/a.js", Line: 12, Col: 5}
	for range 3 {
		d.Add(c)
	}

	got := d.Records()
	if len(got) != 1 {
		t.Fatalf("Records() has %d records, want 1: %+v", len(got), got)
	}
	if got[0].Count != 3 {
		t.Errorf("Count = %d, want 3", got[0].Count)
	}
	if d.Suppressed() != 0 || d.Truncated() {
		t.Errorf("Suppressed() = %d, Truncated() = %v, want 0 and false", d.Suppressed(), d.Truncated())
	}
}

// TestConsoleDeduper_PreservesFirstSeenOrder: the error that broke the page is
// usually the first one, so a repeat must not promote B ahead of A.
func TestConsoleDeduper_PreservesFirstSeenOrder(t *testing.T) {
	t.Parallel()

	a := ConsoleError{Kind: KindException, Text: "A", Line: 1}
	b := ConsoleError{Kind: KindException, Text: "B", Line: 2}

	d := NewConsoleDeduper(20, noTruncate)
	d.Add(a)
	d.Add(b)
	d.Add(a)

	got := d.Records()
	if len(got) != 2 {
		t.Fatalf("Records() has %d records, want 2: %+v", len(got), got)
	}
	if got[0].Text != "A" || got[0].Count != 2 {
		t.Errorf("records[0] = {%q, %d}, want {\"A\", 2}", got[0].Text, got[0].Count)
	}
	if got[1].Text != "B" || got[1].Count != 1 {
		t.Errorf("records[1] = {%q, %d}, want {\"B\", 1}", got[1].Text, got[1].Count)
	}
}

// TestConsoleDeduper_DistinguishesLocationAndKind: the same message thrown from
// two places, or reported over two DevTools channels, is two distinct problems.
func TestConsoleDeduper_DistinguishesLocationAndKind(t *testing.T) {
	t.Parallel()

	base := ConsoleError{Kind: KindException, Text: "Error: same text", Source: "https://example.test/a.js", Line: 1, Col: 1}

	t.Run("different line", func(t *testing.T) {
		t.Parallel()
		other := base
		other.Line = 2

		d := NewConsoleDeduper(20, noTruncate)
		d.Add(base)
		d.Add(other)

		if got := d.Records(); len(got) != 2 {
			t.Errorf("Records() has %d records, want 2: %+v", len(got), got)
		}
	})

	t.Run("different kind", func(t *testing.T) {
		t.Parallel()
		other := base
		other.Kind = KindConsoleAPI

		d := NewConsoleDeduper(20, noTruncate)
		d.Add(base)
		d.Add(other)

		if got := d.Records(); len(got) != 2 {
			t.Errorf("Records() has %d records, want 2: %+v", len(got), got)
		}
	})

	t.Run("different column", func(t *testing.T) {
		t.Parallel()
		other := base
		other.Col = 9

		d := NewConsoleDeduper(20, noTruncate)
		d.Add(base)
		d.Add(other)

		if got := d.Records(); len(got) != 2 {
			t.Errorf("Records() has %d records, want 2: %+v", len(got), got)
		}
	})
}

// TestConsoleDeduper_CollapsesCacheBustedSources: the same bundle served with a
// rotating ?v= is one script, so its errors are one record.
func TestConsoleDeduper_CollapsesCacheBustedSources(t *testing.T) {
	t.Parallel()

	d := NewConsoleDeduper(20, noTruncate)
	d.Add(ConsoleError{Kind: KindException, Text: "Error: boom", Source: "https://example.test/app.js?v=1", Line: 3})
	d.Add(ConsoleError{Kind: KindException, Text: "Error: boom", Source: "https://example.test/app.js?v=2", Line: 3})

	got := d.Records()
	if len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("Records() = %+v, want one record with Count 2", got)
	}
}

// TestConsoleDeduper_CountIsCarriedOver: a caller that already collapsed some
// occurrences hands them over as Count, and a zero Count still means one event.
func TestConsoleDeduper_CountIsCarriedOver(t *testing.T) {
	t.Parallel()

	d := NewConsoleDeduper(20, noTruncate)
	d.Add(ConsoleError{Kind: KindException, Text: "Error: boom"})           // Count 0 -> 1
	d.Add(ConsoleError{Kind: KindException, Text: "Error: boom", Count: 4}) // -> 5

	got := d.Records()
	if len(got) != 1 || got[0].Count != 5 {
		t.Fatalf("Records() = %+v, want one record with Count 5", got)
	}
}

// TestConsoleDeduper_CapAndSuppressed: a hostile page must not be able to grow
// the record set without bound, and the overflow has to be visible.
func TestConsoleDeduper_CapAndSuppressed(t *testing.T) {
	t.Parallel()

	d := NewConsoleDeduper(3, noTruncate)
	for i := range 10 {
		d.Add(ConsoleError{Kind: KindException, Text: "Error: distinct " + strconv.Itoa(i)})
	}

	if got := d.Records(); len(got) != 3 {
		t.Errorf("Records() has %d records, want 3", len(got))
	}
	if d.Suppressed() != 7 {
		t.Errorf("Suppressed() = %d, want 7", d.Suppressed())
	}
	if !d.Truncated() {
		t.Error("Truncated() = false, want true")
	}
}

// TestConsoleDeduper_UnlimitedWhenMaxNonPositive: max <= 0 disables the cap, so
// nothing is silently dropped when a caller opts out.
func TestConsoleDeduper_UnlimitedWhenMaxNonPositive(t *testing.T) {
	t.Parallel()

	d := NewConsoleDeduper(0, noTruncate)
	for i := range 50 {
		d.Add(ConsoleError{Kind: KindException, Text: "Error: distinct " + strconv.Itoa(i)})
	}

	if got := d.Records(); len(got) != 50 {
		t.Errorf("Records() has %d records, want 50", len(got))
	}
	if d.Suppressed() != 0 || d.Truncated() {
		t.Errorf("Suppressed() = %d, Truncated() = %v, want 0 and false", d.Suppressed(), d.Truncated())
	}
}

// TestConsoleDeduper_TruncatesOnAdd: the byte cap is applied before the
// fingerprint, so two messages that differ only past the cap collapse.
func TestConsoleDeduper_TruncatesOnAdd(t *testing.T) {
	t.Parallel()

	d := NewConsoleDeduper(20, 16)
	d.Add(ConsoleError{Kind: KindException, Text: strings.Repeat("a", 40) + "-one"})
	d.Add(ConsoleError{Kind: KindException, Text: strings.Repeat("a", 40) + "-two"})

	got := d.Records()
	if len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("Records() = %+v, want one record with Count 2", got)
	}
	if len(got[0].Text) > 16 {
		t.Errorf("stored text is %d bytes, want <= 16", len(got[0].Text))
	}
}

func TestResourceDeduper_CollapsesCacheBustedURLs(t *testing.T) {
	t.Parallel()

	d := NewResourceDeduper(20)
	d.Add(ResourceError{URL: "https://example.test/a.js?v=1", Type: "Script", Status: 404})
	d.Add(ResourceError{URL: "https://example.test/a.js?v=2", Type: "Script", Status: 404})

	got := d.Records()
	if len(got) != 1 {
		t.Fatalf("Records() has %d records, want 1: %+v", len(got), got)
	}
	if got[0].Count != 2 {
		t.Errorf("Count = %d, want 2", got[0].Count)
	}
}

// TestResourceDeduper_DistinguishesFailureMode: the same URL failing with a 404
// and failing with a transport error are different problems.
func TestResourceDeduper_DistinguishesFailureMode(t *testing.T) {
	t.Parallel()

	d := NewResourceDeduper(20)
	d.Add(ResourceError{URL: "https://example.test/a.js", Type: "Script", Status: 404})
	d.Add(ResourceError{URL: "https://example.test/a.js", Type: "Script", NetError: "net::ERR_CONNECTION_REFUSED"})
	d.Add(ResourceError{URL: "https://example.test/a.js", Type: "XHR", Status: 404})

	if got := d.Records(); len(got) != 3 {
		t.Errorf("Records() has %d records, want 3: %+v", len(got), got)
	}
}

func TestResourceDeduper_CapAndSuppressed(t *testing.T) {
	t.Parallel()

	d := NewResourceDeduper(2)
	for i := range 6 {
		d.Add(ResourceError{URL: "https://example.test/a" + strconv.Itoa(i) + ".js", Type: "Script", Status: 404, Count: 2})
	}

	if got := d.Records(); len(got) != 2 {
		t.Errorf("Records() has %d records, want 2", len(got))
	}
	if d.Suppressed() != 8 { // 4 dropped records x Count 2
		t.Errorf("Suppressed() = %d, want 8", d.Suppressed())
	}
	if !d.Truncated() {
		t.Error("Truncated() = false, want true")
	}
}

func TestResourceDeduper_UnlimitedWhenMaxNonPositive(t *testing.T) {
	t.Parallel()

	d := NewResourceDeduper(0)
	for i := range 30 {
		d.Add(ResourceError{URL: "https://example.test/a" + strconv.Itoa(i) + ".js", Type: "Script", Status: 404})
	}

	if got := d.Records(); len(got) != 30 {
		t.Errorf("Records() has %d records, want 30", len(got))
	}
	if d.Suppressed() != 0 {
		t.Errorf("Suppressed() = %d, want 0", d.Suppressed())
	}
}

func TestNormalizeText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "drops the Uncaught prefix V8 adds",
			in:   "Uncaught TypeError: x is not a function",
			want: "TypeError: x is not a function",
		},
		{
			name: "drops the promise-rejection prefix",
			in:   "Uncaught (in promise) Error: nope",
			want: "Error: nope",
		},
		{
			// The stack lives in ConsoleError.Frame; keeping it here would make
			// every occurrence look distinct.
			name: "keeps only the first line",
			in:   "Uncaught Error: boom\n    at f (https://example.test/a.js:1:1)\n    at g",
			want: "Error: boom",
		},
		{
			name: "collapses runs of whitespace",
			in:   "Error:   too\t\tmany   spaces",
			want: "Error: too many spaces",
		},
		{
			// Short numbers are part of the message; long runs are request ids
			// and timestamps that would fragment the fingerprint.
			name: "blanks digit runs of four or more",
			in:   "failed after 3 tries at 1717171717 for order 12345",
			want: "failed after 3 tries at N for order N",
		},
		{
			name: "blanks lowercase uuids",
			in:   "request a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6 failed",
			want: "request UUID failed",
		},
		{
			name: "blanks uppercase uuids",
			in:   "request A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6 failed",
			want: "request UUID failed",
		},
		{
			name: "leaves a plain message alone",
			in:   "Error: boom",
			want: "Error: boom",
		},
		{
			name: "empty stays empty",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeText(tt.in); got != tt.want {
				t.Errorf("NormalizeText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStripQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"query is dropped", "https://example.test/a.js?v=1", "https://example.test/a.js"},
		{"fragment is dropped", "https://example.test/a.js#L20", "https://example.test/a.js"},
		{"whichever comes first wins", "https://example.test/a.js#f?x=1", "https://example.test/a.js"},
		{"neither present is unchanged", "https://example.test/a.js", "https://example.test/a.js"},
		{"not a url at all is unchanged", "some free text", "some free text"},
		{"empty stays empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := StripQuery(tt.in); got != tt.want {
				t.Errorf("StripQuery(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestTruncateRunes_RuneBoundary is the one that matters: a byte cap landing in
// the middle of a multibyte rune must not emit invalid UTF-8 into the JSONL.
func TestTruncateRunes_RuneBoundary(t *testing.T) {
	t.Parallel()

	// 8 two-byte runes then a four-byte emoji: 20 bytes, so most caps land
	// mid-rune.
	s := strings.Repeat("é", 8) + "🙂"
	if len(s) != 20 {
		t.Fatalf("fixture is %d bytes, want 20", len(s))
	}

	for maxBytes := 1; maxBytes <= len(s)+2; maxBytes++ {
		got := TruncateRunes(s, maxBytes)
		if !utf8.ValidString(got) {
			t.Errorf("TruncateRunes(s, %d) = %q, which is not valid UTF-8", maxBytes, got)
		}
		if len(got) > maxBytes {
			t.Errorf("TruncateRunes(s, %d) is %d bytes, want <= %d", maxBytes, len(got), maxBytes)
		}
	}
}

func TestTruncateRunes_Passthrough(t *testing.T) {
	t.Parallel()

	s := "Error: boom"

	t.Run("non-positive cap disables truncation", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("x", 10_000)
		if got := TruncateRunes(long, 0); got != long {
			t.Errorf("TruncateRunes(long, 0) truncated to %d bytes", len(got))
		}
		if got := TruncateRunes(long, -1); got != long {
			t.Errorf("TruncateRunes(long, -1) truncated to %d bytes", len(got))
		}
	})

	t.Run("string under the cap is returned unchanged", func(t *testing.T) {
		t.Parallel()
		if got := TruncateRunes(s, 100); got != s {
			t.Errorf("TruncateRunes(%q, 100) = %q, want it unchanged", s, got)
		}
	})

	t.Run("string exactly at the cap is returned unchanged", func(t *testing.T) {
		t.Parallel()
		if got := TruncateRunes(s, len(s)); got != s {
			t.Errorf("TruncateRunes(%q, %d) = %q, want it unchanged", s, len(s), got)
		}
	})

	t.Run("clipped strings are marked", func(t *testing.T) {
		t.Parallel()
		got := TruncateRunes(s, len(s)-1)
		if !strings.HasSuffix(got, "…") {
			t.Errorf("TruncateRunes(%q, %d) = %q, want an ellipsis marking the clip", s, len(s)-1, got)
		}
		if len(got) > len(s)-1 {
			t.Errorf("TruncateRunes(%q, %d) is %d bytes, want <= %d", s, len(s)-1, len(got), len(s)-1)
		}
	})
}

func TestConsoleKind_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind ConsoleKind
		want string
	}{
		{KindException, "exception"},
		{KindConsoleAPI, "console.error"},
		{KindBrowserLog, "browser.log"},
		{ConsoleKind(200), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("ConsoleKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
			}
			b, err := tt.kind.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(b) != tt.want {
				t.Errorf("MarshalText() = %q, want %q", b, tt.want)
			}
		})
	}
}
