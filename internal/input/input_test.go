package input

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMain installs the stub resolver once, before any test runs, and nothing
// mutates it afterwards — which is what keeps the parallel tests race-free
// while still exercising the DNS branch of the address guard.
func TestMain(m *testing.M) {
	resolveHost = stubResolve
	m.Run()
}

// read is the common case: DefaultOptions, no source error expected.
func read(t *testing.T, body string) Parsed {
	t.Helper()
	p, err := ReadURLs(t.Context(), strings.NewReader(body), DefaultOptions())
	if err != nil {
		t.Fatalf("ReadURLs() error = %v, want nil", err)
	}
	return p
}

func TestDefaultOptions(t *testing.T) {
	t.Parallel()

	opt := DefaultOptions()
	if !opt.SkipDuplicates {
		t.Error("DefaultOptions().SkipDuplicates = false, want true")
	}
	if opt.AllowLinkLocal {
		t.Error("DefaultOptions().AllowLinkLocal = true, want false")
	}
}

func TestReadURLsAccepts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{"plain https", "https://public.test/", "https://public.test/"},
		{"empty path is normalized", "http://public.test", "http://public.test/"},
		{"query with empty path", "https://public.test?q=1", "https://public.test/?q=1"},
		{"scheme and host are lowercased", "HTTPS://Public.TEST/Path", "https://public.test/Path"},
		{"fragment is dropped", "https://public.test/a#section", "https://public.test/a"},
		{"query survives, fragment does not", "https://public.test/a?q=1#f", "https://public.test/a?q=1"},
		{"surrounding space is trimmed", "  \thttps://public.test/spaced \t", "https://public.test/spaced"},
		{"port survives", "https://public.test:8443/x", "https://public.test:8443/x"},
		{"ipv6 literal survives", "http://[::1]:8080/", "http://[::1]:8080/"},
		{"loopback literal is allowed", "http://127.0.0.1:3000/", "http://127.0.0.1:3000/"},
		{"rfc1918 literal is allowed", "http://192.168.1.10/admin", "http://192.168.1.10/admin"},
		// Credentials are kept: basic-auth staging URLs are a real use case,
		// and redaction happens at log time, not here.
		{"userinfo survives", "https://u:p@public.test/", "https://u:p@public.test/"},
		// Chrome's URL parser unescapes a host before applying IDNA, so the
		// percent-encoded form net/url produces reaches the right site.
		{"non-ascii host is percent-encoded", "https://münchen.test/", "https://m%C3%BCnchen.test/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := read(t, tc.line+"\n")
			if len(p.Bad) != 0 {
				t.Fatalf("ReadURLs(%q) rejected it: %v", tc.line, p.Bad[0].Err)
			}
			if len(p.Entries) != 1 {
				t.Fatalf("ReadURLs(%q) returned %d entries, want 1", tc.line, len(p.Entries))
			}
			if got := p.Entries[0].URL; got != tc.want {
				t.Errorf("ReadURLs(%q) = %q, want %q", tc.line, got, tc.want)
			}
			if p.Entries[0].Index != 1 || p.Entries[0].Line != 1 {
				t.Errorf("entry = %+v, want Index 1 and Line 1", p.Entries[0])
			}
		})
	}
}

func TestReadURLsRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want error
	}{
		// The allowlist rejections. Every one of these is a scheme Chrome
		// would happily navigate if we passed it through.
		{"javascript", "javascript:alert(1)", ErrUnsupportedScheme},
		{"file", "file:///etc/passwd", ErrUnsupportedScheme},
		{"data", "data:text/html,<h1>x</h1>", ErrUnsupportedScheme},
		{"chrome", "chrome://settings", ErrUnsupportedScheme},
		{"view-source", "view-source:http://public.test/", ErrUnsupportedScheme},
		{"blob", "blob:http://public.test/0-0-0", ErrUnsupportedScheme},
		{"about", "about:blank", ErrUnsupportedScheme},
		{"ftp", "ftp://public.test/pub", ErrUnsupportedScheme},
		{"mailto", "mailto:someone@public.test", ErrUnsupportedScheme},
		// "example.com:8080/x" parses as scheme "example.com" with an opaque
		// body, because a scheme may contain dots. It is still not http.
		{"host and port without scheme", "example.com:8080/x", ErrUnsupportedScheme},

		{"absolute path", "/foo", ErrNotAbsolute},
		{"bare hostname", "example.com", ErrNotAbsolute},
		{"protocol-relative", "//example.com/x", ErrNotAbsolute},

		{"empty authority", "http:///path", ErrEmptyHost},
		{"port with no host", "http://:8080/", ErrEmptyHost},
		{"opaque http", "http:relative", ErrEmptyHost},

		{"invalid utf-8", "http://ex\xffample.test/", ErrInvalidUTF8},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := read(t, tc.line+"\n")
			if len(p.Entries) != 0 {
				t.Fatalf("ReadURLs(%q) accepted it as %q", tc.line, p.Entries[0].URL)
			}
			if len(p.Bad) != 1 {
				t.Fatalf("ReadURLs(%q) returned %d bad lines, want 1", tc.line, len(p.Bad))
			}
			bad := p.Bad[0]
			if !errors.Is(bad.Err, tc.want) {
				t.Errorf("ReadURLs(%q) error = %v, want %v", tc.line, bad.Err, tc.want)
			}
			if bad.Line != 1 || bad.Raw != tc.line {
				t.Errorf("bad line = %+v, want Line 1 and the raw text", bad)
			}
		})
	}
}

func TestReadURLsRejectsControlCharacters(t *testing.T) {
	t.Parallel()

	// net/url refuses ASCII control characters; the wrapped error must still
	// name the line, since that is all the user has to go on.
	p := read(t, "http://public.test/a\x00b\n")
	if len(p.Bad) != 1 {
		t.Fatalf("got %d bad lines, want 1", len(p.Bad))
	}
	if !strings.Contains(p.Bad[0].Err.Error(), "invalid control character") {
		t.Errorf("error = %v, want it to mention the control character", p.Bad[0].Err)
	}
}

func TestReadURLsSkips(t *testing.T) {
	t.Parallel()

	const body = "" +
		"# a comment\n" +
		"\n" +
		"   \t\n" +
		"   # an indented comment\n" +
		"https://public.test/a\n" +
		"https://public.test/a\n" + // exact duplicate
		"HTTPS://Public.test/a#top\n" + // duplicate only after normalization
		"https://public.test/b\n"

	p := read(t, body)
	if p.Total != 8 {
		t.Errorf("Total = %d, want 8", p.Total)
	}
	if p.Skipped != 6 {
		t.Errorf("Skipped = %d, want 6 (4 blank/comment + 2 duplicates)", p.Skipped)
	}
	if len(p.Bad) != 0 {
		t.Errorf("Bad = %v, want none", p.Bad)
	}
	want := []Entry{
		{Index: 1, Line: 5, URL: "https://public.test/a"},
		{Index: 2, Line: 8, URL: "https://public.test/b"},
	}
	if len(p.Entries) != len(want) {
		t.Fatalf("Entries = %+v, want %+v", p.Entries, want)
	}
	for i, e := range p.Entries {
		if e != want[i] {
			t.Errorf("Entries[%d] = %+v, want %+v", i, e, want[i])
		}
	}
}

func TestReadURLsKeepsDuplicates(t *testing.T) {
	t.Parallel()

	opt := DefaultOptions()
	opt.SkipDuplicates = false

	p, err := ReadURLs(t.Context(), strings.NewReader("https://public.test/a\nhttps://public.test/a\n"), opt)
	if err != nil {
		t.Fatalf("ReadURLs() error = %v", err)
	}
	if len(p.Entries) != 2 || p.Skipped != 0 {
		t.Fatalf("Entries = %d, Skipped = %d, want 2 and 0", len(p.Entries), p.Skipped)
	}
	if p.Entries[1].Index != 2 || p.Entries[1].Line != 2 {
		t.Errorf("second entry = %+v, want Index 2 and Line 2", p.Entries[1])
	}
}

func TestReadURLsCRLF(t *testing.T) {
	t.Parallel()

	// A list authored on Windows must behave exactly like a Unix one; a
	// surviving \r would make every host end in an unprintable character.
	p := read(t, "# comment\r\nhttps://public.test/a\r\n\r\nhttps://public.test/b\r\n")
	if len(p.Bad) != 0 {
		t.Fatalf("Bad = %v, want none", p.Bad)
	}
	if len(p.Entries) != 2 {
		t.Fatalf("Entries = %+v, want 2", p.Entries)
	}
	if p.Entries[0].URL != "https://public.test/a" {
		t.Errorf("URL = %q, want no trailing carriage return", p.Entries[0].URL)
	}
}

func TestReadURLsBOM(t *testing.T) {
	t.Parallel()

	t.Run("utf-8 bom is stripped from line 1", func(t *testing.T) {
		t.Parallel()
		p := read(t, "\xef\xbb\xbfhttps://public.test/a\nhttps://public.test/b\n")
		if len(p.Bad) != 0 {
			t.Fatalf("Bad = %v, want none", p.Bad)
		}
		if p.Entries[0].URL != "https://public.test/a" {
			t.Errorf("URL = %q, want the BOM gone", p.Entries[0].URL)
		}
	})

	t.Run("a bom later in the file is content", func(t *testing.T) {
		t.Parallel()
		// Only line 1 can carry an encoding declaration; the same bytes on
		// line 2 are part of a URL and must fail validation like any garbage.
		p := read(t, "https://public.test/a\n\xef\xbb\xbfhttps://public.test/b\n")
		if len(p.Entries) != 1 {
			t.Fatalf("Entries = %+v, want only the first line", p.Entries)
		}
		if len(p.Bad) != 1 || p.Bad[0].Line != 2 {
			t.Fatalf("Bad = %+v, want one rejection on line 2", p.Bad)
		}
	})

	for name, body := range map[string]string{
		"utf-16le": "\xff\xfeh\x00t\x00t\x00p\x00",
		"utf-16be": "\xfe\xff\x00h\x00t\x00t\x00p",
	} {
		t.Run(name+" is rejected up front", func(t *testing.T) {
			t.Parallel()
			// Rejected as a file, not line by line: in a UTF-16 file every
			// single line looks like garbage, and a wall of per-line errors
			// sends the user hunting for a problem in their URLs.
			_, err := ReadURLs(t.Context(), strings.NewReader(body), DefaultOptions())
			if !errors.Is(err, ErrUTF16) {
				t.Fatalf("error = %v, want ErrUTF16", err)
			}
			if !strings.Contains(err.Error(), "iconv") {
				t.Errorf("error = %v, want it to say how to fix the file", err)
			}
		})
	}
}

func TestReadURLsBadLineDoesNotAbort(t *testing.T) {
	t.Parallel()

	// The whole point of Parsed.Bad: one typo must not cost the user the rest
	// of the list.
	p := read(t, "https://public.test/a\njavascript:alert(1)\nnot a url\nhttps://public.test/b\n")
	if p.Total != 4 {
		t.Errorf("Total = %d, want 4", p.Total)
	}
	if len(p.Bad) != 2 {
		t.Fatalf("Bad = %+v, want 2", p.Bad)
	}
	if p.Bad[0].Line != 2 || p.Bad[1].Line != 3 {
		t.Errorf("bad lines = %d and %d, want 2 and 3", p.Bad[0].Line, p.Bad[1].Line)
	}
	want := []Entry{
		{Index: 1, Line: 1, URL: "https://public.test/a"},
		{Index: 2, Line: 4, URL: "https://public.test/b"},
	}
	for i, e := range p.Entries {
		if e != want[i] {
			t.Errorf("Entries[%d] = %+v, want %+v", i, e, want[i])
		}
	}
}

func TestReadURLsBlocksGuardedHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		line           string
		allowLinkLocal bool
		blocked        bool
	}{
		{"metadata endpoint", "http://169.254.169.254/latest/meta-data/", false, true},
		{"metadata endpoint ignores opt-in", "http://169.254.169.254/latest/meta-data/", true, true},
		{"ipv4-mapped metadata endpoint", "http://[::ffff:169.254.169.254]/latest/", true, true},
		{"link-local", "http://169.254.10.1/", false, true},
		{"link-local with opt-in", "http://169.254.10.1/", true, false},
		{"resolved metadata name", "http://metadata.test/", false, true},
		{"ordinary host", "http://public.test/", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opt := DefaultOptions()
			opt.AllowLinkLocal = tc.allowLinkLocal
			p, err := ReadURLs(t.Context(), strings.NewReader(tc.line+"\n"), opt)
			if err != nil {
				t.Fatalf("ReadURLs() error = %v", err)
			}
			if tc.blocked {
				if len(p.Bad) != 1 || !errors.Is(p.Bad[0].Err, ErrBlockedAddress) {
					t.Fatalf("Bad = %+v, Entries = %+v, want one blocked address", p.Bad, p.Entries)
				}
				return
			}
			if len(p.Entries) != 1 {
				t.Fatalf("Entries = %+v, Bad = %+v, want the URL accepted", p.Entries, p.Bad)
			}
		})
	}
}

func TestReadURLsChecksEachHostOnce(t *testing.T) {
	t.Parallel()

	// A list is usually one site with many paths. Re-resolving it per line
	// would delay the first page by thousands of pointless queries without
	// making the answer any more trustworthy.
	body := "https://cached.test/a\nhttps://cached.test/b\nhttps://cached.test/c\n"
	p := read(t, body)
	if len(p.Entries) != 3 {
		t.Fatalf("Entries = %+v, want 3", p.Entries)
	}
	if n := dnsCallCount("cached.test"); n != 1 {
		t.Errorf("resolved cached.test %d times, want 1", n)
	}
}

func TestReadURLsLineTooLong(t *testing.T) {
	t.Parallel()

	// Scanner.Err is the one error in this file that cannot be ignored: an
	// oversized line ends the scan exactly like a clean EOF, so without the
	// check every URL after it would vanish from the run silently.
	body := "https://public.test/a\nhttps://public.test/b\nhttps://public.test/" +
		strings.Repeat("x", maxLineBytes) + "\nhttps://public.test/c\n"

	p, err := ReadURLs(t.Context(), strings.NewReader(body), DefaultOptions())
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("error = %v, want ErrLineTooLong", err)
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error = %v, want it to name line 3", err)
	}
	// The partial result is still returned so the caller can say how far it got.
	if len(p.Entries) != 2 {
		t.Errorf("Entries = %+v, want the two lines read before the overrun", p.Entries)
	}
}

func TestReadURLsLongLineUnderLimit(t *testing.T) {
	t.Parallel()

	// Just under the ceiling must be read, not rejected: the initial buffer is
	// 64 KiB and has to grow.
	long := "https://public.test/" + strings.Repeat("x", 200*1024)
	p := read(t, long+"\n")
	if len(p.Entries) != 1 {
		t.Fatalf("Entries = %+v, Bad = %+v, want the long line accepted", p.Entries, p.Bad)
	}
}

// failingReader yields one chunk and then fails, standing in for a truncated
// pipe or a disk error mid-file.
type failingReader struct {
	data string
	err  error
	sent bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, r.err
	}
	r.sent = true
	return copy(p, r.data), nil
}

func TestReadURLsReaderError(t *testing.T) {
	t.Parallel()

	boom := errors.New("disk went away")
	p, err := ReadURLs(t.Context(), &failingReader{data: "https://public.test/a\n", err: boom}, DefaultOptions())
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap %v", err, boom)
	}
	if !strings.Contains(err.Error(), "after line 1") {
		t.Errorf("error = %v, want it to say where reading stopped", err)
	}
	if len(p.Entries) != 1 {
		t.Errorf("Entries = %+v, want the line read before the failure", p.Entries)
	}
}

// cancelingReader dribbles the list out in small chunks and cancels the read's
// context once the first one has been consumed, standing in for a Ctrl-C partway
// through a long list rather than before it starts.
type cancelingReader struct {
	r      io.Reader
	cancel context.CancelFunc
	chunk  int
	reads  int
}

func (c *cancelingReader) Read(p []byte) (int, error) {
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	n, err := c.r.Read(p)
	c.reads++
	if c.reads > 1 {
		c.cancel()
	}
	return n, err
}

func TestReadURLsCanceledBeforeStart(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	p, err := ReadURLs(ctx, strings.NewReader("https://public.test/a\n"), DefaultOptions())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if p.Total != 0 || len(p.Entries) != 0 {
		t.Errorf("Parsed = %+v, want nothing read", p)
	}
}

func TestReadURLsCanceledMidRead(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())

	// Several sampling intervals' worth of lines, so the abort can only come
	// from the loop's own check and has to land well short of EOF.
	const lines = 4 * cancelCheckLines
	var body strings.Builder
	for i := range lines {
		body.WriteString("https://public.test/" + strconv.Itoa(i) + "\n")
	}

	src := &cancelingReader{r: strings.NewReader(body.String()), cancel: cancel, chunk: 4096}
	p, err := ReadURLs(ctx, src, DefaultOptions())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if p.Total == 0 || p.Total >= lines {
		t.Errorf("Total = %d, want the read stopped somewhere between 1 and %d", p.Total, lines)
	}
	// The partial result is still the caller's to report, exactly as for an
	// oversized line or a dead disk.
	if len(p.Entries) != p.Total {
		t.Errorf("Entries = %d for Total = %d, want every line read to be accepted", len(p.Entries), p.Total)
	}
}

func TestReadURLsEmpty(t *testing.T) {
	t.Parallel()

	p := read(t, "")
	if p.Total != 0 || len(p.Entries) != 0 || len(p.Bad) != 0 || p.Skipped != 0 {
		t.Errorf("Parsed = %+v, want the zero value", p)
	}
}

func TestReadURLsClipsRejectedLine(t *testing.T) {
	t.Parallel()

	// BadLine.Raw is echoed into the error report, and the scanner accepts
	// lines up to a megabyte.
	p := read(t, "not-a-url-"+strings.Repeat("ü", 4096)+"\n")
	if len(p.Bad) != 1 {
		t.Fatalf("Bad = %+v, want 1", p.Bad)
	}
	if got := len(p.Bad[0].Raw); got > maxRawBytes+len("…") {
		t.Errorf("len(Raw) = %d, want it clipped to about %d bytes", got, maxRawBytes)
	}
	if !strings.HasSuffix(p.Bad[0].Raw, "…") {
		t.Errorf("Raw = %q, want the clip marked", p.Bad[0].Raw)
	}
}

func TestClip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{"short strings pass through", "abc", 8, "abc"},
		{"exact fit passes through", "abcd", 4, "abcd"},
		{"ascii is cut at the limit", "abcdef", 4, "abcd…"},
		// The cut lands mid-rune and must walk back rather than emit a broken
		// UTF-8 sequence into the log.
		{"multi-byte runes are not split", "üüü", 3, "ü…"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clip(tc.in, tc.limit); got != tc.want {
				t.Errorf("clip(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
			}
		})
	}
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	p, err := ReadFile(t.Context(), filepath.Join("testdata", "list.txt"), DefaultOptions())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if p.Total != 10 {
		t.Errorf("Total = %d, want 10", p.Total)
	}
	if p.Skipped != 5 {
		t.Errorf("Skipped = %d, want 5", p.Skipped)
	}
	want := []Entry{
		{Index: 1, Line: 2, URL: "https://example.test/"},
		{Index: 2, Line: 4, URL: "http://example.test/a?x=1"},
		{Index: 3, Line: 8, URL: "https://example.test/b"},
	}
	if len(p.Entries) != len(want) {
		t.Fatalf("Entries = %+v, want %+v", p.Entries, want)
	}
	for i, e := range p.Entries {
		if e != want[i] {
			t.Errorf("Entries[%d] = %+v, want %+v", i, e, want[i])
		}
	}
	if len(p.Bad) != 2 {
		t.Fatalf("Bad = %+v, want 2", p.Bad)
	}
	if !errors.Is(p.Bad[0].Err, ErrUnsupportedScheme) || !errors.Is(p.Bad[1].Err, ErrNotAbsolute) {
		t.Errorf("Bad = %+v, want an unsupported scheme then a relative URL", p.Bad)
	}
}

func TestReadFileBOMFixture(t *testing.T) {
	t.Parallel()

	p, err := ReadFile(t.Context(), filepath.Join("testdata", "bom-utf8.txt"), DefaultOptions())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(p.Entries) != 2 || p.Entries[0].URL != "https://bom.test/one" {
		t.Errorf("Entries = %+v, want the BOM stripped from line 1", p.Entries)
	}
}

func TestReadFileUTF16Fixture(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"utf16le.txt", "utf16be.txt"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ReadFile(t.Context(), filepath.Join("testdata", name), DefaultOptions())
			if !errors.Is(err, ErrUTF16) {
				t.Fatalf("ReadFile(%s) error = %v, want ErrUTF16", name, err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error = %v, want it to name the file", err)
			}
		})
	}
}

func TestReadFileRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(path, []byte("https://public.test/a\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	p, err := ReadFile(t.Context(), path, DefaultOptions())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(p.Entries) != 1 {
		t.Fatalf("Entries = %+v, want 1", p.Entries)
	}
}

func TestReadFileMissing(t *testing.T) {
	t.Parallel()

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := ReadFile(t.Context(), filepath.Join(t.TempDir(), "nope.txt"), DefaultOptions())
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("error = %v, want it to wrap fs.ErrNotExist", err)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		t.Parallel()
		// The os.Root is opened on the parent, so a bad directory fails before
		// the file is ever named.
		_, err := ReadFile(t.Context(), filepath.Join(t.TempDir(), "nope", "urls.txt"), DefaultOptions())
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("error = %v, want it to wrap fs.ErrNotExist", err)
		}
		if !strings.Contains(err.Error(), "directory") {
			t.Errorf("error = %v, want it to point at the directory", err)
		}
	})
}

func TestReadFileCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// ReadFile wraps the ReadURLs error with the file name; the sentinel has to
	// survive that so the caller can still tell a cancellation from a bad list.
	_, err := ReadFile(ctx, filepath.Join("testdata", "list.txt"), DefaultOptions())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if !strings.Contains(err.Error(), "list.txt") {
		t.Errorf("error = %v, want it to name the file", err)
	}
}

func TestReadFileDirectory(t *testing.T) {
	t.Parallel()

	// Reading a directory fails at the first Read, which exercises the
	// Scanner.Err path through ReadFile rather than through a fake reader.
	_, err := ReadFile(t.Context(), t.TempDir(), DefaultOptions())
	if err == nil {
		t.Fatal("ReadFile(dir) = nil, want an error")
	}
}

func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"", " ", "#", "# comment", "\xef\xbb\xbfhttps://a.test/",
		"https://public.test/a", "HTTP://A.TEST", "http://a.test/#f",
		"javascript:alert(1)", "data:text/html,x", "about:blank", "file:///etc/passwd",
		"//a.test/x", "/x", "a.test", "http:///x", "http://:80/", "http://[::1]:8080/",
		"http://\xff\xfe/", "https://ü.test/", "http://a.test/\x7f", "http:a",
		"https://u:p@a.test/?token=abc#frag", strings.Repeat("a", 4096),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		pl, err := parseLine(line)
		if err != nil || pl.Skip {
			return // any rejection is fine; the property is about what is ACCEPTED
		}

		// Whatever the input, an accepted line must be an absolute http(s) URL
		// with a host and no fragment — that is the guarantee every later layer
		// is built on.
		u, perr := url.Parse(pl.URL)
		if perr != nil {
			t.Fatalf("accepted %q as %q, which does not parse: %v", line, pl.URL, perr)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("accepted %q with scheme %q", line, u.Scheme)
		}
		if u.Host == "" || u.Hostname() == "" {
			t.Fatalf("accepted %q with no host", line)
		}
		if u.Fragment != "" || strings.Contains(pl.URL, "#") {
			t.Fatalf("accepted %q as %q, which still carries a fragment", line, pl.URL)
		}
		if pl.Host == "" {
			t.Fatalf("accepted %q with an empty guard host", line)
		}
	})
}
