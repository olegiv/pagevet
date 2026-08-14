// Package input reads the URL list and decides what is safe to hand to the
// browser.
//
// It is the program's primary security control: the scheme allowlist in
// parseLine is what stops a list from talking Chrome into a javascript:,
// file:// or data: navigation, and every later layer trusts that whatever
// reaches it already passed through ReadURLs.
//
// The list is treated as untrusted input throughout. No single line can abort
// the read, no line can grow without bound, and nothing here touches the
// browser — the whole package is testable against a strings.Reader.
package input

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// The sentinel errors a caller can match with errors.Is. They are wrapped with
// the offending value for humans, so always compare with errors.Is rather than
// with ==.
var (
	// ErrNotAbsolute: the line has no scheme — "/foo", "example.com",
	// "//example.com/x". A relative URL has no defined base here.
	ErrNotAbsolute = errors.New("not an absolute URL")

	// ErrUnsupportedScheme: the scheme is not http or https. This is the
	// allowlist rejection.
	ErrUnsupportedScheme = errors.New("unsupported URL scheme")

	// ErrEmptyHost: absolute and http(s), but with nothing to connect to —
	// "http:///path", "http://:8080/".
	ErrEmptyHost = errors.New("empty host")

	// ErrInvalidUTF8: the line contains bytes that are not valid UTF-8.
	ErrInvalidUTF8 = errors.New("line is not valid UTF-8")

	// ErrLineTooLong: a single line exceeded maxLineBytes. Run-fatal, because
	// the scanner cannot resynchronize and the rest of the file would be lost.
	ErrLineTooLong = errors.New("line too long")

	// ErrUTF16: the file starts with a UTF-16 byte-order mark. Run-fatal.
	ErrUTF16 = errors.New("file is UTF-16 encoded")
)

const (
	// initialBufSize is the scanner's starting buffer; maxLineBytes is the
	// ceiling it may grow to. bufio.Scanner's own default ceiling is 64 KiB and
	// exceeding it ends the scan, so the ceiling is raised here and — far more
	// importantly — Scanner.Err is checked so the overrun is reported instead
	// of silently truncating the file.
	initialBufSize = 64 * 1024
	maxLineBytes   = 1 << 20

	// maxRawBytes caps the copy of a rejected line kept in BadLine.Raw. Raw is
	// printed verbatim in the error report, and a malformed list can hold lines
	// just under maxLineBytes.
	maxRawBytes = 512

	// cancelCheckLines is how often the scan loop samples ctx.Err(). Sampled
	// rather than tested per line because ctx.Err takes a lock on every call,
	// and 256 lines of parsing pass far too quickly for anyone to notice the
	// delay in their Ctrl-C.
	cancelCheckLines = 256
)

// The byte-order marks recognized on line 1.
const (
	bomUTF8    = "\xef\xbb\xbf"
	bomUTF16LE = "\xff\xfe"
	bomUTF16BE = "\xfe\xff"
)

// Entry is one accepted URL, carrying the input line it came from so
// diagnostics can point at it.
type Entry struct {
	Index int    // 1-based ordinal among ACCEPTED urls
	Line  int    // 1-based line number in the source file
	URL   string // normalized absolute URL
}

// BadLine is one rejected line.
type BadLine struct {
	Line int
	Raw  string
	Err  error
}

// Parsed is the result of reading a URL list.
type Parsed struct {
	Entries []Entry
	Bad     []BadLine
	Skipped int // blank, comment, or duplicate lines
	Total   int // lines read
}

// Options tunes ReadURLs. The zero value skips nothing and allows nothing
// extra; use DefaultOptions.
type Options struct {
	// SkipDuplicates drops a URL that already appeared, after normalization,
	// counting it under Parsed.Skipped. Loading the same page twice produces
	// two identical records and doubles its weight in the summary, which is
	// almost never what a list with a copy-paste repeat was meant to say.
	SkipDuplicates bool

	// AllowLinkLocal permits link-local addresses (169.254.0.0/16, fe80::/10),
	// for the rare case of crawling a host that only has one. It deliberately
	// does NOT re-enable the cloud metadata endpoints; see CheckHost.
	AllowLinkLocal bool
}

// DefaultOptions returns the shipped defaults: duplicates are skipped and
// link-local addresses are refused.
func DefaultOptions() Options {
	return Options{SkipDuplicates: true}
}

// ReadURLs reads a URL list from r, one URL per line, and returns what it
// accepted, what it rejected and what it skipped.
//
// The read is streaming and total: a line that fails validation lands in
// Parsed.Bad and scanning continues, because one typo on line 3 must not cost
// the user the other 9,000 URLs.
//
// A non-nil error means the SOURCE could not be read — an oversized line, an
// I/O failure, a UTF-16 file, a canceled ctx — which is not recoverable per
// line. The partial Parsed is still returned so the caller can report how far
// it got, but it must not be treated as the list.
//
// Accepted URLs are additionally passed through CheckHost, so an entry aimed at
// the instance metadata endpoint is rejected here rather than navigated. That
// costs at most one DNS lookup per distinct URL; see CheckHost for what the
// check does and does not promise.
//
// ctx bounds the whole read, not just each lookup: a 10,000-line list spends
// real time in DNS before the first page opens, and a Ctrl-C during that must
// not have to wait for the list to run out.
func ReadURLs(ctx context.Context, r io.Reader, opt Options) (Parsed, error) {
	var p Parsed

	var seen map[string]struct{}
	if opt.SkipDuplicates {
		seen = make(map[string]struct{}, 64)
	}

	// The address guard is memoized per HOST. A 10,000-line list of one site
	// would otherwise fire 10,000 identical DNS queries before the first page
	// even opens, and answer i would not be more trustworthy than answer 1 —
	// see CheckHost on why this check is advisory anyway.
	checked := make(map[string]error, 16)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, initialBufSize), maxLineBytes)

	// CRLF needs no handling of its own: bufio.ScanLines drops the trailing
	// \r, and parseLine trims whatever whitespace survives that.
	for sc.Scan() {
		// Sampled, so cancellation is reported by the loop itself rather than
		// only by whatever lookup happens to be in flight — a list of hosts
		// already in the memo map does no I/O at all and would otherwise run to
		// EOF after the user gave up on it.
		if p.Total%cancelCheckLines == 0 {
			if err := ctx.Err(); err != nil {
				return p, fmt.Errorf("reading URL list after line %d: %w", p.Total, err)
			}
		}

		line := sc.Text()
		p.Total++

		if p.Total == 1 {
			var err error
			if line, err = stripBOM(line); err != nil {
				return p, err
			}
		}

		pl, err := parseLine(line)
		if err != nil {
			p.Bad = append(p.Bad, BadLine{Line: p.Total, Raw: clip(line, maxRawBytes), Err: err})
			continue
		}
		if pl.Skip {
			p.Skipped++
			continue
		}

		// Deduplicate before the host check so a list that repeats a URL 500
		// times does not repeat its DNS lookup 500 times.
		if seen != nil {
			if _, dup := seen[pl.URL]; dup {
				p.Skipped++
				continue
			}
			seen[pl.URL] = struct{}{}
		}

		hostErr, known := checked[pl.Host]
		if !known {
			hostErr = CheckHost(ctx, pl.Host, opt.AllowLinkLocal)
			checked[pl.Host] = hostErr
		}
		if hostErr != nil {
			p.Bad = append(p.Bad, BadLine{Line: p.Total, Raw: clip(line, maxRawBytes), Err: hostErr})
			continue
		}

		p.Entries = append(p.Entries, Entry{Index: len(p.Entries) + 1, Line: p.Total, URL: pl.URL})
	}

	// This check is the reason the function can be trusted. Without it an
	// oversized line ends the scan exactly like a clean EOF, and every URL
	// after it disappears from the run with no error and no warning.
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			// The scanner choked on the line after the last one it handed us.
			return p, fmt.Errorf("line %d: %w (limit %d bytes)", p.Total+1, ErrLineTooLong, maxLineBytes)
		}
		return p, fmt.Errorf("reading URL list after line %d: %w", p.Total, err)
	}
	return p, nil
}

// ReadFile reads a URL list from path.
//
// The file is opened through an os.Root anchored at its own directory, which
// confines the open to that directory — a symlink inside it cannot redirect the
// read elsewhere. It also keeps gosec's G304 quiet structurally rather than by
// suppression: the rule matches package-level os.Open/OpenFile/ReadFile/Create,
// never (*os.Root) methods.
//
// A missing file yields an error wrapping fs.ErrNotExist.
//
// ctx is passed straight through to ReadURLs.
func ReadFile(ctx context.Context, path string, opt Options) (Parsed, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Parsed{}, fmt.Errorf("resolving URL list path %q: %w", path, err)
	}

	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return Parsed{}, fmt.Errorf("opening directory of URL list %q: %w", path, err)
	}
	// Both handles are read-only. A Close failure on a handle we only read from
	// cannot invalidate the bytes already parsed, and returning it would mask
	// the parse error the caller actually needs to see.
	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Base(abs))
	if err != nil {
		return Parsed{}, fmt.Errorf("opening URL list %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	p, err := ReadURLs(ctx, f, opt)
	if err != nil {
		return p, fmt.Errorf("reading URL list %q: %w", path, err)
	}
	return p, nil
}

// parsedLine is what parseLine extracts from one input line.
type parsedLine struct {
	URL  string // normalized, fragment-free, absolute http(s) URL
	Host string // hostname without port or brackets, for the address guard
	Skip bool   // blank or comment: nothing to crawl, and not an error either
}

// parseLine validates and normalizes exactly one line of the list.
//
// It is pure and does no I/O, which is what lets FuzzParseLine hammer it: the
// property under test is that no input string can produce an accepted URL whose
// scheme is outside the allowlist.
func parseLine(raw string) (parsedLine, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return parsedLine{Skip: true}, nil
	}

	// url.Parse happily carries arbitrary bytes through, so invalid UTF-8 would
	// travel all the way into the logs and into results.jsonl as mojibake. It
	// is rejected here, where the line number is still known.
	if !utf8.ValidString(s) {
		return parsedLine{}, ErrInvalidUTF8
	}

	u, err := url.Parse(s)
	if err != nil {
		return parsedLine{}, fmt.Errorf("invalid URL %q: %w", clip(s, maxRawBytes), err)
	}

	// url.Parse already lowercases the scheme; ToLower states the intent rather
	// than relying on that.
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return parsedLine{}, fmt.Errorf("%w: %q", ErrNotAbsolute, clip(s, maxRawBytes))
	}
	// A POSITIVE allowlist, never a denylist. A denylist has to enumerate
	// javascript:, data:, blob:, filesystem:, view-source:, chrome:, about:,
	// file:, ftp:, mailto: and whatever the next Chrome release adds; this
	// enumerates the two schemes the tool is for.
	if scheme != "http" && scheme != "https" {
		return parsedLine{}, fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
	}

	// u.Host is empty for "http:///path" and for opaque forms like "http:x";
	// u.Hostname() is additionally empty for "http://:8080/", which has a port
	// and nothing else.
	host := u.Hostname()
	if u.Host == "" || host == "" {
		return parsedLine{}, fmt.Errorf("%w: %q", ErrEmptyHost, clip(s, maxRawBytes))
	}

	// The fragment is never sent to the server, so keeping it would only split
	// one page into several "distinct" URLs in the dedupe map and the report.
	u.Fragment = ""
	u.RawFragment = ""

	// Host case is not significant, and an empty path addresses the same
	// resource as "/". Normalizing both means Example.com and example.com/ are
	// recognized as the duplicate they are.
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}

	// Userinfo is deliberately preserved: basic-auth staging URLs are a real
	// use case. Credentials are stripped at log time by verdict.RedactURL.
	return parsedLine{URL: u.String(), Host: strings.ToLower(host)}, nil
}

// stripBOM removes a UTF-8 byte-order mark and rejects the UTF-16 ones. It is
// applied to line 1 only: the same bytes further into the file are ordinary
// content, not an encoding declaration.
//
// UTF-16 is caught up front because a UTF-16 file scans as NUL-riddled garbage
// in which every single line fails validation — which sends the user hunting
// for a problem in their URLs rather than in their encoding.
func stripBOM(line string) (string, error) {
	switch {
	case strings.HasPrefix(line, bomUTF8):
		return strings.TrimPrefix(line, bomUTF8), nil
	case strings.HasPrefix(line, bomUTF16LE), strings.HasPrefix(line, bomUTF16BE):
		return "", fmt.Errorf("%w: convert it first, e.g. iconv -f UTF-16 -t UTF-8", ErrUTF16)
	}
	return line, nil
}

// clip shortens a string to at most limit bytes without splitting a rune,
// marking the cut. Rejected lines and their embedded values are echoed into the
// error report, and the scanner accepts lines up to a megabyte.
func clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + "…"
}
