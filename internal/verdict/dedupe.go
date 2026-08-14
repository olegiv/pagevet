package verdict

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// digitRunRe and uuidRe blank out the parts of a message that vary between
// otherwise-identical errors: cache-busting query ids, request ids, epoch
// timestamps. Without this a page that throws once per request fragments into
// hundreds of "distinct" errors and the caps below fire on noise.
var (
	digitRunRe = regexp.MustCompile(`\d{4,}`)
	uuidRe     = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

// Fingerprint is the dedupe key for one console error.
//
// It is deliberately lossy. A requestAnimationFrame loop throwing every frame
// must collapse to a single record with a Count, or one hostile page consumes
// all available memory over a long run.
func (c ConsoleError) Fingerprint() string {
	var b strings.Builder
	b.WriteString(c.Kind.String())
	b.WriteByte(0)
	b.WriteString(NormalizeText(c.Text))
	b.WriteByte(0)
	b.WriteString(StripQuery(c.Source))
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(c.Line, 10))
	b.WriteByte(':')
	b.WriteString(strconv.FormatInt(c.Col, 10))
	return b.String()
}

// Fingerprint is the dedupe key for one subresource failure. The URL keeps its
// path but loses its query, so 50 cache-busted requests for one dead asset
// collapse into a single record.
func (e ResourceError) Fingerprint() string {
	var b strings.Builder
	b.WriteString(StripQuery(e.URL))
	b.WriteByte(0)
	b.WriteString(e.Type)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(e.Status))
	b.WriteByte(0)
	b.WriteString(e.NetError)
	return b.String()
}

// NormalizeText reduces a console message to its stable identity: it drops the
// prefixes V8 adds, keeps only the first line (the stack lives in
// ConsoleError.Frame), collapses whitespace, and blanks long digit runs and
// UUIDs.
//
// UUIDs are replaced BEFORE digit runs. A UUID containing four consecutive
// digits would otherwise be chewed up by the digit rule first and never match
// the UUID pattern, so two requests differing only by request id would
// normalize to different text and fail to collapse.
func NormalizeText(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	s = strings.TrimPrefix(s, "Uncaught (in promise) ")
	s = strings.TrimPrefix(s, "Uncaught ")
	s = strings.Join(strings.Fields(s), " ")
	s = uuidRe.ReplaceAllString(s, "UUID")
	return digitRunRe.ReplaceAllString(s, "N")
}

// StripQuery removes the query string and fragment from a URL-ish string
// without parsing it. Console messages embed URLs in free text, so a parse
// failure here must not lose the value.
func StripQuery(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return s[:i]
	}
	return s
}

// TruncateRunes clips s to at most maxBytes bytes, never splitting a rune, and
// marks the clip so a reader knows the message was cut rather than ending
// there. A non-positive maxBytes disables truncation.
func TruncateRunes(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	const ellipsis = "…"
	// Reserve room for the marker; if the cap is too small to hold even that,
	// fall back to a bare byte-safe clip.
	limit := maxBytes - len(ellipsis)
	if limit <= 0 {
		limit = maxBytes
		for limit > 0 && !utf8.RuneStart(s[limit]) {
			limit--
		}
		return s[:limit]
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + ellipsis
}

// ConsoleDeduper accumulates console errors for one page, collapsing repeats
// and enforcing the per-page cap.
//
// It preserves first-seen order, which makes golden-file tests meaningful and
// puts the error that actually broke the page first, rather than whichever one
// happened to repeat most.
type ConsoleDeduper struct {
	max        int // distinct records retained; <= 0 means unlimited
	maxBytes   int // per-message byte cap
	index      map[string]int
	records    []ConsoleError
	suppressed int
}

// NewConsoleDeduper returns a deduper retaining at most maxRecords distinct
// records, each message truncated to maxBytes bytes.
func NewConsoleDeduper(maxRecords, maxBytes int) *ConsoleDeduper {
	return &ConsoleDeduper{max: maxRecords, maxBytes: maxBytes, index: make(map[string]int, 8)}
}

// Add records one occurrence. Count on the incoming record is ignored; each
// call counts as one occurrence unless c.Count is greater than 1.
func (d *ConsoleDeduper) Add(c ConsoleError) {
	c.Text = TruncateRunes(c.Text, d.maxBytes)
	if c.Count < 1 {
		c.Count = 1
	}
	key := c.Fingerprint()
	if i, ok := d.index[key]; ok {
		d.records[i].Count += c.Count
		return
	}
	if d.max > 0 && len(d.records) >= d.max {
		d.suppressed += c.Count
		return
	}
	d.index[key] = len(d.records)
	d.records = append(d.records, c)
}

// Records returns the deduplicated errors in first-seen order.
func (d *ConsoleDeduper) Records() []ConsoleError { return d.records }

// Suppressed returns the number of occurrences dropped because the per-page cap
// was reached.
func (d *ConsoleDeduper) Suppressed() int { return d.suppressed }

// Truncated reports whether the cap fired.
func (d *ConsoleDeduper) Truncated() bool { return d.suppressed > 0 }

// ResourceDeduper is the subresource-failure equivalent of ConsoleDeduper.
type ResourceDeduper struct {
	max        int
	index      map[string]int
	records    []ResourceError
	suppressed int
}

// NewResourceDeduper returns a deduper retaining at most maxRecords distinct
// records.
func NewResourceDeduper(maxRecords int) *ResourceDeduper {
	return &ResourceDeduper{max: maxRecords, index: make(map[string]int, 8)}
}

// Add records one subresource failure.
func (d *ResourceDeduper) Add(e ResourceError) {
	if e.Count < 1 {
		e.Count = 1
	}
	key := e.Fingerprint()
	if i, ok := d.index[key]; ok {
		d.records[i].Count += e.Count
		return
	}
	if d.max > 0 && len(d.records) >= d.max {
		d.suppressed += e.Count
		return
	}
	d.index[key] = len(d.records)
	d.records = append(d.records, e)
}

// Records returns the deduplicated failures in first-seen order.
func (d *ResourceDeduper) Records() []ResourceError { return d.records }

// Suppressed returns the number of occurrences dropped by the cap.
func (d *ResourceDeduper) Suppressed() int { return d.suppressed }

// Truncated reports whether the cap fired.
func (d *ResourceDeduper) Truncated() bool { return d.suppressed > 0 }
