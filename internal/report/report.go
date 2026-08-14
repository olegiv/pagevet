// Package report turns classified results into pagevet's required outputs:
// opened.log, the per-category error logs, and results.jsonl.
//
// It imports internal/verdict and the standard library only — never chromedp,
// cdproto or internal/loader. That is what lets every byte of every output
// shape below be golden-tested from hand-built verdict.Result literals, with a
// fixed injected clock and no browser anywhere.
package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/olegiv/pagevet/internal/verdict"
)

// The values accepted by Options.Format.
//
// The format governs the LOG FILES only. results.jsonl is always JSON, and the
// summary is always text, because it is written for a human reading a terminal.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// The file names this package writes.
//
// Every path opened here is one of these constants resolved inside an *os.Root,
// so no caller-supplied string ever reaches the filesystem as a path component:
// containment against symlinks and ".." is enforced by the kernel, not by
// string inspection. It also means gosec's G304 — which matches only the
// package-level os.Open/OpenFile/Create — has nothing to fire on, and this repo
// needs no #nosec comments.
const (
	FileOpened      = "opened.log"
	FileResults     = "results.jsonl"
	FileErrors      = "errors.log"
	FileHTTP        = "errors-http.log"
	FileConsole     = "errors-console.log"
	FileSubresource = "errors-subresource.log"
	FileLoad        = "errors-load.log"
)

// fileOrder is the order Files reports created paths in, and therefore the
// order they appear on the summary's "logs" line. It is fixed rather than
// creation-ordered because creation order depends on which worker finished
// first, which would make the summary non-reproducible under concurrency.
var fileOrder = [...]string{
	FileOpened,
	FileErrors,
	FileHTTP,
	FileConsole,
	FileSubresource,
	FileLoad,
	FileResults,
}

// Header is the provenance block stamped at the top of every log file. It
// answers "what produced this file, against what input, with what settings"
// six months later, when the terminal that ran it is long gone.
type Header struct {
	Version     string
	Input       string
	Concurrency int
	Timeout     time.Duration
	Settle      time.Duration

	// Chrome is the browser's self-reported version string, e.g.
	// "Google Chrome 151.0.7922.138 (headless, JavaScript enabled)". Empty
	// omits the line entirely rather than printing "chrome unknown".
	Chrome string
}

// Options configures a Reporter.
type Options struct {
	// Dir is the output directory. Empty means "logs".
	Dir string

	// Format selects the log-file encoding: FormatText or FormatJSON.
	Format string

	// Combined writes one errors.log carrying a type= field instead of the
	// four per-category files. Useful when the consumer is a log shipper
	// rather than a human with four terminal tabs.
	Combined bool

	// Policy must be the same policy the results were classified with;
	// Categories is re-evaluated here to decide which error files a result is
	// written to.
	Policy verdict.Policy

	// Now is the injected clock. Nil means time.Now. Tests pass a fixed clock
	// so the goldens assert the real layout — scrubbing timestamps with a
	// regex would happily accept a broken one.
	Now func() time.Time

	// Header is stamped at the top of every log file.
	Header Header

	// ExitCode optionally overrides the summary's last line. Nil renders the
	// default: a run that reached Summary at all completed, so the code is 0
	// and page errors are reported as data rather than as a tool failure.
	ExitCode func(verdict.Counts) (int, string)
}

// openFile pairs a file with its buffered writer. The error logs are buffered
// because they are written in multi-line blocks that would otherwise cost one
// syscall per line; results.jsonl deliberately is not — see writeResult.
type openFile struct {
	f *os.File
	w *bufio.Writer
}

// msgStat accumulates one normalized console message across the whole run, for
// the summary's "top console errors" block.
type msgStat struct {
	text string
	occ  int
	urls map[string]bool
	seq  int // first-seen ordinal, so equal-ranked messages sort stably
}

// Reporter writes the run's outputs. Emit is safe for concurrent use; the rest
// of the methods are called from the run's own goroutine.
type Reporter struct {
	opts  Options
	root  *os.Root
	dir   string
	start time.Time

	// mu guards every mutable field below AND the file descriptors, so a
	// multi-line error block can never be interleaved with another worker's.
	// One coarse mutex is correct here: Emit is I/O-bound against buffers, and
	// the run's real concurrency lives in the browser, not in this package.
	mu      sync.Mutex
	files   map[string]*openFile
	results *os.File
	console map[string]*msgStat
	seq     int
	closed  bool

	// buf and enc are reused across records to keep the per-URL allocation
	// count flat on long runs. They are only ever touched under mu.
	buf bytes.Buffer
	enc *json.Encoder
}

// New creates the output directory and opens results.jsonl.
//
// results.jsonl is opened eagerly, not lazily like the log files: it is the
// machine-readable ledger, and `tail -f logs/results.jsonl` has to work from
// the moment the run starts, including for a run that ends up producing no
// records at all.
func New(o Options) (*Reporter, error) {
	if o.Dir == "" {
		o.Dir = "logs"
	}
	if o.Format == "" {
		o.Format = FormatText
	}
	if o.Format != FormatText && o.Format != FormatJSON {
		return nil, fmt.Errorf("report: unknown format %q (want %q or %q)", o.Format, FormatText, FormatJSON)
	}
	if o.Now == nil {
		o.Now = time.Now
	}

	if err := ensureDir(o.Dir); err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("report: open output dir %q: %w", o.Dir, err)
	}

	results, err := root.OpenFile(FileResults, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("report: create %s in %q: %w", FileResults, o.Dir, err),
			root.Close(),
		)
	}

	r := &Reporter{
		opts:    o,
		root:    root,
		dir:     o.Dir,
		start:   o.Now(),
		files:   make(map[string]*openFile, len(fileOrder)),
		results: results,
		console: make(map[string]*msgStat, 16),
	}
	r.enc = json.NewEncoder(&r.buf)
	r.enc.SetEscapeHTML(false)
	return r, nil
}

// ensureDir creates the output directory 0700 when it does not exist, and
// leaves an existing directory's mode alone — the user may have deliberately
// widened it, and silently tightening a directory we did not create would be a
// surprising side effect of running a linter.
func ensureDir(dir string) error {
	switch fi, err := os.Stat(dir); {
	case err == nil:
		if !fi.IsDir() {
			return fmt.Errorf("report: output path %q exists and is not a directory", dir)
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("report: stat output dir %q: %w", dir, err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("report: create output dir %q: %w", dir, err)
	}
	// MkdirAll applies the process umask, so a umask of 002 would leave the
	// directory group-writable. The logs can contain URLs with query strings,
	// so the 0700 promise is restated explicitly.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("report: chmod output dir %q: %w", dir, err)
	}
	return nil
}

// Emit records one classified result: one line in opened.log, one object in
// results.jsonl, and one block in each error log the result belongs to.
//
// A result that flags as both http_error and console_error is written to BOTH
// error files, each block carrying an "also" line pointing at the other. That
// is deliberate duplication: someone triaging console errors must not have to
// know that a page was ALSO a 500 to find it.
func (r *Reporter) Emit(res verdict.Result, o verdict.Outcome) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("report: emit %s: %w", res.URL, os.ErrClosed)
	}

	// The ledger goes first: if the process is killed mid-Emit, a record in
	// results.jsonl with no matching log block is recoverable, whereas the
	// reverse leaves the machine-readable output silently short.
	if err := r.writeResult(res, o); err != nil {
		return err
	}
	if err := r.writeOpened(res, o); err != nil {
		return err
	}

	cats := verdict.Categories(res, r.opts.Policy)
	flags := verdict.Flags(res, r.opts.Policy)
	for _, c := range cats {
		if err := r.writeErrorBlock(c, cats, flags, res); err != nil {
			return err
		}
	}

	r.trackConsole(res)
	return nil
}

// writeOpened appends one line to opened.log. Caller holds r.mu.
func (r *Reporter) writeOpened(res verdict.Result, o verdict.Outcome) error {
	w, err := r.writer(FileOpened)
	if err != nil {
		return err
	}
	var line string
	if r.opts.Format == FormatJSON {
		line, err = openedJSON(res, o)
		if err != nil {
			return err
		}
	} else {
		line = openedLine(res, o)
	}
	if _, err := w.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("report: write %s for %s: %w", FileOpened, res.URL, err)
	}
	return nil
}

// writeErrorBlock appends one record to the log for category c. Caller holds
// r.mu.
func (r *Reporter) writeErrorBlock(c verdict.Category, cats []verdict.Category, flags []verdict.Outcome, res verdict.Result) error {
	name := r.errorFileName(c)
	w, err := r.writer(name)
	if err != nil {
		return err
	}
	var block string
	if r.opts.Format == FormatJSON {
		block, err = r.errorJSON(c, cats, flags, res)
		if err != nil {
			return err
		}
		block += "\n"
	} else {
		block = r.errorBlockText(c, cats, flags, res)
	}
	if _, err := w.WriteString(block); err != nil {
		return fmt.Errorf("report: write %s for %s: %w", name, res.URL, err)
	}
	return nil
}

// errorFileName maps a category to its log file, honoring -combined.
func (r *Reporter) errorFileName(c verdict.Category) string {
	if r.opts.Combined {
		return FileErrors
	}
	switch c {
	case verdict.CategoryHTTP:
		return FileHTTP
	case verdict.CategoryConsole:
		return FileConsole
	case verdict.CategorySubresource:
		return FileSubresource
	case verdict.CategoryLoad:
		return FileLoad
	case verdict.CategoryNone:
		return FileErrors
	}
	return FileErrors
}

// trackConsole accumulates the run-wide "top console errors" tally. Messages
// are keyed by verdict.NormalizeText so the same exception thrown on twenty
// pages — each with its own request ids baked into the text — collapses to one
// row. Caller holds r.mu.
func (r *Reporter) trackConsole(res verdict.Result) {
	for _, c := range res.Console {
		key := verdict.NormalizeText(c.Text)
		if key == "" {
			continue
		}
		st, ok := r.console[key]
		if !ok {
			r.seq++
			st = &msgStat{text: key, urls: make(map[string]bool, 4), seq: r.seq}
			r.console[key] = st
		}
		st.occ += c.Count
		st.urls[res.URL] = true
	}
}

// topConsole returns the n most frequent normalized console messages, most
// occurrences first. Ties break on distinct-URL count, then on first-seen
// order, so the block is byte-identical across runs of the same input.
func (r *Reporter) topConsole(n int) []msgStat {
	out := make([]msgStat, 0, len(r.console))
	for _, st := range r.console {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.occ != b.occ {
			return a.occ > b.occ
		}
		if len(a.urls) != len(b.urls) {
			return len(a.urls) > len(b.urls)
		}
		return a.seq < b.seq
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// writer returns the buffered writer for name, creating the file and stamping
// its header on first use.
//
// Creation is lazy so that a run with no console errors leaves no empty
// errors-console.log behind — an empty error log reads as "checked and clean"
// to some people and "the tool broke" to others, and the absence of the file
// is unambiguous. Caller holds r.mu.
func (r *Reporter) writer(name string) (*bufio.Writer, error) {
	if of, ok := r.files[name]; ok {
		return of.w, nil
	}

	f, err := r.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("report: create %s in %q: %w", name, r.dir, err)
	}
	w := bufio.NewWriter(f)
	r.files[name] = &openFile{f: f, w: w}

	if err := r.writeFileHeader(w, name); err != nil {
		return nil, err
	}
	return w, nil
}

// writeFileHeader stamps the provenance block. Caller holds r.mu.
func (r *Reporter) writeFileHeader(w *bufio.Writer, name string) error {
	var s string
	var err error
	if r.opts.Format == FormatJSON {
		s, err = r.headerJSON(name)
		if err != nil {
			return err
		}
		s += "\n"
	} else {
		s = r.headerText(name)
	}
	if _, err := w.WriteString(s); err != nil {
		return fmt.Errorf("report: write header of %s: %w", name, err)
	}
	return nil
}

// Files returns the paths actually created, in fileOrder.
func (r *Reporter) Files() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.filesLocked()
}

func (r *Reporter) filesLocked() []string {
	out := make([]string, 0, len(fileOrder))
	for _, name := range fileOrder {
		if name == FileResults {
			if r.results != nil {
				out = append(out, filepath.Join(r.dir, name))
			}
			continue
		}
		if _, ok := r.files[name]; ok {
			out = append(out, filepath.Join(r.dir, name))
		}
	}
	return out
}

// Close flushes and closes every open file. It is idempotent, and reports the
// first failure of each file rather than the last, because a failed Flush on
// the ledger means the run's output is incomplete and the exit code has to say
// so.
func (r *Reporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	var errs []error
	for _, name := range fileOrder {
		of, ok := r.files[name]
		if !ok {
			continue
		}
		if err := of.w.Flush(); err != nil {
			errs = append(errs, fmt.Errorf("report: flush %s: %w", name, err))
		}
		if err := of.f.Close(); err != nil {
			errs = append(errs, fmt.Errorf("report: close %s: %w", name, err))
		}
	}
	if r.results != nil {
		if err := r.results.Close(); err != nil {
			errs = append(errs, fmt.Errorf("report: close %s: %w", FileResults, err))
		}
	}
	if err := r.root.Close(); err != nil {
		errs = append(errs, fmt.Errorf("report: close output dir %q: %w", r.dir, err))
	}
	return errors.Join(errs...)
}

// Summary renders the human-facing run summary. It is always text and never
// colored: no ANSI escapes are emitted at all, which honors NO_COLOR by
// construction and needs no isatty probe.
func (r *Reporter) Summary(c verdict.Counts, w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s := r.summaryText(c, r.opts.Now().Sub(r.start))
	if _, err := io.WriteString(w, s); err != nil {
		return fmt.Errorf("report: write summary: %w", err)
	}
	return nil
}
