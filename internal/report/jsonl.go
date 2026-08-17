package report

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/olegiv/pagevet/internal/verdict"
)

// jsonlRecord is one line of results.jsonl: the frozen verdict.Result schema,
// widened with the classification.
//
// Result is embedded rather than nested, so its fields stay at the top level of
// the object and `jq '.status'` keeps working — the JSON field names in
// verdict.Result are frozen API, and nesting them under a key would break every
// consumer for the sake of a tidier Go struct.
type jsonlRecord struct {
	verdict.Result
	Outcome verdict.Outcome   `json:"outcome"`
	Flags   []verdict.Outcome `json:"flags"`
}

// openedRecord is the JSON-format equivalent of one opened.log row. It is
// deliberately narrow: opened.log answers "what did we touch, and how did it
// go", and the full record is one file away in results.jsonl.
type openedRecord struct {
	TS            string          `json:"ts"`
	Index         int             `json:"i"`
	Outcome       verdict.Outcome `json:"outcome"`
	Status        int             `json:"status"`
	DurationMS    int64           `json:"duration_ms"`
	URL           string          `json:"url"`
	Console       int             `json:"console,omitempty"`
	ConsoleEvents int             `json:"console_events,omitempty"`
	Resources     int             `json:"resources,omitempty"`
	NetError      string          `json:"net_error,omitempty"`
}

// errorRecord is one JSON-format error-log entry. Type comes first because in
// combined mode it is the field a consumer filters on.
type errorRecord struct {
	Type verdict.Category `json:"type"`
	verdict.Result
	Outcome verdict.Outcome    `json:"outcome"`
	Flags   []verdict.Outcome  `json:"flags"`
	Also    []verdict.Category `json:"also,omitempty"`
}

// headerRecord is the first line of a JSON-format log file, carrying the same
// provenance the text header puts in its "#" comments. A JSON log cannot use
// comments, and dropping the provenance entirely would make the two formats
// carry different information.
type headerRecord struct {
	Type        string `json:"type"`
	Log         string `json:"log"`
	Tool        string `json:"tool"`
	Version     string `json:"version"`
	StartedAt   string `json:"started_at"`
	Input       string `json:"input,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
	Timeout     string `json:"timeout,omitempty"`
	Settle      string `json:"settle,omitempty"`
	Chrome      string `json:"chrome,omitempty"`

	// Login is omitted entirely on a run without -login, so an existing
	// consumer of these files sees no new field until authentication is
	// actually in play. It never carries a password.
	Login string `json:"login,omitempty"`
}

// encodeJSON renders v as a single line, without the trailing newline the
// caller controls.
//
// HTML escaping is off: by default encoding/json rewrites the characters
// ampersand, less-than and greater-than as numeric escapes, which mangles every
// URL carrying a query string into something no human can read in a log file.
// Nothing written here is ever interpolated into an HTML document, so the
// escaping buys nothing and costs legibility.
func encodeJSON(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("report: encode json record: %w", err)
	}
	return string(bytes.TrimRight(b.Bytes(), "\n")), nil
}

// writeResult appends one object to results.jsonl.
//
// The ledger is UNBUFFERED and written with exactly one Write call per record,
// under r.mu. That costs a syscall per URL, and buys two things worth more than
// the syscall: `tail -f logs/results.jsonl` shows records as they happen, and a
// run killed with SIGKILL mid-crawl still leaves a file where every line is a
// complete JSON object. A bufio.Writer would truncate the last record mid-token
// and make the whole file unparseable by jq for the sake of a few microseconds.
//
// A single Write of a single complete line also means the kernel never
// interleaves two records, which matters because Emit is called from the worker
// goroutines. Caller holds r.mu.
func (r *Reporter) writeResult(res verdict.Result, o verdict.Outcome) error {
	rec := jsonlRecord{
		Result:  res,
		Outcome: o,
		Flags:   verdict.Flags(res, r.opts.Policy),
	}
	r.buf.Reset()
	if err := r.enc.Encode(rec); err != nil {
		return fmt.Errorf("report: encode %s record for %s: %w", FileResults, res.URL, err)
	}
	if _, err := r.results.Write(r.buf.Bytes()); err != nil {
		return fmt.Errorf("report: write %s for %s: %w", FileResults, res.URL, err)
	}
	return nil
}

// openedJSON renders one opened.log row in JSON format.
func openedJSON(res verdict.Result, o verdict.Outcome) (string, error) {
	rec := openedRecord{
		TS:         stamp(completedAt(res)),
		Index:      res.Index,
		Outcome:    o,
		Status:     res.Status,
		DurationMS: res.DurationMS,
		URL:        res.URL,
		Console:    len(res.Console),
		Resources:  len(res.Resources),
		NetError:   res.NetError,
	}
	if rec.Console > 0 {
		rec.ConsoleEvents = res.ConsoleEvents()
	}
	return encodeJSON(rec)
}

// errorJSON renders one error-log entry in JSON format. The whole Result is
// carried, because a machine consumer of errors-console.log should not have to
// join against results.jsonl to see the status that came with the exception.
func (r *Reporter) errorJSON(c verdict.Category, cats []verdict.Category, flags []verdict.Outcome, res verdict.Result) (string, error) {
	rec := errorRecord{
		Type:    c,
		Result:  res,
		Outcome: outcomeFor(c, flags),
		Flags:   flags,
	}
	for _, other := range cats {
		if other != c {
			rec.Also = append(rec.Also, other)
		}
	}
	return encodeJSON(rec)
}

// headerJSON renders the provenance line of a JSON-format log file.
func (r *Reporter) headerJSON(name string) (string, error) {
	h := r.opts.Header
	rec := headerRecord{
		Type:        "header",
		Log:         name,
		Tool:        "pagevet",
		Version:     h.Version,
		StartedAt:   stamp(r.start),
		Input:       h.Input,
		Concurrency: h.Concurrency,
		Chrome:      h.Chrome,
		Login:       h.Login,
	}
	if h.Timeout > 0 {
		rec.Timeout = h.Timeout.String()
	}
	if h.Settle > 0 {
		rec.Settle = h.Settle.String()
	}
	return encodeJSON(rec)
}
