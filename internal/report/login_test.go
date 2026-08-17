package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/verdict"
)

// Header.Login is the only provenance a reader will ever have for "these
// results were gathered as somebody". These tests pin two things about it: it
// appears when a login happened, and it is completely absent when one did not.
//
// The second matters as much as the first. Every existing golden was recorded
// before -login existed, and they all still pass — which is only true because
// an unauthenticated run's header is byte-identical to what it was.

// loginNote is what internal/login's Spec.Describe produces. It never contains
// a password, and this package takes it as given.
const loginNote = "editor at https://example.com/login (form user-login-form)"

// newLoginReporter builds a reporter whose header carries a login line.
func newLoginReporter(t *testing.T, dir, format string) *Reporter {
	t.Helper()
	h := testHeader()
	h.Login = loginNote

	r, err := New(Options{
		Dir:    dir,
		Format: format,
		Policy: verdict.DefaultPolicy(),
		Now:    stepClock(baseTime, baseTime.Add(41300*time.Millisecond)),
		Header: h,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close in cleanup: %v", err)
		}
	})
	return r
}

func TestGolden_OpenedTextWithLogin(t *testing.T) {
	t.Parallel()

	dir := outDir(t)
	r := newLoginReporter(t, dir, FormatText)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	checkGolden(t, "opened_text_login", scrubGot(readFile(t, dir, FileOpened), dir))
}

func TestLoginHeaderAbsentByDefault(t *testing.T) {
	t.Parallel()

	dir := outDir(t)
	r := newReporter(t, dir, FormatText, false)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := readFile(t, dir, FileOpened)
	if strings.Contains(got, "# login") {
		t.Errorf("a header with no Login rendered a login line:\n%s", got)
	}
}

func TestLoginHeaderInJSON(t *testing.T) {
	t.Parallel()

	dir := outDir(t)
	r := newLoginReporter(t, dir, FormatJSON)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	first, _, _ := strings.Cut(readFile(t, dir, FileOpened), "\n")

	var rec map[string]any
	if err := json.Unmarshal([]byte(first), &rec); err != nil {
		t.Fatalf("header line is not JSON: %v\n%s", err, first)
	}
	if got := rec["login"]; got != loginNote {
		t.Errorf("login = %v, want %q", got, loginNote)
	}
}

func TestLoginFieldOmittedFromJSONWhenUnset(t *testing.T) {
	t.Parallel()

	dir := outDir(t)
	r := newReporter(t, dir, FormatJSON, false)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	first, _, _ := strings.Cut(readFile(t, dir, FileOpened), "\n")

	var rec map[string]any
	if err := json.Unmarshal([]byte(first), &rec); err != nil {
		t.Fatalf("header line is not JSON: %v\n%s", err, first)
	}
	// omitempty, so an existing consumer of results.jsonl sees no new key until
	// authentication is actually in play.
	if _, present := rec["login"]; present {
		t.Errorf("login key is present on an unauthenticated run: %s", first)
	}
}

// TestLoginHeaderReachesErrorLogs checks the provenance is not only on
// opened.log. A reader who opens errors-http.log alone still has to be able to
// tell whether these 403s were seen signed in or signed out.
//
// FileResults is deliberately not in the list: results.jsonl carries no header
// at all, by design — it is an append-only ledger so that a kill -9 mid-run
// still leaves every line jq-able.
func TestLoginHeaderReachesErrorLogs(t *testing.T) {
	t.Parallel()

	dir := outDir(t)
	r := newLoginReporter(t, dir, FormatJSON)
	emitFixtures(t, r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, name := range []string{FileHTTP, FileConsole, FileSubresource, FileLoad} {
		if !exists(t, dir, name) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			first, _, _ := strings.Cut(readFile(t, dir, name), "\n")
			if !strings.Contains(first, loginNote) {
				t.Errorf("%s header has no login provenance: %s", name, first)
			}
		})
	}
}
