package app_test

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/app"
)

// inputFile is the positional argument almost every case needs. ParseFlags
// never opens it — validation is about the flags, not about the filesystem —
// so a name is enough.
const inputFile = "urls.txt"

// parse runs ParseFlags against a buffer instead of a real stream, which is the
// entire reason the writer is a parameter: -help and every flag-package
// diagnostic are assertable without a pipe and without os.Exit.
func parse(t *testing.T, args ...string) (app.Config, *bytes.Buffer, error) {
	t.Helper()
	var out bytes.Buffer
	cfg, err := app.ParseFlags(args, &out)
	return cfg, &out, err
}

func TestParseFlags_Defaults(t *testing.T) {
	t.Parallel()

	cfg, out, err := parse(t, inputFile)
	if err != nil {
		t.Fatalf("ParseFlags(%q): %v", inputFile, err)
	}
	// A successful parse is silent. Anything on the writer means a diagnostic
	// leaked into a run that had nothing to complain about.
	if out.Len() != 0 {
		t.Errorf("ParseFlags wrote %q on the success path, want nothing", out.String())
	}

	if cfg.Input != inputFile {
		t.Errorf("Input = %q, want %q", cfg.Input, inputFile)
	}
	if cfg.Out != "logs" {
		t.Errorf("Out = %q, want %q", cfg.Out, "logs")
	}
	if cfg.Format != "text" {
		t.Errorf("Format = %q, want %q", cfg.Format, "text")
	}
	if cfg.Concurrency != 4 {
		t.Errorf("Concurrency = %d, want 4", cfg.Concurrency)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %s, want 30s", cfg.Timeout)
	}
	if cfg.Settle != 1500*time.Millisecond {
		t.Errorf("Settle = %s, want 1.5s", cfg.Settle)
	}
	if cfg.MaxConsole != 20 {
		t.Errorf("MaxConsole = %d, want 20", cfg.MaxConsole)
	}
	if cfg.OKStatusMin != 200 || cfg.OKStatusMax != 399 {
		t.Errorf("OK band = %d-%d, want 200-399", cfg.OKStatusMin, cfg.OKStatusMax)
	}
	// These two default to TRUE, which is the whole point of the tool: console
	// errors and dead subresources are failures unless the user says otherwise.
	if !cfg.FailOnConsole {
		t.Error("FailOnConsole = false, want true")
	}
	if !cfg.FailOnResource {
		t.Error("FailOnResource = false, want true")
	}

	// The remaining booleans default off; a flipped default here would silently
	// change what a bare `pagevet urls.txt` does.
	for _, tc := range []struct {
		name string
		got  bool
	}{
		{"Combined", cfg.Combined},
		{"Quiet", cfg.Quiet},
		{"ConsoleWarnings", cfg.ConsoleWarnings},
		{"Headed", cfg.Headed},
		{"SiteIsolation", cfg.SiteIsolation},
		{"DebugChrome", cfg.DebugChrome},
		{"LogFullURLs", cfg.LogFullURLs},
		{"AllowLinkLocal", cfg.AllowLinkLocal},
		// Off by default matters more here than elsewhere: a .env left in the
		// working directory must never silently authenticate a run.
		{"Login", cfg.Login},
		{"FailOnErrors", cfg.FailOnErrors},
		{"ShowVersion", cfg.ShowVersion},
	} {
		if tc.got {
			t.Errorf("%s = true, want false by default", tc.name)
		}
	}
	if cfg.ChromePath != "" {
		t.Errorf("ChromePath = %q, want empty (autodetect)", cfg.ChromePath)
	}
	if cfg.UserAgent != "" {
		t.Errorf("UserAgent = %q, want empty", cfg.UserAgent)
	}
}

func TestParseFlags_InputSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantInput string // empty means the case must be rejected
	}{
		{
			name:      "positional, which is what people actually type",
			args:      []string{inputFile},
			wantInput: inputFile,
		},
		{
			name:      "-input flag",
			args:      []string{"-input", inputFile},
			wantInput: inputFile,
		},
		{
			name:      "-input combined with other flags",
			args:      []string{"-quiet", "-input", inputFile},
			wantInput: inputFile,
		},
		{
			// Silently preferring one of the two would hide a typo in the other.
			name: "both -input and a positional file",
			args: []string{"-input", inputFile, "other.txt"},
		},
		{
			// The signature of an unquoted shell glob.
			name: "two positional files",
			args: []string{"a.txt", "b.txt"},
		},
		{
			name: "no input at all",
			args: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, _, err := parse(t, tc.args...)

			if tc.wantInput == "" {
				requireUsageError(t, err)
				return
			}
			if err != nil {
				t.Fatalf("ParseFlags(%q): %v", tc.args, err)
			}
			if cfg.Input != tc.wantInput {
				t.Errorf("Input = %q, want %q", cfg.Input, tc.wantInput)
			}
		})
	}
}

// TestParseFlags_Rejects covers every rule in Config.validate that can fire on
// this platform. Each case asserts errors.Is(err, ErrUsage) rather than merely
// "err != nil": Main routes on that sentinel, so an error that is not a usage
// error would exit 3 (tool broken) instead of 2 (you typed it wrong).
func TestParseFlags_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"concurrency 0", []string{"-concurrency", "0", inputFile}},
		{"concurrency -1", []string{"-concurrency", "-1", inputFile}},
		{"concurrency 17", []string{"-concurrency", "17", inputFile}},
		{"timeout 0s", []string{"-timeout", "0s", inputFile}},
		{"timeout negative", []string{"-timeout", "-5s", inputFile}},
		{"settle negative", []string{"-settle", "-1s", inputFile}},
		// A settle window at or beyond the deadline leaves no time to load
		// anything, so every single URL would report a timeout.
		{"settle equal to timeout", []string{"-timeout", "10s", "-settle", "10s", inputFile}},
		{"settle greater than timeout", []string{"-timeout", "10s", "-settle", "11s", inputFile}},
		{"max-console 0", []string{"-max-console", "0", inputFile}},
		{"max-console 1001", []string{"-max-console", "1001", inputFile}},
		{"format xml", []string{"-format", "xml", inputFile}},
		{"empty out", []string{"-out", "", inputFile}},
		{"ok-status without a dash", []string{"-ok-status", "200", inputFile}},
		{"ok-status lower bound not a number", []string{"-ok-status", "abc-200", inputFile}},
		{"ok-status upper bound not a number", []string{"-ok-status", "200-abc", inputFile}},
		{"ok-status below 100", []string{"-ok-status", "99-200", inputFile}},
		{"ok-status above 599", []string{"-ok-status", "200-600", inputFile}},
		{"ok-status min greater than max", []string{"-ok-status", "400-200", inputFile}},
		{"relative -chrome path", []string{"-chrome", "chrome", inputFile}},
		{"relative -chrome path with dots", []string{"-chrome", "./bin/chrome", inputFile}},
		{"-chrome path with a NUL byte", []string{"-chrome", "/usr/bin/chr\x00me", inputFile}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := parse(t, tc.args...)
			requireUsageError(t, err)
		})
	}
}

// TestParseFlags_Accepts pins the boundaries of the same rules from the inside:
// a range check that rejects its own endpoints is just as broken as one that
// accepts everything.
func TestParseFlags_Accepts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, cfg app.Config)
	}{
		{
			name: "concurrency 1",
			args: []string{"-concurrency", "1", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.Concurrency != 1 {
					t.Errorf("Concurrency = %d, want 1", cfg.Concurrency)
				}
			},
		},
		{
			name: "concurrency 16",
			args: []string{"-concurrency", "16", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.Concurrency != 16 {
					t.Errorf("Concurrency = %d, want 16", cfg.Concurrency)
				}
			},
		},
		{
			name: "max-console 1",
			args: []string{"-max-console", "1", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.MaxConsole != 1 {
					t.Errorf("MaxConsole = %d, want 1", cfg.MaxConsole)
				}
			},
		},
		{
			name: "max-console 1000",
			args: []string{"-max-console", "1000", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.MaxConsole != 1000 {
					t.Errorf("MaxConsole = %d, want 1000", cfg.MaxConsole)
				}
			},
		},
		{
			name: "settle zero disables the quiet window",
			args: []string{"-settle", "0s", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.Settle != 0 {
					t.Errorf("Settle = %s, want 0s", cfg.Settle)
				}
			},
		},
		{
			name: "timeout above settle",
			args: []string{"-timeout", "5s", "-settle", "1s", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.Timeout != 5*time.Second || cfg.Settle != time.Second {
					t.Errorf("timeout/settle = %s/%s, want 5s/1s", cfg.Timeout, cfg.Settle)
				}
			},
		},
		{
			name: "format text",
			args: []string{"-format", "text", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.Format != "text" {
					t.Errorf("Format = %q, want text", cfg.Format)
				}
			},
		},
		{
			name: "format json",
			args: []string{"-format", "json", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.Format != "json" {
					t.Errorf("Format = %q, want json", cfg.Format)
				}
			},
		},
		{
			name: "absolute -chrome path",
			args: []string{"-chrome", "/opt/chrome/chrome", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.ChromePath != "/opt/chrome/chrome" {
					t.Errorf("ChromePath = %q, want /opt/chrome/chrome", cfg.ChromePath)
				}
			},
		},
		{
			name: "boolean flags flipped on",
			args: []string{"-quiet", "-combined-error-log", "-console-warnings", "-fail-on-errors", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if !cfg.Quiet || !cfg.Combined || !cfg.ConsoleWarnings || !cfg.FailOnErrors {
					t.Errorf("one of -quiet/-combined-error-log/-console-warnings/-fail-on-errors did not stick: %+v", cfg)
				}
			},
		},
		{
			name: "the fail-on switches can be turned off",
			args: []string{"-fail-on-console=false", "-fail-on-resource=false", inputFile},
			check: func(t *testing.T, cfg app.Config) {
				if cfg.FailOnConsole || cfg.FailOnResource {
					t.Errorf("FailOnConsole=%v FailOnResource=%v, want both false", cfg.FailOnConsole, cfg.FailOnResource)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, _, err := parse(t, tc.args...)
			if err != nil {
				t.Fatalf("ParseFlags(%q): %v", tc.args, err)
			}
			tc.check(t, cfg)
		})
	}
}

func TestParseFlags_OKStatusBand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		value            string
		wantMin, wantMax int
	}{
		{name: "the default band", value: "200-399", wantMin: 200, wantMax: 399},
		{name: "a single-status band", value: "200-200", wantMin: 200, wantMax: 200},
		{name: "the widest legal band", value: "100-599", wantMin: 100, wantMax: 599},
		// Someone will type this with spaces around the dash; rejecting it would
		// be pedantry, not validation.
		{name: "spaces around the bounds", value: " 200 - 299 ", wantMin: 200, wantMax: 299},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, _, err := parse(t, "-ok-status", tc.value, inputFile)
			if err != nil {
				t.Fatalf("ParseFlags(-ok-status %q): %v", tc.value, err)
			}
			if cfg.OKStatusMin != tc.wantMin || cfg.OKStatusMax != tc.wantMax {
				t.Errorf("-ok-status %q gave %d-%d, want %d-%d",
					tc.value, cfg.OKStatusMin, cfg.OKStatusMax, tc.wantMin, tc.wantMax)
			}
		})
	}
}

// TestParseFlags_Help asserts the two properties -help has to satisfy: the text
// reaches the INJECTED writer, and os.Stdout is never touched. The second one is
// why the writer is a parameter at all — a library that prints to os.Stdout
// cannot be tested and cannot be embedded.
func TestParseFlags_Help(t *testing.T) {
	// Deliberately not parallel: it swaps os.Stdout for the duration.
	var out bytes.Buffer
	var (
		cfg app.Config
		err error
	)

	captured := captureStdout(t, func() {
		cfg, err = app.ParseFlags([]string{"-help"}, &out)
	})

	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("ParseFlags(-help) error = %v, want flag.ErrHelp", err)
	}
	if cfg.ShowVersion {
		t.Error("ShowVersion = true after -help, want false")
	}
	if captured != "" {
		t.Errorf("ParseFlags wrote %q to os.Stdout; it must only write to the injected writer", captured)
	}

	got := out.String()
	for _, want := range []string{
		"usage: pagevet",
		"Exit codes:",
		"-ok-status",
		"-fail-on-errors",
		// -login is useless without knowing which keys .env must carry, and
		// -help is the only place that list is printed.
		"-login",
		"LOGIN_PATH",
		"LOGIN_FORM_ID",
		"USERNAME_NAME",
		"PASSWORD_NAME",
		"USER_ADMIN_NAME",
		"USER_ADMIN_PASS",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("usage text is missing %q; got:\n%s", want, got)
		}
	}
}

// TestExitCodesAreDistinct pins the contract CI scripts branch on. Two codes
// sharing a value would make "the login is broken" and "Chrome is broken"
// indistinguishable, which is the whole reason they are separate.
func TestExitCodesAreDistinct(t *testing.T) {
	t.Parallel()

	codes := map[string]int{
		"ExitOK":          app.ExitOK,
		"ExitPageErrors":  app.ExitPageErrors,
		"ExitUsage":       app.ExitUsage,
		"ExitInternal":    app.ExitInternal,
		"ExitInterrupted": app.ExitInterrupted,
		"ExitLoginFailed": app.ExitLoginFailed,
	}

	seen := make(map[int]string, len(codes))
	for name, code := range codes {
		if other, dup := seen[code]; dup {
			t.Errorf("%s and %s are both %d", name, other, code)
		}
		seen[code] = name
	}
	if app.ExitLoginFailed != 5 {
		t.Errorf("ExitLoginFailed = %d, want 5 (it is documented in -help and the README)", app.ExitLoginFailed)
	}
}

func TestParseFlags_HelpShortForm(t *testing.T) {
	t.Parallel()

	_, out, err := parse(t, "-h")
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("ParseFlags(-h) error = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(out.String(), "usage: pagevet") {
		t.Errorf("-h did not write the usage text; got:\n%s", out.String())
	}
}

func TestParseFlags_UnknownFlag(t *testing.T) {
	t.Parallel()

	_, out, err := parse(t, "-not-a-flag", inputFile)
	if err == nil {
		t.Fatal("ParseFlags(-not-a-flag) succeeded, want an error")
	}
	// The flag package owns this diagnostic, so it is neither ErrUsage nor
	// ErrHelp; Main's default branch is what turns it into exit 2.
	if errors.Is(err, flag.ErrHelp) {
		t.Errorf("error = %v, want a parse error rather than ErrHelp", err)
	}
	if !strings.Contains(out.String(), "not-a-flag") {
		t.Errorf("the diagnostic did not name the offending flag; got:\n%s", out.String())
	}
}

// TestParseFlags_Version pins the short circuit: -version is answered before
// validation, so `pagevet -version` works without an input file.
func TestParseFlags_Version(t *testing.T) {
	t.Parallel()

	cfg, out, err := parse(t, "-version")
	if err != nil {
		t.Fatalf("ParseFlags(-version): %v", err)
	}
	if !cfg.ShowVersion {
		t.Error("ShowVersion = false, want true")
	}
	if cfg.Input != "" {
		t.Errorf("Input = %q, want empty: -version must not require one", cfg.Input)
	}
	if out.Len() != 0 {
		t.Errorf("ParseFlags(-version) wrote %q, want nothing", out.String())
	}
}

// TestParseFlags_VersionSkipsValidation states the same short circuit from the
// other side: a combination that validate would reject is still accepted,
// because nothing is going to run.
func TestParseFlags_VersionSkipsValidation(t *testing.T) {
	t.Parallel()

	cfg, _, err := parse(t, "-version", "-concurrency", "999")
	if err != nil {
		t.Fatalf("ParseFlags(-version -concurrency 999): %v", err)
	}
	if !cfg.ShowVersion {
		t.Error("ShowVersion = false, want true")
	}
}

// requireUsageError asserts the error is the actionable, exit-2 kind.
func requireUsageError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("ParseFlags succeeded, want a usage error")
	}
	if !errors.Is(err, app.ErrUsage) {
		t.Fatalf("error %v does not wrap ErrUsage; Main would exit 3 instead of 2", err)
	}
}

// captureStdout replaces os.Stdout for the duration of fn and returns whatever
// was written to it. The only thing it is used to prove is that nothing was.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()

	fn()

	// Close the writer before reading, or io.Copy waits for an EOF that the
	// still-open descriptor will never produce.
	if err := w.Close(); err != nil {
		t.Fatalf("closing the capture pipe: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("closing the capture pipe reader: %v", err)
	}
	return buf.String()
}
