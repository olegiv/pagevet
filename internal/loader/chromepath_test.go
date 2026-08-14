package loader

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeExecutable creates a stand-in browser binary. It is written 0600 and then
// chmod'd, because the executable bit is the property under test.
func writeExecutable(t *testing.T, dir, name string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

// resolved is what ResolveChromePath is expected to return: on macOS every
// t.TempDir lives under /var, which is itself a symlink to /private/var.
func resolvedPath(t *testing.T, path string) string {
	t.Helper()

	got, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}
	return got
}

func TestResolveChromePath_ExplicitRejections(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	nonExecutable := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", nonExecutable, err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), dangling); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{name: "relative path", path: "bin/chrome"},
		{name: "bare command name", path: "google-chrome"},
		{name: "path containing a NUL byte", path: "/Applications/Chr\x00ome"},
		{name: "directory", path: dir},
		{name: "non-executable regular file", path: nonExecutable},
		{name: "dangling symlink", path: dangling},
		{name: "missing file", path: filepath.Join(dir, "absent")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ResolveChromePath(tt.path)
			if err == nil {
				t.Fatalf("ResolveChromePath(%q) = %q, want an error", tt.path, got)
			}
			if got != "" {
				t.Errorf("path = %q on the error path, want empty", got)
			}
			// The caller distinguishes run-fatal from per-URL failures purely by
			// this sentinel.
			if !errors.Is(err, ErrBrowserUnavailable) {
				t.Errorf("error %v does not wrap ErrBrowserUnavailable", err)
			}
		})
	}
}

func TestResolveChromePath_AcceptsAnExecutable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := writeExecutable(t, dir, "Google Chrome")

	got, err := ResolveChromePath(bin)
	if err != nil {
		t.Fatalf("ResolveChromePath(%q): %v", bin, err)
	}
	if want := resolvedPath(t, bin); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestResolveChromePath_ResolvesSymlinks pins the EvalSymlinks step: Homebrew and
// the various *-stable wrappers are all symlinks, and the resolved target is
// what actually has to be a runnable regular file.
func TestResolveChromePath_ResolvesSymlinks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := writeExecutable(t, dir, "chromium-real")
	link := filepath.Join(dir, "chromium")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got, err := ResolveChromePath(link)
	if err != nil {
		t.Fatalf("ResolveChromePath(%q): %v", link, err)
	}
	want := resolvedPath(t, target)
	if got != want {
		t.Errorf("got %q, want the symlink target %q", got, want)
	}
}

// TestResolveChromePath_SymlinkToDirectoryIsRejected: the check has to apply to
// what the link points at, not to the link.
func TestResolveChromePath_SymlinkToDirectoryIsRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	link := filepath.Join(dir, "chrome")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := ResolveChromePath(link); !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("err = %v, want one wrapping ErrBrowserUnavailable", err)
	}
}

// TestResolveChromePath_Autodetect exercises the detection order without
// asserting a machine-specific outcome: either a browser is installed and the
// answer is a runnable absolute path, or none is and the error tells the user
// which flag to reach for.
func TestResolveChromePath_Autodetect(t *testing.T) {
	t.Parallel()

	got, err := ResolveChromePath("")
	if err != nil {
		if !errors.Is(err, ErrBrowserUnavailable) {
			t.Fatalf("error %v does not wrap ErrBrowserUnavailable", err)
		}
		if !strings.Contains(err.Error(), "-chrome") {
			t.Errorf("error %q does not tell the user about -chrome", err)
		}
		return
	}

	if !filepath.IsAbs(got) {
		t.Errorf("autodetected %q, want an absolute path", got)
	}
	fi, statErr := os.Stat(got)
	if statErr != nil {
		t.Fatalf("stat %q: %v", got, statErr)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("autodetected %q is not a runnable regular file (%v)", got, fi.Mode())
	}
}
