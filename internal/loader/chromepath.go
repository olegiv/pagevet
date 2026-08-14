package loader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// bundlePaths are the macOS app-bundle locations probed before $PATH, in
// preference order: a stable Google Chrome (this machine has Chrome 151
// installed there), then Chromium, then Canary. Canary is last because it is
// usually a second, experimental install rather than the browser the user meant.
var bundlePaths = []string{
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
}

// commandNames are the $PATH names used on Linux and by some Homebrew formulae.
var commandNames = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
}

// ResolveChromePath returns the absolute, symlink-resolved path of the browser
// binary to launch.
//
// An explicit path is validated rather than trusted: a typo would otherwise
// surface as a Chrome start-up failure several layers down, where the message
// says nothing about which path was wrong. Autodetection falls back to the
// macOS app bundles and then to $PATH.
//
// Every failure wraps ErrBrowserUnavailable, because none of them is a per-URL
// problem — the run cannot start at all.
func ResolveChromePath(explicit string) (string, error) {
	if explicit != "" {
		path, err := validateChromePath(explicit)
		if err != nil {
			return "", fmt.Errorf("-chrome %q: %w", explicit, err)
		}
		return path, nil
	}

	for _, candidate := range bundlePaths {
		if path, err := validateChromePath(candidate); err == nil {
			return path, nil
		}
	}
	for _, name := range commandNames {
		found, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		abs, err := filepath.Abs(found)
		if err != nil {
			continue
		}
		if path, err := validateChromePath(abs); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf(
		"no Chrome or Chromium binary found in /Applications or $PATH; pass -chrome PATH to point at one: %w",
		ErrBrowserUnavailable)
}

// validateChromePath enforces the four properties that make a path launchable.
func validateChromePath(path string) (string, error) {
	// A NUL byte truncates the string at the syscall boundary, so a path
	// containing one does not name the file the caller believes it does.
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains a NUL byte: %w", ErrBrowserUnavailable)
	}
	// Relative paths would resolve against whatever directory the process
	// happens to be in, which for a long-running crawl is not a property worth
	// depending on.
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute: %w", ErrBrowserUnavailable)
	}

	// Resolve before inspecting: a symlink pointing at a directory, or a
	// dangling one, has to fail as what it points AT.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w: %w", path, err, ErrBrowserUnavailable)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat %q: %w: %w", resolved, err, ErrBrowserUnavailable)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file: %w", resolved, ErrBrowserUnavailable)
	}
	// Mode bits, not an effective-uid comparison: doing that properly needs
	// platform-specific syscalls and races the exec anyway. Clear bits mean the
	// file is definitely not runnable; set bits leave any remaining problem to
	// exec, which reports it precisely.
	if fi.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("%q is not executable: %w", resolved, ErrBrowserUnavailable)
	}
	return resolved, nil
}
