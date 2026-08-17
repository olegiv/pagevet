package app_test

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olegiv/pagevet/internal/loader/browsertest"
	"github.com/olegiv/pagevet/internal/report"
	"github.com/olegiv/pagevet/internal/testfixtures"
)

// TestE2E_Login runs the real binary, against a real Chrome, against the login
// fixture. It is the only test that exercises the whole path end to end: flag
// -> .env -> resolved URL -> form fill -> shared cookie jar -> exit code.
//
// Everything below asserts on the exit code and the files on disk, because
// those are the contract a CI script actually consumes.
func TestE2E_Login(t *testing.T) {
	browsertest.Guard(t)

	chrome := browsertest.ChromePath(t)

	ctx, cancel := context.WithTimeout(t.Context(), buildTimeout)
	defer cancel()

	bin := buildBinary(ctx, t)
	srv := testfixtures.New(t)

	// /private is 403 to a stranger and 200 to a session, so the same list
	// produces different logs depending only on whether the login took.
	urls := writeLines(t, srv.URL+"/private", srv.URL+"/ok")

	t.Run("signs in and reaches the protected page", func(t *testing.T) {
		dir := envDir(t, srv.URL, testfixtures.LoginUser, testfixtures.LoginPass)
		logs := filepath.Join(t.TempDir(), "logs")

		code, stdout, stderr := runBinaryIn(ctx, t, dir, bin,
			"-chrome", chrome, "-out", logs, "-timeout", "20s", "-login", urls)

		if code != 0 {
			t.Fatalf("exit code = %d, want 0\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}

		opened := readLog(t, logs, report.FileOpened)

		// The assertion the whole feature exists for.
		if !strings.Contains(opened, "/private") || strings.Contains(opened, "403") {
			t.Errorf("/private was not fetched as a signed-in user:\n%s", opened)
		}
		// Provenance, so the log says which session produced it.
		if !strings.Contains(opened, "# login "+testfixtures.LoginUser+" at "+srv.URL+"/login") {
			t.Errorf("opened.log has no login provenance line:\n%s", firstLines(opened, 4))
		}
		// A signed-in run has nothing to report, so the HTTP error log must not
		// exist at all: error files are created only when they get a record.
		if _, err := os.Stat(filepath.Join(logs, report.FileHTTP)); err == nil {
			t.Errorf("%s was written on a successful login:\n%s", report.FileHTTP,
				readLog(t, logs, report.FileHTTP))
		}
		if !strings.Contains(stderr, "logged in as "+testfixtures.LoginUser) {
			t.Errorf("stderr does not report the sign-in:\n%s", stderr)
		}
	})

	t.Run("without -login the same page is a 403", func(t *testing.T) {
		dir := envDir(t, srv.URL, testfixtures.LoginUser, testfixtures.LoginPass)
		logs := filepath.Join(t.TempDir(), "logs")

		// The .env is present and valid; only the flag is missing. This is what
		// makes the previous subtest's 200 attributable to -login rather than
		// to the fixture being unprotected.
		code, stdout, stderr := runBinaryIn(ctx, t, dir, bin,
			"-chrome", chrome, "-out", logs, "-timeout", "20s", urls)

		if code != 0 {
			t.Fatalf("exit code = %d, want 0\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}
		http := readLog(t, logs, report.FileHTTP)
		if !strings.Contains(http, "403") {
			t.Errorf("expected a 403 for /private without -login:\n%s", http)
		}
	})

	t.Run("LOGOUT_PATH is fetched before the login page", func(t *testing.T) {
		// /login-anon serves its form only to a signed-out visitor, and
		// /grant is crawled first so the browser arrives already signed in.
		// The sign-in can therefore only work if LOGOUT_PATH was fetched in
		// between — which is the whole claim.
		dir := envDirWith(t, srv.URL, testfixtures.LoginUser, testfixtures.LoginPass,
			map[string]string{
				"LOGIN_PATH":  srv.URL + "/login-anon",
				"LOGOUT_PATH": srv.URL + "/logout",
			})
		logs := filepath.Join(t.TempDir(), "logs")

		grantThenPrivate := writeLines(t, srv.URL+"/grant", srv.URL+"/private")

		code, stdout, stderr := runBinaryIn(ctx, t, dir, bin,
			"-chrome", chrome, "-out", logs, "-timeout", "20s", "-login", grantThenPrivate)

		if code != 0 {
			t.Fatalf("exit code = %d, want 0\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}
		if opened := readLog(t, logs, report.FileOpened); strings.Contains(opened, "403") {
			t.Errorf("a page came back 403, so the session did not survive:\n%s", opened)
		}
	})

	t.Run("a broken LOGOUT_PATH exits 5 and names the key", func(t *testing.T) {
		dir := envDirWith(t, srv.URL, testfixtures.LoginUser, testfixtures.LoginPass,
			map[string]string{
				// RFC 6761 reserves .invalid, so this can only be NXDOMAIN.
				"LOGOUT_PATH": "http://pagevet-does-not-exist.invalid/logout",
			})
		logs := filepath.Join(t.TempDir(), "logs")

		code, stdout, stderr := runBinaryIn(ctx, t, dir, bin,
			"-chrome", chrome, "-out", logs, "-timeout", "20s", "-login", urls)

		if code != 5 {
			t.Fatalf("exit code = %d, want 5\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "LOGOUT_PATH") {
			t.Errorf("stderr does not name the key to fix:\n%s", stderr)
		}
	})

	t.Run("wrong credentials exit 5 and crawl nothing", func(t *testing.T) {
		dir := envDir(t, srv.URL, testfixtures.LoginUser, "wrong-password")
		logs := filepath.Join(t.TempDir(), "logs")

		code, stdout, stderr := runBinaryIn(ctx, t, dir, bin,
			"-chrome", chrome, "-out", logs, "-timeout", "20s", "-login", urls)

		// 5, not 3: "your credentials are wrong" and "Chrome would not start"
		// call for different responses in CI.
		if code != 5 {
			t.Fatalf("exit code = %d, want 5\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "login failed") {
			t.Errorf("stderr does not say the login failed:\n%s", stderr)
		}
		// The password must not reach the terminal.
		if strings.Contains(stderr, "wrong-password") || strings.Contains(stdout, "wrong-password") {
			t.Errorf("the password leaked into the output\n--- stdout ---\n%s\n--- stderr ---\n%s", stdout, stderr)
		}
		// Nothing was crawled, so there is no summary and no ledger to mislead
		// anyone into thinking these pages were checked.
		if _, err := os.Stat(filepath.Join(logs, report.FileResults)); err == nil {
			t.Error("results.jsonl was written despite the run never starting")
		}
	})

	t.Run("a missing .env exits 2", func(t *testing.T) {
		dir := t.TempDir() // no .env in it
		logs := filepath.Join(t.TempDir(), "logs")

		code, stdout, stderr := runBinaryIn(ctx, t, dir, bin,
			"-chrome", chrome, "-out", logs, "-login", urls)

		// A configuration problem, fixed in an editor, exactly like a missing
		// input file. Exit 5 means a sign-in was attempted and did not take.
		if code != 2 {
			t.Fatalf("exit code = %d, want 2\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout, stderr)
		}
		// -login always reads ./.env, so "wrong directory" is the likeliest
		// mistake and the absolute path is what answers it.
		if !strings.Contains(stderr, filepath.Join(dir, ".env")) {
			t.Errorf("stderr does not name the file it looked for:\n%s", stderr)
		}
	})

	t.Run("the password never reaches the logs", func(t *testing.T) {
		const password = "zebra-quartz-lantern"

		dir := envDir(t, srv.URL, testfixtures.LoginUser, password)
		logs := filepath.Join(t.TempDir(), "logs")

		// Deliberately with -log-full-urls, the flag that turns redaction OFF:
		// even in the most permissive configuration there is no path from the
		// .env to a file on disk.
		code, stdout, stderr := runBinaryIn(ctx, t, dir, bin,
			"-chrome", chrome, "-out", logs, "-timeout", "20s",
			"-login", "-log-full-urls", urls)

		// The password is wrong for the fixture, so this exits 5; the point is
		// what got written on the way there.
		if code != 5 {
			t.Fatalf("exit code = %d, want 5\n--- stderr ---\n%s", code, stderr)
		}

		for _, name := range logFileNames(t, logs) {
			if strings.Contains(readLog(t, logs, name), password) {
				t.Errorf("%s contains the password", name)
			}
		}
		if strings.Contains(stdout+stderr, password) {
			t.Error("the password reached stdout or stderr")
		}
	})
}

// envDir writes a .env for the fixture server into a fresh directory and
// returns it, to be used as the binary's working directory.
func envDir(t *testing.T, srvURL, user, pass string) string {
	t.Helper()
	return envDirWith(t, srvURL, user, pass, nil)
}

// envDirWith is envDir with per-test key overrides — a different LOGIN_PATH, an
// added LOGOUT_PATH. A nil map is the default file.
//
// Keys are written in a fixed order rather than map order so that a failing
// test's .env is the same on every run.
func envDirWith(t *testing.T, srvURL, user, pass string, override map[string]string) string {
	t.Helper()

	kv := map[string]string{
		// Absolute, so the file does not depend on the URL list's order.
		"LOGIN_PATH":      srvURL + "/login",
		"LOGIN_FORM_ID":   testfixtures.LoginFormID,
		"USERNAME_NAME":   testfixtures.LoginUserField,
		"PASSWORD_NAME":   testfixtures.LoginPassField,
		"USER_ADMIN_NAME": user,
		"USER_ADMIN_PASS": pass,
	}
	order := []string{
		"LOGIN_PATH", "LOGOUT_PATH", "LOGIN_FORM_ID",
		"USERNAME_NAME", "PASSWORD_NAME", "USER_ADMIN_NAME", "USER_ADMIN_PASS",
	}
	maps.Copy(kv, override)

	var b strings.Builder
	b.WriteString("# written by TestE2E_Login\n")
	for _, k := range order {
		if v, ok := kv[k]; ok {
			fmt.Fprintf(&b, "%s=%q\n", k, v)
		}
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("writing .env: %v", err)
	}
	return dir
}

// readLog reads one log file, failing the test if it is not there.
//
// It goes through an *os.Root for the same reason the reporter writes through
// one: it keeps a computed directory out of os.Open, and the repo free of gosec
// suppressions.
func readLog(t *testing.T, dir, name string) string {
	t.Helper()

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("opening %s: %v", dir, err)
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(name)
	if err != nil {
		t.Fatalf("opening %s/%s: %v", dir, name, err)
	}
	defer func() { _ = f.Close() }()

	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading %s/%s: %v", dir, name, err)
	}
	return string(b)
}

// logFileNames lists what the run actually wrote. A missing directory is not a
// failure: a run that exits before the reporter opens is exactly the case the
// caller is checking.
func logFileNames(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// firstLines trims a log down to its header for a failure message.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
