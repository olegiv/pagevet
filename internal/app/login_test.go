package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olegiv/pagevet/internal/loader"
	"github.com/olegiv/pagevet/internal/loader/fake"
)

// These tests drive the -login path through run() with no browser anywhere. The
// browser interface gained loader.Authenticator precisely so that this is
// possible: the ordering guarantee the whole feature rests on - sign in first,
// dispatch second - is asserted here rather than only in an e2e test that needs
// Chrome and a network stack.
//
// They call t.Chdir, so none of them can be parallel: -login reads ./.env, and
// the working directory is process-wide. t.Chdir enforces that itself.

// envBody is a complete .env pointing at the host the test's URL list uses.
const envBody = `LOGIN_PATH="/login"
LOGIN_FORM_ID="user-login-form"
USERNAME_NAME="name"
PASSWORD_NAME="pass"
USER_ADMIN_NAME="editor"
USER_ADMIN_PASS="s3cret"
`

// chdirWithEnv moves the test into a scratch directory containing the given
// .env body, mirroring how a user runs pagevet from the directory holding it.
// An empty body writes no file at all.
func chdirWithEnv(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
			t.Fatalf("writing .env: %v", err)
		}
	}
	t.Chdir(dir)
}

// loginCfg is runCfg plus -login. The input list is written before the chdir,
// under its own temp dir, so it stays reachable by absolute path.
func loginCfg(t *testing.T, urls ...string) Config {
	t.Helper()
	cfg := runCfg(t, writeURLs(t, urls...))
	cfg.Login = true
	return cfg
}

func TestLogin_FailureExitsFiveAndCrawlsNothing(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://a.test/", "https://b.test/")
	fb := &fakeBrowser{FakeLoader: fake.New()}
	fb.SetLoginErr(errors.New("no new cookie was set"))

	var stdout, stderr bytes.Buffer
	code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

	if code != ExitLoginFailed {
		t.Errorf("run() = %d, want %d (ExitLoginFailed)", code, ExitLoginFailed)
	}
	// This is the point of aborting. Crawling on anonymously would fill the
	// logs with redirects and 403s that read as page failures.
	if n := fb.CallCount(); n != 0 {
		t.Errorf("loaded %d URLs after a failed login, want 0", n)
	}
	if !strings.Contains(stderr.String(), "no new cookie was set") {
		t.Errorf("stderr = %q, want it to carry the loader's explanation", stderr.String())
	}
}

func TestLogin_SucceedsBeforeAnyLoad(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://a.test/", "https://b.test/", "https://c.test/")
	fb := &fakeBrowser{FakeLoader: fake.New()}

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr); code != ExitOK {
		t.Fatalf("run() = %d, want %d; stderr=%s", code, ExitOK, stderr.String())
	}

	// Exactly once: zero means the crawl went out anonymous, and more than one
	// means a second sign-in raced the pool.
	if n := fb.LoginCalls(); n != 1 {
		t.Errorf("LoginCalls() = %d, want 1", n)
	}
	// A session established after the first page load did not apply to that
	// page. This is the ordering the shared cookie jar depends on.
	if n := fb.LoadsBeforeLogin(); n != 0 {
		t.Errorf("%d URLs were loaded before the login, want 0", n)
	}
	if n := fb.CallCount(); n != 3 {
		t.Errorf("loaded %d URLs, want 3", n)
	}
}

func TestLogin_NotAttemptedWhenFlagIsOff(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://a.test/")
	cfg.Login = false

	fb := &fakeBrowser{FakeLoader: fake.New()}
	// Scripted to fail, to prove it is never called: a .env sitting in the
	// working directory must not authenticate a run that did not ask for it.
	fb.SetLoginErr(errors.New("should not be reached"))

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr); code != ExitOK {
		t.Fatalf("run() = %d, want %d; stderr=%s", code, ExitOK, stderr.String())
	}
	if n := fb.LoginCalls(); n != 0 {
		t.Errorf("LoginCalls() = %d without -login, want 0", n)
	}
}

func TestLogin_SpecReachesTheLoader(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://example.com/deep/page?q=1", "https://example.com/other")

	var opts loader.Options
	fb := &fakeBrowser{FakeLoader: fake.New()}

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, &opts), &stdout, &stderr); code != ExitOK {
		t.Fatalf("run() = %d, want %d; stderr=%s", code, ExitOK, stderr.String())
	}

	if opts.Login == nil {
		t.Fatal("loader.Options.Login is nil, want the resolved spec")
	}
	// Origin of the first URL, not its path: LOGIN_PATH is "/login".
	if got, want := opts.Login.URL, "https://example.com/login"; got != want {
		t.Errorf("Login.URL = %q, want %q", got, want)
	}
	if got, want := opts.Login.FormID, "user-login-form"; got != want {
		t.Errorf("Login.FormID = %q, want %q", got, want)
	}
	if got, want := opts.Login.Username, "editor"; got != want {
		t.Errorf("Login.Username = %q, want %q", got, want)
	}
	if got, want := opts.Login.Password, "s3cret"; got != want {
		t.Errorf("Login.Password did not survive the trip (got %d bytes, want %d)", len(got), len(want))
	}
}

func TestLogin_LogoutURLReachesTheLoader(t *testing.T) {
	chdirWithEnv(t, envBody+`LOGOUT_PATH="/user/logout"`+"\n")

	cfg := loginCfg(t, "https://example.com/deep/page", "https://example.com/other")

	var opts loader.Options
	fb := &fakeBrowser{FakeLoader: fake.New()}

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, &opts), &stdout, &stderr); code != ExitOK {
		t.Fatalf("run() = %d, want %d; stderr=%s", code, ExitOK, stderr.String())
	}

	if opts.Login == nil {
		t.Fatal("loader.Options.Login is nil, want the resolved spec")
	}
	// Origin of the first URL, same rule as LOGIN_PATH.
	if got, want := opts.Login.LogoutURL, "https://example.com/user/logout"; got != want {
		t.Errorf("Login.LogoutURL = %q, want %q", got, want)
	}
	if got, want := opts.Login.URL, "https://example.com/login"; got != want {
		t.Errorf("Login.URL = %q, want %q", got, want)
	}
}

func TestLogin_LogoutURLEmptyWhenUnset(t *testing.T) {
	chdirWithEnv(t, envBody) // no LOGOUT_PATH

	cfg := loginCfg(t, "https://example.com/a")

	var opts loader.Options
	fb := &fakeBrowser{FakeLoader: fake.New()}

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, &opts), &stdout, &stderr); code != ExitOK {
		t.Fatalf("run() = %d, want %d; stderr=%s", code, ExitOK, stderr.String())
	}

	if opts.Login == nil {
		t.Fatal("loader.Options.Login is nil, want the resolved spec")
	}
	// An empty LogoutURL is how the loader knows to skip the step. A .env
	// written before LOGOUT_PATH existed has to keep working unchanged.
	if got := opts.Login.LogoutURL; got != "" {
		t.Errorf("Login.LogoutURL = %q with no LOGOUT_PATH, want empty", got)
	}
}

func TestLogin_NilSpecWithoutFlag(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://a.test/")
	cfg.Login = false

	var opts loader.Options
	fb := &fakeBrowser{FakeLoader: fake.New()}

	var stdout, stderr bytes.Buffer
	run(deadline(t), cfg, factoryFor(fb, &opts), &stdout, &stderr)

	// Nil and "a spec with empty fields" must not be the same value, or a
	// misconfigured run would try to sign in with nothing.
	if opts.Login != nil {
		t.Errorf("loader.Options.Login = %+v without -login, want nil", opts.Login)
	}
}

func TestLogin_BadEnvExitsUsage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string // substring of the message
	}{
		{"missing file", "", "does not exist"},
		{"missing key", "LOGIN_PATH=\"/login\"\n", "LOGIN_FORM_ID"},
		{"malformed line", envBody + "garbage\n", "expected KEY=VALUE"},
		{"duplicate key", envBody + "LOGIN_PATH=\"/other\"\n", "set twice"},
		{
			// The .env must not be a way around the scheme allowlist that
			// internal/input applies to every crawled URL.
			name: "non-http scheme",
			body: strings.Replace(envBody, `LOGIN_PATH="/login"`, `LOGIN_PATH="file:///etc/passwd"`, 1),
			want: "only http and https",
		},
		{
			name: "selector injection in the form id",
			body: strings.Replace(envBody, `LOGIN_FORM_ID="user-login-form"`,
				`LOGIN_FORM_ID="x\"] , [name=\"pass"`, 1),
			want: "not a valid HTML identifier",
		},
		{
			// LOGOUT_PATH is a URL this program navigates to, so it gets the
			// same allowlist as everything else.
			name: "non-http logout scheme",
			body: envBody + `LOGOUT_PATH="file:///etc/passwd"` + "\n",
			want: "only http and https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chdirWithEnv(t, tt.body)

			cfg := loginCfg(t, "https://a.test/")
			fb := &fakeBrowser{FakeLoader: fake.New()}

			var stdout, stderr bytes.Buffer
			code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

			// A broken .env is a configuration error, fixed in an editor,
			// exactly like a missing input file. Exit 5 is reserved for a
			// sign-in that was actually attempted and did not take.
			if code != ExitUsage {
				t.Errorf("run() = %d, want %d (ExitUsage)", code, ExitUsage)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.want)
			}
			if n := fb.LoginCalls(); n != 0 {
				t.Errorf("LoginCalls() = %d after a bad .env, want 0", n)
			}
		})
	}
}

func TestLogin_EnvIsReadBeforeChromeStarts(t *testing.T) {
	chdirWithEnv(t, "") // no .env at all

	cfg := loginCfg(t, "https://a.test/")

	// A factory that fails the test if it is ever called. A typo in .env should
	// cost milliseconds, not a Chrome launch.
	factory := func(loader.Options) (browser, error) {
		t.Error("the browser was constructed despite an unreadable .env")
		return &fakeBrowser{FakeLoader: fake.New()}, nil
	}

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factory, &stdout, &stderr); code != ExitUsage {
		t.Errorf("run() = %d, want %d", code, ExitUsage)
	}
}

func TestLogin_HeaderRecordsTheSession(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://example.com/a")
	fb := &fakeBrowser{FakeLoader: fake.New()}

	var stdout, stderr bytes.Buffer
	if code := run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr); code != ExitOK {
		t.Fatalf("run() = %d, want %d; stderr=%s", code, ExitOK, stderr.String())
	}

	opened, err := os.ReadFile(filepath.Join(cfg.Out, "opened.log"))
	if err != nil {
		t.Fatalf("reading opened.log: %v", err)
	}
	got := string(opened)

	// Provenance: "why did this URL return 200 here and 403 there" has no other
	// answer six months later.
	if !strings.Contains(got, "# login editor at https://example.com/login (form user-login-form)") {
		t.Errorf("opened.log has no login provenance line:\n%s", firstLines(got, 4))
	}
	// The password must not be in any file this program writes.
	if strings.Contains(got, "s3cret") {
		t.Error("opened.log contains the password")
	}
}

func TestLogin_HeaderAbsentWithoutFlag(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://example.com/a")
	cfg.Login = false
	fb := &fakeBrowser{FakeLoader: fake.New()}

	var stdout, stderr bytes.Buffer
	run(deadline(t), cfg, factoryFor(fb, nil), &stdout, &stderr)

	opened, err := os.ReadFile(filepath.Join(cfg.Out, "opened.log"))
	if err != nil {
		t.Fatalf("reading opened.log: %v", err)
	}
	// An ordinary run's header must be byte-identical to what it was before
	// this feature existed, which is also what keeps the golden files green.
	if strings.Contains(string(opened), "# login") {
		t.Errorf("opened.log carries a login line on a run without -login:\n%s", firstLines(string(opened), 4))
	}
}

func TestLogin_InterruptedDuringSignInExitsFour(t *testing.T) {
	chdirWithEnv(t, envBody)

	cfg := loginCfg(t, "https://a.test/")
	fb := &fakeBrowser{FakeLoader: fake.New()}

	ctx, cancel := context.WithCancel(deadline(t))
	cancel() // already canceled when Login is reached

	var stdout, stderr bytes.Buffer
	code := run(ctx, cfg, factoryFor(fb, nil), &stdout, &stderr)

	// Ctrl-C during the sign-in is an interruption, not a credential problem.
	if code != ExitInterrupted {
		t.Errorf("run() = %d, want %d (ExitInterrupted); stderr=%s", code, ExitInterrupted, stderr.String())
	}
}

// firstLines trims a file down to its header for a failure message.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
