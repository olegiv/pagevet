package login

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// testConfig is a valid Config that a test mutates one field of.
func testConfig() Config {
	return Config{
		path:      "/tmp/.env",
		LoginPath: "/login",
		FormID:    "user-login-form",
		UserField: "name",
		PassField: "pass",
		Username:  "editor",
		Password:  "s3cret",
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		loginPath string
		firstURL  string
		want      string
	}{
		{
			name:      "path resolves against the first URL's origin",
			loginPath: "/login",
			firstURL:  "https://example.com/",
			want:      "https://example.com/login",
		},
		{
			// Only the origin is taken. Inheriting the path would make the
			// login URL depend on whichever URL happened to sort first, which
			// is a surprise nobody wants to debug.
			name:      "path ignores the first URL's own path",
			loginPath: "/login",
			firstURL:  "https://example.com/deep/page?q=1#frag",
			want:      "https://example.com/login",
		},
		{
			name:      "port is part of the origin",
			loginPath: "/login",
			firstURL:  "http://127.0.0.1:8080/ok",
			want:      "http://127.0.0.1:8080/login",
		},
		{
			name:      "relative path with no leading slash",
			loginPath: "user/login",
			firstURL:  "https://example.com/a/b",
			want:      "https://example.com/user/login",
		},
		{
			name:      "query in the login path survives",
			loginPath: "/login?destination=/admin",
			firstURL:  "https://example.com/",
			want:      "https://example.com/login?destination=/admin",
		},
		{
			name:      "absolute URL is used as-is",
			loginPath: "https://auth.example.com/sso/login",
			firstURL:  "https://example.com/",
			want:      "https://auth.example.com/sso/login",
		},
		{
			// The list may span hosts; an absolute LOGIN_PATH is how you say
			// which one carries the login form.
			name:      "absolute URL wins over the first URL's host",
			loginPath: "http://other.example.net/login",
			firstURL:  "https://example.com/",
			want:      "http://other.example.net/login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := testConfig()
			c.LoginPath = tt.loginPath

			spec, err := c.Resolve(tt.firstURL)
			if err != nil {
				t.Fatalf("Resolve(%q) error = %v", tt.firstURL, err)
			}
			if spec.URL != tt.want {
				t.Errorf("Resolve(%q).URL = %q, want %q", tt.firstURL, spec.URL, tt.want)
			}
		})
	}
}

func TestResolveCarriesEveryField(t *testing.T) {
	t.Parallel()

	c := testConfig()
	spec, err := c.Resolve("https://example.com/")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	want := Spec{
		URL:       "https://example.com/login",
		FormID:    c.FormID,
		UserField: c.UserField,
		PassField: c.PassField,
		Username:  c.Username,
		Password:  c.Password,
	}
	if spec != want {
		t.Errorf("Resolve() = %+v, want %+v", spec, want)
	}
}

func TestResolveLogoutPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		logoutPath string
		firstURL   string
		want       string
	}{
		{
			// The overwhelmingly common case: absent means no logout step, and
			// an empty LogoutURL is what the loader checks for.
			name:       "absent stays empty",
			logoutPath: "",
			firstURL:   "https://example.com/",
			want:       "",
		},
		{
			name:       "path resolves against the first URL's origin",
			logoutPath: "/user/logout",
			firstURL:   "https://example.com/deep/page",
			want:       "https://example.com/user/logout",
		},
		{
			name:       "absolute URL is used as-is",
			logoutPath: "https://auth.example.com/sso/logout",
			firstURL:   "https://example.com/",
			want:       "https://auth.example.com/sso/logout",
		},
		{
			// Drupal 10 wants a CSRF token on the logout route, so the query
			// has to survive intact.
			name:       "query survives",
			logoutPath: "/user/logout?token=abc123",
			firstURL:   "https://example.com/",
			want:       "https://example.com/user/logout?token=abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := testConfig()
			c.LogoutPath = tt.logoutPath

			spec, err := c.Resolve(tt.firstURL)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if spec.LogoutURL != tt.want {
				t.Errorf("LogoutURL = %q, want %q", spec.LogoutURL, tt.want)
			}
			// Resolving one must never disturb the other. LOGIN_PATH is
			// "/login" in every case here, so it always lands on the first
			// URL's origin regardless of what LOGOUT_PATH did.
			wantLogin := "https://" + hostOf(tt.firstURL) + "/login"
			if spec.URL != wantLogin {
				t.Errorf("URL = %q, want %q; resolving LOGOUT_PATH disturbed LOGIN_PATH", spec.URL, wantLogin)
			}
		})
	}
}

func TestResolveRejectsBadLogoutPath(t *testing.T) {
	t.Parallel()

	// LOGOUT_PATH goes through the same allowlist as LOGIN_PATH: it is a URL
	// this program navigates to, so it gets the same treatment.
	for _, bad := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"ftp://example.com/logout",
	} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()

			c := testConfig()
			c.LogoutPath = bad

			_, err := c.Resolve("https://example.com/")
			if err == nil {
				t.Fatalf("Resolve() accepted LOGOUT_PATH=%q, want an error", bad)
			}
			if !errors.Is(err, ErrConfig) {
				t.Errorf("error = %v, want it to wrap ErrConfig", err)
			}
			// The message must name the key that is wrong, not the other one.
			if !strings.Contains(err.Error(), KeyLogoutPath) {
				t.Errorf("error = %q, want it to name %s", err, KeyLogoutPath)
			}
			if strings.Contains(err.Error(), KeyLoginPath+"=") {
				t.Errorf("error = %q, blames %s for a %s problem", err, KeyLoginPath, KeyLogoutPath)
			}
		})
	}
}

func TestLogoutHost(t *testing.T) {
	t.Parallel()

	// The caller runs the address policy over both hosts, and LOGOUT_PATH may
	// name a different origin than LOGIN_PATH.
	c := testConfig()
	c.LogoutPath = "https://auth.example.net/logout"

	spec, err := c.Resolve("https://example.com/")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got, want := spec.LogoutHost(), "auth.example.net"; got != want {
		t.Errorf("LogoutHost() = %q, want %q", got, want)
	}
	if got, want := spec.Host(), "example.com"; got != want {
		t.Errorf("Host() = %q, want %q", got, want)
	}

	// No logout configured means no host to check, which the caller uses to
	// decide whether to run the policy at all.
	if got := (Spec{}).LogoutHost(); got != "" {
		t.Errorf("LogoutHost() with no logout = %q, want empty", got)
	}
}

func TestResolveRejectsNonHTTPSchemes(t *testing.T) {
	t.Parallel()

	// The same positive allowlist internal/input applies to every crawled URL.
	// Without it the .env would be a way around that check.
	for _, path := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/html,<form>",
		"ftp://example.com/login",
		"chrome://settings",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			c := testConfig()
			c.LoginPath = path

			_, err := c.Resolve("https://example.com/")
			if err == nil {
				t.Fatalf("Resolve() accepted %q, want an error", path)
			}
			if !errors.Is(err, ErrConfig) {
				t.Errorf("error = %v, want it to wrap ErrConfig", err)
			}
		})
	}
}

func TestResolveRejectsUnusableBase(t *testing.T) {
	t.Parallel()

	c := testConfig()
	if _, err := c.Resolve("://not-a-url"); err == nil {
		t.Error("Resolve() accepted an unparseable first URL, want an error")
	}

	// A relative path with no host to resolve against cannot produce a URL.
	if _, err := c.Resolve(""); err == nil {
		t.Error("Resolve() accepted an empty first URL, want an error")
	}
}

// TestValidateRejectsControlCharacters covers the only thing this package now
// refuses in these three values.
//
// The selector-injection defense deliberately lives elsewhere: internal/loader
// escapes these into quoted CSS strings and JSON-encoded JavaScript literals,
// and TestCSSString / TestJSString over there are what prove `x"] , [name="pass`
// is neutralized. Rejecting it here as well would cost real configurations —
// Rails and PHP forms use `user[email]` — for no additional safety.
func TestValidateRejectsControlCharacters(t *testing.T) {
	t.Parallel()

	bad := []string{
		"x\ny",
		"x\ry",
		"x\x00y",  // NUL
		"x\x7fy",  // DEL
		"x\u2028", // JS line separator
		"x\u2029",
		"", // empty
	}

	for _, v := range bad {
		t.Run(v, func(t *testing.T) {
			t.Parallel()

			for _, field := range []string{"FormID", "UserField", "PassField"} {
				c := testConfig()
				switch field {
				case "FormID":
					c.FormID = v
				case "UserField":
					c.UserField = v
				case "PassField":
					c.PassField = v
				}

				err := c.validate()
				if err == nil {
					t.Errorf("validate() accepted %s = %q, want an error", field, v)
					continue
				}
				if !errors.Is(err, ErrConfig) {
					t.Errorf("validate() error = %v, want it to wrap ErrConfig", err)
				}
			}
		})
	}
}

// TestValidateAcceptsNestedFieldNames is the regression for the bracketed-name
// bug: `user[email]` and `user[password]` are ordinary Rails and PHP field
// names, and an identifier allowlist rejected them before Chrome ever started.
func TestValidateAcceptsNestedFieldNames(t *testing.T) {
	t.Parallel()

	for _, pair := range [][2]string{
		{"user[email]", "user[password]"},
		{"session[login]", "session[password]"},
		{"data[User][username]", "data[User][passwd]"},
		{"form.username", "form.password"},
		{"login-email", "login-password"},
		{"q_1", "q_2"},
	} {
		t.Run(pair[0], func(t *testing.T) {
			t.Parallel()

			c := testConfig()
			c.UserField, c.PassField = pair[0], pair[1]
			if err := c.validate(); err != nil {
				t.Errorf("validate() rejected %q / %q: %v", pair[0], pair[1], err)
			}
		})
	}
}

func TestValidateAcceptsRealIdentifiers(t *testing.T) {
	t.Parallel()

	// Everything an HTML id or a form field name legitimately uses. Drupal's
	// own login form supplies the last of these.
	for _, ok := range []string{
		"name",
		"pass",
		"user_login",
		"user-login-form",
		"iru-user-login-inline-form",
		"form.field",
		"ns:field",
		"_private",
		"a1",
	} {
		t.Run(ok, func(t *testing.T) {
			t.Parallel()

			c := testConfig()
			c.FormID = ok
			if err := c.validate(); err != nil {
				t.Errorf("validate() rejected %q: %v", ok, err)
			}
		})
	}
}

func TestValidateRejectsIdenticalFields(t *testing.T) {
	t.Parallel()

	// Both selectors would resolve to the same input, so the password would be
	// typed into the username box and posted in the clear.
	c := testConfig()
	c.UserField = "name"
	c.PassField = "name"

	err := c.validate()
	if err == nil {
		t.Fatal("validate() accepted identical field names, want an error")
	}
	if !strings.Contains(err.Error(), "different inputs") {
		t.Errorf("error = %q, want it to explain the problem", err)
	}
}

// TestPasswordNeverRendered is the test that has to keep passing.
//
// Spec.String is what every caller reaches for when it wants to say what
// pagevet did, and it is reachable implicitly through any %v on a Spec. If a
// password can get out of this package at all, this is the crack it goes
// through.
func TestPasswordNeverRendered(t *testing.T) {
	t.Parallel()

	const password = "correct-horse-battery-staple"

	c := testConfig()
	c.Password = password
	spec, err := c.Resolve("https://example.com/")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if got := spec.String(); strings.Contains(got, password) {
		t.Errorf("String() rendered the password: %q", got)
	}
	if got := spec.Describe("https://redacted.example/login"); strings.Contains(got, password) {
		t.Errorf("Describe() rendered the password: %q", got)
	}

	// Every verb that can render a struct, on both the value and the pointer. A
	// Spec reached by %v somewhere far from this package is how a password
	// escapes without anyone meaning it to, and %#v — the debugging verb —
	// ignores Stringer entirely, which is why GoString exists.
	for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
		for what, arg := range map[string]any{"value": spec, "pointer": &spec} {
			if got := fmt.Sprintf(verb, arg); strings.Contains(got, password) {
				t.Errorf("%s on a Spec %s rendered the password: %q", verb, what, got)
			}
		}
	}

	// The same, one level down: a Spec is reached through loader.Options in
	// real code, so it is a struct field far more often than it is an operand.
	nested := struct {
		Note  string
		Login *Spec
	}{Note: "options", Login: &spec}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, nested); strings.Contains(got, password) {
			t.Errorf("%s on a struct holding a *Spec rendered the password: %q", verb, got)
		}
	}

	// It must still be useful, or callers will build their own string and this
	// protection stops applying.
	if !strings.Contains(spec.String(), "editor") {
		t.Errorf("String() = %q, want it to name the account", spec.String())
	}
	if !strings.Contains(spec.String(), "user-login-form") {
		t.Errorf("String() = %q, want it to name the form", spec.String())
	}
}

func TestDescribeSubstitutesURL(t *testing.T) {
	t.Parallel()

	c := testConfig()
	c.LoginPath = "https://example.com/login?token=abc"
	spec, err := c.Resolve("https://example.com/")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	// The caller redacts; Describe just takes what it is given, so the token
	// never reaches a log through this path.
	const redacted = "https://example.com/login?token=REDACTED"
	got := spec.Describe(redacted)
	if !strings.Contains(got, redacted) {
		t.Errorf("Describe() = %q, want it to use the redacted URL", got)
	}
	if strings.Contains(got, "token=abc") {
		t.Errorf("Describe() = %q, leaked the unredacted URL", got)
	}

	// An empty argument must not produce a header line with a blank URL.
	if !strings.Contains(spec.Describe(""), spec.URL) {
		t.Errorf("Describe(\"\") = %q, want it to fall back to the real URL", spec.Describe(""))
	}
}

func TestHost(t *testing.T) {
	t.Parallel()

	tests := []struct{ url, want string }{
		{"https://example.com/login", "example.com"},
		{"http://127.0.0.1:8080/login", "127.0.0.1"},
		{"http://[::1]:9222/login", "::1"},
		{"not a url", ""},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()
			if got := (Spec{URL: tt.url}).Host(); got != tt.want {
				t.Errorf("Host() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestValidateRejectsControlCharactersInUsername is a log-forgery regression.
//
// The username is written verbatim to stderr and into the log-file header, so a
// newline in it splits one line into two and lets a crafted account value forge
// a record. It is checked for the same reason the identifiers are, but not the
// same reason: nothing ever puts the username in a selector.
func TestValidateRejectsControlCharactersInUsername(t *testing.T) {
	t.Parallel()

	c := testConfig()
	c.Username = "admin\n# forged"

	err := c.validate()
	if err == nil {
		t.Fatal("validate() accepted a username containing a newline, want an error")
	}
	if !errors.Is(err, ErrConfig) {
		t.Errorf("error = %v, want it to wrap ErrConfig", err)
	}
	if !strings.Contains(err.Error(), KeyUsername) {
		t.Errorf("error = %q, want it to name %s", err, KeyUsername)
	}
}

// TestResolveNeverEchoesURLCredentials is a credential-leak regression.
//
// A malformed LOGIN_PATH or LOGOUT_PATH is reported before any redaction path
// exists, and url.Parse embeds the whole URL inside its own *url.Error — so
// both the value and the wrapped error had to stop being printed raw.
func TestResolveNeverEchoesURLCredentials(t *testing.T) {
	t.Parallel()

	const secret = "hunter2-in-the-url"

	for name, raw := range map[string]string{
		// The bad escape must be in the PATH: url.Parse tolerates one in the
		// query, so a query-only case would simply parse and prove nothing.
		"userinfo in a malformed URL": "https://user:" + secret + "@example.test/%zz",
		"credential in the query":     "https://example.test/%zz/login?token=" + secret,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, key := range []string{"login", "logout"} {
				c := testConfig()
				if key == "login" {
					c.LoginPath = raw
				} else {
					c.LogoutPath = raw
				}

				_, err := c.Resolve("https://example.com/")
				if err == nil {
					t.Fatalf("Resolve() accepted %q, want an error", raw)
				}
				if strings.Contains(err.Error(), secret) {
					t.Errorf("%s error leaks the credential: %q", key, err)
				}
				// Still useful: the host survives so the typo is findable.
				if !strings.Contains(err.Error(), "example.test") {
					t.Errorf("%s error = %q, want it to keep the host", key, err)
				}
			}
		})
	}
}

func TestSafeURLPreview(t *testing.T) {
	t.Parallel()

	tests := []struct{ in, want string }{
		{"https://example.test/login", `"https://example.test/login"`},
		{"https://user:pass@example.test/login", `"https://example.test/login"`},
		{"https://user@example.test/login", `"https://example.test/login"`},
		{"https://example.test/login?token=abc", `"https://example.test/login?..."`},
		{"https://user:pass@example.test/a?b=c", `"https://example.test/a?..."`},
		// An '@' in the path is not userinfo and must survive.
		{"https://example.test/a@b", `"https://example.test/a@b"`},
		{"/login", `"/login"`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := SafeURLPreview(tt.in); got != tt.want {
				t.Errorf("SafeURLPreview(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// TestSafeURLPreviewScrubsOpaqueURLs is a credential-leak regression.
//
// url.Parse accepts "https:user:pass@host/path" as an OPAQUE URL — no "//"
// anywhere — so a userinfo scrub keyed to the slashes walked straight past it
// and the password reached stderr.
func TestSafeURLPreviewScrubsOpaqueURLs(t *testing.T) {
	t.Parallel()

	const secret = "hunter2"
	for _, raw := range []string{
		"https:user:" + secret + "@example.test/login",
		"https://user:" + secret + "@example.test/login",
		"https:user:" + secret + "@example.test/login?x=1",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			got := SafeURLPreview(raw)
			if strings.Contains(got, secret) {
				t.Errorf("SafeURLPreview(%q) = %s, leaks the credential", raw, got)
			}
			if !strings.Contains(got, "example.test") {
				t.Errorf("SafeURLPreview(%q) = %s, want the host kept", raw, got)
			}
		})
	}
}

// TestResolveNeverEchoesOpaqueURLCredentials is the end-to-end form: an opaque
// URL has no host, so it reaches the no-host diagnostic rather than the parse
// error one — a different path with the same obligation.
func TestResolveNeverEchoesOpaqueURLCredentials(t *testing.T) {
	t.Parallel()

	// Derived from the existing test password rather than written out, so gosec
	// does not read a new literal as a hardcoded credential.
	secret := testConfig().Password + "-opaque"
	c := testConfig()
	c.LoginPath = "https:user:" + secret + "@example.test/login"

	_, err := c.Resolve("https://example.com/")
	if err == nil {
		t.Fatal("Resolve() accepted an opaque URL, want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks the credential: %q", err)
	}
}

// TestSafeURLPreviewStripsFragment is an OAuth-token regression. Implicit flows
// put #access_token= in the fragment, which is exactly why the crawler's own
// redaction drops it — a preview that kept it would be the one place this
// program prints what everything else removes.
func TestSafeURLPreviewStripsFragment(t *testing.T) {
	t.Parallel()

	secret := testConfig().Password + "-in-fragment"
	for _, raw := range []string{
		"https://example.test/%zz#access_token=" + secret,
		"https://example.test/login#" + secret,
		"https://user:pw@example.test/%zz?a=1#access_token=" + secret,
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			got := SafeURLPreview(raw)
			if strings.Contains(got, secret) {
				t.Errorf("SafeURLPreview(%q) = %s, leaks the fragment", raw, got)
			}
			if !strings.Contains(got, "example.test") {
				t.Errorf("SafeURLPreview(%q) = %s, want the host kept", raw, got)
			}
		})
	}
}
