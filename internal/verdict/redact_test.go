package verdict

import (
	"net/url"
	"strings"
	"testing"
)

// mustParse re-parses a redacted URL so assertions are made on its semantics.
// Comparing raw strings would be brittle: url.Values.Encode sorts keys, so a
// full-string compare fails on parameter order rather than on redaction.
func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("re-parsing redacted URL %q: %v", raw, err)
	}
	return u
}

// TestRedactURL_StripsEveryCredentialSurface covers all three leaks at once:
// userinfo, fragment, and credential-like query values.
func TestRedactURL_StripsEveryCredentialSurface(t *testing.T) {
	t.Parallel()

	got := RedactURL("https://u:p@h/x?access_token=abc&q=1#access_token=z")
	u := mustParse(t, got)

	// The placeholder round-trips as %2A%2A%2A, so read it back decoded rather
	// than looking for a literal "***@" in the string.
	if u.User == nil || u.User.Username() != RedactedUser {
		t.Errorf("userinfo = %v, want %q", u.User, RedactedUser)
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		t.Error("redacted URL still carries a password")
	}
	if u.Fragment != "" || strings.Contains(got, "#") {
		t.Errorf("fragment survived in %q", got)
	}

	q := u.Query()
	if q.Get("access_token") != RedactedValue {
		t.Errorf("access_token = %q, want %q", q.Get("access_token"), RedactedValue)
	}
	if q.Get("q") != "1" {
		t.Errorf("q = %q, want %q (non-credential parameters must survive)", q.Get("q"), "1")
	}
	if u.Host != "h" || u.Path != "/x" {
		t.Errorf("host/path = %q/%q, want %q/%q", u.Host, u.Path, "h", "/x")
	}
}

func TestRedactURL_KeyMatchingIsCaseInsensitiveAndExact(t *testing.T) {
	t.Parallel()

	got := RedactURL("https://example.test/a?ACCESS_TOKEN=x&Api_Key=y&tokenizer=z&sig=s")
	q := mustParse(t, got).Query()

	for _, key := range []string{"ACCESS_TOKEN", "Api_Key", "sig"} {
		if q.Get(key) != RedactedValue {
			t.Errorf("%s = %q, want %q", key, q.Get(key), RedactedValue)
		}
	}
	// Partial matching would redact half of every analytics URL.
	if q.Get("tokenizer") != "z" {
		t.Errorf("tokenizer = %q, want %q — only exact key matches are credentials", q.Get("tokenizer"), "z")
	}
}

func TestRedactURL_RedactsEveryValueOfARepeatedKey(t *testing.T) {
	t.Parallel()

	q := mustParse(t, RedactURL("https://example.test/a?token=one&token=two")).Query()
	want := []string{RedactedValue, RedactedValue}
	got := q["token"]
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("token values = %v, want %v", got, want)
	}
}

// TestRedactURL_EmptyCredentialValueIsLeftAlone: there is nothing to hide, and
// rewriting the query for nothing would reorder it in the logs.
func TestRedactURL_EmptyCredentialValueIsLeftAlone(t *testing.T) {
	t.Parallel()

	const raw = "https://example.test/a?token=&q=1"
	if got := RedactURL(raw); got != raw {
		t.Errorf("RedactURL(%q) = %q, want it unchanged", raw, got)
	}
}

func TestRedactURL_Idempotent(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://u:p@h/x?access_token=abc&q=1#access_token=z",
		"https://example.test/a?ACCESS_TOKEN=x&tokenizer=z",
		"https://example.test/a/b?q=1",
		"http://%zz/path#frag",
		"",
	} {
		once := RedactURL(raw)
		if twice := RedactURL(once); twice != once {
			t.Errorf("RedactURL is not idempotent for %q: %q -> %q", raw, once, twice)
		}
	}
}

func TestRedactURL_NoCredentialsIsUnchanged(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://example.test/a/b?q=1&r=2",
		"https://example.test/",
		"https://example.test/path%20with%20space",
	} {
		if got := RedactURL(raw); got != raw {
			t.Errorf("RedactURL(%q) = %q, want it unchanged", raw, got)
		}
	}
}

func TestRedactURL_UnparseableIsSafelyRedacted(t *testing.T) {
	t.Parallel()

	// "%zz" is an invalid percent-escape, which makes url.Parse reject the
	// whole string and sends RedactURL down its by-hand path.
	fixtures := []string{"http://user:pass@host/%zz?password=SECRET#frag", "http://%zz/path"}
	for _, raw := range fixtures {
		if _, err := url.Parse(raw); err == nil {
			t.Fatalf("fixture %q parses cleanly; it no longer exercises the fallback", raw)
		}
	}

	if got, want := RedactURL(fixtures[0]), "http://redacted@host/%zz?password=REDACTED"; got != want {
		t.Errorf("RedactURL(%q) = %q, want %q", fixtures[0], got, want)
	}
	if got, want := RedactURL(fixtures[1]), "http://%zz/path"; got != want {
		t.Errorf("RedactURL(%q) = %q, want %q", fixtures[1], got, want)
	}
}

func TestRedactURL_MalformedQueryDoesNotBypassRedaction(t *testing.T) {
	t.Parallel()

	raw := "https://example.test/cb?access_token=SECRET%zz&keep=%zz"
	got := RedactURL(raw)
	if strings.Contains(got, "SECRET") {
		t.Fatalf("RedactURL(%q) = %q, still contains the credential", raw, got)
	}
	if want := "https://example.test/cb?access_token=REDACTED&keep=%zz"; got != want {
		t.Errorf("RedactURL(%q) = %q, want %q", raw, got, want)
	}
}

func TestRedactText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "redacts a URL embedded in an exception message",
			in:   "TypeError: failed to fetch https://api.example.test/v1?access_token=abc123 in handler",
			want: "TypeError: failed to fetch https://api.example.test/v1?access_token=REDACTED in handler",
		},
		{
			name: "redacts every URL in the string",
			in:   "from https://a.example.test/?token=1 to https://b.example.test/?api_key=2",
			want: "from https://a.example.test/?token=REDACTED to https://b.example.test/?api_key=REDACTED",
		},
		{
			// Stack frames wrap the URL in parentheses; the match must stop at
			// the closing paren rather than swallowing it.
			name: "stops at the punctuation that ends a stack frame",
			in:   "at fetchIt (https://example.test/app.js:12:3)",
			want: "at fetchIt (https://example.test/app.js:12:3)",
		},
		{
			// The frame's trailing ":12:3" is part of the query value as far as
			// url.Parse is concerned, so it disappears with the secret. Losing
			// a line number beats leaking a key.
			name: "line and column glued to a credential value go with it",
			in:   "at fetchIt (https://example.test/app.js?key=secret:12:3)",
			want: "at fetchIt (https://example.test/app.js?key=REDACTED)",
		},
		{
			name: "leaves text without URLs alone",
			in:   "Uncaught ReferenceError: x is not defined",
			want: "Uncaught ReferenceError: x is not defined",
		},
		{
			name: "redacts malformed embedded URL",
			in:   "failed at https://user:pass@example.test/%zz?password=SECRET#fragment after",
			want: "failed at https://redacted@example.test/%zz?password=REDACTED after",
		},
		{
			name: "empty stays empty",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactText(tt.in); got != tt.want {
				t.Errorf("RedactText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRedactText_FragmentInEmbeddedURL: OAuth implicit flows put the token in
// the fragment, which is exactly the case a text-embedded URL leaks.
func TestRedactText_FragmentInEmbeddedURL(t *testing.T) {
	t.Parallel()

	got := RedactText("redirected to https://example.test/cb#access_token=sekrit now")
	if strings.Contains(got, "sekrit") {
		t.Errorf("RedactText() = %q, still carries the fragment token", got)
	}
	if !strings.HasPrefix(got, "redirected to ") || !strings.HasSuffix(got, " now") {
		t.Errorf("RedactText() = %q, want the surrounding text preserved", got)
	}
}
