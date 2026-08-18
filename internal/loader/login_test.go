package loader

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// These are the security tests for the login feature, and they need no browser.
//
// internal/login deliberately accepts almost anything in LOGIN_FORM_ID,
// USERNAME_NAME and PASSWORD_NAME, because `user[email]` is an ordinary Rails
// or PHP field name. What stands between a hostile .env and a password typed
// into an element of its choosing is therefore here, and it is two different
// mechanisms for two different targets:
//
//   - CSS selectors are built by ESCAPING, since a selector has to be a string.
//   - JavaScript is never built at all. Every evaluated expression is a
//     constant function applied to a JSON argument array, so a value is data
//     the engine binds rather than program text.

// hostile is the corpus both mechanisms must neutralize. Each entry is a value
// that, interpolated raw, would end one string or selector and start another.
var hostile = []string{
	`x"] , [name="pass`,
	`x'] , [name='pass`,
	`x"><script>fetch(1)</script>`,
	`x\"`,
	`x\`,
	`form, script`,
	`" or "1`,
	"x`y",
	"x y",
	"x#y",
	"x.y z",
	`*`,
	`]`,
	`[`,
}

func TestCSSString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{`name`, `"name"`},
		{`user[email]`, `"user[email]"`}, // brackets need no escaping inside a string
		{`form.field`, `"form.field"`},
		{`ns:field`, `"ns:field"`},
		{``, `""`},

		// The two characters that actually terminate a CSS string.
		{`a"b`, `"a\"b"`},
		{`a\b`, `"a\\b"`},
		{`x"] , [name="pass`, `"x\"] , [name=\"pass"`},

		// Non-ASCII passes through unchanged. This is why %q is not used: it
		// would emit é, which CSS reads as a hex escape and mangles.
		{`café`, `"café"`},
		{`пароль`, `"пароль"`},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := cssString(tt.in); got != tt.want {
				t.Errorf("cssString(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// TestCSSStringNeutralizesInjection is the property that matters: whatever goes
// in, the result is ONE quoted string. If a value could close its own quote,
// the selector it lands in would gain a second clause.
func TestCSSStringNeutralizesInjection(t *testing.T) {
	t.Parallel()

	for _, v := range hostile {
		t.Run(v, func(t *testing.T) {
			t.Parallel()

			got := cssString(v)
			if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
				t.Fatalf("cssString(%q) = %s, want it wrapped in quotes", v, got)
			}

			// Walk the body and confirm every quote is escaped: an unescaped
			// one would end the string early, and everything after it would be
			// read as selector syntax.
			body := got[1 : len(got)-1]
			for i := 0; i < len(body); i++ {
				switch body[i] {
				case '\\':
					i++ // whatever follows is escaped, including a backslash
				case '"':
					t.Errorf("cssString(%q) = %s has an unescaped quote at %d", v, got, i)
				}
			}
		})
	}
}

func TestJSCall(t *testing.T) {
	t.Parallel()

	got, err := jsCall("function (a, b) { return a + b; }", "x", "y")
	if err != nil {
		t.Fatalf("jsCall() error = %v", err)
	}
	const want = `(function (a, b) { return a + b; }).apply(null, ["x","y"])`
	if got != want {
		t.Errorf("jsCall() = %s, want %s", got, want)
	}
}

// TestJSCallNeutralizesInjection is the security property, and it is a stronger
// one than the escaping it replaced: the JavaScript SOURCE is a constant, so a
// hostile value is an argument the engine binds rather than text spliced into a
// program. There is no quoted context for it to close.
func TestJSCallNeutralizesInjection(t *testing.T) {
	t.Parallel()

	const fn = "function (id) { return document.getElementById(id); }"

	for _, v := range hostile {
		t.Run(v, func(t *testing.T) {
			t.Parallel()

			got, err := jsCall(fn, v)
			if err != nil {
				t.Fatalf("jsCall(%q) error = %v", v, err)
			}
			// The function source must survive byte for byte: if a value could
			// alter it, that is the injection.
			if !strings.HasPrefix(got, "("+fn+").apply(null, [") {
				t.Fatalf("jsCall(%q) altered the function source: %s", v, got)
			}
			// And the argument array must be valid JSON holding exactly the
			// value handed in — no more, no fewer.
			arr := strings.TrimSuffix(strings.TrimPrefix(got, "("+fn+").apply(null, "), ")")
			var back []string
			if err := json.Unmarshal([]byte(arr), &back); err != nil {
				t.Fatalf("argument array is not valid JSON: %s: %v", arr, err)
			}
			if len(back) != 1 || back[0] != v {
				t.Errorf("round trip changed the value: got %q, want %q", back, v)
			}
		})
	}
}

// TestEvaluatedJSIsConstant is a guard against the old shape creeping back: the
// four expressions this package evaluates must be constants, carrying no part
// of any value the user configured.
func TestEvaluatedJSIsConstant(t *testing.T) {
	t.Parallel()

	const hostileID = `x"); alert(1); (`

	for name, fn := range map[string]string{
		"jsFormAbsent":          jsFormAbsent,
		"jsRequestSubmit":       jsRequestSubmit,
		"jsSubmitDestination":   jsSubmitDestination,
		"jsMarkClickableSubmit": jsMarkClickableSubmit,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := jsCall(fn, hostileID, submitMarker, submitControls)
			if err != nil {
				t.Fatalf("jsCall(%s) error = %v", name, err)
			}
			if !strings.Contains(got, fn) {
				t.Errorf("%s: the function source did not survive interpolation", name)
			}
			if strings.Contains(got, `alert(1); (")`) {
				t.Errorf("%s: the hostile id escaped its argument: %s", name, got)
			}
		})
	}
}

func TestChangedNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		before, after map[string]string
		want          []string
	}{
		{
			name:   "a brand new cookie",
			before: map[string]string{},
			after:  map[string]string{"SSESS\x00.example.com/": "aaaa"},
			want:   []string{"SSESS"},
		},
		{
			// THE regression: a PHP/Express flow where the login page hands out
			// an anonymous session and the POST authenticates that same one.
			// The name never changes, so a name-only check saw nothing.
			name:   "same name, rotated value",
			before: map[string]string{"PHPSESSID\x00.example.com/": "aaaa"},
			after:  map[string]string{"PHPSESSID\x00.example.com/": "bbbb"},
			want:   []string{"PHPSESSID"},
		},
		{
			name:   "nothing changed",
			before: map[string]string{"PHPSESSID\x00.example.com/": "aaaa"},
			after:  map[string]string{"PHPSESSID\x00.example.com/": "aaaa"},
			want:   nil,
		},
		{
			name:   "a cookie only removed is not a change we act on",
			before: map[string]string{"old\x00.example.com/": "aaaa"},
			after:  map[string]string{},
			want:   nil,
		},
		{
			// Same name on two hosts must not mask one another.
			name: "same name, different domain",
			before: map[string]string{
				"sid\x00.a.example/": "aaaa",
			},
			after: map[string]string{
				"sid\x00.a.example/": "aaaa",
				"sid\x00.b.example/": "cccc",
			},
			want: []string{"sid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := changedNames(tt.before, tt.after)
			if len(got) != len(tt.want) {
				t.Fatalf("changedNames() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("changedNames() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestEntryName(t *testing.T) {
	t.Parallel()

	if got, want := entryName("SSESS\x00.example.com/"), "SSESS"; got != want {
		t.Errorf("entryName() = %q, want %q", got, want)
	}
	if got, want := entryName("bare"), "bare"; got != want {
		t.Errorf("entryName() = %q, want %q", got, want)
	}
}

// TestCheckHostOnceMemoizes is a budget regression, not a correctness one.
//
// A sign-in validates up to five addresses — the logout page, the login page,
// the form target before and after filling, and where the submission landed —
// and on a real site they are all the same host. Each uncached check is a DNS
// lookup; against an mDNS ".local" name those cost seconds apiece and were
// enough to spend the whole per-URL budget resolving one name repeatedly.
func TestCheckHostOnceMemoizes(t *testing.T) {
	t.Parallel()

	var calls int
	b := &Browser{opts: Options{
		CheckHost: func(context.Context, string) error {
			calls++
			return nil
		},
	}}

	for range 5 {
		if err := b.checkHostOnce(t.Context(), "example.com"); err != nil {
			t.Fatalf("checkHostOnce() error = %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("CheckHost called %d times for one host, want 1", calls)
	}

	// A different host is still its own question.
	if err := b.checkHostOnce(t.Context(), "other.example"); err != nil {
		t.Fatalf("checkHostOnce() error = %v", err)
	}
	if calls != 2 {
		t.Errorf("CheckHost called %d times for two hosts, want 2", calls)
	}
}

// TestCheckHostOnceRemembersRejection keeps the cache from being a way past the
// policy: a blocked host stays blocked on every later check.
func TestCheckHostOnceRemembersRejection(t *testing.T) {
	t.Parallel()

	blocked := errors.New("blocked by the address policy")
	b := &Browser{opts: Options{
		CheckHost: func(_ context.Context, host string) error {
			if host == "169.254.169.254" {
				return blocked
			}
			return nil
		},
	}}

	for i := range 3 {
		if err := b.checkHostOnce(t.Context(), "169.254.169.254"); !errors.Is(err, blocked) {
			t.Errorf("check %d = %v, want the rejection to persist", i, err)
		}
	}
}

// TestCheckHostOnceDoesNotCacheACanceledCheck matters because CheckHost reports
// a canceled lookup as "no opinion". Remembering that would let one interrupted
// check bless a host for the rest of the run.
func TestCheckHostOnceDoesNotCacheACanceledCheck(t *testing.T) {
	t.Parallel()

	var calls int
	b := &Browser{opts: Options{
		CheckHost: func(context.Context, string) error {
			calls++
			return nil
		},
	}}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_ = b.checkHostOnce(ctx, "example.com")

	// A later check on a live context must ask again.
	_ = b.checkHostOnce(t.Context(), "example.com")
	if calls != 2 {
		t.Errorf("CheckHost called %d times, want 2: a canceled check must not be cached", calls)
	}
}

// TestSnapshotChangedSince covers the origin rule, which is the subtle half of
// treating web storage as session evidence.
func TestSnapshotChangedSince(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		before, after snapshot
		want          []string
	}{
		{
			name:   "a cookie changed",
			before: snapshot{origin: "https://a.test", cookies: map[string]string{"sid\x00.a/": "1"}},
			after:  snapshot{origin: "https://a.test", cookies: map[string]string{"sid\x00.a/": "2"}},
			want:   []string{"sid"},
		},
		{
			// The token-backed SPA: no cookie anywhere, a token appears.
			name:   "storage changed on the same origin",
			before: snapshot{origin: "https://a.test", cookies: map[string]string{}, storage: map[string]string{}},
			after: snapshot{origin: "https://a.test", cookies: map[string]string{},
				storage: map[string]string{"localStorage:access_token\x00": "abc"}},
			want: []string{"localStorage:access_token"},
		},
		{
			// THE false positive this rule exists to prevent. Storage is
			// per-origin, so after a redirect elsewhere every key looks new —
			// and a failed login would have been declared a success.
			name:   "storage ignored when the origin moved",
			before: snapshot{origin: "https://a.test", cookies: map[string]string{}, storage: map[string]string{"localStorage:x\x00": "1"}},
			after: snapshot{origin: "https://b.test", cookies: map[string]string{},
				storage: map[string]string{"localStorage:y\x00": "2", "localStorage:z\x00": "3"}},
			want: nil,
		},
		{
			// A cookie change still counts across an origin move: the jar is
			// not scoped the way storage is.
			name:   "cookies still count when the origin moved",
			before: snapshot{origin: "https://a.test", cookies: map[string]string{}},
			after:  snapshot{origin: "https://b.test", cookies: map[string]string{"sid\x00.b/": "1"}},
			want:   []string{"sid"},
		},
		{
			name:   "unreadable storage is not evidence",
			before: snapshot{origin: "", cookies: map[string]string{}, storage: map[string]string{}},
			after:  snapshot{origin: "", cookies: map[string]string{}, storage: map[string]string{"localStorage:x\x00": "1"}},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.after.changedSince(tt.before)
			if len(got) != len(tt.want) {
				t.Fatalf("changedSince() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("changedSince() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

// TestDisplayTargetDropsTheQuery is a credential-leak regression.
//
// A form with method="get" puts the configured field names in the query, and
// those are whatever the .env says. verdict.RedactURL blanks a fixed list of
// credential-like parameter names, which does not include user[password] — an
// explicitly supported field name. So the query is dropped outright rather than
// redacted whenever a URL the browser navigated to is printed.
func TestDisplayTargetDropsTheQuery(t *testing.T) {
	t.Parallel()

	b := &Browser{opts: Options{RedactURLs: true}}

	const secret = "hunter2-in-the-query"
	tests := []struct {
		name, in string
		wantOmit bool
	}{
		{"password in a non-standard field", "https://x.test/login?user%5Bpassword%5D=" + secret, true},
		{"password in a plain field", "https://x.test/login?pass=" + secret, true},
		{"no query at all", "https://x.test/login", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := b.displayTarget(tt.in)
			if strings.Contains(got, secret) {
				t.Errorf("displayTarget(%q) = %q, leaks the credential", tt.in, got)
			}
			if tt.wantOmit && !strings.Contains(got, "query omitted") {
				t.Errorf("displayTarget(%q) = %q, want it to say the query was omitted", tt.in, got)
			}
			// It still has to be useful: host and path survive.
			if !strings.Contains(got, "x.test/login") {
				t.Errorf("displayTarget(%q) = %q, want the host and path kept", tt.in, got)
			}
		})
	}
}
