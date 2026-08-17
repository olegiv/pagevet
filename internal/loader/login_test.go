package loader

import (
	"strings"
	"testing"
)

// These are the security tests for the login feature, and they need no browser.
//
// internal/login deliberately accepts almost anything in LOGIN_FORM_ID,
// USERNAME_NAME and PASSWORD_NAME, because `user[email]` is an ordinary Rails
// or PHP field name. That makes the escaping here — not a config allowlist —
// the thing standing between a hostile .env and a password typed into an
// element of its choosing.

// hostile is the corpus both escapers must neutralize. Each entry is a value
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

func TestJSString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{`form`, `"form"`},
		{`user[email]`, `"user[email]"`},
		{`a"b`, `"a\"b"`},
		{`a\b`, `"a\\b"`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := jsString(tt.in); got != tt.want {
				t.Errorf("jsString(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// TestJSStringNeutralizesInjection pins the same property for the JavaScript
// side, which is where the form id ends up via document.getElementById.
func TestJSStringNeutralizesInjection(t *testing.T) {
	t.Parallel()

	for _, v := range hostile {
		t.Run(v, func(t *testing.T) {
			t.Parallel()

			got := jsString(v)
			if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
				t.Fatalf("jsString(%q) = %s, want a quoted literal", v, got)
			}
			body := got[1 : len(got)-1]
			for i := 0; i < len(body); i++ {
				switch body[i] {
				case '\\':
					i++
				case '"':
					t.Errorf("jsString(%q) = %s has an unescaped quote at %d", v, got, i)
				}
			}
		})
	}
}

// TestJSSubmitFormEscapesID checks the expression actually built for the
// submit fallbacks, since that is a second place the form id reaches the page.
func TestJSSubmitFormEscapesID(t *testing.T) {
	t.Parallel()

	expr := jsSubmitForm(`x"); alert(1); (`, "requestSubmit")
	if strings.Contains(expr, `getElementById("x"); alert(1); (")`) {
		t.Fatalf("jsSubmitForm built an injectable expression: %s", expr)
	}
	if !strings.Contains(expr, `getElementById("x\"); alert(1); (")`) {
		t.Errorf("jsSubmitForm did not escape the id: %s", expr)
	}
}

func TestChangedCookies(t *testing.T) {
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

			got := changedCookies(tt.before, tt.after)
			if len(got) != len(tt.want) {
				t.Fatalf("changedCookies() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("changedCookies() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestCookieName(t *testing.T) {
	t.Parallel()

	if got, want := cookieName("SSESS\x00.example.com/"), "SSESS"; got != want {
		t.Errorf("cookieName() = %q, want %q", got, want)
	}
	if got, want := cookieName("bare"), "bare"; got != want {
		t.Errorf("cookieName() = %q, want %q", got, want)
	}
}
