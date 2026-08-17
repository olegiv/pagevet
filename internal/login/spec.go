package login

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// identRE is the allowlist for the three values that reach the browser as part
// of a CSS selector: the form id and the two field names.
//
// This is a security control, not tidiness. internal/loader builds selectors
// like `#FormID input[name="UserField"]`, so a .env carrying
//
//	LOGIN_FORM_ID=x"] , [name="pass
//
// would otherwise break out of the attribute selector and retarget the typing
// at an element of the file's choosing. A positive allowlist closes that the
// same way internal/input's scheme allowlist closes URL smuggling, and it costs
// nothing real: these are HTML identifiers, and every character HTML actually
// uses for one is here.
var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_:.\-]*$`)

// Config is a parsed, self-consistent .env. Everything in it is validated
// except the login URL, which cannot be settled until the URL list is read —
// LOGIN_PATH may be a bare path that resolves against the first entry.
type Config struct {
	path string // where this came from, for error messages

	LoginPath string

	// LogoutPath is optional. When set, pagevet loads it before the login page,
	// so the sign-in always starts from a signed-out state.
	LogoutPath string

	FormID    string
	UserField string
	PassField string
	Username  string
	Password  string
}

// Spec is a fully resolved login: everything internal/loader needs to sign in,
// with the login URL now absolute.
type Spec struct {
	// URL is the absolute http(s) URL of the page carrying the login form.
	URL string

	// LogoutURL is loaded before URL, to guarantee the sign-in starts signed
	// out. Empty — the default, and the value when LOGOUT_PATH is absent —
	// skips that step entirely.
	LogoutURL string

	// FormID is the id attribute of the <form> element. It is also the element
	// whose disappearance after submit is half of the success check.
	FormID string

	// UserField and PassField are the name attributes of the two inputs.
	UserField string
	PassField string

	// Username is the account to sign in as.
	Username string

	// Password is the only secret in the program. It is never logged, never
	// interpolated into JavaScript, and never included in an error message.
	// String omits it; see that method's comment.
	Password string
}

// validate checks everything that does not need the URL list.
func (c Config) validate() error {
	for _, f := range []struct {
		key, val string
	}{
		{KeyFormID, c.FormID},
		{KeyUserField, c.UserField},
		{KeyPassField, c.PassField},
	} {
		if !identRE.MatchString(f.val) {
			return fmt.Errorf(
				"%w: %s: %s=%q is not a valid HTML identifier "+
					"(letters, digits and _ : . - only, starting with a letter or _)",
				ErrConfig, display(c.path), f.key, clip(f.val))
		}
	}
	if c.UserField == c.PassField {
		return fmt.Errorf("%w: %s: %s and %s are both %q; they must name different inputs",
			ErrConfig, display(c.path), KeyUserField, KeyPassField, c.UserField)
	}
	return nil
}

// Resolve turns LOGIN_PATH, and LOGOUT_PATH when present, into absolute URLs.
//
// Either may be given in either form:
//
//	https://staging.example.com/login   used as-is
//	/login                              resolved against firstURL's origin
//
// firstURL is the first entry of the input list, already parsed and validated
// by internal/input. Only its scheme and host are used, so a login page never
// inherits a path or query from whichever URL happened to sort first.
func (c Config) Resolve(firstURL string) (Spec, error) {
	loginURL, err := c.resolveOne(KeyLoginPath, c.LoginPath, firstURL)
	if err != nil {
		return Spec{}, err
	}

	// LOGOUT_PATH is optional, and an absent one is not a failure: it means the
	// run simply does not visit a logout page first.
	var logoutURL string
	if c.LogoutPath != "" {
		logoutURL, err = c.resolveOne(KeyLogoutPath, c.LogoutPath, firstURL)
		if err != nil {
			return Spec{}, err
		}
	}

	return Spec{
		URL:       loginURL,
		LogoutURL: logoutURL,
		FormID:    c.FormID,
		UserField: c.UserField,
		PassField: c.PassField,
		Username:  c.Username,
		Password:  c.Password,
	}, nil
}

// resolveOne turns one path-or-URL value into an absolute http(s) URL.
//
// key names the .env entry being resolved, so a failure points at the line the
// user has to go and edit rather than at "a URL".
func (c Config) resolveOne(key, value, firstURL string) (string, error) {
	ref, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %s=%q is not a valid URL or path: %w",
			ErrConfig, display(c.path), key, clip(value), err)
	}

	if !ref.IsAbs() {
		base, err := url.Parse(firstURL)
		if err != nil {
			return "", fmt.Errorf("%w: %s is a path, so it resolves against the first URL "+
				"in the input file, but %q does not parse: %w",
				ErrConfig, key, clip(firstURL), err)
		}
		// Origin only. ResolveReference against the full first URL would let a
		// relative path land somewhere that depends on that URL's path, which
		// is a surprise nobody wants to debug.
		origin := &url.URL{Scheme: base.Scheme, Host: base.Host}
		ref = origin.ResolveReference(ref)
	}

	// Same positive allowlist the crawler applies to every input URL. A
	// file:// or javascript: login page is not a thing, and rejecting it here
	// keeps the .env from being a way around internal/input's scheme check.
	if ref.Scheme != "http" && ref.Scheme != "https" {
		return "", fmt.Errorf("%w: %s: %s resolves to %q, but only http and https are allowed",
			ErrConfig, display(c.path), key, clip(ref.Scheme+"://"+ref.Host))
	}
	if ref.Host == "" {
		return "", fmt.Errorf("%w: %s: %s=%q has no host",
			ErrConfig, display(c.path), key, clip(value))
	}
	return ref.String(), nil
}

// Host returns the login URL's host, for the caller's address policy check.
func (s Spec) Host() string { return hostOf(s.URL) }

// LogoutHost returns the logout URL's host, or "" when there is no logout step.
// It is separate because LOGOUT_PATH may point at a different origin, and the
// caller has to run the address policy over both.
func (s Spec) LogoutHost() string {
	if s.LogoutURL == "" {
		return ""
	}
	return hostOf(s.LogoutURL)
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// String renders the Spec for a log header or a progress line.
//
// The password is not merely masked here, it is absent: there is no format
// verb, no length, no hint. This is the method every caller reaches for when it
// wants to say what pagevet did, so it is the one place a password would
// plausibly escape into a file that outlives the run.
//
// Callers that log a URL should pass the result of verdict.RedactURL as the
// url argument rather than calling this on a Spec holding a userinfo URL.
func (s Spec) String() string {
	return fmt.Sprintf("%s at %s (form %s)", s.Username, s.URL, s.FormID)
}

// GoString implements fmt.GoStringer.
//
// String is not enough on its own: %#v ignores Stringer and prints every field
// of the struct verbatim, password included. %#v is also precisely the verb
// somebody reaches for while debugging, which makes it the likeliest way for a
// credential to end up pasted into an issue. Implementing this closes the last
// fmt-shaped hole; the field list is kept identical to the default rendering so
// that the only visible difference is the redaction.
func (s Spec) GoString() string {
	return fmt.Sprintf(
		"login.Spec{URL:%q, LogoutURL:%q, FormID:%q, UserField:%q, PassField:%q, "+
			"Username:%q, Password:REDACTED}",
		s.URL, s.LogoutURL, s.FormID, s.UserField, s.PassField, s.Username)
}

// Describe renders the Spec with an already-redacted URL substituted in, which
// is what the report header wants: the same provenance line, but with the URL
// having been through the crawler's own redaction.
func (s Spec) Describe(redactedURL string) string {
	if strings.TrimSpace(redactedURL) == "" {
		redactedURL = s.URL
	}
	return fmt.Sprintf("%s at %s (form %s)", s.Username, redactedURL, s.FormID)
}
