package login

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// controlChars matches the characters that have no business in an HTML id or
// name attribute and would corrupt any selector or script they were pasted
// into: C0 controls, DEL, and the Unicode line separators.
//
// This is the ONLY restriction on these three values, and it is a sanity check
// rather than the security boundary. The boundary is escaping: internal/loader
// puts them inside quoted CSS attribute selectors and JSON-encoded JavaScript
// string literals, so `x"] , [name="pass` is neutralized by being escaped, not
// by being rejected.
//
// An allowlist was tried first and was wrong. Rails and PHP forms routinely use
// nested parameter names — `user[email]`, `user[password]` — which are entirely
// valid `name` attributes, and refusing them rejected working configurations
// before Chrome even started.
var controlChars = regexp.MustCompile(`[\x00-\x1f\x7f\x{2028}\x{2029}]`)

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
		// The username is here for a different reason than the other three. It
		// is not a selector — it is written verbatim to stderr and into the
		// log-file header, so a newline in it forges a log line. A value like
		// "admin\n# forged" is exactly the shape that does it. The password is
		// NOT checked, because it is never written anywhere and a control
		// character in one is legal.
		{KeyUsername, c.Username},
	} {
		if f.val == "" {
			return fmt.Errorf("%w: %s: %s is empty", ErrConfig, display(c.path), f.key)
		}
		if controlChars.MatchString(f.val) {
			return fmt.Errorf(
				"%w: %s: %s=%q contains a control character, which cannot appear in an "+
					"HTML id or name attribute",
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
		// Neither the value nor the error is printed as-is. A URL may carry
		// userinfo or a credential-like query value, and url.Parse wraps the
		// whole URL inside its own *url.Error - so quoting either would put
		// credentials on stderr before any redaction path exists.
		return "", fmt.Errorf("%w: %s: %s=%s is not a valid URL or path: %s",
			ErrConfig, display(c.path), key, safeURLPreview(value), parseReason(err))
	}

	if !ref.IsAbs() {
		base, err := url.Parse(firstURL)
		if err != nil {
			return "", fmt.Errorf("%w: %s is a path, so it resolves against the first URL "+
				"in the input file, but %s does not parse: %s",
				ErrConfig, key, safeURLPreview(firstURL), parseReason(err))
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
		return "", fmt.Errorf("%w: %s: %s=%s has no host",
			ErrConfig, display(c.path), key, safeURLPreview(value))
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

// safeURLPreview renders a URL for an error message with the two places
// credentials hide removed: the userinfo, and the query values.
//
// It works on a string that may not parse, which is exactly when it is needed —
// the redaction in internal/verdict operates on a parsed URL and is unavailable
// here anyway, since this package imports nothing outside the standard library.
// Scheme, host and path survive, which is what a user needs to spot the typo.
func safeURLPreview(raw string) string {
	s := raw

	// Userinfo is scrubbed whether or not the URL has an authority component.
	// url.Parse accepts "https:user:hunter2@example.test/login" as an OPAQUE
	// URL — no "//" anywhere — and a scrub keyed to "//" walked straight past
	// it, putting the password on stderr. So the search starts after the scheme
	// separator and does not require the slashes.
	start := 0
	if colon := strings.IndexByte(s, ':'); colon >= 0 {
		start = colon + 1
	}
	start += len(leadingSlashes(s[start:]))

	rest := s[start:]
	// Userinfo ends at the first '@' BEFORE the first '/', so an '@' in the
	// path is left alone.
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		if slash := strings.IndexByte(rest, '/'); slash < 0 || at < slash {
			s = s[:start] + rest[at+1:]
		}
	}
	if q := strings.IndexByte(s, '?'); q >= 0 {
		s = s[:q] + "?..."
	}
	return strconv.Quote(clip(s))
}

// leadingSlashes returns the run of '/' at the start of s, so the userinfo
// search can skip an authority's "//" when there is one and skip nothing when
// there is not.
func leadingSlashes(s string) string {
	i := 0
	for i < len(s) && s[i] == '/' {
		i++
	}
	return s[:i]
}

// parseReason extracts the reason from a *url.Error without its URL field,
// which holds the whole value the caller is trying not to print.
func parseReason(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err.Error()
	}
	return err.Error()
}
