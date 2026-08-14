package verdict

import (
	"net/url"
	"regexp"
	"strings"
)

// RedactedValue replaces the value of a credential-like query parameter. The
// key survives so logs stay diagnosable — knowing a request carried an
// access_token is useful; knowing its value is a liability.
const RedactedValue = "REDACTED"

// RedactedUser replaces the userinfo component.
//
// It is a bare word rather than something like "***" on purpose: url.URL.String
// percent-encodes userinfo, so "***" would render as "%2A%2A%2A@host" and make
// every redacted log line harder to read than the thing it replaced.
const RedactedUser = "redacted"

// credentialKeys are the query-parameter names whose VALUES are redacted.
// Matching is case-insensitive and exact: "token" matches, "tokenizer" does
// not, because partial matching would redact half of every analytics URL.
var credentialKeys = map[string]bool{
	"access_token":         true,
	"api_key":              true,
	"apikey":               true,
	"auth":                 true,
	"bearer":               true,
	"code":                 true,
	"id_token":             true,
	"jwt":                  true,
	"key":                  true,
	"password":             true,
	"passwd":               true,
	"pwd":                  true,
	"refresh_token":        true,
	"sas":                  true,
	"secret":               true,
	"session":              true,
	"sessionid":            true,
	"sig":                  true,
	"signature":            true,
	"token":                true,
	"x-amz-credential":     true,
	"x-amz-security-token": true,
	"x-amz-signature":      true,
}

// RedactURL strips credentials from a URL for logging.
//
// Three things are removed:
//
//   - userinfo (the "user:pass@" part), which is always a credential;
//   - the fragment, because OAuth implicit flows put #access_token= there and
//     a fragment is never sent to the server anyway;
//   - the VALUES of credential-like query parameters, with the key preserved.
//
// A string that does not parse as a URL is returned with a best-effort
// fragment strip rather than being dropped: console messages embed URLs in free
// text, and losing the diagnostic entirely would be worse than an imperfect
// redaction.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			return raw[:i]
		}
		return raw
	}

	if u.User != nil {
		u.User = url.User(RedactedUser)
	}
	u.Fragment = ""
	u.RawFragment = ""

	if u.RawQuery != "" {
		q := u.Query()
		changed := false
		for k, vs := range q {
			if !credentialKeys[strings.ToLower(k)] {
				continue
			}
			for i := range vs {
				if vs[i] != "" {
					vs[i] = RedactedValue
					changed = true
				}
			}
			q[k] = vs
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}

	return u.String()
}

// urlInTextRe finds absolute http(s) URLs embedded in free text. The character
// class stops at whitespace and at the punctuation that typically terminates a
// URL in a sentence or a stack frame.
var urlInTextRe = regexp.MustCompile(`https?://[^\s"'<>)\]}]+`)

// RedactText redacts every URL embedded in a free-text string.
//
// Chrome puts full URLs inside exception messages and log entries, so redacting
// only the Result.URL field would leak the very credentials the URL redaction
// exists to protect.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	return urlInTextRe.ReplaceAllStringFunc(s, RedactURL)
}
