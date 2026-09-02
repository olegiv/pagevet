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
// A string that does not parse as a URL is redacted by inspecting its URL
// delimiters directly. Console messages can contain malformed URLs, but their
// diagnostics must not be allowed to bypass credential redaction.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactMalformedURL(raw)
	}

	if u.User != nil {
		u.User = url.User(RedactedUser)
	}
	u.Fragment = ""
	u.RawFragment = ""

	if u.RawQuery != "" {
		u.RawQuery = redactRawQuery(u.RawQuery)
	}

	return u.String()
}

// redactRawQuery processes each pair independently. URL.Query silently drops
// pairs containing malformed escapes, which is unsafe for a redaction helper.
func redactRawQuery(raw string) string {
	pairs := strings.Split(raw, "&")
	for i, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		if !found || value == "" {
			continue
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			decodedKey = key
		}
		if credentialKeys[strings.ToLower(decodedKey)] {
			pairs[i] = key + "=" + RedactedValue
		}
	}
	return strings.Join(pairs, "&")
}

func redactMalformedURL(raw string) string {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		query := redactRawQuery(raw[i+1:])
		raw = raw[:i+1] + query
	}

	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		authorityStart := scheme + 3
		authorityEnd := len(raw)
		if i := strings.IndexAny(raw[authorityStart:], "/?"); i >= 0 {
			authorityEnd = authorityStart + i
		}
		if at := strings.LastIndexByte(raw[authorityStart:authorityEnd], '@'); at >= 0 {
			at += authorityStart
			raw = raw[:authorityStart] + RedactedUser + raw[at:]
		}
	}
	return raw
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
