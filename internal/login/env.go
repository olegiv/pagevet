// Package login reads pagevet's .env file and turns it into a validated login
// Spec: which page carries the login form, which form and fields on it, and
// which account to sign in as.
//
// It imports nothing outside the standard library, and `make arch` enforces
// that. This package holds the only password in the program, and the cheapest
// way to keep a credential from leaking into a dependency's logging, telemetry
// or error formatting is for there to be no dependency at all.
//
// Nothing here touches a browser. The Spec produced here is consumed by
// internal/loader, which is the only package that may drive Chrome.
package login

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// DefaultPath is the only file pagevet ever reads credentials from. It is
// deliberately relative: -login is scoped to the directory you run it from, so
// a staging .env cannot be picked up by a run you started somewhere else.
const DefaultPath = ".env"

// maxEnvBytes bounds the file. A .env holding these keys is a few hundred bytes;
// anything past this is a wrong path (a log, a database dump) and reading it
// into memory to fail on it later helps nobody.
const maxEnvBytes = 64 << 10

// ErrConfig marks a problem with the .env file itself — missing, unreadable,
// malformed, or missing a key. It is a configuration error the user fixes in an
// editor, so callers map it to the usage exit code, not to a login failure.
var ErrConfig = errors.New("login config")

// The keys pagevet reads. All but KeyLogoutPath are required: a login with a
// guessed field name is a login that fails in the browser with a much worse
// error message.
const (
	KeyLoginPath  = "LOGIN_PATH"
	KeyLogoutPath = "LOGOUT_PATH"
	KeyFormID     = "LOGIN_FORM_ID"
	KeyUserField  = "USERNAME_NAME"
	KeyPassField  = "PASSWORD_NAME"
	KeyUsername   = "USER_ADMIN_NAME"
	KeyPassword   = "USER_ADMIN_PASS"
)

// requiredKeys is the order missing keys are reported in, which is the order
// they appear in .env.example. Reporting them in map order instead would make
// the error message differ between runs on identical input.
var requiredKeys = []string{
	KeyLoginPath,
	KeyFormID,
	KeyUserField,
	KeyPassField,
	KeyUsername,
	KeyPassword,
}

// ReadFile parses path and validates everything that does not depend on the URL
// list. It is called before the input file is read, so a typo in .env costs
// milliseconds instead of a Chrome launch.
//
// warn receives advisory messages — currently only the file-permissions notice.
// It may be nil.
//
// The returned Config still carries LOGIN_PATH unresolved; see Config.Resolve.
func ReadFile(path string, warn func(format string, args ...any)) (Config, error) {
	kv, err := parseFile(path)
	if err != nil {
		return Config{}, err
	}
	checkPerm(path, warn)

	var missing []string
	for _, k := range requiredKeys {
		if strings.TrimSpace(kv[k]) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("%w: %s is missing %s",
			ErrConfig, display(path), strings.Join(missing, ", "))
	}

	c := Config{
		path:      path,
		LoginPath: strings.TrimSpace(kv[KeyLoginPath]),
		// Optional. Empty means "do not visit a logout page first", which is
		// the behavior every .env written before this key existed still gets.
		LogoutPath: strings.TrimSpace(kv[KeyLogoutPath]),
		FormID:     strings.TrimSpace(kv[KeyFormID]),
		UserField:  strings.TrimSpace(kv[KeyUserField]),
		PassField:  strings.TrimSpace(kv[KeyPassField]),
		Username:   kv[KeyUsername],
		// The password is NOT trimmed. A trailing space is a legal password
		// character, and silently eating it would produce a login failure whose
		// cause is invisible in the file.
		Password: kv[KeyPassword],
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// parseFile reads path and returns its key/value pairs.
//
// The file is opened through an *os.Root rooted at its own directory, the same
// way internal/input opens the URL list. That keeps a computed path out of
// os.Open — so a symlink in place of .env cannot read something else — and
// keeps this package free of a gosec suppression.
func parseFile(path string) (map[string]string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("%w: resolving %q: %w", ErrConfig, path, err)
	}

	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("%w: opening the directory of %s: %w", ErrConfig, display(path), err)
	}
	// Both handles are read-only: a Close failure cannot invalidate bytes we
	// have already read, and returning it would mask the parse error the caller
	// actually needs.
	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Base(abs))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist; copy .env.example to .env and fill it in",
				ErrConfig, display(path))
		}
		return nil, fmt.Errorf("%w: opening %s: %w", ErrConfig, display(path), err)
	}
	defer func() { _ = f.Close() }()

	// One byte past the cap distinguishes "exactly at the limit" from "over it".
	data, err := io.ReadAll(io.LimitReader(f, maxEnvBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrConfig, display(path), err)
	}
	if len(data) > maxEnvBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes; is that really an env file?",
			ErrConfig, display(path), maxEnvBytes)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: %s is not valid UTF-8", ErrConfig, display(path))
	}

	return parse(string(data), path)
}

// parse turns the file body into key/value pairs.
//
// The accepted grammar is the common .env subset, spelled out so there is no
// question later about what this does and does not support:
//
//	KEY=value                 bare, trailing # comment stripped
//	KEY="value"               double-quoted, \n \r \t \" \\ unescaped
//	KEY='value'               single-quoted, wholly literal
//	export KEY=value          the export prefix is tolerated and ignored
//	# comment                 a whole-line comment
//
// A duplicate key is an error rather than last-one-wins. Silently preferring
// the second USER_ADMIN_PASS is exactly how someone spends an afternoon on a
// login that fails with credentials that are visibly right in the file.
func parse(body, path string) (map[string]string, error) {
	kv := make(map[string]string, len(requiredKeys))

	for i, raw := range strings.Split(body, "\n") {
		lineNo := i + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, rest, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%w: %s:%d: expected KEY=VALUE, got %q",
				ErrConfig, display(path), lineNo, clip(line))
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("%w: %s:%d: empty key", ErrConfig, display(path), lineNo)
		}
		if _, dup := kv[key]; dup {
			return nil, fmt.Errorf("%w: %s:%d: %s is set twice; delete one",
				ErrConfig, display(path), lineNo, key)
		}

		val, err := parseValue(strings.TrimSpace(rest))
		if err != nil {
			return nil, fmt.Errorf("%w: %s:%d: %s: %w", ErrConfig, display(path), lineNo, key, err)
		}
		kv[key] = val
	}
	return kv, nil
}

// parseValue decodes the right-hand side of one assignment.
func parseValue(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	switch s[0] {
	case '\'':
		body, ok := closingQuote(s, '\'')
		if !ok {
			return "", errors.New("unterminated single quote")
		}
		// Single quotes are literal all the way through, backslashes included.
		return body, nil
	case '"':
		body, ok := closingQuote(s, '"')
		if !ok {
			return "", errors.New("unterminated double quote")
		}
		return unescape(body), nil
	}

	// Unquoted: a # begins a comment. Quoted values are exempt, which is what
	// lets a password contain a # at all.
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s), nil
}

// closingQuote returns the contents between s[0] and the matching closing
// quote. A backslash escapes the quote character inside a double-quoted value;
// inside a single-quoted one nothing does, so the first quote closes it.
func closingQuote(s string, q byte) (string, bool) {
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && q == '"' {
			i++ // skip the escaped byte, whatever it is
			continue
		}
		if s[i] == q {
			return s[1:i], true
		}
	}
	return "", false
}

// unescape expands the escapes recognized inside a double-quoted value. An
// unknown escape keeps its backslash rather than swallowing it, so a Windows
// path or a regex in a value survives a round trip.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i == len(s)-1 {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"', '\'', '\\':
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// checkPerm warns when the file other users can read holds a password.
//
// It warns rather than refuses: a .env checked out on a shared box is a real
// situation, and refusing to run would be a worse answer than saying so. The
// tool's own log files are 0600 for the same reason this matters.
func checkPerm(path string, warn func(format string, args ...any)) {
	if warn == nil {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		warn("%s is mode %04o and holds a password; chmod 600 %s", display(path), mode, path)
	}
}

// display renders path absolutely for error messages.
//
// -login always reads ./.env, so "no such file: .env" is the least helpful
// possible phrasing of the most likely mistake, which is running pagevet from
// the wrong directory. Printing the full path answers that in one line.
func display(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// clip shortens a value for an error message so a pathological line cannot
// scroll the real error off the screen.
func clip(s string) string {
	const maxRunes = 60
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "..."
}
