package login

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEnv drops body into a temp file and returns its path.
func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

// validEnv is a complete, well-formed file. Tests that care about one key
// override it rather than restating all six.
const validEnv = `LOGIN_PATH="/login"
LOGIN_FORM_ID="user-login-form"
USERNAME_NAME="name"
PASSWORD_NAME="pass"
USER_ADMIN_NAME="editor"
USER_ADMIN_PASS="s3cret"
`

func TestParseValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{"double quoted", `K="value"`, "value"},
		{"single quoted", `K='value'`, "value"},
		{"bare", `K=value`, "value"},
		{"bare trimmed", `K=   value   `, "value"},
		{"empty", `K=`, ""},
		{"empty quoted", `K=""`, ""},

		// A password is far more likely to contain these than a hostname is.
		{"quoted spaces kept", `K="two words"`, "two words"},
		{"quoted hash kept", `K="a#b"`, "a#b"},
		{"single quoted hash kept", `K='a#b'`, "a#b"},
		{"bare hash starts comment", `K=value # note`, "value"},
		{"quoted equals", `K="a=b=c"`, "a=b=c"},
		{"bare equals", `K=a=b=c`, "a=b=c"},

		{"escaped quote", `K="say \"hi\""`, `say "hi"`},
		{"escaped backslash", `K="a\\b"`, `a\b`},
		{"escaped newline", `K="a\nb"`, "a\nb"},
		{"escaped tab", `K="a\tb"`, "a\tb"},
		// An unknown escape keeps its backslash: a Windows path or a regex in a
		// value has to survive the round trip.
		{"unknown escape kept", `K="a\db"`, `a\db`},
		// Single quotes are literal all the way through.
		{"single quotes are literal", `K='a\nb'`, `a\nb`},

		{"export prefix", `export K=value`, "value"},
		{"leading whitespace", "   K=value", "value"},
		{"space around equals", `K = value`, "value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kv, err := parse(tt.line, ".env")
			if err != nil {
				t.Fatalf("parse(%q) error = %v", tt.line, err)
			}
			if got := kv["K"]; got != tt.want {
				t.Errorf("parse(%q)[K] = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestParseSkipsAndStructure(t *testing.T) {
	t.Parallel()

	body := "# a comment\n" +
		"\n" +
		"   \n" +
		"A=1\r\n" + // CRLF must not leave a \r in the value
		"   # an indented comment\n" +
		"B=2\n"

	kv, err := parse(body, ".env")
	if err != nil {
		t.Fatalf("parse() error = %v", err)
	}
	if len(kv) != 2 {
		t.Fatalf("parse() got %d keys, want 2: %v", len(kv), kv)
	}
	if kv["A"] != "1" {
		t.Errorf("A = %q, want %q (a stray \\r means CRLF is not being trimmed)", kv["A"], "1")
	}
	if kv["B"] != "2" {
		t.Errorf("B = %q, want %q", kv["B"], "2")
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string // substring the message must contain
	}{
		{"no equals", "LOGIN_PATH\n", "expected KEY=VALUE"},
		{"junk after a double-quoted value", `K="v"oops` + "\n", "unexpected text after the closing quote"},
		{"junk after a single-quoted value", `K='v'oops` + "\n", "unexpected text after the closing quote"},
		{"empty key", "=value\n", "empty key"},
		{"unterminated double quote", `K="value` + "\n", "unterminated double quote"},
		{"unterminated single quote", `K='value` + "\n", "unterminated single quote"},

		// Last-one-wins would silently pick a password that is not the one
		// visibly first in the file. That is a debugging afternoon nobody
		// should have to spend, so it is an error.
		{"duplicate key", "K=1\nK=2\n", "set twice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parse(tt.body, ".env")
			if err == nil {
				t.Fatalf("parse(%q) succeeded, want an error", tt.body)
			}
			if !errors.Is(err, ErrConfig) {
				t.Errorf("parse() error = %v, want it to wrap ErrConfig", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("parse() error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseReportsLineNumbers(t *testing.T) {
	t.Parallel()

	// The offending line is fourth, after a comment and a blank.
	_, err := parse("# c\n\nA=1\nbroken\n", ".env")
	if err == nil {
		t.Fatal("parse() succeeded, want an error")
	}
	if !strings.Contains(err.Error(), ":4:") {
		t.Errorf("parse() error = %q, want it to name line 4 (comments and blanks still count)", err)
	}
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	c, err := ReadFile(writeEnv(t, validEnv), nil)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	want := Config{
		LoginPath: "/login",
		FormID:    "user-login-form",
		UserField: "name",
		PassField: "pass",
		Username:  "editor",
		Password:  "s3cret",
	}
	got := c
	got.path = "" // not part of the comparison
	if got != want {
		t.Errorf("ReadFile() = %+v, want %+v", got, want)
	}
}

func TestReadFileKeepsPasswordWhitespace(t *testing.T) {
	t.Parallel()

	// A trailing space is a legal password character. Trimming it would produce
	// a login failure whose cause is invisible in the file.
	body := strings.Replace(validEnv, `USER_ADMIN_PASS="s3cret"`, `USER_ADMIN_PASS=" pad "`, 1)
	c, err := ReadFile(writeEnv(t, body), nil)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if c.Password != " pad " {
		t.Errorf("Password = %q, want %q", c.Password, " pad ")
	}
}

func TestReadFileLogoutPathIsOptional(t *testing.T) {
	t.Parallel()

	// validEnv has no LOGOUT_PATH. Every .env written before the key existed
	// has to keep working, and an absent one means "skip the logout step".
	c, err := ReadFile(writeEnv(t, validEnv), nil)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if c.LogoutPath != "" {
		t.Errorf("LogoutPath = %q with no LOGOUT_PATH in the file, want empty", c.LogoutPath)
	}
}

func TestReadFileLogoutPath(t *testing.T) {
	t.Parallel()

	c, err := ReadFile(writeEnv(t, validEnv+`LOGOUT_PATH="/user/logout"`+"\n"), nil)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if c.LogoutPath != "/user/logout" {
		t.Errorf("LogoutPath = %q, want %q", c.LogoutPath, "/user/logout")
	}
}

func TestReadFileIgnoresUnknownKeys(t *testing.T) {
	t.Parallel()

	// A .env is often shared with other tools, so an unrecognized key is not
	// this program's business.
	if _, err := ReadFile(writeEnv(t, validEnv+"DATABASE_URL=postgres://x\n"), nil); err != nil {
		t.Errorf("ReadFile() error = %v, want an unknown key to be ignored", err)
	}
}

func TestReadFileRequiresEveryKey(t *testing.T) {
	t.Parallel()

	for _, key := range requiredKeys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			var kept []string
			for line := range strings.SplitSeq(strings.TrimSpace(validEnv), "\n") {
				if !strings.HasPrefix(line, key+"=") {
					kept = append(kept, line)
				}
			}
			body := strings.Join(kept, "\n") + "\n"

			_, err := ReadFile(writeEnv(t, body), nil)
			if err == nil {
				t.Fatalf("ReadFile() without %s succeeded, want an error", key)
			}
			// The message must name the key. A typo'd key reaches the user as
			// "missing X", and that is only useful if X is printed.
			if !strings.Contains(err.Error(), key) {
				t.Errorf("ReadFile() error = %q, want it to name %s", err, key)
			}
		})
	}
}

func TestReadFileTreatsEmptyValueAsMissing(t *testing.T) {
	t.Parallel()

	body := strings.Replace(validEnv, `USER_ADMIN_PASS="s3cret"`, `USER_ADMIN_PASS=""`, 1)
	_, err := ReadFile(writeEnv(t, body), nil)
	if err == nil {
		t.Fatal("ReadFile() with an empty password succeeded, want an error")
	}
	if !strings.Contains(err.Error(), KeyPassword) {
		t.Errorf("ReadFile() error = %q, want it to name %s", err, KeyPassword)
	}
}

func TestReadFileMissing(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".env")
	_, err := ReadFile(path, nil)
	if err == nil {
		t.Fatal("ReadFile() on a missing file succeeded, want an error")
	}
	if !errors.Is(err, ErrConfig) {
		t.Errorf("error = %v, want it to wrap ErrConfig", err)
	}
	// -login always reads ./.env, so "wrong directory" is the likeliest
	// mistake and the absolute path is what answers it.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to contain the absolute path %q", err, path)
	}
	if !strings.Contains(err.Error(), ".env.example") {
		t.Errorf("error = %q, want it to point at .env.example", err)
	}
}

func TestReadFileRejectsOversized(t *testing.T) {
	t.Parallel()

	body := validEnv + "PADDING=" + strings.Repeat("x", maxEnvBytes) + "\n"
	_, err := ReadFile(writeEnv(t, body), nil)
	if err == nil {
		t.Fatal("ReadFile() on an oversized file succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error = %q, want it to mention the size limit", err)
	}
}

func TestReadFileRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	_, err := ReadFile(writeEnv(t, validEnv+"BAD=\xff\xfe\n"), nil)
	if err == nil {
		t.Fatal("ReadFile() on invalid UTF-8 succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error = %q, want it to mention UTF-8", err)
	}
}

func TestReadFileWarnsOnLoosePermissions(t *testing.T) {
	t.Parallel()

	path := writeEnv(t, validEnv)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	var warnings []string
	if _, err := ReadFile(path, func(format string, _ ...any) {
		warnings = append(warnings, format)
	}); err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	// A warning, not a refusal: a .env on a shared box is a real situation, and
	// refusing to run would be a worse answer than saying so.
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "chmod 600") {
		t.Errorf("warning = %q, want it to say how to fix the problem", warnings[0])
	}
}

func TestReadFileQuietAt0600(t *testing.T) {
	t.Parallel()

	var warned bool
	if _, err := ReadFile(writeEnv(t, validEnv), func(string, ...any) { warned = true }); err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if warned {
		t.Error("ReadFile() warned about a 0600 file, want silence")
	}
}

// FuzzParse pins the two properties that matter regardless of input: parsing
// never panics, and it never invents a key that was not written down. The
// second is what keeps a malformed file from silently satisfying the
// required-key check with garbage.
func FuzzParse(f *testing.F) {
	f.Add(validEnv)
	f.Add("K=v")
	f.Add(`K="\`)
	f.Add("K='")
	f.Add("=\n=\n")
	f.Add("export K=v # c")
	f.Add("K=\xff")

	f.Fuzz(func(t *testing.T, body string) {
		kv, err := parse(body, ".env")
		if err != nil {
			if kv != nil {
				t.Errorf("parse() returned both a map and an error %v", err)
			}
			return
		}
		for k := range kv {
			if k == "" {
				t.Error("parse() produced an empty key")
			}
			if !strings.Contains(body, k) {
				t.Errorf("parse() produced key %q, which does not appear in the input", k)
			}
		}
	})
}

// TestParseNeverEchoesAMalformedLine is a password-leak regression.
//
// A line with no '=' has no key/value split, so the parser cannot tell a stray
// word from a mistyped credential. Quoting it back put a line like
// `USER_ADMIN_PASS "s3cret"` on stderr and into whatever CI log was watching,
// breaking the promise that the password is never written anywhere.
func TestParseNeverEchoesAMalformedLine(t *testing.T) {
	t.Parallel()

	const password = "correct-horse-battery-staple"

	bodies := map[string]string{
		"equals mistyped as a space": `USER_ADMIN_PASS "` + password + `"` + "\n",
		"value pasted on its own":    password + "\n",
		"yaml habits":                `USER_ADMIN_PASS: "` + password + `"` + "\n",
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := parse(body, "/tmp/.env")
			if err == nil {
				t.Fatalf("parse(%q) succeeded, want an error", body)
			}
			if strings.Contains(err.Error(), password) {
				t.Errorf("the error quotes the password back: %q", err)
			}
			// It still has to be findable: the path and line number are what
			// the user needs to open the right line in an editor.
			if !strings.Contains(err.Error(), ":1:") {
				t.Errorf("error = %q, want it to name the line number", err)
			}
		})
	}
}

// TestParseTrailerNeverEchoesTheValue is the same guarantee for the other new
// rejection: text after a closing quote is part of what the user was writing,
// which on a credential line is the credential.
func TestParseTrailerNeverEchoesTheValue(t *testing.T) {
	t.Parallel()

	const password = "correct-horse-battery-staple"

	_, err := parse(`USER_ADMIN_PASS="x"`+password+"\n", "/tmp/.env")
	if err == nil {
		t.Fatal("parse() accepted trailing text after a quoted value, want an error")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("the error quotes the trailing text back: %q", err)
	}
}

// TestParseAcceptsCommentAfterQuotedValue keeps the new trailer check from
// rejecting the one thing that legitimately follows a closing quote.
func TestParseAcceptsCommentAfterQuotedValue(t *testing.T) {
	t.Parallel()

	for _, line := range []string{
		`K="v" # a note`,
		`K="v"   `,
		`K='v' # a note`,
		`K="v"`,
	} {
		t.Run(line, func(t *testing.T) {
			t.Parallel()

			kv, err := parse(line, ".env")
			if err != nil {
				t.Fatalf("parse(%q) error = %v", line, err)
			}
			if kv["K"] != "v" {
				t.Errorf("parse(%q)[K] = %q, want %q", line, kv["K"], "v")
			}
		})
	}
}
