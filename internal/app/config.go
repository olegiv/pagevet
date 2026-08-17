// Package app wires pagevet together: flag parsing, signal handling, the
// bounded worker pool, and the exit-code policy.
//
// It depends on the loader only through loader.PageLoader, so every test in
// this package runs against loader/fake.FakeLoader with no browser.
package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Version is the reported build version.
const Version = "0.1.0"

// Exit codes. The split between 1 and 3 is what makes this usable in CI: a
// broken URL is a DATA outcome, whereas a browser that would not start is a
// TOOL outcome, and conflating them makes every alert ambiguous.
const (
	ExitOK          = 0 // the run completed; URLs may still have had errors
	ExitPageErrors  = 1 // only with -fail-on-errors: the run completed, some URLs failed
	ExitUsage       = 2 // bad flags, or an unusable input file
	ExitInternal    = 3 // the tool itself failed: no Chrome, unwritable logs
	ExitInterrupted = 4 // SIGINT/SIGTERM; partial results were written
	ExitLoginFailed = 5 // -login was set and the sign-in did not take
)

// ErrUsage marks a configuration problem that should exit with ExitUsage and a
// message the user can act on, rather than a stack-shaped internal error.
var ErrUsage = errors.New("usage")

// Config is the fully validated runtime configuration.
type Config struct {
	Input string
	Out   string

	Format   string
	Combined bool
	Quiet    bool

	Concurrency int
	Timeout     time.Duration
	Settle      time.Duration

	OKStatusMin     int
	OKStatusMax     int
	FailOnConsole   bool
	FailOnResource  bool
	ConsoleWarnings bool
	MaxConsole      int

	ChromePath    string
	Headed        bool
	SiteIsolation bool
	UserAgent     string
	DebugChrome   bool

	LogFullURLs    bool
	AllowLinkLocal bool

	// Login signs in once before the crawl, reading login.DefaultPath for the
	// form spec and the account. The session then applies to every URL, because
	// all of them are loaded in tabs of one browser.
	Login bool

	FailOnErrors bool

	// ShowVersion short-circuits the run.
	ShowVersion bool
}

const usageText = `usage: pagevet [flags] URLS.txt
       pagevet -input URLS.txt [flags]

Loads every URL in URLS.txt with headless Google Chrome (JavaScript enabled),
logs each URL that was opened, and logs failures to separate files - keeping
HTTP errors (a non-2xx/3xx main-document status), browser console errors
(uncaught JS exceptions and console.error output) and subresource errors
(assets the page failed to load) apart from one another.

Input is a plain .txt file, one full http:// or https:// URL per line. Blank
lines and lines starting with '#' are ignored; duplicates are skipped. Other
URL schemes are rejected with a line number.

Input and output:
  -input FILE          .txt file, one URL per line (or pass it positionally)
  -out DIR             directory for the logs (default "logs")
  -format text|json    format of the logs and the summary (default "text")
  -combined-error-log  one errors.log with a type= field instead of separate
                       errors-http.log / errors-console.log / errors-subresource.log
                       / errors-load.log
  -quiet               no per-URL progress on stderr

Crawling:
  -concurrency N       URLs loaded in parallel, 1..16 (default 4)
  -timeout D           hard per-URL deadline (default 30s)
  -settle D            quiet window kept open after page load, to catch errors
                       thrown from setTimeout / fetch handlers / SPA hydration
                       (default 1.5s)

Classification:
  -ok-status MIN-MAX   main-document statuses treated as OK (default "200-399")
  -fail-on-console     count browser console errors as failures (default true)
  -fail-on-resource    count failed subresources as failures (default true)
  -console-warnings    also count console.warn as an error (default false)
  -max-console N       distinct console errors retained per URL (default 20)

Browser:
  -chrome PATH         absolute path to the Chrome/Chromium binary
                       (default: autodetect)
  -headed              run with a visible window, for debugging (default false)
  -site-isolation      re-enable Chrome's per-site process isolation. More
                       defensive against hostile pages, but cross-origin iframes
                       then run in separate renderer processes and their console
                       errors are NOT captured. (default false)
  -user-agent S        override the User-Agent. Chrome's default contains
                       "HeadlessChrome", which some sites answer with 403.
  -debug-chrome        forward Chrome's stdout/stderr to this process's stderr

Authentication:
  -login               sign in once before crawling and reuse that session for
                       every URL, so pages behind a login report their real
                       errors instead of a redirect. Reads ./.env in the CURRENT
                       directory - every key but LOGOUT_PATH is required:
                         LOGIN_PATH      login page: a path resolved against the
                                         first URL in the input file, or a full
                                         http(s):// URL
                         LOGOUT_PATH     optional. A sign-out page loaded just
                                         BEFORE the login page, so the sign-in
                                         starts signed out. Omit to go straight
                                         to the login page.
                         LOGIN_FORM_ID   id of the <form> element
                         USERNAME_NAME   name= of the username input
                         PASSWORD_NAME   name= of the password input
                         USER_ADMIN_NAME the account to sign in as
                         USER_ADMIN_PASS its password
                       See .env.example. Keep .env mode 0600: it holds a
                       password. The session lives in the run's throwaway Chrome
                       profile and is destroyed with it. (default false)

Safety:
  -log-full-urls       write URLs verbatim. By default userinfo is stripped, the
                       fragment is dropped, and the VALUES of credential-like
                       query parameters (token, api_key, secret, sig, code, ...)
                       are replaced with REDACTED. UNSAFE: may write credentials
                       to disk. (default false)
  -allow-link-local    allow URLs whose host resolves to a link-local address,
                       including the cloud metadata endpoint 169.254.169.254
                       (default false)

Other:
  -fail-on-errors      exit 1 when any URL had an error, for CI use
                       (default false: a completed run exits 0)
  -version             print version and exit
  -h, -help            print this help and exit

Exit codes:
  0  the run completed (URLs may still have had errors - see the summary)
  1  only with -fail-on-errors: the run completed and some URLs had errors
  2  usage error, or the input file is missing / unreadable / has no valid URLs,
     or .env is missing / malformed when -login is set
  3  internal failure (could not start Chrome, could not write the logs)
  4  interrupted by SIGINT/SIGTERM (partial results written, summary printed)
  5  only with -login: the sign-in failed, so nothing was crawled

Notes:
  * Output is never colorized.
  * Log files are created 0600 in a 0700 directory: they contain the URLs you
    supplied, which can carry credentials. See -log-full-urls.
  * Refuses to run as root: Chrome would be started with --no-sandbox, which
    disables the OS sandbox around a renderer parsing untrusted pages.
  * -login never writes the password anywhere: not to a log, not into an error
    message, not into the JavaScript it evaluates.
`

// ParseFlags parses argv into a validated Config.
//
// The output writer is injected so -help and every usage error are testable
// without os.Exit inside the test binary. A flag.ErrHelp return means the user
// asked for help and the caller should exit 0.
func ParseFlags(args []string, out io.Writer) (Config, error) {
	var c Config
	var okStatus string

	fs := flag.NewFlagSet("pagevet", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(out, usageText) }

	fs.StringVar(&c.Input, "input", "", "input .txt file, one URL per line")
	fs.StringVar(&c.Out, "out", "logs", "output directory")
	fs.StringVar(&c.Format, "format", "text", "text|json")
	fs.BoolVar(&c.Combined, "combined-error-log", false, "one errors.log instead of per-category files")
	fs.BoolVar(&c.Quiet, "quiet", false, "no per-URL progress on stderr")

	fs.IntVar(&c.Concurrency, "concurrency", 4, "URLs loaded in parallel, 1..16")
	fs.DurationVar(&c.Timeout, "timeout", 30*time.Second, "hard per-URL deadline")
	fs.DurationVar(&c.Settle, "settle", 1500*time.Millisecond, "quiet window after load")

	fs.StringVar(&okStatus, "ok-status", "200-399", "main-document statuses treated as OK")
	fs.BoolVar(&c.FailOnConsole, "fail-on-console", true, "count console errors as failures")
	fs.BoolVar(&c.FailOnResource, "fail-on-resource", true, "count failed subresources as failures")
	fs.BoolVar(&c.ConsoleWarnings, "console-warnings", false, "also count console.warn")
	fs.IntVar(&c.MaxConsole, "max-console", 20, "distinct console errors retained per URL")

	fs.StringVar(&c.ChromePath, "chrome", "", "path to the Chrome/Chromium binary")
	fs.BoolVar(&c.Headed, "headed", false, "run with a visible window")
	fs.BoolVar(&c.SiteIsolation, "site-isolation", false, "re-enable per-site process isolation")
	fs.StringVar(&c.UserAgent, "user-agent", "", "override the User-Agent")
	fs.BoolVar(&c.DebugChrome, "debug-chrome", false, "forward Chrome's output to stderr")

	fs.BoolVar(&c.LogFullURLs, "log-full-urls", false, "write URLs verbatim (UNSAFE)")
	fs.BoolVar(&c.AllowLinkLocal, "allow-link-local", false, "allow link-local hosts")

	fs.BoolVar(&c.Login, "login", false, "sign in once before crawling, using ./.env")

	fs.BoolVar(&c.FailOnErrors, "fail-on-errors", false, "exit 1 when any URL had an error")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		// flag has already written the message and the usage banner.
		return c, err
	}
	if c.ShowVersion {
		return c, nil
	}

	// The input file may be given positionally, which is what people actually
	// type. Reject extra positional arguments rather than silently ignoring
	// them - a stray shell glob is otherwise invisible.
	switch rest := fs.Args(); {
	case len(rest) == 1 && c.Input == "":
		c.Input = rest[0]
	case len(rest) == 1 && c.Input != "":
		return c, fmt.Errorf("%w: input file given both with -input (%s) and positionally (%s)",
			ErrUsage, c.Input, rest[0])
	case len(rest) > 1:
		return c, fmt.Errorf("%w: expected at most one input file, got %d: %s",
			ErrUsage, len(rest), strings.Join(rest, " "))
	}

	if err := c.validate(okStatus); err != nil {
		return c, err
	}
	return c, nil
}

func (c *Config) validate(okStatus string) error {
	if c.Input == "" {
		return fmt.Errorf("%w: no input file; pass one positionally or with -input", ErrUsage)
	}

	// Refuse root before doing anything else. chromedp adds --no-sandbox when
	// uid is 0, which would drop the OS sandbox around a renderer that is about
	// to parse pages we do not control.
	if os.Geteuid() == 0 {
		return fmt.Errorf("%w: refusing to run as root; Chrome would lose its sandbox", ErrUsage)
	}

	if c.Concurrency < 1 || c.Concurrency > 16 {
		return fmt.Errorf("%w: -concurrency must be between 1 and 16, got %d", ErrUsage, c.Concurrency)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("%w: -timeout must be positive, got %s", ErrUsage, c.Timeout)
	}
	if c.Settle < 0 {
		return fmt.Errorf("%w: -settle cannot be negative, got %s", ErrUsage, c.Settle)
	}
	if c.Settle >= c.Timeout {
		return fmt.Errorf("%w: -settle (%s) must be less than -timeout (%s), or every URL times out",
			ErrUsage, c.Settle, c.Timeout)
	}
	if c.MaxConsole < 1 || c.MaxConsole > 1000 {
		return fmt.Errorf("%w: -max-console must be between 1 and 1000, got %d", ErrUsage, c.MaxConsole)
	}
	if c.Format != "text" && c.Format != "json" {
		return fmt.Errorf("%w: -format must be text or json, got %q", ErrUsage, c.Format)
	}
	if c.Out == "" {
		return fmt.Errorf("%w: -out cannot be empty", ErrUsage)
	}

	lo, hi, err := parseStatusBand(okStatus)
	if err != nil {
		return err
	}
	c.OKStatusMin, c.OKStatusMax = lo, hi

	if c.ChromePath != "" {
		if !filepath.IsAbs(c.ChromePath) {
			return fmt.Errorf("%w: -chrome must be an absolute path, got %q", ErrUsage, c.ChromePath)
		}
		if strings.ContainsRune(c.ChromePath, 0) {
			return fmt.Errorf("%w: -chrome path contains a NUL byte", ErrUsage)
		}
	}

	// A visible window needs a display, which a headless machine does not have.
	// Failing here beats failing inside Chrome with an opaque message.
	if c.Headed && runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("%w: -headed needs a display, but neither DISPLAY nor WAYLAND_DISPLAY is set", ErrUsage)
	}

	return nil
}

// parseStatusBand parses the "MIN-MAX" form used by -ok-status.
func parseStatusBand(s string) (minStatus, maxStatus int, err error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("%w: -ok-status must look like MIN-MAX, got %q", ErrUsage, s)
	}
	minStatus, err = strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return 0, 0, fmt.Errorf("%w: -ok-status lower bound %q is not a number", ErrUsage, lo)
	}
	maxStatus, err = strconv.Atoi(strings.TrimSpace(hi))
	if err != nil {
		return 0, 0, fmt.Errorf("%w: -ok-status upper bound %q is not a number", ErrUsage, hi)
	}
	if minStatus < 100 || maxStatus > 599 || minStatus > maxStatus {
		return 0, 0, fmt.Errorf("%w: -ok-status must satisfy 100 <= MIN <= MAX <= 599, got %d-%d",
			ErrUsage, minStatus, maxStatus)
	}
	return minStatus, maxStatus, nil
}
