package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/olegiv/pagevet/internal/input"
	"github.com/olegiv/pagevet/internal/loader"
	"github.com/olegiv/pagevet/internal/login"
	"github.com/olegiv/pagevet/internal/report"
	"github.com/olegiv/pagevet/internal/verdict"
)

// displayURL applies the run's redaction policy to a URL bound for a log file
// or the terminal. The crawler does this to every URL it reports; the login URL
// is not an exception just because it came from a config file.
func displayURL(rawURL string, logFullURLs bool) string {
	if logFullURLs {
		return rawURL
	}
	return verdict.RedactURL(rawURL)
}

// Main is the whole program. It returns a process exit code rather than
// calling os.Exit, so that cmd/pagevet stays a six-line shim and so that
// e2e tests can call it in-process.
func Main(args []string, stdout, stderr io.Writer) int {
	cfg, err := ParseFlags(args, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return ExitOK
	case errors.Is(err, ErrUsage):
		fmt.Fprintf(stderr, "pagevet: %v\n\nRun 'pagevet -help' for usage.\n", err)
		return ExitUsage
	case err != nil:
		// flag already printed the specific problem and the usage banner.
		return ExitUsage
	}
	if cfg.ShowVersion {
		fmt.Fprintf(stdout, "pagevet %s\n", Version)
		return ExitOK
	}

	// Signals root the entire context tree, so a Ctrl-C reaches Chrome, the
	// worker pool and the reporter in one hop. This matters more than usual on
	// macOS: chromedp's process-group cleanup is a no-op on non-Linux, so an
	// exit that skips our cancels leaves Chrome running.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return run(ctx, cfg, chromeLoader, stdout, stderr)
}

// browser is the slice of *loader.Browser that run actually depends on.
//
// Naming it here is what keeps the wiring - the reporter setup, the exit-code
// policy, the summary - testable without launching Chrome. Without this seam
// run would construct its own browser and none of that could be exercised
// except through a subprocess.
type browser interface {
	loader.PageLoader
	loader.Authenticator
	Describe() string
	Close()
}

// newBrowser builds the page loader for a run. Tests substitute a fake.
type newBrowser func(loader.Options) (browser, error)

// chromeLoader is the real implementation, and the only place the concrete
// Chrome type is named outside internal/loader.
func chromeLoader(o loader.Options) (browser, error) { return loader.NewChrome(o) }

func run(ctx context.Context, cfg Config, newLoader newBrowser, stdout, stderr io.Writer) int {
	// The .env is parsed before anything expensive happens. A typo in it is the
	// most likely failure of a -login run, and finding out about it after a
	// 4000-URL address-policy sweep and a Chrome launch would be gratuitous.
	// Only LOGIN_PATH is left unresolved here; it may need the first URL.
	var loginCfg login.Config
	if cfg.Login {
		c, err := login.ReadFile(login.DefaultPath, func(format string, args ...any) {
			fmt.Fprintf(stderr, "pagevet: warning: "+format+"\n", args...)
		})
		if err != nil {
			fmt.Fprintf(stderr, "pagevet: %v\n", err)
			return ExitUsage
		}
		loginCfg = c
	}

	// Reading takes the context because it resolves every host to enforce the
	// address policy; on a large list that is the one phase before crawling
	// that could otherwise ignore a Ctrl-C for a noticeable while.
	parsed, err := input.ReadFile(ctx, cfg.Input, input.Options{
		AllowLinkLocal: cfg.AllowLinkLocal,
		SkipDuplicates: true,
	})
	switch {
	case errors.Is(err, context.Canceled):
		fmt.Fprintf(stderr, "pagevet: interrupted while reading %s\n", cfg.Input)
		return ExitInterrupted
	case err != nil:
		fmt.Fprintf(stderr, "pagevet: %v\n", err)
		return ExitUsage
	}
	for _, b := range parsed.Bad {
		fmt.Fprintf(stderr, "%s:%d: skipping %q: %v\n", cfg.Input, b.Line, b.Raw, b.Err)
	}
	if len(parsed.Entries) == 0 {
		fmt.Fprintf(stderr, "pagevet: %s contains no valid http/https URLs\n", cfg.Input)
		return ExitUsage
	}

	// LOGIN_PATH may be a bare path, which resolves against the origin of the
	// first URL in the list. That is why this happens here and not in
	// login.ReadFile: it is the earliest point at which the answer exists.
	var loginSpec *login.Spec
	if cfg.Login {
		spec, resolveErr := loginCfg.Resolve(parsed.Entries[0].URL)
		if resolveErr != nil {
			fmt.Fprintf(stderr, "pagevet: %v\n", resolveErr)
			return ExitUsage
		}
		// The login and logout pages are subject to the same address policy as
		// every crawled URL. Without this a .env would be a way to reach the
		// cloud metadata endpoint that -allow-link-local exists to keep out.
		// LOGOUT_PATH is checked separately because it may name another origin.
		for _, page := range []struct{ what, rawURL, host string }{
			{"login page", spec.URL, spec.Host()},
			{"logout page", spec.LogoutURL, spec.LogoutHost()},
		} {
			if page.host == "" {
				continue // no logout configured
			}
			if hostErr := input.CheckHost(ctx, page.host, cfg.AllowLinkLocal); hostErr != nil {
				fmt.Fprintf(stderr, "pagevet: %s %s: %v\n",
					page.what, verdict.RedactURL(page.rawURL), hostErr)
				return ExitUsage
			}
		}
		loginSpec = &spec
	}

	opts := loader.DefaultOptions()
	opts.ExecPath = cfg.ChromePath
	opts.Timeout = cfg.Timeout
	opts.Settle = cfg.Settle
	opts.Headless = !cfg.Headed
	opts.SiteIsolation = cfg.SiteIsolation
	opts.UserAgent = cfg.UserAgent
	opts.MaxConsolePerPage = cfg.MaxConsole
	opts.ConsoleWarnings = cfg.ConsoleWarnings
	opts.RedactURLs = !cfg.LogFullURLs
	opts.Login = loginSpec
	// The loader re-runs this against the page that actually commits, because a
	// login page may redirect somewhere the pre-flight check never saw.
	opts.CheckHost = func(ctx context.Context, host string) error {
		return input.CheckHost(ctx, host, cfg.AllowLinkLocal)
	}
	if cfg.DebugChrome {
		opts.ChromeStderr = stderr
	}

	// The loader takes no context on purpose - see loader.NewChrome's doc
	// comment. Binding the browser to ctx would mean the signal that asks for
	// shutdown also cancels the shutdown, leaving Chrome running on macOS where
	// chromedp has no process-group cleanup to fall back on.
	br, err := newLoader(opts)
	if err != nil {
		fmt.Fprintf(stderr, "pagevet: %v\n", err)
		return ExitInternal
	}
	defer br.Close()

	// Sign in before the pool starts, never during it. Every tab the loader
	// opens from here on shares this browser's cookie jar, which is the entire
	// mechanism - and it only works if the session exists before the first URL
	// is dispatched.
	var loginNote string
	if loginSpec != nil {
		switch loginErr := br.Login(ctx); {
		case errors.Is(loginErr, context.Canceled), ctx.Err() != nil:
			fmt.Fprintf(stderr, "pagevet: interrupted while signing in\n")
			return ExitInterrupted
		case errors.Is(loginErr, loader.ErrBrowserUnavailable):
			// Chrome died mid-sign-in. That is a TOOL failure, not a credential
			// one, and the whole reason 3 and 5 are separate codes is so an
			// alert can tell them apart. Checked before the catch-all below,
			// which would otherwise claim the login was rejected.
			fmt.Fprintf(stderr, "pagevet: %v\n", loginErr)
			return ExitInternal
		case loginErr != nil:
			// Crawling on anonymously would fill the logs with redirects and
			// 403s that look like page failures, so this stops the run. The
			// exit code is its own, because "your credentials are wrong" and
			// "Chrome would not start" want different responses in CI.
			fmt.Fprintf(stderr, "pagevet: %v\n", loginErr)
			return ExitLoginFailed
		}
		loginNote = loginSpec.Describe(displayURL(loginSpec.URL, cfg.LogFullURLs))
		if !cfg.Quiet {
			fmt.Fprintf(stderr, "pagevet: logged in as %s\n", loginNote)
		}
	}

	policy := verdict.Policy{
		OKStatusMin:    cfg.OKStatusMin,
		OKStatusMax:    cfg.OKStatusMax,
		FailOnConsole:  cfg.FailOnConsole,
		FailOnResource: cfg.FailOnResource,
	}

	rep, err := report.New(report.Options{
		Dir:      cfg.Out,
		Format:   cfg.Format,
		Combined: cfg.Combined,
		Policy:   policy,
		Now:      time.Now,
		Header: report.Header{
			Version:     Version,
			Input:       cfg.Input,
			Concurrency: cfg.Concurrency,
			Timeout:     cfg.Timeout,
			Settle:      cfg.Settle,
			Chrome:      br.Describe(),
			// Empty unless -login ran, so a run without it produces byte-identical
			// headers to before this feature existed. Never holds the password:
			// login.Spec.Describe cannot render one.
			Login: loginNote,
		},
		// -fail-on-errors changes only the reported code, never whether the
		// run is considered to have completed.
		// The reporter wraps this note in parentheses itself, so it must not
		// carry its own.
		ExitCode: func(c verdict.Counts) (int, string) {
			n := c.Errored()
			switch {
			case cfg.FailOnErrors && n > 0:
				return ExitPageErrors, fmt.Sprintf("run completed; %d URLs had errors, -fail-on-errors set", n)
			case n > 0:
				return ExitOK, fmt.Sprintf("run completed; %d URLs had errors", n)
			}
			return ExitOK, "run completed; no errors"
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "pagevet: %v\n", err)
		return ExitInternal
	}

	// io.Discard is itself declared as an io.Writer, so this variable has that
	// type without the annotation revive objects to.
	progress := io.Discard
	if !cfg.Quiet {
		progress = stderr
	}

	counts, runErr := Run(ctx, cfg, policy, parsed, br, rep, progress)

	if err := rep.Close(); err != nil {
		fmt.Fprintf(stderr, "pagevet: closing logs: %v\n", err)
		if runErr == nil {
			runErr = err
		}
	}

	// The reporter computes elapsed time from its own header and knows which
	// files it created, so neither has to travel through Counts - which stays
	// a pure tally.
	if err := rep.Summary(counts, stdout); err != nil {
		fmt.Fprintf(stderr, "pagevet: writing summary: %v\n", err)
		return ExitInternal
	}

	switch {
	case errors.Is(runErr, context.Canceled), ctx.Err() != nil:
		return ExitInterrupted
	case runErr != nil:
		fmt.Fprintf(stderr, "pagevet: %v\n", runErr)
		return ExitInternal
	case cfg.FailOnErrors && counts.Errored() > 0:
		return ExitPageErrors
	}
	return ExitOK
}

// item carries one finished load from a worker to the drain.
type item struct {
	index int
	res   verdict.Result
	err   error
}

// Run loads every entry and reports the results in input order.
//
// The concurrency model has one non-obvious property worth stating plainly:
// the semaphore slot is released by the DRAIN when a result is emitted, not by
// the worker when it finishes. Results must come out in input order, so a slow
// URL at the head of the line holds back everything behind it; releasing on
// emit rather than on completion caps the number of finished-but-unemitted
// results at Concurrency. Releasing on completion instead would let one
// 30-second URL accumulate an unbounded pending map over a large run.
func Run(
	ctx context.Context,
	cfg Config,
	policy verdict.Policy,
	parsed input.Parsed,
	pl loader.PageLoader,
	rep *report.Reporter,
	progress io.Writer,
) (verdict.Counts, error) {
	counts := verdict.Counts{
		InvalidLines: len(parsed.Bad),
		SkippedLines: parsed.Skipped,
	}

	sem := make(chan struct{}, cfg.Concurrency)
	ch := make(chan item, cfg.Concurrency)

	var (
		notRun   atomic.Int64
		fatalMu  sync.Mutex
		fatalErr error
	)
	setFatal := func(err error) {
		fatalMu.Lock()
		defer fatalMu.Unlock()
		if fatalErr == nil {
			fatalErr = err
		}
	}

	go func() {
		var wg sync.WaitGroup
		defer func() {
			wg.Wait()
			close(ch)
		}()

		for _, e := range parsed.Entries {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				notRun.Add(1)
				continue
			}
			wg.Go(func() {
				// A panic in one page load must not take down a long run; it
				// becomes that URL's load error and the crawl continues.
				defer func() {
					if p := recover(); p != nil {
						ch <- item{index: e.Index, res: panicResult(e, p)}
					}
				}()
				res, err := pl.Load(ctx, e.Index, e.URL)
				ch <- item{index: e.Index, res: res, err: err}
			})
		}
	}()

	total := len(parsed.Entries)
	emitted := 0
	sink := report.NewOrdered(func(res verdict.Result, o verdict.Outcome) error {
		counts.Add(res, o)
		emitted++
		writeProgress(progress, emitted, total, res, o)
		err := rep.Emit(res, o)
		// Releasing here, rather than in the worker, is what bounds the
		// reorder buffer. See the doc comment above.
		<-sem
		return err
	})

	for it := range ch {
		if it.err != nil {
			// A loader error means the browser itself is unusable. Record it
			// and stop dispatching; the drain still finishes what is in flight.
			setFatal(fmt.Errorf("loading %s: %w", it.res.URL, it.err))
			<-sem
			notRun.Add(1)
			continue
		}
		o := verdict.Classify(it.res, policy)
		// Entry indices are 1-based for humans; the sink counts positions from 0.
		if err := sink.Push(it.index-1, it.res, o); err != nil {
			setFatal(err)
		}
	}
	if err := sink.Flush(); err != nil {
		setFatal(err)
	}

	counts.NotRun = int(notRun.Load())

	fatalMu.Lock()
	defer fatalMu.Unlock()
	return counts, fatalErr
}

// panicResult turns a recovered worker panic into an honest load error rather
// than a silently missing URL.
func panicResult(e input.Entry, p any) verdict.Result {
	return verdict.Result{
		Index:         e.Index,
		URL:           e.URL,
		NetError:      fmt.Sprintf("internal panic: %v", p),
		NetErrorClass: "OTHER",
		SettledBy:     "crash",
		Started:       time.Now(),
	}
}

func writeProgress(w io.Writer, n, total int, res verdict.Result, o verdict.Outcome) {
	if w == io.Discard || o == verdict.OutcomeOK {
		return
	}
	status := "  -"
	if res.Status != 0 {
		status = fmt.Sprintf("%3d", res.Status)
	}
	detail := ""
	switch {
	case res.NetError != "":
		detail = "  " + res.NetError
	case len(res.Console) > 0:
		detail = fmt.Sprintf("  (%d console error(s))", len(res.Console))
	case len(res.Resources) > 0:
		detail = fmt.Sprintf("  (%d failed subresource(s))", len(res.Resources))
	}
	fmt.Fprintf(w, "[%3d/%d] %-18s %s  %s%s\n", n, total, o, status, res.URL, detail)
}
