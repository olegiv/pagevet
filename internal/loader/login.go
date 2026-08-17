package loader

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"

	"github.com/olegiv/pagevet/internal/login"
	"github.com/olegiv/pagevet/internal/verdict"
)

// errLoginTimeout is the cause attached to the login deadline, so a hung login
// page is distinguishable from a Ctrl-C. Same pattern as errPageTimeout.
var errLoginTimeout = errors.New("login deadline exceeded")

var _ Authenticator = (*Browser)(nil)

// Login signs in once, before the crawl starts, so that every URL afterwards is
// fetched as an authenticated user.
//
// The mechanism is the property that README's "known limitations" used to warn
// about: every tab this Browser opens is a child of one browser context, so all
// of them share one cookie jar. Signing in on this tab therefore signs in on
// every tab that follows, with no cookie copying and no change to the worker
// pool. The session lives in the run's throwaway profile and dies with it.
//
// Success is two independent signals, both required:
//
//  1. a cookie exists now whose name did not exist before the submit, and
//  2. the login form is gone from the page.
//
// Either alone lies in a common case. A site that sets a CSRF or flash-message
// cookie on a FAILED login satisfies (1) while still being logged out; a site
// that renders its login block only for anonymous users can satisfy (2) via a
// redirect that dropped the session. Requiring both, and reporting which one
// failed, is what makes the resulting error message actionable.
//
// Per the Authenticator contract every non-nil error here is run-fatal.
//
//nolint:contextcheck // The tab context deliberately descends from browserCtx, exactly as in Load.
func (b *Browser) Login(ctx context.Context) error {
	spec := b.opts.Login
	if spec == nil {
		return fmt.Errorf("%w: Login called with no login configured", ErrLoginFailed)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.browserCtx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrBrowserUnavailable, err)
	}

	// The login tab hangs off the browser for the same reason every Load tab
	// does — chromedp requires it, and it is what puts the cookies in the jar
	// the crawl will use. The caller's cancellation is forwarded explicitly.
	tabCtx, cancelTab := chromedp.NewContext(b.browserCtx)
	defer cancelTab()

	stopForward := context.AfterFunc(ctx, cancelTab)
	defer stopForward()

	runCtx, cancelRun := context.WithTimeoutCause(tabCtx, b.opts.Timeout, errLoginTimeout)
	defer cancelRun()

	err := b.doLogin(runCtx, spec)
	if err == nil {
		return nil
	}

	// An interruption or a dead browser explains the failure better than
	// whatever chromedp said on the way down, so they replace it. The overall
	// deadline does NOT: doLogin already named the step that ran out of time,
	// and that is the actionable half of the message. Adding the budget to it
	// beats swapping a precise error for a vague one.
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case b.browserCtx.Err() != nil:
		return fmt.Errorf("%w: browser exited during login", ErrBrowserUnavailable)
	case errors.Is(context.Cause(runCtx), errLoginTimeout):
		return fmt.Errorf("%w (the whole sign-in is budgeted at %s, from -timeout)", err, b.opts.Timeout)
	}
	return err
}

// findTimeout bounds ONE element lookup, as a slice of the overall login
// budget rather than the whole of it.
//
// Without this a typo in LOGIN_FORM_ID costs the entire -timeout and then
// reports a bare "deadline exceeded", because chromedp's selector actions poll
// until their context dies. A third of the budget is enough for a form that
// renders after hydration, leaves room for the submit and the settle, and turns
// the common misconfiguration into a fast, specific answer.
func (b *Browser) findTimeout() time.Duration {
	const (
		floor = 2 * time.Second
		ceil  = 10 * time.Second
	)
	return min(max(b.opts.Timeout/3, floor), ceil, b.opts.Timeout)
}

// runFind executes a selector-bound action under findTimeout.
//
// timedOut distinguishes "this element is not on the page" from "the caller
// gave up", which are the same context error but completely different findings.
func (b *Browser) runFind(ctx context.Context, action chromedp.Action) (timedOut bool, err error) {
	stepCtx, cancel := context.WithTimeout(ctx, b.findTimeout())
	defer cancel()

	err = chromedp.Run(stepCtx, action)
	return err != nil && stepCtx.Err() != nil && ctx.Err() == nil, err
}

// doLogin is the sequence itself, kept apart from Login's context plumbing and
// error triage so that each reads as one thing.
func (b *Browser) doLogin(ctx context.Context, spec *login.Spec) error {
	// The form is matched with [id="..."] rather than #id because login.identRE
	// allows '.' and ':', which are legal in an HTML id and both special in a
	// CSS selector: #a.b means "id a, class b", not "id a.b". Quoting the value
	// sidesteps the escaping entirely, and matches how the field selectors
	// already work.
	//
	// formLabel is the same thing written the way the user wrote it in .env,
	// for error messages only. Nothing is ever queried with it.
	formSel := fmt.Sprintf(`[id=%q]`, spec.FormID)
	formLabel := "#" + spec.FormID
	userSel := fmt.Sprintf(`%s [name=%q]`, formSel, spec.UserField)
	passSel := fmt.Sprintf(`%s [name=%q]`, formSel, spec.PassField)

	// Sign out first, when LOGOUT_PATH says how.
	//
	// The profile is fresh, so there is usually nothing to sign out OF — but
	// "usually" is doing real work in that sentence. A site that keeps a
	// session in a long-lived cookie the crawl itself picked up, or one whose
	// login page simply does not render the form to an authenticated visitor
	// (Drupal's inline login block is exactly this), would otherwise fail here
	// with "no visible form" and no hint as to why.
	//
	// It runs before the cookie snapshot below on purpose: a session cleared
	// here must not count as one of the cookies that was already present, or
	// the new-cookie check would compare against the wrong baseline.
	if spec.LogoutURL != "" {
		if _, err := chromedp.RunResponse(ctx, chromedp.Navigate(spec.LogoutURL)); err != nil {
			return fmt.Errorf("%w: opening the logout page %s: %w. Check LOGOUT_PATH, or remove it",
				ErrLoginFailed, b.display(spec.LogoutURL), err)
		}
	}

	if _, err := chromedp.RunResponse(ctx, chromedp.Navigate(spec.URL)); err != nil {
		return fmt.Errorf("%w: opening %s: %w", ErrLoginFailed, b.display(spec.URL), err)
	}

	before, err := cookieNames(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading cookies before submit: %w", ErrLoginFailed, err)
	}

	switch timedOut, findErr := b.runFind(ctx, chromedp.WaitVisible(formSel, chromedp.ByQuery)); {
	case timedOut:
		return fmt.Errorf("%w: no visible form %s on %s after %s. Check LOGIN_FORM_ID",
			ErrLoginFailed, formLabel, b.display(spec.URL), b.findTimeout())
	case findErr != nil:
		return fmt.Errorf("%w: looking for the form %s on %s: %w",
			ErrLoginFailed, formLabel, b.display(spec.URL), findErr)
	}

	// SendKeys dispatches real key events, so a field with a JS input handler
	// (a framework-controlled input, a "show password" toggle) sees what a
	// human would. Nothing here interpolates the password into JavaScript or
	// into a selector; it travels only as an argument.
	switch timedOut, findErr := b.runFind(ctx, chromedp.SendKeys(userSel, spec.Username, chromedp.ByQuery)); {
	case timedOut:
		return fmt.Errorf("%w: %s has no field named %q. Check USERNAME_NAME",
			ErrLoginFailed, formLabel, spec.UserField)
	case findErr != nil:
		return fmt.Errorf("%w: filling the username field %s: %w", ErrLoginFailed, userSel, findErr)
	}

	// Every error below names the SELECTOR, never the value typed into it.
	switch timedOut, findErr := b.runFind(ctx, chromedp.SendKeys(passSel, spec.Password, chromedp.ByQuery)); {
	case timedOut:
		return fmt.Errorf("%w: %s has no field named %q. Check PASSWORD_NAME",
			ErrLoginFailed, formLabel, spec.PassField)
	case findErr != nil:
		return fmt.Errorf("%w: filling the password field %s: %w", ErrLoginFailed, passSel, findErr)
	}

	// submit builds its own message, including the ErrLoginFailed wrapper.
	if submitErr := b.submit(ctx, formSel, formLabel, spec.FormID); submitErr != nil {
		return submitErr
	}

	// A session cookie is often set by script after the navigation commits, so
	// the same quiet window the crawler uses applies here.
	if b.opts.Settle > 0 {
		// Best effort: the checks below are the real verdict, and a canceled
		// sleep will show up there as a much clearer failure than here.
		_ = chromedp.Run(ctx, chromedp.Sleep(b.opts.Settle))
	}

	after, err := cookieNames(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading cookies after submit: %w", ErrLoginFailed, err)
	}
	gained := newNames(before, after)

	formGone, err := formAbsent(ctx, spec.FormID)
	if err != nil {
		return fmt.Errorf("%w: checking whether %s is gone: %w", ErrLoginFailed, formLabel, err)
	}

	// The two failures below are worded to be told apart at a glance, because
	// they have completely different fixes.
	switch {
	case len(gained) == 0 && !formGone:
		return fmt.Errorf("%w: submitted %s but nothing happened: no new cookie was set and %s "+
			"is still on the page. The usual cause is wrong credentials",
			ErrLoginFailed, b.display(spec.URL), formLabel)
	case len(gained) == 0:
		return fmt.Errorf("%w: %s went away after submit, but no new cookie was set, so there is "+
			"no session to crawl with", ErrLoginFailed, formLabel)
	case !formGone:
		return fmt.Errorf("%w: a new cookie was set (%s) but %s is still on the page. If this site "+
			"shows its login form to signed-in users too, this check is the one to revisit",
			ErrLoginFailed, joinNames(gained), formLabel)
	}
	return nil
}

// submit sends the filled-in form and waits for the resulting navigation.
//
// Three ways are tried in order, because no single one works on every real
// login form:
//
//  1. Click the submit control. Highest fidelity — some sites bind their
//     handler to the button's own click rather than to the form's submit
//     event — but chromedp waits for the node to be VISIBLE, and a submit
//     input styled entirely in CSS (`value=""` plus a background image, which
//     is a common way to render an icon button) may never satisfy that.
//  2. form.requestSubmit(). Fires the submit event and runs constraint
//     validation, exactly as a real click would, but needs no visible button
//     and works on a form that has no submit control at all.
//  3. form.submit(). The blunt fallback. It BYPASSES the submit event, so a
//     form whose handler attaches a CSRF token would post without it — which
//     is precisely why it is last rather than first.
//
// After a failed attempt the form is re-checked: an attempt that navigated
// away but whose response chromedp did not match must not be followed by a
// second attempt against a page that no longer has the form on it.
func (b *Browser) submit(ctx context.Context, formSel, formLabel, formID string) error {
	attempts := []struct {
		how    string
		action chromedp.Action
	}{
		{
			"clicking its submit control",
			// Two selectors, not one: a <button> with no type attribute is a
			// submit button per the HTML spec, but [type="submit"] matches on
			// the attribute being literally present.
			chromedp.Click(formSel+` [type="submit"], `+formSel+` button:not([type])`, chromedp.ByQuery),
		},
		{
			"calling requestSubmit() on it",
			chromedp.Evaluate(jsSubmitForm(formID, "requestSubmit"), nil),
		},
		{
			"calling submit() on it",
			chromedp.Evaluate(jsSubmitForm(formID, "submit"), nil),
		},
	}

	var failures []string
	for _, a := range attempts {
		stepCtx, cancel := context.WithTimeout(ctx, b.findTimeout())
		_, err := chromedp.RunResponse(stepCtx, a.action)
		cancel()

		if err == nil {
			return nil
		}
		// Only the caller giving up ends things here; everything else is worth
		// another way of asking.
		if ctx.Err() != nil {
			return fmt.Errorf("%w: submitting %s by %s: %w", ErrLoginFailed, formLabel, a.how, err)
		}
		failures = append(failures, fmt.Sprintf("%s: %v", a.how, err))

		// If the form has gone, something did navigate and the checks in
		// doLogin are a better judge of the outcome than another attempt.
		if gone, gErr := formAbsent(ctx, formID); gErr == nil && gone {
			return nil
		}
	}

	return fmt.Errorf("%w: could not submit %s. Tried %s",
		ErrLoginFailed, formLabel, strings.Join(failures, "; "))
}

// jsSubmitForm builds the expression that submits the form by the named method.
//
// The id is interpolated into JavaScript, which is safe only because
// login.Config rejects anything outside [A-Za-z0-9_:.-] before a Spec exists;
// see login.identRE. method is a literal from this file, never user input.
//
// The expression throws rather than returning false when the method is missing,
// so a browser too old for requestSubmit falls through to the next attempt
// instead of reporting a silent success.
func jsSubmitForm(formID, method string) string {
	return fmt.Sprintf(
		`(() => { const f = document.getElementById(%q);`+
			` if (!f) throw new Error("form is gone");`+
			` if (typeof f.%s !== "function") throw new Error("no %s()");`+
			` f.%s(); return true; })()`,
		formID, method, method, method)
}

// cookieNames returns the names of every cookie in the browser's jar.
//
// Storage.getCookies with no browser-context id covers the whole default
// browser context, which is precisely the jar every crawl tab will read from —
// so this measures the thing the crawl actually depends on, rather than the
// login tab's view of it.
//
// Only names are kept. Values are session tokens, and this program has no
// reason to hold one in a variable that some future error path might format.
func cookieNames(ctx context.Context) ([]string, error) {
	var names []string
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := storage.GetCookies().Do(ctx)
		if err != nil {
			return err
		}
		names = make([]string, 0, len(cookies))
		for _, c := range cookies {
			names = append(names, c.Name)
		}
		slices.Sort(names)
		return nil
	}))
	return names, err
}

// newNames returns the names present in after but not in before.
func newNames(before, after []string) []string {
	var gained []string
	for _, n := range after {
		if !slices.Contains(before, n) {
			gained = append(gained, n)
		}
	}
	return gained
}

// joinNames renders gained cookie names for an error message, capped so a site
// that sets thirty analytics cookies does not produce a thirty-name error.
func joinNames(names []string) string {
	const maxShown = 3
	if len(names) > maxShown {
		return fmt.Sprintf("%s and %d more", strings.Join(names[:maxShown], ", "), len(names)-maxShown)
	}
	return strings.Join(names, ", ")
}

// formAbsent reports whether the login form is gone from the current page.
//
// The id is interpolated into JavaScript, which is safe only because
// login.Config rejects anything outside [A-Za-z0-9_:.-] before a Spec exists.
// That allowlist is load-bearing here; see login.identRE.
func formAbsent(ctx context.Context, formID string) (bool, error) {
	var absent bool
	expr := fmt.Sprintf("document.getElementById(%q) === null", formID)
	if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &absent)); err != nil {
		return false, err
	}
	return absent, nil
}

// display renders a URL for an error message under the run's redaction policy,
// so a login URL carrying a token in its query is treated like every other URL
// this program prints.
func (b *Browser) display(rawURL string) string {
	if b.opts.RedactURLs {
		return verdict.RedactURL(rawURL)
	}
	return rawURL
}
