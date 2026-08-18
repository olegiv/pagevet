package loader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/chromedp/cdproto/input"
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
//  1. the cookie jar changed — a cookie appeared, or an existing one's value
//     was replaced — and
//  2. the login form is gone from the page.
//
// Either alone lies in a common case. A site that sets a CSRF or flash-message
// cookie on a FAILED login satisfies (1) while still being logged out; a site
// that renders its login block only for anonymous users can satisfy (2) via a
// redirect that dropped the session. Requiring both, and reporting which one
// failed, is what makes the resulting error message actionable.
//
// (1) is a value comparison rather than a new-name check on purpose. The
// PHP/Express shape — the login page hands out an anonymous session cookie and
// the POST authenticates that same server-side session — never introduces a new
// name, and demanding one made -login unusable on those sites.
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
	// Selectors are built by ESCAPING, not by trusting the values.
	//
	// internal/login deliberately allows anything short of a control character
	// in these three, because `user[email]` is a perfectly ordinary Rails or PHP
	// field name. That makes the escaping here the security boundary: a .env
	// carrying `x"] , [name="pass` must end up as one attribute selector
	// matching a literal element of that name, never as two selectors.
	//
	// [id="..."] rather than #id for the same reason a quoted attribute selector
	// is used for the fields: an id may legally contain '.' or ':', and #a.b
	// means "id a, class b", not "id a.b".
	//
	// formLabel is the value as the user wrote it in .env, for error messages
	// only. Nothing is ever queried with it.
	formSel := fmt.Sprintf("[id=%s]", cssString(spec.FormID))
	formLabel := "#" + spec.FormID
	userSel := fieldSelector(spec.FormID, spec.UserField)
	passSel := fieldSelector(spec.FormID, spec.PassField)

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
		// The logout page may redirect too, and only the CONFIGURED host was
		// checked before the browser started. No credentials are typed here,
		// but the address policy is about where this program points Chrome at
		// all, not only about where it types.
		if err := b.checkCommitted(ctx, "the logout page "+b.display(spec.LogoutURL)); err != nil {
			return err
		}
	}

	if _, err := chromedp.RunResponse(ctx, chromedp.Navigate(spec.URL)); err != nil {
		return fmt.Errorf("%w: opening %s: %w", ErrLoginFailed, b.display(spec.URL), err)
	}

	// Re-check where we actually landed, BEFORE typing a password into it.
	//
	// app.run validated the configured LOGIN_PATH host, but Navigate follows
	// redirects: a login page that 302s elsewhere means the checks were run
	// against a URL that never received the credentials. A redirect to another
	// origin is legitimate (an SSO hop), so this does not demand the origin be
	// unchanged - it demands the destination pass the same checks the
	// configured one did.
	if err := b.checkCommitted(ctx, b.display(spec.URL)); err != nil {
		return err
	}

	before, err := b.takeSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading the session state before submit: %w", ErrLoginFailed, err)
	}

	switch timedOut, findErr := b.runFind(ctx, chromedp.WaitVisible(formSel, chromedp.ByQuery)); {
	case timedOut:
		return fmt.Errorf("%w: no visible form %s on %s after %s. Check LOGIN_FORM_ID",
			ErrLoginFailed, formLabel, b.display(spec.URL), b.findTimeout())
	case findErr != nil:
		return fmt.Errorf("%w: looking for the form %s on %s: %w",
			ErrLoginFailed, formLabel, b.display(spec.URL), findErr)
	}

	// Choose the submit control BEFORE filling anything: the destination check
	// below consults it, since a submitter's formaction overrides the form's
	// action, and submit() reuses the mark rather than choosing again.
	if _, markErr := b.markClickableSubmit(ctx, spec.FormID); markErr != nil {
		return fmt.Errorf("%w: looking for the submit control of %s: %w", ErrLoginFailed, formLabel, markErr)
	}

	// Where would this form POST? An allowed login page can host a form whose
	// action points at a blocked address, and a cross-origin form submission
	// needs no CORS permission — so this has to be settled before the password
	// is typed, not after.
	if destErr := b.checkSubmitDestination(ctx, formLabel, spec.FormID); destErr != nil {
		return destErr
	}

	// Choose and validate each control, then act on the element that was
	// chosen rather than re-running a selector that might resolve elsewhere.
	if markErr := b.markCredentialField(ctx, "username", spec.FormID, spec.UserField); markErr != nil {
		return markErr
	}
	markedUser := "[" + fieldMarker + "]"

	// Fill both fields. Errors below name the SELECTOR, never the value.
	switch timedOut, findErr := b.runFind(ctx, b.fillField(markedUser, spec.Username)); {
	case timedOut:
		return fmt.Errorf("%w: %s has no field named %q. Check USERNAME_NAME",
			ErrLoginFailed, formLabel, spec.UserField)
	case findErr != nil:
		return fmt.Errorf("%w: filling the username field %s: %w", ErrLoginFailed, userSel, findErr)
	}

	if markErr := b.markCredentialField(ctx, "password", spec.FormID, spec.PassField); markErr != nil {
		return markErr
	}
	switch timedOut, findErr := b.runFind(ctx, b.fillField("["+fieldMarker+"]", spec.Password)); {
	case timedOut:
		return fmt.Errorf("%w: %s has no field named %q. Check PASSWORD_NAME",
			ErrLoginFailed, formLabel, spec.PassField)
	case findErr != nil:
		return fmt.Errorf("%w: filling the password field %s: %w", ErrLoginFailed, passSel, findErr)
	}

	// submit builds its own message, including the ErrLoginFailed wrapper.
	// Ask BEFORE submitting, while the form is still in the document to be
	// asked about.
	targeted, targetErr := b.submitTargetsElsewhere(ctx, spec.FormID)
	if targetErr != nil {
		return targetErr
	}

	navigated, submitErr := b.submit(ctx, formLabel, spec.FormID)
	if submitErr != nil {
		return submitErr
	}

	// A session cookie is often set by script after the navigation commits, so
	// the same quiet window the crawler uses applies here.
	if b.opts.Settle > 0 {
		// Best effort: the checks below are the real verdict, and a canceled
		// sleep will show up there as a much clearer failure than here.
		_ = chromedp.Run(ctx, chromedp.Sleep(b.opts.Settle))
	}

	// Where did the submission actually end up?
	//
	// This is DETECTION, not prevention, and the difference matters. A 307 or
	// 308 answer from an allowed form target preserves the POST method and
	// body, so Chrome re-sends the credentials to wherever it points before
	// this code regains control. Nothing here can stop that; what it can do is
	// refuse to pretend the run was fine, and say plainly that the credentials
	// may have traveled. Preventing it needs CDP request interception — see
	// the known limitation in README.md.
	// Poll the verdict rather than reading it once.
	//
	// The submission is dispatched exactly once and never repeated, so the only
	// question left is how long to wait for it to take effect. A POST — or an
	// SPA's fetch — can finish well after the navigation wait gave up while
	// still being comfortably inside the overall budget, and checking a single
	// time meant a valid slow authentication was reported as exit 5 against a
	// document that had simply not caught up yet.
	//
	// The last observation is what the failure message is built from, so a run
	// that genuinely did not authenticate still says exactly which check failed.
	// Poll only when the submission did NOT navigate.
	//
	// A completed navigation means the document being examined IS the answer to
	// the submission: a wrong password has already re-rendered the form, and
	// waiting longer changes nothing but the user's patience. The cases that
	// need time are the ones with no navigation to observe — a POST slower than
	// the navigation wait, and an SPA that authenticates over fetch and never
	// navigates at all.
	//
	// Bounded even then: polling to the end of the overall budget would make a
	// mistyped password cost the full -timeout before saying so.
	pollFor := time.Duration(0)
	if !navigated {
		pollFor = b.findTimeout()
	}
	pollCtx, cancelPoll := context.WithTimeout(ctx, pollFor)
	defer cancelPoll()

	var (
		changed  []string
		formGone bool
	)
	for {
		if landedErr := b.checkCommitted(ctx, "the submitted form "+formLabel); landedErr != nil {
			return fmt.Errorf("%w. The credentials may already have reached it", landedErr)
		}

		after, err := b.takeSnapshot(ctx)
		if err != nil {
			return fmt.Errorf("%w: reading the session state after submit: %w", ErrLoginFailed, err)
		}
		changed = after.changedSince(before)

		formGone, err = formAbsent(ctx, spec.FormID)
		if err != nil {
			return fmt.Errorf("%w: checking whether %s is gone: %w", ErrLoginFailed, formLabel, err)
		}
		// A targeted submission sends its answer to another tab or frame, so
		// this document keeping its form is expected and proves nothing. The
		// session-state half still has to hold — the cookie jar is shared
		// across contexts, which is the whole mechanism this feature runs on.
		if len(changed) > 0 && (formGone || targeted) {
			return nil
		}

		// Out of polling budget, or the caller gave up: report what was last
		// seen.
		if ctx.Err() != nil || !sleepWithin(pollCtx, verdictPollInterval) {
			break
		}
	}

	// The three failures below are worded to be told apart at a glance, because
	// they have completely different fixes.
	switch {
	case targeted:
		return fmt.Errorf("%w: submitted %s, which targets another tab or frame, and no cookie or "+
			"stored session changed. The form staying on this page is expected for such a form and "+
			"is not the problem", ErrLoginFailed, b.display(spec.URL))
	case len(changed) == 0 && !formGone:
		return fmt.Errorf("%w: submitted %s but nothing happened: no cookie or stored session changed, "+
			"and %s is still on the page. The usual cause is wrong credentials",
			ErrLoginFailed, b.display(spec.URL), formLabel)
	case len(changed) == 0:
		return fmt.Errorf("%w: %s went away after submit, but no cookie or stored session changed, so "+
			"there is no session to crawl with", ErrLoginFailed, formLabel)
	default:
		return fmt.Errorf("%w: the session state changed (%s) but %s is still on the page. If this site "+
			"shows its login form to signed-in users too, this check is the one to revisit",
			ErrLoginFailed, joinNames(changed), formLabel)
	}
}

// verdictPollInterval is how often the post-submit signals are re-read. Short
// enough that a fast login is not noticeably delayed, long enough that a slow
// one does not spend the budget on round trips.
const verdictPollInterval = 250 * time.Millisecond

// sleepWithin waits for d, reporting false if the context ran out first.
func sleepWithin(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// fieldSelector matches a named control of the form, whether it sits inside the
// form element or is associated with it from outside.
//
// The second half is not exotic HTML. `<input name="pass" form="login-form">`
// placed anywhere in the document is a member of that form: the browser puts it
// in form.elements and submits it normally. A descendant selector alone misses
// it entirely, and the symptom is the least helpful one possible — the field
// times out and the run reports "no field named pass", pointing the user at a
// PASSWORD_NAME that was right all along.
func fieldSelector(formID, fieldName string) string {
	id, name := cssString(formID), cssString(fieldName)
	return fmt.Sprintf("[id=%s] [name=%s], [form=%s][name=%s]", id, name, id, name)
}

// fieldMarker is stamped on the control a credential will be typed into, so
// every later action addresses the exact element that was validated rather than
// re-running a selector that could resolve elsewhere.
const fieldMarker = "data-pagevet-field"

// textCapable lists the controls a credential may be typed into.
//
// A positive allowlist, for the same reason internal/input allowlists schemes:
// the failure mode of guessing wrong is disclosure of a local file. See
// fillField for why that is not hypothetical.
var textCapable = map[string]bool{
	"textarea":       true,
	"input:text":     true,
	"input:password": true,
	"input:email":    true,
	"input:tel":      true,
	"input:url":      true,
	"input:search":   true,
	"input:number":   true,
}

// jsMarkField picks the control a credential should go into and stamps it,
// returning its kind as "tag" or "input:type" — or "" when there is no match.
//
// Two things it must get right that a bare querySelector does not:
//
//   - The FIRST match is not necessarily the usable one. A password-manager
//     decoy, or an inactive copy from a responsive layout, sits before the real
//     field often enough to matter; an invisible control is skipped when a
//     visible one exists.
//   - Membership is decided by e.form, so a control associated from outside the
//     form via form="<id>" is included, exactly as for submit controls.
const jsMarkField = `function (formID, name, marker) {
  const f = document.getElementById(formID);
  if (!f) return "";
  // Clear the mark EVERYWHERE, not just from controls of this name. The
  // username is marked and filled before the password is marked, so a mark
  // left behind would make the marker selector match two elements and the
  // password would be typed into whichever came first — the username box.
  for (const e of document.querySelectorAll("[" + marker + "]")) { e.removeAttribute(marker); }
  const named = Array.from(document.getElementsByName(name)).filter((e) => e.form === f);
  // :disabled rather than .disabled — a control inside <fieldset disabled> has
  // .disabled false while HTML treats it as disabled for focus and for
  // submission, so filling it would put the credential somewhere the request
  // never carries.
  const visible = (e) => !e.matches(":disabled") && e.getClientRects().length > 0 &&
    getComputedStyle(e).visibility !== "hidden";
  const chosen = named.find(visible) || named[0];
  if (!chosen) return "";
  chosen.setAttribute(marker, "");
  // The COMPUTED type, not the attribute. <input type="username"> is an
  // invalid value, so HTML treats the control as a text input and .type
  // reports "text" — while the raw attribute would fail the allowlist and
  // reject a perfectly usable form. It still reports "file" for a file input,
  // which is the case the allowlist exists to catch.
  const tag = chosen.tagName.toLowerCase();
  return tag === "input" ? "input:" + chosen.type.toLowerCase() : tag;
}`

// markCredentialField chooses the control for one credential, stamps it, and
// refuses anything a credential must not be typed into.
func (b *Browser) markCredentialField(ctx context.Context, what, formID, name string) error {
	expr, err := jsCall(jsMarkField, formID, name, fieldMarker)
	if err != nil {
		return err
	}

	var kind string
	stepCtx, cancel := context.WithTimeout(ctx, b.findTimeout())
	defer cancel()
	if err := chromedp.Run(stepCtx, chromedp.Evaluate(expr, &kind)); err != nil {
		return fmt.Errorf("%w: inspecting the %s field: %w", ErrLoginFailed, what, err)
	}

	switch {
	case kind == "":
		return nil // not there yet; the fill below reports it properly
	case kind == "input:file":
		return fmt.Errorf("%w: the %s field is a file input. Refusing to enter credentials: "+
			"typing into one uploads a LOCAL FILE named by the value instead of entering it",
			ErrLoginFailed, what)
	case !textCapable[kind]:
		return fmt.Errorf("%w: the %s field is a %s, which cannot hold a typed credential. "+
			"Check the name in .env", ErrLoginFailed, what, kind)
	}
	return nil
}

// fillField types value into the field at sel, REPLACING whatever is there.
//
// The text is INSERTED, never sent as keystrokes. chromedp.SendKeys inspects
// the node it lands on and, for <input type="file">, calls
// DOM.setFileInputFiles instead — so a path-shaped password would upload a
// local file to the site. A type check before typing narrows that but cannot
// close it: SendKeys re-resolves the node, and a focus handler is free to
// change an input's type in between. Input.insertText has no such branch, so
// the dangerous path simply does not exist here.
//
// It still fires an input event, which is what a framework-controlled input
// listens for, and it treats a tab or newline in a password as text rather than
// as Tab and Enter.
//
// The existing contents are selected first, so the insertion replaces them: a
// server-prefilled username would otherwise turn "editor" into "guesteditor".
// Input.dispatchKeyEvent carries a native "selectAll" editing command, which
// needs no Ctrl-versus-Cmd guess.
func (b *Browser) fillField(sel, value string) chromedp.Action {
	return chromedp.Tasks{
		chromedp.Focus(sel, chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return input.DispatchKeyEvent(input.KeyRawDown).
				WithCommands([]string{"selectAll"}).
				Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// insertText with "" does not clear a selection, so an empty
			// credential needs the delete command explicitly.
			if value == "" {
				return input.DispatchKeyEvent(input.KeyRawDown).
					WithCommands([]string{"deleteBackward"}).
					Do(ctx)
			}
			return input.InsertText(value).Do(ctx)
		}),
	}
}

// submitControls is the CANDIDATE query for a form's submit controls. It casts
// wide on purpose and lets the JavaScript predicate decide, because no CSS
// selector expresses what HTML actually means by "submit button".
//
// A <button> with no type attribute is a submit button; so is one with an
// INVALID type, including type="" — but an attribute selector sees a present
// attribute and matches neither :not([type]) nor [type="submit"]. Only the
// computed .type reports "submit" for all of them. <input type="image"> is a
// submit control too, with its own formaction and name.x/name.y fields.
//
// Filtering a few dozen elements in the page costs nothing; missing the control
// that carries name="op" costs a login.
const submitControls = `button, input`

// submitMarker is stamped on the control this run intends to click, so Go can
// address the exact element JavaScript chose. querySelector returns only the
// FIRST match, and the first submit control is not always the usable one — a
// hidden control followed by the real Sign in button is an ordinary layout.
// Picking by position in CSS cannot express "the first visible one".
const submitMarker = "data-pagevet-submit"

// submit sends the filled-in form.
//
// EXACTLY ONE submission is ever dispatched. An earlier version tried three
// methods in turn and fell through on failure, which had a nasty edge: a POST
// slower than one step's slice of the budget is indistinguishable from one that
// never happened, because the old document keeps rendering the form until the
// response commits. The loop would then send the credentials a SECOND time —
// spending a one-time CSRF token, tripping rate limits, or walking an account
// toward a lockout.
//
// So the method is chosen up front from the DOM:
//
//   - The first CLICKABLE submit control is clicked. Highest fidelity, and some
//     sites bind their handler to the button's click rather than to the form's
//     submit event.
//   - Otherwise requestSubmit(submitter). It fires the submit event and runs
//     constraint validation exactly as a click would, needs no visible button,
//     and — passing the submitter — still contributes that control's name/value
//     and honors its formaction, which a bare requestSubmit() would drop.
//   - Only a browser without requestSubmit falls back to submit(), inside the
//     same expression. That one BYPASSES the submit event, so a form whose
//     handler attaches a CSRF token would post without it.
//
// A navigation is awaited but NOT required. A single-page login handles submit
// in JavaScript, calls preventDefault(), authenticates over fetch and never
// navigates at all; demanding a navigation there burned the whole budget and
// reported exit 5 on a sign-in that had plainly worked. When no navigation
// arrives, the cookie and form checks in doLogin are left to judge the outcome
// — which is what they are for.
func (b *Browser) submit(ctx context.Context, formLabel, formID string) (navigated bool, err error) {
	// Re-mark rather than trusting the earlier pass: filling the fields can run
	// page script that enables a previously disabled button, which is a common
	// "enable Sign in once both fields are non-empty" pattern.
	clickable, err := b.markClickableSubmit(ctx, formID)
	if err != nil {
		return false, fmt.Errorf("%w: looking for the submit control of %s: %w", ErrLoginFailed, formLabel, err)
	}

	// The destination was checked before the fields were filled, but the
	// selection above deliberately runs AGAIN afterwards, because filling can
	// run page script that enables a different button. That script can equally
	// well have changed form.action, or the newly-enabled control can carry its
	// own formaction — so the target is re-checked against the FINAL selection,
	// immediately before anything is dispatched.
	if destErr := b.checkSubmitDestination(ctx, formLabel, formID); destErr != nil {
		return false, destErr
	}

	submitExpr, err := jsCall(jsRequestSubmit, formID, submitMarker, submitControls)
	if err != nil {
		return false, err
	}

	how := "calling requestSubmit() on it"
	var action chromedp.Action = chromedp.Evaluate(submitExpr, nil)
	if clickable {
		how = "clicking its submit control"
		action = chromedp.Click("["+submitMarker+"]", chromedp.ByQuery)
	}

	// The navigation wait gets a slice of the budget, not all of it: when it
	// expires we carry on to the success checks rather than failing, so the
	// non-navigating case costs one findTimeout instead of the whole sign-in.
	waitCtx, cancel := context.WithTimeout(ctx, b.findTimeout())
	defer cancel()

	if _, err := chromedp.RunResponse(waitCtx, action); err != nil {
		switch {
		case ctx.Err() != nil:
			return false, fmt.Errorf("%w: submitting %s by %s: %w", ErrLoginFailed, formLabel, how, err)
		case waitCtx.Err() != nil:
			// No navigation within the window. Either the page authenticated
			// without one — a slow POST, or an SPA that never navigates at all
			// — or nothing happened. doLogin's checks tell those apart, and
			// re-sending the credentials is never the answer.
			return false, nil
		default:
			return false, fmt.Errorf("%w: submitting %s by %s: %w (the credentials may already have been "+
				"sent; pagevet will not submit them a second time)", ErrLoginFailed, formLabel, how, err)
		}
	}
	return true, nil
}

// markClickableSubmit finds the first submit control that could actually be
// clicked and stamps it, reporting whether one was found.
//
// chromedp.Click waits for a node to be VISIBLE, so a control rendered entirely
// in CSS — `value=""` plus a background image, a common icon-button idiom, and
// exactly what a real Drupal site does — would hang until its deadline. Asking
// the DOM first turns that into an immediate, correct choice of method.
//
// getClientRects() is the check the spec itself uses for "renders a box": it is
// empty for display:none, for a detached node, and for a zero-size element.
func (b *Browser) markClickableSubmit(ctx context.Context, formID string) (bool, error) {
	expr, err := jsCall(jsMarkClickableSubmit, formID, submitMarker, submitControls)
	if err != nil {
		return false, err
	}

	var ok bool
	stepCtx, cancel := context.WithTimeout(ctx, b.findTimeout())
	defer cancel()
	if err := chromedp.Run(stepCtx, chromedp.Evaluate(expr, &ok)); err != nil {
		return false, err
	}
	return ok, nil
}

// jsSubmitsOf is the shared body that resolves a form's submit controls. It is
// spliced into every expression that needs them rather than written out four
// times, because a duplicated predicate is how three separate review findings
// happened: the rule was corrected in one copy and left wrong in the others.
//
// It expects `f` (the form) and `controls` (the candidate query) in scope, and
// leaves `submits` defined.
//
// Membership is the element's own form owner, so a control associated from
// outside via form="<id>" counts and an image button — which f.elements
// excludes by spec — is not lost. Submit-ness is the COMPUTED type, because
// <button type=""> is a submit button per the spec while matching no attribute
// selector.
const jsSubmitsOf = `
  const isSubmit = (e) => e.form === f &&
    (e.tagName === "BUTTON" ? e.type === "submit" : (e.type === "submit" || e.type === "image"));
  const submits = Array.from(document.querySelectorAll(controls)).filter(isSubmit);
`

// jsMarkClickableSubmit stamps the first clickable submit control and reports
// whether it found one. getClientRects() is the check the spec itself uses for
// "renders a box": empty for display:none, for a detached node, and for a
// zero-size element.
var jsMarkClickableSubmit = `function (formID, marker, controls) {
  const f = document.getElementById(formID);
  if (!f) return false;
  // Membership is decided by e.form, the element's own form owner, not by
  // descendancy and not by f.elements.
  //
  // Descendancy misses <button form="login"> placed elsewhere in the document,
  // which the browser submits normally. And f.elements is not a superset of it:
  // the spec has it exclude input elements in the Image Button state, so
  // <input type="image"> — a submit control with its own formaction and its own
  // name.x/name.y fields — is absent from it entirely.
  // Membership and submit-ness in one predicate, using the element's own form
  // owner and its COMPUTED type.
  //
  // e.form covers <button form="login"> placed elsewhere in the document, which
  // a descendant query misses, and image buttons, which f.elements excludes by
  // spec. e.type covers <button type=""> — any invalid value is a submit button
  // per the spec, and HTMLButtonElement.type reports "submit" for exactly the
  // cases an attribute selector sees nothing.
` + jsSubmitsOf + `  // Clear the mark EVERYWHERE, not just from this form's submit controls. A
  // mark left on an element that has since changed type or form association
  // would survive, and the click selector — which is document-wide — would
  // press that stale element instead of the control whose destination was just
  // validated.
  for (const c of document.querySelectorAll("[" + marker + "]")) { c.removeAttribute(marker); }
  for (const c of submits) {
    if (c.matches(":disabled")) continue;
    if (c.getClientRects().length === 0) continue;
    const st = getComputedStyle(c);
    if (st.visibility === "hidden" || st.display === "none") continue;
    c.setAttribute(marker, "");
    return true;
  }
  return false;
}`

// jsRequestSubmit builds the one expression used for every non-click
// submission.
//
// The submitter is passed on purpose: requestSubmit(control) contributes that
// control's name and value to the submitted data and honors its formaction,
// where a bare requestSubmit() drops both. Servers that branch on op= — Drupal
// among them — need it. It prefers the marked control when there is one, so
// click and no-click paths agree on which button they are speaking for.
//
// The submit() fallback lives inside the same expression rather than in a
// second round trip, so there is still only one dispatch: a browser without
// requestSubmit takes the other branch without anything having been sent yet.
//
// The id goes through jsString, so any value is a literal.
var jsRequestSubmit = `function (formID, marker, controls) {
  const f = document.getElementById(formID);
  if (!f) throw new Error("form is gone");
  // Membership is decided by e.form, the element's own form owner, not by
  // descendancy and not by f.elements.
  //
  // Descendancy misses <button form="login"> placed elsewhere in the document,
  // which the browser submits normally. And f.elements is not a superset of it:
  // the spec has it exclude input elements in the Image Button state, so
  // <input type="image"> — a submit control with its own formaction and its own
  // name.x/name.y fields — is absent from it entirely.
  // Membership and submit-ness in one predicate, using the element's own form
  // owner and its COMPUTED type.
  //
  // e.form covers <button form="login"> placed elsewhere in the document, which
  // a descendant query misses, and image buttons, which f.elements excludes by
  // spec. e.type covers <button type=""> — any invalid value is a submit button
  // per the spec, and HTMLButtonElement.type reports "submit" for exactly the
  // cases an attribute selector sees nothing.
` + jsSubmitsOf + `  const c = submits.find((e) => e.hasAttribute(marker)) || submits[0];
  if (typeof f.requestSubmit === "function") { c ? f.requestSubmit(c) : f.requestSubmit(); return "requestSubmit"; }
  f.submit(); return "submit";
}`

// jsSubmitTargetsElsewhere reports whether the form, or the control chosen to
// submit it, sends its response to another browsing context.
//
// target="_blank", or a name that is not this window, means the answer arrives
// in a tab or frame that is not the one being examined — so the login form
// staying put in THIS document says nothing about whether the sign-in worked.
// A submitter's formtarget overrides the form's target, so the marked control
// is consulted first.
var jsSubmitTargetsElsewhere = `function (formID, marker, controls) {
  const f = document.getElementById(formID);
  if (!f) return false;
` + jsSubmitsOf + `  const c = submits.find((e) => e.hasAttribute(marker)) || submits[0];
  const t = (c && c.hasAttribute("formtarget") ? c.getAttribute("formtarget") : f.getAttribute("target")) || "";
  return t !== "" && t !== "_self";
}`

// submitTargetsElsewhere reports whether submitting this form sends its answer
// to another browsing context. See jsSubmitTargetsElsewhere.
func (b *Browser) submitTargetsElsewhere(ctx context.Context, formID string) (bool, error) {
	expr, err := jsCall(jsSubmitTargetsElsewhere, formID, submitMarker, submitControls)
	if err != nil {
		return false, err
	}

	var targeted bool
	stepCtx, cancel := context.WithTimeout(ctx, b.findTimeout())
	defer cancel()
	if err := chromedp.Run(stepCtx, chromedp.Evaluate(expr, &targeted)); err != nil {
		return false, fmt.Errorf("%w: reading the submission target of %s: %w", ErrLoginFailed, formID, err)
	}
	return targeted, nil
}

// checkSubmitDestination validates where the form would POST, before anything
// is typed into it.
//
// The login PAGE passing the address policy says nothing about where its form
// sends the data. A form on an allowed page can carry action="http://169.254.169.254/…",
// and a cross-origin form submission needs no CORS permission whatsoever — the
// browser just sends it. Without this, the configured username and password
// would be typed and posted to an address the policy exists to keep out.
//
// The submitter's formaction overrides the form's action, so the control this
// run intends to use is consulted too. Both are read as resolved absolute URLs.
func (b *Browser) checkSubmitDestination(ctx context.Context, formLabel, formID string) error {
	expr, err := jsCall(jsSubmitDestination, formID, submitMarker, submitControls)
	if err != nil {
		return err
	}

	var dest string
	stepCtx, cancel := context.WithTimeout(ctx, b.findTimeout())
	defer cancel()
	if err := chromedp.Run(stepCtx, chromedp.Evaluate(expr, &dest)); err != nil {
		return fmt.Errorf("%w: reading the submission target of %s: %w", ErrLoginFailed, formID, err)
	}
	if dest == "" {
		// No action attribute and no document URL to inherit is not something a
		// submittable form has; the committed-page check already covered where
		// we are.
		return nil
	}
	return b.checkDestination(ctx, "the form "+formLabel, dest)
}

// cookieDigests returns every cookie in the browser's jar as name -> digest of
// its value.
//
// Storage.getCookies with no browser-context id covers the whole default
// browser context, which is precisely the jar every crawl tab will read from —
// so this measures the thing the crawl actually depends on, rather than the
// login tab's view of it.
//
// Values are DIGESTED rather than kept. A session token has no business sitting
// in a variable that some future error path might format, and a digest answers
// the only question asked of it: did this cookie change? SHA-256 truncated to
// eight bytes is far more than enough to distinguish two values that a server
// meant to be different.
func cookieDigests(ctx context.Context) (map[string]string, error) {
	digests := make(map[string]string)
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := storage.GetCookies().Do(ctx)
		if err != nil {
			return err
		}
		clear(digests)
		for _, c := range cookies {
			sum := sha256.Sum256([]byte(c.Value))
			// Domain and path are part of the identity: two cookies can share
			// a name across hosts, and collapsing them would hide a change.
			digests[c.Name+"\x00"+c.Domain+c.Path] = hex.EncodeToString(sum[:8])
		}
		return nil
	}))
	return digests, err
}

// snapshot is the shared state a sign-in could plausibly change: the cookie
// jar, plus the page's localStorage.
//
// origin is recorded because web storage is PER-ORIGIN. The before and after
// snapshots are taken either side of a submission that may navigate somewhere
// else entirely, and comparing origin A's storage against origin B's would
// report every key in B as new — declaring a failed login a success. When the
// origin moves, the storage half is simply not evidence, and the cookie jar
// (which is not origin-scoped in this way) answers alone.
type snapshot struct {
	origin  string
	cookies map[string]string
	storage map[string]string
}

// takeSnapshot records the session state as it is now.
//
// Cookies alone were not enough. A token-backed SPA authenticates over fetch,
// puts its access token in localStorage and removes the form, setting no cookie
// at all — and because every crawl tab shares that origin's storage, it really
// is signed in. Demanding a cookie mutation called that a failure.
func (b *Browser) takeSnapshot(ctx context.Context) (snapshot, error) {
	cookies, err := cookieDigests(ctx)
	if err != nil {
		return snapshot{}, err
	}
	snap := snapshot{cookies: cookies, storage: map[string]string{}}

	var raw struct {
		Origin  string            `json:"origin"`
		Entries map[string]string `json:"entries"`
	}
	// Storage is unreadable on an opaque origin and when a policy forbids it.
	// That is not a login failure, so the error is deliberately dropped: the
	// cookie half still answers the question. Assigned to _ so the decision is
	// visible and greppable.
	readErr := chromedp.Run(ctx, chromedp.Evaluate("("+jsStorageSnapshot+").call(null)", &raw))
	_ = readErr

	snap.origin = raw.Origin
	for k, v := range raw.Entries {
		sum := sha256.Sum256([]byte(v))
		snap.storage[k] = hex.EncodeToString(sum[:8])
	}
	return snap, nil
}

// changedSince returns the names of entries that appeared, or whose value
// changed, between two snapshots.
//
// Storage is compared only when the origin has not moved; see snapshot.origin.
func (s snapshot) changedSince(before snapshot) []string {
	changed := changedNames(before.cookies, s.cookies)
	if s.origin != "" && s.origin == before.origin {
		changed = append(changed, changedNames(before.storage, s.storage)...)
		slices.Sort(changed)
		changed = slices.Compact(changed)
	}
	return changed
}

// jsStorageSnapshot returns the page's origin and its localStorage entries.
// Accessing storage throws on an opaque origin, so the read is guarded.
const jsStorageSnapshot = `function () {
  const out = {};
  const read = (store, label) => {
    try {
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        out[label + ":" + k + "\u0000"] = store.getItem(k) || "";
      }
    } catch (e) { /* opaque origin or storage disabled */ }
  };
  // localStorage ONLY. sessionStorage belongs to the browsing context, and
  // this tab is closed the moment Login returns — the crawl tabs are created
  // independently and start with an empty one. Counting it would report a
  // session the crawl will never have, and the run would crawl anonymously
  // while believing itself signed in.
  read(window.localStorage, "localStorage");
  return { origin: window.location.origin, entries: out };
}`

// changedNames returns the names of entries that appeared, or whose value
// changed, between the two snapshots.
//
// A NEW NAME is not required, and that is the point. The obvious flow — the
// login page hands out an anonymous session cookie, the POST authenticates that
// same server-side session — leaves the name set identical while the session
// becomes a completely different thing. Demanding an unseen name rejected those
// sites outright. Any server that upgrades a session in place still rotates the
// identifier, because not rotating it is session fixation, so the value change
// is the signal that actually generalizes.
func changedNames(before, after map[string]string) []string {
	var changed []string
	for key, digest := range after {
		if old, existed := before[key]; !existed || old != digest {
			changed = append(changed, entryName(key))
		}
	}
	slices.Sort(changed)
	return slices.Compact(changed)
}

// entryName recovers the display name from a sessionEvidence key.
func entryName(key string) string {
	name, _, _ := strings.Cut(key, "\x00")
	return name
}

// checkHostOnce applies the address policy to a host, reusing the answer it
// already has for that host. See Browser.hostChecked for why.
//
// A plain map under a mutex rather than a sync.Map: the entries are answers to
// "is this host allowed", so storing them typed keeps an unchecked type
// assertion out of the one path that decides whether credentials may be sent.
func (b *Browser) checkHostOnce(ctx context.Context, host string) error {
	b.hostMu.Lock()
	cached, ok := b.hostChecked[host]
	b.hostMu.Unlock()
	if ok {
		return cached
	}

	err := b.opts.CheckHost(ctx, host)

	// A canceled lookup is not cached: CheckHost reports one as "no opinion",
	// and remembering that would let an interrupted check bless the host for
	// the rest of the run.
	if ctx.Err() == nil {
		b.hostMu.Lock()
		if b.hostChecked == nil {
			b.hostChecked = make(map[string]error, 4)
		}
		b.hostChecked[host] = err
		b.hostMu.Unlock()
	}
	return err
}

// checkCommitted re-runs the address policy against the page that actually
// committed, which after redirects need not be the one that was navigated to.
//
// what names the thing being checked, for the error message.
func (b *Browser) checkCommitted(ctx context.Context, what string) error {
	var href string
	if err := chromedp.Run(ctx, chromedp.Evaluate("document.location.href", &href)); err != nil {
		return fmt.Errorf("%w: reading the address of %s after navigation: %w",
			ErrLoginFailed, what, err)
	}
	return b.checkDestination(ctx, what, href)
}

// checkDestination applies the run's address policy to one absolute URL.
//
// Shared by the two places a credential could otherwise reach an unchecked
// address: the page that commits after a redirect, and the target the form
// would POST to. what names the thing being checked, for the error message.
func (b *Browser) checkDestination(ctx context.Context, what, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Neither the URL nor the error is printed raw. url.Parse returns a
		// *url.Error carrying the WHOLE url, so %w would leak a form action
		// like https://user:pass@host/%zz?token=... straight to stderr —
		// before any credential has even been typed.
		return fmt.Errorf("%w: %s leads to an unparseable address %s: %s",
			ErrLoginFailed, what, login.SafeURLPreview(rawURL), login.ParseReason(err))
	}

	// Same positive allowlist internal/input applies to every crawled URL. A
	// javascript:, data: or file: destination must not be typed into.
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: %s leads to a %q URL; refusing to enter credentials",
			ErrLoginFailed, what, u.Scheme)
	}
	if b.opts.CheckHost == nil {
		return nil
	}
	if err := b.checkHostOnce(ctx, u.Hostname()); err != nil {
		return fmt.Errorf("%w: %s leads to %s, which fails the address policy: %w. "+
			"Refusing to enter credentials", ErrLoginFailed, what, b.displayTarget(rawURL), err)
	}
	return nil
}

// joinNames renders changed cookie names for an error message, capped so a site
// that sets thirty analytics cookies does not produce a thirty-name error.
func joinNames(names []string) string {
	const maxShown = 3
	if len(names) > maxShown {
		return fmt.Sprintf("%s and %d more", strings.Join(names[:maxShown], ", "), len(names)-maxShown)
	}
	return strings.Join(names, ", ")
}

// cssString renders s as a quoted CSS string, for use inside an attribute
// selector such as [name="..."].
//
// Per the CSS syntax spec a double-quoted string may contain anything except an
// unescaped double quote, backslash or newline, and a backslash escapes the
// character after it. Escaping those two characters is therefore sufficient to
// make any value a single, literal string — which is what stops a field name
// from closing the selector and starting another. login.Config has already
// rejected the newlines and other control characters.
//
// Go's %q is deliberately NOT used: it emits Go escape syntax (é for a
// non-ASCII rune), and CSS reads a backslash-escape as hexadecimal, so %q would
// silently mangle any non-ASCII name.
func cssString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// jsCall renders a call of a CONSTANT JavaScript function with its arguments
// supplied as data.
//
// Nothing is interpolated into the JavaScript source. Every expression this
// package evaluates is a compile-time constant applied to a JSON array, so a
// form id or field name is an argument the engine binds — never text spliced
// into a program, and never inside a quoted context it could close.
//
// The previous approach escaped each value and interpolated it, which was
// correct but had to be re-proved at every call site, and read as string-built
// code to anything auditing it (CodeQL's go/unsafe-quoting among them). This
// shape removes the question instead of answering it repeatedly.
//
// JSON is a subset of JavaScript expression syntax, so the marshaled array is
// itself a valid JS array literal; Function.prototype.apply spreads it.
func jsCall(fn string, args ...string) (string, error) {
	enc, err := json.Marshal(args)
	if err != nil {
		// Only invalid UTF-8 can fail here, and the .env reader rejects that
		// before a Spec exists.
		return "", fmt.Errorf("encoding javascript arguments: %w", err)
	}
	return "(" + fn + ").apply(null, " + string(enc) + ")", nil
}

// jsFormAbsent reports whether the login form has gone from the page.
const jsFormAbsent = `function (formID) {
  return document.getElementById(formID) === null;
}`

// jsSubmitDestination returns the URL the form would POST to: the submitter's
// formaction when it has one, otherwise the form's action. Both are read as
// resolved absolute URLs.
var jsSubmitDestination = `function (formID, marker, controls) {
  const f = document.getElementById(formID);
  if (!f) return "";
  // Membership is decided by e.form, the element's own form owner, not by
  // descendancy and not by f.elements.
  //
  // Descendancy misses <button form="login"> placed elsewhere in the document,
  // which the browser submits normally. And f.elements is not a superset of it:
  // the spec has it exclude input elements in the Image Button state, so
  // <input type="image"> — a submit control with its own formaction and its own
  // name.x/name.y fields — is absent from it entirely.
  // Membership and submit-ness in one predicate, using the element's own form
  // owner and its COMPUTED type.
  //
  // e.form covers <button form="login"> placed elsewhere in the document, which
  // a descendant query misses, and image buttons, which f.elements excludes by
  // spec. e.type covers <button type=""> — any invalid value is a submit button
  // per the spec, and HTMLButtonElement.type reports "submit" for exactly the
  // cases an attribute selector sees nothing.
` + jsSubmitsOf + `  const c = submits.find((e) => e.hasAttribute(marker)) || submits[0];
  if (c && c.hasAttribute("formaction")) { return c.formAction || ""; }
  return f.action || "";
}`

// formAbsent reports whether the login form is gone from the current page.
func formAbsent(ctx context.Context, formID string) (bool, error) {
	expr, err := jsCall(jsFormAbsent, formID)
	if err != nil {
		return false, err
	}
	var absent bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &absent)); err != nil {
		return false, err
	}
	return absent, nil
}

// displayTarget renders a URL the BROWSER navigated to, for an error message.
//
// The query is dropped entirely rather than redacted. verdict.RedactURL blanks
// the values of about twenty credential-like parameter names, which is right
// for a crawled URL but not sufficient here: a form with method="get" puts the
// configured field names in the query, and those are whatever the .env says —
// `user[password]` is explicitly supported and is not on any fixed list. The
// host and path are what a reader needs to act on an address-policy rejection;
// the query never is.
func (b *Browser) displayTarget(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Unparseable, so fall back to the textual scrub, which needs no
		// successful parse and removes userinfo, query and fragment alike.
		return login.SafeURLPreview(rawURL)
	}
	u.RawQuery = ""
	u.Fragment = ""
	if u.RawQuery == "" && strings.Contains(rawURL, "?") {
		return b.display(u.String()) + " (query omitted: it may hold a credential)"
	}
	return b.display(u.String())
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
