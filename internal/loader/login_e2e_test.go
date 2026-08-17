package loader

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/login"
	"github.com/olegiv/pagevet/internal/testfixtures"
	"github.com/olegiv/pagevet/internal/verdict"
)

// These tests drive a real Chrome against the login fixture in
// internal/testfixtures. They are gated by browsertest.Guard, so `make test`
// skips them and `make test-e2e` runs them.
//
// Each test gets its own Browser rather than borrowing the shared one, because
// signing in mutates the cookie jar for the whole browser — which is exactly
// the property under test, and exactly why it must not leak into a neighbor.

// loginBrowser starts a Chrome configured to sign in against srv with the given
// spec overrides applied.
func loginBrowser(t *testing.T, srvURL string, tweak func(*login.Spec)) *Browser {
	t.Helper()

	spec := login.Spec{
		URL:       srvURL + "/login",
		FormID:    testfixtures.LoginFormID,
		UserField: testfixtures.LoginUserField,
		PassField: testfixtures.LoginPassField,
		Username:  testfixtures.LoginUser,
		Password:  testfixtures.LoginPass,
	}
	if tweak != nil {
		tweak(&spec)
	}

	o := DefaultOptions()
	o.Timeout = e2eTimeout
	o.Settle = 250 * time.Millisecond
	o.Login = &spec
	return newBrowser(t, o)
}

// signIn calls Login with a caller-side deadline, so a regression fails with an
// attributed error instead of hanging until the whole binary times out.
func signIn(t *testing.T, br *Browser) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), loadDeadline)
	defer cancel()
	return br.Login(ctx)
}

// -- proof of the core requirement ---------------------------------------------

// TestLogin_SessionAppliesToLaterTabs is the whole feature in one test.
//
// /private answers 403 to a stranger and 200 to a session. The sign-in happens
// on the login tab, which is closed before Load ever runs; the assertion is
// that a DIFFERENT tab, opened afterwards, is nonetheless authenticated. That
// only holds because every tab is a child of one browser context and therefore
// shares one cookie jar — the mechanism the whole design rests on.
func TestLogin_SessionAppliesToLaterTabs(t *testing.T) {
	env := e2e(t)

	// Baseline, on a browser that never signed in: the page really is
	// protected, so the "after" assertion is measuring something.
	anon := newBrowser(t, func() Options {
		o := DefaultOptions()
		o.Timeout = e2eTimeout
		return o
	}())
	if res, _ := loadURL(t, anon, env.url("/private")); res.Status != 403 {
		t.Fatalf("/private without a session = %d, want 403 (the fixture is not protecting it)", res.Status)
	}

	br := loginBrowser(t, env.srv.URL, nil)
	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	res, _ := loadURL(t, br, env.url("/private"))
	if res.Status != 200 {
		t.Errorf("/private after Login = %d, want 200; the session did not reach the crawl tab", res.Status)
	}
	if got := outcomeOf(res); got != verdict.OutcomeOK {
		t.Errorf("outcome = %s, want ok", got)
	}
}

// TestLogin_SessionSurvivesConcurrentTabs pins the property at the concurrency
// the tool actually runs at. The pool opens up to -concurrency tabs at once;
// every one of them has to see the session, not just the first.
func TestLogin_SessionSurvivesConcurrentTabs(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, nil)
	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	const tabs = 8
	ctx, cancel := context.WithTimeout(t.Context(), loadDeadline)
	defer cancel()

	var (
		mu       sync.Mutex
		statuses []int
		wg       sync.WaitGroup
	)
	for i := range tabs {
		wg.Go(func() {
			res, err := br.Load(ctx, i+1, env.url("/private"))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("Load #%d returned a loader error: %v", i+1, err)
				return
			}
			statuses = append(statuses, res.Status)
		})
	}
	wg.Wait()

	if len(statuses) != tabs {
		t.Fatalf("got %d results, want %d", len(statuses), tabs)
	}
	for i, s := range statuses {
		if s != 200 {
			t.Errorf("concurrent load %d = %d, want 200", i, s)
		}
	}
}

// TestLogin_WrongPasswordFails is the failure that matters most in practice.
//
// The fixture sets no cookie on a bad password, so both success signals are
// absent and the run must stop. It also checks the one thing that must never
// happen: the password appearing in the error text.
func TestLogin_WrongPasswordFails(t *testing.T) {
	env := e2e(t)

	const wrong = "definitely-not-the-password"
	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.Password = wrong })

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() with a wrong password succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
	// Distinct wording per failing check is the point: the user has to be able
	// to tell "wrong credentials" from "this site keeps its form".
	if !strings.Contains(err.Error(), "no cookie was set or changed") {
		t.Errorf("error = %q, want it to say no cookie was set", err)
	}
	if strings.Contains(err.Error(), wrong) {
		t.Errorf("error message contains the password: %q", err)
	}

	// The failure must be honest about the session, too.
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 403 {
		t.Errorf("/private after a failed login = %d, want 403", res.Status)
	}
}

// TestLogin_StickyFormFails covers the other half of the two-signal check: a
// cookie WAS set, but the form is still on the page. pagevet cannot tell that
// apart from a sign-in that silently did nothing, so it fails — and the error
// has to say which check tripped, because that is the only thing that tells the
// user where to look.
func TestLogin_StickyFormFails(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.URL = env.url("/login-sticky") })

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() against a sticky form succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
	if !strings.Contains(err.Error(), "still on the page") {
		t.Errorf("error = %q, want it to name the form-still-present check", err)
	}
	// It must be distinguishable from the wrong-password message.
	if strings.Contains(err.Error(), "nothing happened") {
		t.Errorf("error = %q, want the sticky-form wording, not the wrong-credentials one", err)
	}
	if !strings.Contains(err.Error(), testfixtures.LoginCookie) {
		t.Errorf("error = %q, want it to name the cookie that WAS set", err)
	}
}

// TestLogin_LogoutRunsFirst is the proof that LOGOUT_PATH is fetched, and
// fetched BEFORE the login page.
//
// /login-anon renders its form only to a signed-out visitor. The browser is put
// into the signed-in state first, so the form is not there when the sign-in
// starts — and the only thing that can bring it back is the logout page having
// been visited in between. The companion test below removes LOGOUT_PATH and
// watches the same sign-in fail, which is what makes this one attributable.
func TestLogin_LogoutRunsFirst(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) {
		s.URL = env.url("/login-anon")
		s.LogoutURL = env.url("/logout")
	})

	// Arrive already signed in. /grant sets the session with no form involved.
	if res, _ := loadURL(t, br, env.url("/grant")); res.Status != 200 {
		t.Fatalf("/grant = %d, want 200", res.Status)
	}
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
		t.Fatalf("/private after /grant = %d, want 200 (the fixture did not grant a session)", res.Status)
	}

	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() error = %v; the logout page did not clear the session before the login", err)
	}

	// And the sign-in that followed produced a working session of its own.
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
		t.Errorf("/private after Login = %d, want 200", res.Status)
	}
}

// TestLogin_WithoutLogoutStillSignedIn is the control for the test above.
//
// Same fixture, same starting state, LOGOUT_PATH removed. /login-anon shows no
// form to a signed-in visitor, so the sign-in has nothing to fill in. If this
// ever passes, the test above proves nothing.
func TestLogin_WithoutLogoutStillSignedIn(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) {
		s.URL = env.url("/login-anon")
		s.LogoutURL = "" // the difference
	})

	if res, _ := loadURL(t, br, env.url("/grant")); res.Status != 200 {
		t.Fatalf("/grant = %d, want 200", res.Status)
	}

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() succeeded with no LOGOUT_PATH against a form that hides from signed-in users")
	}
	if !strings.Contains(err.Error(), "no visible form") {
		t.Errorf("error = %q, want it to report the missing form", err)
	}
}

// TestLogin_LogoutIsOptional pins that a .env written before LOGOUT_PATH
// existed keeps working: an empty LogoutURL skips the step rather than
// navigating to "".
func TestLogin_LogoutIsOptional(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.LogoutURL = "" })
	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() with no LOGOUT_PATH error = %v", err)
	}
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
		t.Errorf("/private after Login = %d, want 200", res.Status)
	}
}

func TestLogin_UnreachableLogoutPageFails(t *testing.T) {
	env := e2e(t)

	// A dead host, so the navigation itself fails rather than returning a
	// status. RFC 6761 reserves .invalid, so this can only be NXDOMAIN.
	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) {
		s.LogoutURL = "http://pagevet-does-not-exist.invalid/logout"
	})

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() with an unreachable logout page succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
	// The message has to point at the key to edit, and say it can be dropped.
	if !strings.Contains(err.Error(), "LOGOUT_PATH") {
		t.Errorf("error = %q, want it to name LOGOUT_PATH", err)
	}
}

// TestLogin_SubmitsWithoutAClickableButton covers the two shapes that a click
// alone cannot handle.
//
// The first is not hypothetical: a real Drupal site's inline login form uses
// <input type="submit" value=""> styled entirely in CSS, chromedp waits for a
// node to be visible before clicking it, and the first implementation of this
// feature hung on exactly that until its deadline. requestSubmit() is what gets
// through, and it still fires the submit event a click would have.
func TestLogin_SubmitsWithoutAClickableButton(t *testing.T) {
	for _, tt := range []struct{ name, path string }{
		{"submit button is display:none", "/login-hidden"},
		{"form has no submit control at all", "/login-nobutton"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := e2e(t)

			br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.URL = env.url(tt.path) })
			if err := signIn(t, br); err != nil {
				t.Fatalf("Login() error = %v", err)
			}
			if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
				t.Errorf("/private after Login = %d, want 200", res.Status)
			}
		})
	}
}

// TestLogin_SessionReusingAnExistingCookieName is the regression for the
// new-cookie-NAME check.
//
// /login-samecookie hands anonymous visitors a session cookie and, on a correct
// POST, authenticates that same session by rotating its value — the ordinary
// PHP and Express shape. No name ever appears that was not already there, so a
// check demanding an unseen name aborted the run on a sign-in that plainly
// worked.
func TestLogin_SessionReusingAnExistingCookieName(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.URL = env.url("/login-samecookie") })
	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() error = %v; a rotated value on an existing cookie name was not seen", err)
	}
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
		t.Errorf("/private after Login = %d, want 200", res.Status)
	}
}

// TestLogin_SameCookieNameWrongPasswordStillFails is the control: the same
// route, wrong credentials, keeps the anonymous value unchanged. If this ever
// passes, the test above proves nothing — a value comparison that accepted
// anything would accept this too.
func TestLogin_SameCookieNameWrongPasswordStillFails(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) {
		s.URL = env.url("/login-samecookie")
		s.Password = "definitely-not-the-password"
	})

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() with a wrong password succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
}

// TestLogin_ReplacesPrefilledField covers a form whose username arrives already
// filled in. SendKeys appends, so without clearing first the POST carries
// "guesteditor" and a valid account fails to authenticate.
func TestLogin_ReplacesPrefilledField(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.URL = env.url("/login-prefilled") })
	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() error = %v; the prefilled username was probably appended to", err)
	}
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
		t.Errorf("/private after Login = %d, want 200", res.Status)
	}
}

// TestLogin_FollowsRedirectToAllowedPage checks the address re-check accepts a
// redirect whose destination passes the policy — the common case, and the one
// that must not regress into a refusal.
func TestLogin_FollowsRedirectToAllowedPage(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.URL = env.url("/login-redirect") })
	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() through a redirect error = %v", err)
	}
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
		t.Errorf("/private after Login = %d, want 200", res.Status)
	}
}

// TestLogin_RefusesRedirectToBlockedHost is the security half of the same
// check: only the CONFIGURED login URL passed the address policy before the
// browser started, so a redirect must be re-checked before any password is
// typed into where it landed.
func TestLogin_RefusesRedirectToBlockedHost(t *testing.T) {
	env := e2e(t)

	o := DefaultOptions()
	o.Timeout = e2eTimeout
	o.Settle = 250 * time.Millisecond
	o.Login = &login.Spec{
		URL:       env.url("/login-redirect"),
		FormID:    testfixtures.LoginFormID,
		UserField: testfixtures.LoginUserField,
		PassField: testfixtures.LoginPassField,
		Username:  testfixtures.LoginUser,
		Password:  testfixtures.LoginPass,
	}
	// Reject exactly the host the redirect lands on. This stands in for the
	// real policy refusing a link-local or metadata address.
	o.CheckHost = func(_ context.Context, host string) error {
		if host == "127.0.0.1" {
			return errors.New("blocked by the address policy")
		}
		return nil
	}
	br := newBrowser(t, o)

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() typed credentials into a page the address policy rejects")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
	if !strings.Contains(err.Error(), "Refusing to enter credentials") {
		t.Errorf("error = %q, want it to say the credentials were withheld", err)
	}
}

func TestLogin_UnknownFormFails(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.FormID = "no-such-form" })

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() with an unknown form id succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
	// LOGIN_FORM_ID is the key the user has to go and fix, so it has to be in
	// the message.
	if !strings.Contains(err.Error(), "no-such-form") {
		t.Errorf("error = %q, want it to name the form it looked for", err)
	}
}

func TestLogin_UnknownFieldFails(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.PassField = "not_a_field" })

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() with an unknown password field succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
	if !strings.Contains(err.Error(), "not_a_field") {
		t.Errorf("error = %q, want it to name the field it looked for", err)
	}
}

func TestLogin_UnreachableLoginPageFails(t *testing.T) {
	env := e2e(t)

	// A 404 has no form on it, so this exercises the navigation-succeeded-but-
	// the-page-is-wrong path rather than a network failure.
	br := loginBrowser(t, env.srv.URL, func(s *login.Spec) { s.URL = env.url("/status/404") })

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() against a 404 succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
}

func TestLogin_WithoutSpecIsAnError(t *testing.T) {
	env := e2e(t)

	// Calling Login on a loader with no spec is a programming error, and
	// silently succeeding would mean an unauthenticated crawl reporting itself
	// as authenticated.
	o := DefaultOptions()
	o.Timeout = e2eTimeout
	br := newBrowser(t, o)
	_ = env

	err := signIn(t, br)
	if err == nil {
		t.Fatal("Login() with no spec succeeded, want an error")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want it to wrap ErrLoginFailed", err)
	}
}

// TestLogin_CanceledContextStops checks that a Ctrl-C during the sign-in comes
// back as a context error rather than as a login failure. The two mean
// different things to the caller and map to different exit codes.
func TestLogin_CanceledContextStops(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, nil)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := br.Login(ctx)
	if err == nil {
		t.Fatal("Login() with a canceled context succeeded, want an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
	if errors.Is(err, ErrLoginFailed) {
		t.Errorf("error = %v, want an interruption rather than a login failure", err)
	}
}

// TestLogin_DoesNotLeakIntoAFreshBrowser guards the security claim in the
// README: the session lives in the run's throwaway profile. A second Chrome
// started afterwards must be a stranger to /private again.
func TestLogin_DoesNotLeakIntoAFreshBrowser(t *testing.T) {
	env := e2e(t)

	br := loginBrowser(t, env.srv.URL, nil)
	if err := signIn(t, br); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if res, _ := loadURL(t, br, env.url("/private")); res.Status != 200 {
		t.Fatalf("/private after Login = %d, want 200", res.Status)
	}

	o := DefaultOptions()
	o.Timeout = e2eTimeout
	fresh := newBrowser(t, o)

	if res, _ := loadURL(t, fresh, env.url("/private")); res.Status != 403 {
		t.Errorf("/private in a fresh browser = %d, want 403; the session outlived its profile", res.Status)
	}
}
