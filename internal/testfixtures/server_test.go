package testfixtures_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/olegiv/pagevet/internal/testfixtures"
)

// reply is a fully consumed response. get returns this rather than an
// *http.Response so the body is closed in exactly one place — and so bodyclose
// does not have to reason about a helper that already did the right thing.
type reply struct {
	status int
	header http.Header
	body   string
}

// get performs one request with the test's context. Every request in this file
// goes through it so that no handler outlives the test that started it.
func get(t *testing.T, client *http.Client, url string) reply {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request %q: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %q: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %q: %v", url, err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

func TestRoutes(t *testing.T) {
	t.Parallel()

	srv := testfixtures.New(t)

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string // substring; empty means the body is not asserted
	}{
		{"index", "/", http.StatusOK, "pagevet fixtures"},
		{"ok runs javascript", "/ok", http.StatusOK, `document.title = "js-ran"`},
		{"throw", "/throw", http.StatusOK, "o.boom()"},
		{"reject exposes a pollable flag", "/reject", http.StatusOK, "__rejectionSeen"},
		{"console error", "/console-error", http.StatusOK, `console.error("boom", 42)`},
		{"console noise", "/console-noise", http.StatusOK, `console.warn("warn")`},
		{"console dup throws three times", "/console-dup", http.StatusOK, "setTimeout(pagevetBoom, 0);\nsetTimeout(pagevetBoom, 0);\nsetTimeout(pagevetBoom, 0);"},
		{"csp", "/csp", http.StatusOK, `document.title = "csp-ran"`},
		{"subresource 404 references a dead script", "/subresource-404", http.StatusOK, `<script src="/status/404?empty=1">`},
		{"status 404", "/status/404", http.StatusNotFound, "status 404"},
		{"status 500", "/status/500", http.StatusInternalServerError, "status 500"},
		{"status 418", "/status/418", http.StatusTeapot, "status 418"},
		{"status 301 is served as-is, not followed", "/status/301", http.StatusMovedPermanently, "status 301"},
		{"status out of range", "/status/99", http.StatusBadRequest, "bad status code"},
		{"status not a number", "/status/abc", http.StatusBadRequest, "bad status code"},
		{"slow with a short delay", "/slow?d=10ms", http.StatusOK, "slow"},
		{"slow without a duration", "/slow", http.StatusBadRequest, "requires ?d="},
		{"alert", "/alert", http.StatusOK, `alert("pagevet alert")`},
		{"unknown path", "/no-such-route", http.StatusNotFound, "no such fixture"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := get(t, srv.Client(), srv.URL+tc.path)
			if got.status != tc.wantStatus {
				t.Errorf("status = %d, want %d", got.status, tc.wantStatus)
			}
			if tc.wantBody != "" && !strings.Contains(got.body, tc.wantBody) {
				t.Errorf("body does not contain %q; got:\n%s", tc.wantBody, got.body)
			}
			if cc := got.header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
		})
	}
}

func TestEmptyBodyStatuses(t *testing.T) {
	t.Parallel()

	srv := testfixtures.New(t)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"explicitly empty", "/status/500?empty=1", http.StatusInternalServerError},
		{"204 is always empty", "/status/204", http.StatusNoContent},
		{"304 is always empty", "/status/304", http.StatusNotModified},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := get(t, srv.Client(), srv.URL+tc.path)
			if got.status != tc.wantStatus {
				t.Errorf("status = %d, want %d", got.status, tc.wantStatus)
			}
			if got.body != "" {
				t.Errorf("body = %q, want empty", got.body)
			}
		})
	}
}

// TestFavicon guards FLAKE RULE 2: a 404 here would give every fixture page a
// phantom subresource failure.
func TestFavicon(t *testing.T) {
	t.Parallel()

	srv := testfixtures.New(t)

	got := get(t, srv.Client(), srv.URL+"/favicon.ico")
	if got.status != http.StatusNoContent {
		t.Errorf("status = %d, want %d", got.status, http.StatusNoContent)
	}
	if got.body != "" {
		t.Errorf("body = %q, want empty", got.body)
	}
}

func TestDownload(t *testing.T) {
	t.Parallel()

	srv := testfixtures.New(t)

	got := get(t, srv.Client(), srv.URL+"/download")
	if got.status != http.StatusOK {
		t.Errorf("status = %d, want 200", got.status)
	}
	if cd := got.header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	if got.body == "" {
		t.Error("download body is empty")
	}
}

func TestRedirect(t *testing.T) {
	t.Parallel()

	srv := testfixtures.New(t)

	// A client that stops at the first hop, so the chain can be walked one
	// Location header at a time.
	noFollow := &http.Client{
		Transport: srv.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Run("each hop points at the next", func(t *testing.T) {
		t.Parallel()

		first := get(t, noFollow, srv.URL+"/redirect/3/ok")
		if first.status != http.StatusFound {
			t.Fatalf("status = %d, want 302", first.status)
		}
		if got := first.header.Get("Location"); got != "/redirect/2/ok" {
			t.Errorf("Location = %q, want /redirect/2/ok", got)
		}

		last := get(t, noFollow, srv.URL+"/redirect/1/ok")
		if got := last.header.Get("Location"); got != "/ok" {
			t.Errorf("last hop Location = %q, want /ok", got)
		}
	})

	t.Run("the chain lands on the target", func(t *testing.T) {
		t.Parallel()

		got := get(t, srv.Client(), srv.URL+"/redirect/3/ok")
		if got.status != http.StatusOK {
			t.Errorf("status = %d, want 200", got.status)
		}
		if !strings.Contains(got.body, "js-ran") {
			t.Error("did not land on /ok")
		}
	})

	t.Run("the query string survives the chain", func(t *testing.T) {
		t.Parallel()

		got := get(t, srv.Client(), srv.URL+"/redirect/2/status/500?empty=1")
		if got.status != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", got.status)
		}
		if got.body != "" {
			t.Errorf("body = %q, want empty; ?empty=1 was dropped", got.body)
		}
	})

	t.Run("a nonsense hop count is rejected", func(t *testing.T) {
		t.Parallel()

		got := get(t, noFollow, srv.URL+"/redirect/0/ok")
		if got.status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", got.status)
		}
	})
}

// TestSlowHonorsCancellation guards FLAKE RULE 3. If the handler ever stops
// selecting on r.Context().Done(), srv.Close blocks on the in-flight sleep and
// t.Cleanup deadlocks the whole binary — so this test asserts both that the
// request returns promptly AND, by finishing at all, that cleanup does too.
func TestSlowHonorsCancellation(t *testing.T) {
	t.Parallel()

	srv := testfixtures.New(t)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/slow?d=30s", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	start := time.Now()
	resp, err := srv.Client().Do(req)
	if err == nil {
		defer resp.Body.Close()
		t.Fatal("GET /slow?d=30s returned a response; the handler ignored the deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("returned after %v; the sleep was not interruptible", elapsed)
	}
}

// TestHangup asserts the dropped-connection route really drops: Chrome reports
// this as net::ERR_EMPTY_RESPONSE, and Go's client reports it as EOF.
func TestHangup(t *testing.T) {
	t.Parallel()

	srv := testfixtures.New(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/hangup", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err == nil {
		defer resp.Body.Close()
		t.Fatalf("GET /hangup returned %d; want a transport error", resp.StatusCode)
	}
}
