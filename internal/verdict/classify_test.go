package verdict

import (
	"encoding/json"
	"slices"
	"strconv"
	"testing"
)

// consoleErrs builds n console errors. Classification only ever looks at
// len(Console), but distinct texts keep a failure message readable.
func consoleErrs(n int) []ConsoleError {
	if n <= 0 {
		return nil
	}
	out := make([]ConsoleError, 0, n)
	for i := range n {
		out = append(out, ConsoleError{
			Kind:  KindException,
			Text:  "TypeError: boom " + strconv.Itoa(i),
			Count: 1,
		})
	}
	return out
}

// resourceErrs builds n subresource failures, one per distinct asset.
func resourceErrs(n int) []ResourceError {
	if n <= 0 {
		return nil
	}
	out := make([]ResourceError, 0, n)
	for i := range n {
		out = append(out, ResourceError{
			URL:    "https://example.test/a" + strconv.Itoa(i) + ".js",
			Type:   "Script",
			Status: 404,
			Count:  1,
		})
	}
	return out
}

// TestClassify is the behavior table for the precedence rules. Each row is one
// situation a real crawl produces; the table, not the implementation, is the
// specification.
func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result Result
		want   Outcome
	}{
		{
			name:   "clean page",
			result: Result{Status: 200},
			want:   OutcomeOK,
		},
		{
			// 204 carries no body but is a perfectly good response.
			name:   "204 no-content",
			result: Result{Status: 204},
			want:   OutcomeOK,
		},
		{
			// 304 is inside the default 200-399 band: a cache revalidation is
			// not a failure.
			name:   "304 not-modified",
			result: Result{Status: 304},
			want:   OutcomeOK,
		},
		{
			// Only the FINAL status matters; the 301 hop is diagnostic data.
			name: "3xx chain ending 200",
			result: Result{
				Status:    200,
				Redirects: []Hop{{Status: 301, URL: "https://example.test/old"}},
			},
			want: OutcomeOK,
		},
		{
			name: "3xx chain ending 404",
			result: Result{
				Status:    404,
				Redirects: []Hop{{Status: 302, URL: "https://example.test/old"}},
			},
			want: OutcomeHTTPError,
		},
		{
			name:   "plain 404",
			result: Result{Status: 404},
			want:   OutcomeHTTPError,
		},
		{
			// HTTPError outranks ConsoleError: the status is the actionable
			// fact, the exception is a symptom of the error page.
			name:   "500 that also throws",
			result: Result{Status: 500, Console: consoleErrs(1)},
			want:   OutcomeHTTPError,
		},
		{
			name:   "200 that throws",
			result: Result{Status: 200, Console: consoleErrs(1)},
			want:   OutcomeConsoleError,
		},
		{
			name:   "200 + subresource 404",
			result: Result{Status: 200, Resources: resourceErrs(1)},
			want:   OutcomeSubresourceError,
		},
		{
			// ConsoleError outranks SubresourceError: broken page JS beats a
			// missing asset.
			name:   "200 + throws + bad asset",
			result: Result{Status: 200, Console: consoleErrs(1), Resources: resourceErrs(1)},
			want:   OutcomeConsoleError,
		},
		{
			// Reachable only because the collector keeps the main-document
			// status independently of chromedp.RunResponse.
			name:   "500 that then hangs",
			result: Result{Status: 500, TimedOut: true, SettledBy: "deadline"},
			want:   OutcomeHTTPError,
		},
		{
			name:   "200 that never fires load",
			result: Result{Status: 200, TimedOut: true, SettledBy: "deadline"},
			want:   OutcomeTimeout,
		},
		{
			name:   "bad DNS",
			result: Result{NetError: "net::ERR_NAME_NOT_RESOLVED", NetErrorClass: "DNS", SettledBy: "netfail"},
			want:   OutcomeLoadError,
		},
		{
			name:   "connection refused",
			result: Result{NetError: "net::ERR_CONNECTION_REFUSED", NetErrorClass: "CONNECT", SettledBy: "netfail"},
			want:   OutcomeLoadError,
		},
		{
			name:   "expired cert",
			result: Result{NetError: "net::ERR_CERT_DATE_INVALID", NetErrorClass: "TLS", SettledBy: "netfail"},
			want:   OutcomeLoadError,
		},
		{
			// while(true) in a <script>: the response never completes, so there
			// is no status to report and the deadline is all we have.
			name:   "infinite loop (while(true))",
			result: Result{TimedOut: true, SettledBy: "deadline"},
			want:   OutcomeTimeout,
		},
		{
			name:   "renderer crash",
			result: Result{NetError: "net::ERR_RENDERER_CRASHED", Crashed: true, SettledBy: "crash"},
			want:   OutcomeLoadError,
		},
		{
			name:   "blocked request",
			result: Result{BlockReason: "mixed-content", SettledBy: "netfail"},
			want:   OutcomeLoadError,
		},
		{
			// Chrome answers a Content-Disposition attachment with a healthy 200
			// and then aborts the navigation without rendering. Reporting that
			// as a working page would be a lie, so Download outranks the status.
			name:   "download served as an attachment is not a page",
			result: Result{Status: 200, Download: true, SettledBy: "download"},
			want:   OutcomeLoadError,
		},
		{
			// ...and no console or subresource observation on a file transfer
			// can promote it back to a page-level verdict.
			name: "download outranks console and subresource findings",
			result: Result{
				Status:    200,
				Download:  true,
				Console:   []ConsoleError{{Kind: KindException, Text: "boom", Count: 1}},
				Resources: []ResourceError{{URL: "https://ex.test/a.js", Status: 404, Count: 1}},
			},
			want: OutcomeLoadError,
		},
		{
			// The "we don't know" fallback. It must never read as OK.
			name:   "nothing at all - unknown",
			result: Result{},
			want:   OutcomeLoadError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Classify(tt.result, DefaultPolicy()); got != tt.want {
				t.Errorf("Classify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestClassify_CrashedWithoutNetError covers the crash signal on its own: a
// renderer that dies without Chrome attributing a net::ERR_* to the navigation
// must still be a load error, not the unknown fallback by accident.
func TestClassify_CrashedWithoutNetError(t *testing.T) {
	t.Parallel()

	r := Result{Crashed: true, SettledBy: "crash"}
	if got := Classify(r, DefaultPolicy()); got != OutcomeLoadError {
		t.Errorf("Classify(crashed only) = %v, want %v", got, OutcomeLoadError)
	}
}

func TestClassify_FailOnConsoleDisabledDemotesToOK(t *testing.T) {
	t.Parallel()

	r := Result{Status: 200, Console: consoleErrs(1)}

	p := DefaultPolicy()
	if got := Classify(r, p); got != OutcomeConsoleError {
		t.Fatalf("precondition: Classify() = %v, want %v", got, OutcomeConsoleError)
	}

	p.FailOnConsole = false
	if got := Classify(r, p); got != OutcomeOK {
		t.Errorf("FailOnConsole=false: Classify() = %v, want %v", got, OutcomeOK)
	}
}

func TestClassify_FailOnResourceDisabledDemotesToOK(t *testing.T) {
	t.Parallel()

	r := Result{Status: 200, Resources: resourceErrs(1)}

	p := DefaultPolicy()
	if got := Classify(r, p); got != OutcomeSubresourceError {
		t.Fatalf("precondition: Classify() = %v, want %v", got, OutcomeSubresourceError)
	}

	p.FailOnResource = false
	if got := Classify(r, p); got != OutcomeOK {
		t.Errorf("FailOnResource=false: Classify() = %v, want %v", got, OutcomeOK)
	}
}

func TestClassify_BothChecksDisabledDemotesToOK(t *testing.T) {
	t.Parallel()

	r := Result{Status: 200, Console: consoleErrs(1), Resources: resourceErrs(1)}

	p := DefaultPolicy()
	if got := Classify(r, p); got != OutcomeConsoleError {
		t.Fatalf("precondition: Classify() = %v, want %v", got, OutcomeConsoleError)
	}

	p.FailOnConsole = false
	p.FailOnResource = false
	if got := Classify(r, p); got != OutcomeOK {
		t.Errorf("both checks off: Classify() = %v, want %v", got, OutcomeOK)
	}
}

// TestClassify_NarrowedBandRejects304 proves the OK band is data, not a
// hardcoded "3xx is fine" rule.
func TestClassify_NarrowedBandRejects304(t *testing.T) {
	t.Parallel()

	r := Result{Status: 304}

	p := DefaultPolicy()
	if got := Classify(r, p); got != OutcomeOK {
		t.Fatalf("precondition: Classify(304) = %v, want %v", got, OutcomeOK)
	}

	p.OKStatusMax = 299
	if got := Classify(r, p); got != OutcomeHTTPError {
		t.Errorf("OKStatusMax=299: Classify(304) = %v, want %v", got, OutcomeHTTPError)
	}
}

// TestClassify_WidenedBandAccepts500 proves nothing special-cases 5xx: a caller
// crawling a deliberately erroring endpoint can widen the band and get OK.
func TestClassify_WidenedBandAccepts500(t *testing.T) {
	t.Parallel()

	r := Result{Status: 500}

	p := DefaultPolicy()
	if got := Classify(r, p); got != OutcomeHTTPError {
		t.Fatalf("precondition: Classify(500) = %v, want %v", got, OutcomeHTTPError)
	}

	p.OKStatusMax = 599
	if got := Classify(r, p); got != OutcomeOK {
		t.Errorf("band 200-599: Classify(500) = %v, want %v", got, OutcomeOK)
	}
}

// TestFlags_BothHTTPAndConsole is why Classify and Flags are two functions: the
// counters must see one outcome, the error logs must see both.
func TestFlags_BothHTTPAndConsole(t *testing.T) {
	t.Parallel()

	r := Result{Status: 500, Console: consoleErrs(1)}
	p := DefaultPolicy()

	got := Flags(r, p)
	if !slices.Contains(got, OutcomeHTTPError) || !slices.Contains(got, OutcomeConsoleError) {
		t.Errorf("Flags() = %v, want both %v and %v", got, OutcomeHTTPError, OutcomeConsoleError)
	}
	if len(got) != 2 {
		t.Errorf("Flags() = %v, want exactly 2 outcomes", got)
	}
	if c := Classify(r, p); c != OutcomeHTTPError {
		t.Errorf("Classify() = %v, want only %v", c, OutcomeHTTPError)
	}
}

func TestFlags_ConsoleAndSubresource(t *testing.T) {
	t.Parallel()

	got := Flags(Result{Status: 200, Console: consoleErrs(1), Resources: resourceErrs(2)}, DefaultPolicy())
	want := []Outcome{OutcomeConsoleError, OutcomeSubresourceError}
	if !slices.Equal(got, want) {
		t.Errorf("Flags() = %v, want %v", got, want)
	}
}

func TestFlags_HTTPErrorAndTimeout(t *testing.T) {
	t.Parallel()

	got := Flags(Result{Status: 500, TimedOut: true}, DefaultPolicy())
	want := []Outcome{OutcomeHTTPError, OutcomeTimeout}
	if !slices.Equal(got, want) {
		t.Errorf("Flags() = %v, want %v", got, want)
	}
}

// TestFlags_DownloadReportsOnlyLoadError pins the one branch where Flags
// deliberately reports LESS than the observations would suggest: a file
// transfer never became a page, so listing it under console or subresource
// errors as well would send the reader looking for a page that never existed.
func TestFlags_DownloadReportsOnlyLoadError(t *testing.T) {
	t.Parallel()

	r := Result{
		Status:    200,
		Download:  true,
		Console:   []ConsoleError{{Kind: KindException, Text: "boom", Count: 1}},
		Resources: []ResourceError{{URL: "https://ex.test/a.js", Status: 404, Count: 1}},
	}

	got := Flags(r, DefaultPolicy())
	want := []Outcome{OutcomeLoadError}
	if !slices.Equal(got, want) {
		t.Errorf("Flags() = %v, want %v", got, want)
	}
	if cats := Categories(r, DefaultPolicy()); !slices.Equal(cats, []Category{CategoryLoad}) {
		t.Errorf("Categories() = %v, want [load]", cats)
	}
}

func TestFlags_CleanPageReturnsOK(t *testing.T) {
	t.Parallel()

	got := Flags(Result{Status: 200}, DefaultPolicy())
	want := []Outcome{OutcomeOK}
	if !slices.Equal(got, want) {
		t.Errorf("Flags() = %v, want %v", got, want)
	}
}

// TestFlags_NeverEmpty sweeps the whole input space Flags can see. An empty
// slice would silently drop a URL from every error log, so this asserts the
// two properties the reporter depends on: Flags is never empty, and its first
// element is exactly what Classify returns.
func TestFlags_NeverEmpty(t *testing.T) {
	t.Parallel()

	statuses := []int{0, 200, 204, 304, 399, 400, 404, 500}
	netErrors := []string{"", "net::ERR_NAME_NOT_RESOLVED"}
	blockReasons := []string{"", "csp"}
	policies := []Policy{
		DefaultPolicy(),
		{OKStatusMin: 200, OKStatusMax: 399},
		{OKStatusMin: 200, OKStatusMax: 599, FailOnConsole: true, FailOnResource: true},
		{OKStatusMin: 200, OKStatusMax: 299, FailOnConsole: true},
		{},
	}

	for _, status := range statuses {
		for _, netError := range netErrors {
			for _, blockReason := range blockReasons {
				for _, crashed := range []bool{false, true} {
					for _, timedOut := range []bool{false, true} {
						for _, nConsole := range []int{0, 2} {
							for _, nResource := range []int{0, 2} {
								r := Result{
									Status:      status,
									NetError:    netError,
									BlockReason: blockReason,
									Crashed:     crashed,
									TimedOut:    timedOut,
									Console:     consoleErrs(nConsole),
									Resources:   resourceErrs(nResource),
								}
								for _, p := range policies {
									flags := Flags(r, p)
									if len(flags) == 0 {
										t.Fatalf("Flags(%+v, %+v) = empty", r, p)
									}
									if primary := Classify(r, p); flags[0] != primary {
										t.Fatalf("Flags(%+v, %+v)[0] = %v, want Classify() = %v", r, p, flags[0], primary)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestFlags_RespectsPolicy(t *testing.T) {
	t.Parallel()

	r := Result{Status: 500, Console: consoleErrs(1)}

	p := DefaultPolicy()
	if got := Flags(r, p); !slices.Contains(got, OutcomeConsoleError) {
		t.Fatalf("precondition: Flags() = %v, want it to contain %v", got, OutcomeConsoleError)
	}

	p.FailOnConsole = false
	got := Flags(r, p)
	if slices.Contains(got, OutcomeConsoleError) {
		t.Errorf("FailOnConsole=false: Flags() = %v, want no %v", got, OutcomeConsoleError)
	}
	if !slices.Contains(got, OutcomeHTTPError) {
		t.Errorf("FailOnConsole=false: Flags() = %v, want it to keep %v", got, OutcomeHTTPError)
	}
}

func TestCategories(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result Result
		want   []Category
	}{
		{
			// Timeout and LoadError share errors-load.log, so a page that both
			// timed out and failed to resolve is ONE record, not two.
			name:   "timed out and net error collapse to one load category",
			result: Result{NetError: "net::ERR_TIMED_OUT", TimedOut: true},
			want:   []Category{CategoryLoad},
		},
		{
			name:   "500 that throws lands in two logs",
			result: Result{Status: 500, Console: consoleErrs(1)},
			want:   []Category{CategoryHTTP, CategoryConsole},
		},
		{
			// Ordering follows ErrorCategories, not the order Flags produced.
			name: "all four categories in ErrorCategories order",
			result: Result{
				Status:    503,
				TimedOut:  true,
				Console:   consoleErrs(1),
				Resources: resourceErrs(1),
			},
			want: []Category{CategoryHTTP, CategoryConsole, CategorySubresource, CategoryLoad},
		},
		{
			name:   "clean page belongs to no error log",
			result: Result{Status: 200},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Categories(tt.result, DefaultPolicy()); !slices.Equal(got, tt.want) {
				t.Errorf("Categories() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestOutcome_StringRoundTrip guards the frozen names that appear in the logs
// and in results.jsonl: every real outcome has one, and no two share one.
func TestOutcome_StringRoundTrip(t *testing.T) {
	t.Parallel()

	seen := make(map[string]Outcome, numOutcomes)
	for o := Outcome(0); o < numOutcomes; o++ {
		name := o.String()
		if name == "" || name == "unknown" {
			t.Errorf("Outcome(%d).String() = %q, want a real name", o, name)
			continue
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("Outcome(%d) and Outcome(%d) both stringify to %q", prev, o, name)
		}
		seen[name] = o
	}
	if len(seen) != int(numOutcomes) {
		t.Errorf("got %d distinct names, want %d", len(seen), numOutcomes)
	}

	// The bound itself and any out-of-range value must not masquerade as a
	// real outcome.
	if got := numOutcomes.String(); got != "unknown" {
		t.Errorf("numOutcomes.String() = %q, want %q", got, "unknown")
	}
	if got := Outcome(200).String(); got != "unknown" {
		t.Errorf("Outcome(200).String() = %q, want %q", got, "unknown")
	}
}

func TestOutcome_IsError(t *testing.T) {
	t.Parallel()

	if OutcomeOK.IsError() {
		t.Error("OutcomeOK.IsError() = true, want false")
	}
	for _, o := range ErrorOutcomes {
		if !o.IsError() {
			t.Errorf("%v.IsError() = false, want true", o)
		}
	}
}

func TestOutcome_MarshalText(t *testing.T) {
	t.Parallel()

	for o := Outcome(0); o < numOutcomes; o++ {
		b, err := o.MarshalText()
		if err != nil {
			t.Fatalf("Outcome(%d).MarshalText() error = %v", o, err)
		}
		if string(b) != o.String() {
			t.Errorf("Outcome(%d).MarshalText() = %q, want %q", o, b, o.String())
		}
	}

	// The whole point is JSON: results.jsonl must carry names, not integers.
	got, err := json.Marshal(struct {
		Outcome  Outcome  `json:"outcome"`
		Category Category `json:"category"`
	}{OutcomeHTTPError, CategoryHTTP})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"outcome":"http_error","category":"http"}`
	if string(got) != want {
		t.Errorf("json.Marshal() = %s, want %s", got, want)
	}
}

func TestOutcome_Category(t *testing.T) {
	t.Parallel()

	tests := []struct {
		outcome Outcome
		want    Category
	}{
		{OutcomeOK, CategoryNone},
		{OutcomeConsoleError, CategoryConsole},
		{OutcomeSubresourceError, CategorySubresource},
		{OutcomeTimeout, CategoryLoad},
		{OutcomeHTTPError, CategoryHTTP},
		{OutcomeLoadError, CategoryLoad},
		{numOutcomes, CategoryNone},
		{Outcome(200), CategoryNone},
	}

	for _, tt := range tests {
		t.Run(tt.outcome.String()+"/"+strconv.Itoa(int(tt.outcome)), func(t *testing.T) {
			t.Parallel()
			if got := tt.outcome.Category(); got != tt.want {
				t.Errorf("Category() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCategory_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		category Category
		want     string
	}{
		{CategoryNone, "none"},
		{CategoryHTTP, "http"},
		{CategoryConsole, "console"},
		{CategorySubresource, "subresource"},
		{CategoryLoad, "load"},
		{Category(200), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.category.String(); got != tt.want {
				t.Errorf("Category(%d).String() = %q, want %q", tt.category, got, tt.want)
			}
			b, err := tt.category.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(b) != tt.want {
				t.Errorf("MarshalText() = %q, want %q", b, tt.want)
			}
		})
	}
}

func TestPolicy_StatusOK(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	tests := []struct {
		status int
		want   bool
	}{
		// A missing response is never OK, whatever the band says.
		{0, false},
		{199, false},
		{200, true},
		{304, true},
		{399, true},
		{400, false},
		{500, false},
	}

	for _, tt := range tests {
		if got := p.StatusOK(tt.status); got != tt.want {
			t.Errorf("StatusOK(%d) = %v, want %v", tt.status, got, tt.want)
		}
	}
}
