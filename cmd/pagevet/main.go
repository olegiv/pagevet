// Command pagevet loads a list of URLs in headless Chrome and reports HTTP
// errors, browser console errors and failed subresources.
//
// See 'pagevet -help' for usage.
package main

import (
	"os"

	"github.com/olegiv/pagevet/internal/app"
)

// main is deliberately trivial. os.Exit skips deferred functions, so every
// cleanup - canceling Chrome's context, flushing and closing the log files -
// has to complete inside app.Main before the exit code reaches here. On macOS
// that is not a nicety: chromedp's process-group cleanup is a no-op on
// non-Linux, so a skipped cancel leaves Chrome running after we are gone.
func main() {
	os.Exit(app.Main(os.Args[1:], os.Stdout, os.Stderr))
}
