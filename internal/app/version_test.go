package app

import "testing"

// versionLine has to render two audiences from one function: a developer
// running a `go build` binary, who gets the bare version they have always got,
// and whoever holds a release binary, who needs to know WHICH build it is.
//
// The empty cases are the load-bearing ones. `go build ./cmd/pagevet` links no
// -X flags, so Commit and BuildTime are empty there and the output must not
// grow a "(, )" or an "(unknown, unknown)" tail.
func TestVersionLine(t *testing.T) {
	t.Parallel()

	const (
		version   = "0.1.0"
		commit    = "a1b2c3d"
		buildTime = "2026-08-18T09:54:00Z"
	)

	tests := []struct {
		name      string
		commit    string
		buildTime string
		want      string
	}{
		{
			name: "unstamped",
			want: "pagevet 0.1.0",
		},
		{
			name:   "commit only",
			commit: commit,
			want:   "pagevet 0.1.0 (a1b2c3d)",
		},
		{
			// Not reachable through the Makefile, which always sets both, but
			// -X is a command line and command lines get edited.
			name:      "build time only",
			buildTime: buildTime,
			want:      "pagevet 0.1.0 (2026-08-18T09:54:00Z)",
		},
		{
			name:      "fully stamped",
			commit:    commit,
			buildTime: buildTime,
			want:      "pagevet 0.1.0 (a1b2c3d, 2026-08-18T09:54:00Z)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := versionLine(version, tt.commit, tt.buildTime); got != tt.want {
				t.Errorf("versionLine(%q, %q, %q) = %q, want %q",
					version, tt.commit, tt.buildTime, got, tt.want)
			}
		})
	}
}

// TestVersionLine_UsesTheDefaults pins the shipped defaults, which is what
// makes TestMain_Version's plain "pagevet <Version>" expectation correct: the
// test binary is linked without -X, so the stamped branch is never taken there.
func TestVersionLine_UsesTheDefaults(t *testing.T) {
	t.Parallel()

	if Commit != "" || BuildTime != "" {
		t.Fatalf("Commit = %q, BuildTime = %q: a `go test` binary is linked without -X, so both must be empty",
			Commit, BuildTime)
	}
	if got, want := versionLine(Version, Commit, BuildTime), "pagevet "+Version; got != want {
		t.Errorf("versionLine = %q, want %q", got, want)
	}
}
