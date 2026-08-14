package input

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// stubDNS is the fake zone this package's tests resolve against. TestMain
// installs stubResolve before any test runs, so no test in this package ever
// touches the machine's resolver: the address guard runs inside ReadURLs, and a
// test suite that needs DNS is a test suite that fails on a plane.
//
// Names absent from the map are treated as NXDOMAIN.
var stubDNS = map[string][]netip.Addr{
	"public.test":    {netip.MustParseAddr("93.184.216.34")},
	"lan.test":       {netip.MustParseAddr("192.168.1.10")},
	"metadata.test":  {netip.MustParseAddr("169.254.169.254")},
	"mapped.test":    {netip.MustParseAddr("::ffff:169.254.169.254")},
	"linklocal.test": {netip.MustParseAddr("169.254.10.1")},
	// One good address and one bad one: the guard must reject on ANY answer,
	// because Chrome picks from the same set and we cannot predict which.
	"mixed.test": {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("fe80::1")},
	// Owned by TestReadURLsChecksEachHostOnce; no other test may resolve it,
	// or the call count stops meaning anything.
	"cached.test": {netip.MustParseAddr("93.184.216.34")},
}

var (
	dnsMu    sync.Mutex
	dnsCalls = map[string]int{}
)

func stubResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	// The stub honors ctx like a real resolver would, which is what lets a
	// test prove CheckHost threads the caller's context in rather than minting
	// its own.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}

	dnsMu.Lock()
	dnsCalls[host]++
	dnsMu.Unlock()

	if addrs, ok := stubDNS[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func dnsCallCount(host string) int {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return dnsCalls[host]
}

func TestCheckAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		blocked bool
	}{
		// The cloud metadata endpoint, in both of the forms it can arrive in.
		{"ipv4 metadata endpoint", "169.254.169.254", true},
		{"ipv4-mapped metadata endpoint", "::ffff:169.254.169.254", true},
		{"aws ipv6 metadata endpoint", "fd00:ec2::254", true},

		{"ipv4 link-local", "169.254.10.1", true},
		{"ipv6 link-local", "fe80::1", true},
		{"ipv4-mapped link-local", "::ffff:169.254.10.1", true},

		{"ipv4 unspecified", "0.0.0.0", true},
		{"ipv6 unspecified", "::", true},
		{"ipv4-mapped unspecified", "::ffff:0.0.0.0", true},

		{"ipv4 multicast", "224.0.0.1", true},
		{"ipv6 multicast", "ff02::1", true},
		{"ipv6 interface-local multicast", "ff01::1", true},
		{"ipv4-mapped multicast", "::ffff:224.0.0.1", true},

		// Loopback and RFC1918 stay allowed: crawling your own staging box is
		// the tool's primary use case.
		{"ipv4 loopback", "127.0.0.1", false},
		{"ipv6 loopback", "::1", false},
		{"ipv4-mapped loopback", "::ffff:127.0.0.1", false},
		{"rfc1918 10/8", "10.0.0.1", false},
		{"rfc1918 192.168/16", "192.168.1.1", false},
		{"rfc1918 172.16/12", "172.16.0.1", false},
		{"public ipv4", "8.8.8.8", false},
		{"public ipv6", "2001:4860:4860::8888", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkAddr(netip.MustParseAddr(tc.addr), false)
			if tc.blocked && err == nil {
				t.Fatalf("checkAddr(%s) = nil, want blocked", tc.addr)
			}
			if !tc.blocked && err != nil {
				t.Fatalf("checkAddr(%s) = %v, want allowed", tc.addr, err)
			}
			if tc.blocked && !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("checkAddr(%s) = %v, want ErrBlockedAddress", tc.addr, err)
			}
		})
	}
}

func TestCheckAddrAllowLinkLocal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		blocked bool
	}{
		{"link-local unicast is opt-in", "169.254.10.1", false},
		{"ipv6 link-local unicast is opt-in", "fe80::1", false},
		// The escape hatch is for link-local hosts, not for credentials.
		{"metadata endpoint stays blocked", "169.254.169.254", true},
		{"mapped metadata endpoint stays blocked", "::ffff:169.254.169.254", true},
		// Multicast is checked before the link-local case precisely so these
		// two cannot be unblocked by the flag.
		{"link-local multicast stays blocked", "224.0.0.1", true},
		{"ipv6 link-local multicast stays blocked", "ff02::1", true},
		{"unspecified stays blocked", "0.0.0.0", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkAddr(netip.MustParseAddr(tc.addr), true)
			if tc.blocked != (err != nil) {
				t.Fatalf("checkAddr(%s, allowLinkLocal=true) = %v, blocked=%v", tc.addr, err, tc.blocked)
			}
		})
	}
}

func TestCheckAddrZeroValue(t *testing.T) {
	t.Parallel()

	// The zero Addr is what a mis-wired caller hands us; it must not read as
	// "fine".
	if err := checkAddr(netip.Addr{}, false); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("checkAddr(zero) = %v, want ErrBlockedAddress", err)
	}
}

func TestCheckHostLiteral(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		{"loopback literal", "127.0.0.1", false},
		{"ipv6 loopback literal", "::1", false},
		{"bracketed ipv6 literal", "[::1]", false},
		{"metadata literal", "169.254.169.254", true},
		{"bracketed mapped metadata literal", "[::ffff:169.254.169.254]", true},
		{"unspecified literal", "0.0.0.0", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// A literal must be decided without any lookup: stubDNS has no
			// entry for these, so a lookup would silently allow everything.
			if err := CheckHost(t.Context(), tc.host, false); tc.blocked != (err != nil) {
				t.Fatalf("CheckHost(%q) = %v, blocked=%v", tc.host, err, tc.blocked)
			}
		})
	}
}

func TestCheckHostResolved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		host           string
		allowLinkLocal bool
		blocked        bool
	}{
		{"public name", "public.test", false, false},
		{"private name", "lan.test", false, false},
		{"metadata name", "metadata.test", false, true},
		{"ipv4-mapped metadata name", "mapped.test", false, true},
		{"any bad answer blocks", "mixed.test", false, true},
		{"link-local name", "linklocal.test", false, true},
		{"link-local name with opt-in", "linklocal.test", true, false},
		{"metadata name ignores opt-in", "metadata.test", true, true},
		// An unresolvable name is Chrome's story to tell: it produces
		// net::ERR_NAME_NOT_RESOLVED, which is a far better diagnostic than
		// anything the guard could invent.
		{"nxdomain is not a guard failure", "nope.test", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckHost(t.Context(), tc.host, tc.allowLinkLocal)
			if tc.blocked != (err != nil) {
				t.Fatalf("CheckHost(%q, %v) = %v, blocked=%v", tc.host, tc.allowLinkLocal, err, tc.blocked)
			}
			if tc.blocked && !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("CheckHost(%q) = %v, want ErrBlockedAddress", tc.host, err)
			}
		})
	}
}

func TestCheckHostEmpty(t *testing.T) {
	t.Parallel()

	if err := CheckHost(t.Context(), "", false); !errors.Is(err, ErrEmptyHost) {
		t.Fatalf("CheckHost(%q) = %v, want ErrEmptyHost", "", err)
	}
}

func TestCheckHostCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// metadata.test is blocked whenever it resolves, so a nil verdict can only
	// mean the canceled ctx reached the resolver. A lookup that did not happen
	// is not a guard failure — the caller is the one that has to stop.
	if err := CheckHost(ctx, "metadata.test", false); err != nil {
		t.Fatalf("CheckHost(canceled, %q) = %v, want nil", "metadata.test", err)
	}
	// A literal is decided without the resolver, so cancellation cannot turn it
	// into an accidental allow.
	if err := CheckHost(ctx, "169.254.169.254", false); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("CheckHost(canceled, literal) = %v, want ErrBlockedAddress", err)
	}
}

// prodResolve captures the production DNS function before TestMain swaps in the
// stub, so the wiring itself can be tested rather than only the stub.
var prodResolve = resolveHost

func TestProductionResolver(t *testing.T) {
	t.Parallel()

	// localhost comes from the hosts file, so this needs no network — but skip
	// rather than fail if the machine disagrees, since the resolver is not what
	// this package is responsible for.
	addrs, err := prodResolve(t.Context(), "localhost")
	if err != nil || len(addrs) == 0 {
		t.Skipf("no local resolver answer for localhost: %v", err)
	}
	for _, addr := range addrs {
		if !addr.Unmap().IsLoopback() {
			t.Fatalf("localhost resolved to %s, want a loopback address", addr)
		}
	}
}
