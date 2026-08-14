package input

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ErrBlockedAddress means the host is, or resolves to, an address the crawler
// refuses to open.
var ErrBlockedAddress = errors.New("blocked address")

// lookupTimeout bounds the pre-flight DNS query on top of the caller's ctx. It
// is deliberately short: the check is advisory (see CheckHost), so a slow or
// unreachable resolver must not stall the run before the first page is even
// opened.
const lookupTimeout = 2 * time.Second

// metadataAddrs are the cloud instance-metadata endpoints. They serve IAM
// credentials to anything that can issue an HTTP GET from inside the instance,
// which is exactly what this program does, so they stay blocked even when
// link-local addresses are allowed: a page list has no legitimate reason to
// contain one, and the cost of being wrong is a leaked role credential.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, DigitalOcean IMDS
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
}

// resolveHost is the DNS seam. It is a variable so tests can drive every branch
// of the guard deterministically, without the machine's resolver or a network.
var resolveHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// CheckHost reports whether host may be opened, rejecting addresses that should
// never be crawled: the cloud metadata endpoints, link-local ranges, the
// unspecified address and multicast.
//
// Loopback and RFC1918 are ALLOWED. Crawling your own staging box or an
// internal site is the primary use case for this tool; blocking private
// addresses would make it useless for the job it exists to do.
//
// host is a hostname or IP literal without a port, i.e. what url.Hostname()
// returns. A bracketed IPv6 literal is accepted too.
//
// # What this check is worth
//
// It is a pre-flight sanity check, not a security boundary. Chrome resolves the
// name again, independently, when it navigates. Between our lookup and Chrome's
// the answer can change — a DNS rebinding record, a short TTL, a round-robin
// set from which Chrome draws an address we never saw — and we would never know.
// It catches the ordinary accident of a metadata or link-local URL sitting in a
// list. It does not defend against a list written by an attacker.
//
// A DNS failure is not a guard failure: it returns nil so Chrome can produce the
// real net::ERR_NAME_NOT_RESOLVED, which tells the user far more than anything
// this function could synthesize. A canceled ctx arrives here as exactly that
// kind of failure, so the caller — not the guard — is the one that has to stop.
func CheckHost(ctx context.Context, host string, allowLinkLocal bool) error {
	if host == "" {
		return ErrEmptyHost
	}
	// url.Hostname() already unwraps "[::1]", but accept the bracketed form so
	// the function is usable on a raw u.Host too.
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	// An IP literal is checked as written. Handing it to the resolver would be
	// both pointless and, for a literal the system resolver rewrites, wrong.
	if addr, err := netip.ParseAddr(h); err == nil {
		return checkAddr(addr, allowLinkLocal)
	}

	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	addrs, lookupErr := resolveHost(ctx, h)
	// Phrased as a positive test rather than an early "if err != nil { return
	// nil }" so the intent is unmistakable: an unresolvable name is Chrome's
	// story to tell, not a rejection.
	if lookupErr == nil {
		for _, addr := range addrs {
			if err := checkAddr(addr, allowLinkLocal); err != nil {
				return fmt.Errorf("host %q: %w", host, err)
			}
		}
	}
	return nil
}

// checkAddr is the address policy: pure, DNS-free, and therefore exhaustively
// testable over netip.MustParseAddr literals.
func checkAddr(addr netip.Addr, allowLinkLocal bool) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid IP address", ErrBlockedAddress)
	}

	// Unmap FIRST, before any predicate. ::ffff:169.254.169.254 is the
	// IPv4-mapped form of the metadata endpoint: as an IPv6 address it is not
	// IsLinkLocalUnicast (that predicate tests the fe80::/10 prefix) and it
	// equals no IPv4 literal, so every naive check waves it straight through.
	a := addr.Unmap()

	for _, m := range metadataAddrs {
		if a == m {
			return fmt.Errorf("%w: cloud instance metadata endpoint %s", ErrBlockedAddress, a)
		}
	}

	switch {
	case a.IsUnspecified():
		// 0.0.0.0 and :: are not destinations; connecting to them lands on
		// localhost on most stacks, which is never what the list meant.
		return fmt.Errorf("%w: unspecified address %s", ErrBlockedAddress, a)

	case a.IsMulticast():
		// Checked before the link-local case: 224.0.0.1 and ff02::1 are
		// link-local multicast, and AllowLinkLocal must not unblock them.
		return fmt.Errorf("%w: multicast address %s", ErrBlockedAddress, a)

	case a.IsLinkLocalUnicast() && !allowLinkLocal:
		return fmt.Errorf("%w: link-local address %s", ErrBlockedAddress, a)
	}
	return nil
}
