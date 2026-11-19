package clientidentity

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func mustNetworks(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()
	networks, err := ParseTrustedProxies(values)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v): %v", values, err)
	}
	return networks
}

func newRequest(remoteAddr string, xff ...string) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Del(HeaderXForwardedFor)
	for _, value := range xff {
		req.Header.Add(HeaderXForwardedFor, value)
	}
	return req
}

func ipValue(t *testing.T, value string) net.IP {
	t.Helper()
	ip := net.ParseIP(value)
	if ip == nil {
		t.Fatalf("invalid test IP %q", value)
	}
	return ip
}

func wantErrsContain(t *testing.T, errs []error, target error) {
	t.Helper()
	for _, err := range errs {
		if errors.Is(err, target) {
			return
		}
	}
	t.Fatalf("errors %v do not contain %v", errs, target)
}

// A direct TLS client without any forwarding headers is identified by its
// own peer address and produces no rejection evidence.
func TestResolve_DirectClientCompatibility(t *testing.T) {
	resolver := NewResolver(nil)
	req := newRequest("203.0.113.9:51234")
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "203.0.113.9"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	if identity.TrustedChain {
		t.Fatal("TrustedChain: got true, want false")
	}
	if len(identity.Errs) != 0 {
		t.Fatalf("Errs: got %v, want none", identity.Errs)
	}
	if identity.TLS == nil || identity.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("TLS evidence was not preserved: %#v", identity.TLS)
	}
	if got, want := identity.ForwardedHeaderValue(), "203.0.113.9"; got != want {
		t.Fatalf("ForwardedHeaderValue: got %q, want %q", got, want)
	}
}

// Headline attack: with an empty trust set, an attacker connecting directly
// cannot make X-Forwarded-For change the resolved identity.
func TestResolve_DirectConnectionForgedXFF_FailsClosed(t *testing.T) {
	resolver := NewResolver(nil)
	req := newRequest("198.51.100.66:443", "10.0.0.7", "192.0.2.200")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "198.51.100.66"; got != want {
		t.Fatalf("ClientIP: got %q, want %q (forged XFF must not win)", got, want)
	}
	if identity.TrustedChain {
		t.Fatal("TrustedChain: got true, want false")
	}
	wantErrsContain(t, identity.Errs, ErrUntrustedForwarded)
	if got, want := identity.ForwardedHeaderValue(), "198.51.100.66"; got != want {
		t.Fatalf("upstream header value: got %q, want only the real peer %q", got, want)
	}
}

// Even when trusted proxies are configured, a direct untrusted peer still
// cannot claim an identity via XFF.
func TestResolve_UntrustedDirectPeerWithTrustConfigured_FailsClosed(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8"))
	req := newRequest("198.51.100.66:443", "10.0.0.7")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "198.51.100.66"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	wantErrsContain(t, identity.Errs, ErrUntrustedForwarded)
}

// A single trusted proxy legitimately forwards the real client address.
func TestResolve_TrustedProxyChain(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8"))
	req := newRequest("10.0.0.2:443", "203.0.113.50")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "203.0.113.50"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	if !identity.TrustedChain {
		t.Fatal("TrustedChain: got false, want true")
	}
	if got, want := identity.DirectIP.String(), "10.0.0.2"; got != want {
		t.Fatalf("DirectIP: got %q, want %q", got, want)
	}
	if got, want := identity.ForwardedHeaderValue(), "203.0.113.50, 10.0.0.2"; got != want {
		t.Fatalf("ForwardedHeaderValue: got %q, want %q", got, want)
	}
}

// When an intermediate hop is not in the trust set, every entry it claims
// further left is unattested and cannot influence identity. Here the direct
// peer 10.0.0.9 is trusted and attests 198.51.100.7, which is not trusted, so
// the spoofed 1.2.3.4 that 198.51.100.7 claims upstream is rejected.
func TestResolve_ChainStopsAtFirstUntrustedHop(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8"))
	req := newRequest("10.0.0.9:443", "1.2.3.4", "198.51.100.7")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "198.51.100.7"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	wantErrsContain(t, identity.Errs, ErrUntrustedHop)
	if got, want := identity.ForwardedHeaderValue(), "198.51.100.7, 10.0.0.9"; got != want {
		t.Fatalf("ForwardedHeaderValue: got %q, want %q", got, want)
	}
}

// A trusted proxy may legitimately forward an untrusted client address it
// observed directly: that entry is the real client identity.
func TestResolve_TrustedProxyAttestsUntrustedClient(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8", "172.16.0.0/12"))
	req := newRequest("10.0.0.9:443", "1.2.3.4", "172.16.0.1")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "1.2.3.4"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	if !identity.TrustedChain {
		t.Fatal("TrustedChain: got false, want true")
	}
}

// A fully trusted multi-hop chain resolves all the way to the real client.
func TestResolve_FullTrustedMultiHopChain(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8", "172.16.0.0/12"))
	req := newRequest("10.0.0.9:443", "203.0.113.50", "172.16.0.1")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "203.0.113.50"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	if !identity.TrustedChain {
		t.Fatal("TrustedChain: got false, want true")
	}
	if got, want := identity.ForwardedHeaderValue(), "203.0.113.50, 172.16.0.1, 10.0.0.9"; got != want {
		t.Fatalf("ForwardedHeaderValue: got %q, want %q", got, want)
	}
}

// Non-IP garbage in the chain fails closed: traversal stops at the invalid
// entry, so the identity falls back to the attested trusted proxy rather than
// accepting any left-hand attacker value.
func TestResolve_InvalidForwardedEntryFailsClosed(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8"))
	req := newRequest("10.0.0.2:443", "spoofed.example", "203.0.113.50")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "10.0.0.2"; got != want {
		t.Fatalf("ClientIP: got %q, want %q (invalid chain must fall back to direct peer)", got, want)
	}
	wantErrsContain(t, identity.Errs, ErrInvalidForwardedHop)
	if got, want := identity.ForwardedHeaderValue(), "10.0.0.2"; got != want {
		t.Fatalf("ForwardedHeaderValue: got %q, want %q", got, want)
	}
}

// Malformed direct addresses never fall back to header values.
func TestResolve_InvalidRemoteAddrFailsClosed(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8"))
	req := newRequest("not-an-address", "203.0.113.50")

	identity := resolver.Resolve(req)

	if identity.DirectIP != nil || identity.ClientIP != nil {
		t.Fatalf("expected no asserted identity, got %#v", identity)
	}
	wantErrsContain(t, identity.Errs, ErrInvalidRemoteAddr)
	if got := identity.ForwardedHeaderValue(); got != "" {
		t.Fatalf("ForwardedHeaderValue: got %q, want empty", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	networks, err := ParseTrustedProxies([]string{" 127.0.0.1 ", "10.0.0.0/8", "", "::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := len(networks), 3; got != want {
		t.Fatalf("network count: got %d, want %d", got, want)
	}
	resolver := NewResolver(networks)
	if !resolver.IsTrusted(ipValue(t, "127.0.0.1")) {
		t.Error("bare IPv4 loopback should be trusted")
	}
	if !resolver.IsTrusted(ipValue(t, "10.1.2.3")) {
		t.Error("CIDR member should be trusted")
	}
	if !resolver.IsTrusted(ipValue(t, "::1")) {
		t.Error("bare IPv6 loopback should be trusted")
	}
	if resolver.IsTrusted(ipValue(t, "203.0.113.5")) {
		t.Error("outside all networks must not be trusted")
	}

	if _, err := ParseTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Error("expected error for invalid proxy entry")
	}
	if _, err := ParseTrustedProxies([]string{"10.0.0.0/notacidr"}); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIdentity_ForwardedForOrdering(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8", "172.16.0.0/12"))
	req := newRequest("10.0.0.9:443", "203.0.113.50", "172.16.0.1")

	identity := resolver.Resolve(req)

	got := make([]string, len(identity.ForwardedFor))
	for i, ip := range identity.ForwardedFor {
		got[i] = ip.String()
	}
	want := []string{"203.0.113.50", "172.16.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ForwardedFor: got %v, want %v", got, want)
	}
}

func TestResolve_IPv6DirectAndTrusted(t *testing.T) {
	// Direct IPv6 client with a forged header: identity stays the direct peer.
	resolver := NewResolver(nil)
	req := newRequest("[2001:db8::1]:54321", "10.0.0.7")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "2001:db8::1"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	wantErrsContain(t, identity.Errs, ErrUntrustedForwarded)
	if got, want := identity.ForwardedHeaderValue(), "2001:db8::1"; got != want {
		t.Fatalf("ForwardedHeaderValue: got %q, want %q", got, want)
	}

	// A trusted IPv6 proxy attests a real IPv4 client.
	trusted := NewResolver(mustNetworks(t, "2001:db8::/32"))
	proxyReq := newRequest("[2001:db8::9]:443", "203.0.113.50")
	proxyIdentity := trusted.Resolve(proxyReq)
	if got, want := proxyIdentity.ClientIP.String(), "203.0.113.50"; got != want {
		t.Fatalf("trusted ClientIP: got %q, want %q", got, want)
	}
	if got, want := proxyIdentity.ForwardedHeaderValue(), "203.0.113.50, 2001:db8::9"; got != want {
		t.Fatalf("trusted ForwardedHeaderValue: got %q, want %q", got, want)
	}
}

// Multiple X-Forwarded-For header lines are folded into one chain and still
// fail closed when the direct peer is untrusted.
func TestResolve_MultipleHeaderLinesFolded(t *testing.T) {
	resolver := NewResolver(nil)
	req := newRequest("198.51.100.66:443")
	req.Header.Add(HeaderXForwardedFor, "10.0.0.1")
	req.Header.Add(HeaderXForwardedFor, "10.0.0.2, 10.0.0.3")

	identity := resolver.Resolve(req)

	if got, want := identity.ClientIP.String(), "198.51.100.66"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}
	wantErrsContain(t, identity.Errs, ErrUntrustedForwarded)
	if got, want := identity.ForwardedHeaderValue(), "198.51.100.66"; got != want {
		t.Fatalf("ForwardedHeaderValue: got %q, want %q", got, want)
	}
}

func TestMiddleware_AttachesSingleIdentity(t *testing.T) {
	resolver := NewResolver(nil)
	var seen *Identity
	handler := resolver.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		seen, _ = FromRequest(req)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), newRequest("198.51.100.66:443", "10.0.0.7"))

	if seen == nil {
		t.Fatal("identity was not attached to the request context")
	}
	if got, want := seen.ClientIP.String(), "198.51.100.66"; got != want {
		t.Fatalf("ClientIP: got %q, want %q", got, want)
	}

	// FromRequest returns the same instance for the whole request lifecycle.
	req := newRequest("198.51.100.66:443")
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestMiddleware_ContextRoundTrip(t *testing.T) {
	identity := &Identity{DirectAddr: "127.0.0.1:1", ClientIP: ipValue(t, "127.0.0.1")}
	req := newRequest("127.0.0.1:1")
	req = req.WithContext(WithIdentity(req.Context(), identity))

	got, ok := FromRequest(req)
	if !ok || got != identity {
		t.Fatalf("FromRequest round trip failed: %#v ok=%v", got, ok)
	}
}
