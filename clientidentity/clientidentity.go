// Package clientidentity resolves the single, authoritative security identity
// of a request's client.
//
// The identity is derived from the direct peer address of the underlying
// (TLS) connection and the X-Forwarded-For chain attested by explicitly
// trusted proxies only. Every other layer of ssl-proxy -- proxy header
// rewriting, upstream selection, logging and the connection lifecycle -- must
// use the Identity resolved here instead of reading forwarding headers
// directly, so a client that can open a direct connection can never forge its
// identity by sending an X-Forwarded-For header.
package clientidentity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Header names handled by this package, already in canonical form.
const (
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-Ip"
	HeaderForwarded     = "Forwarded"
)

var (
	// ErrInvalidRemoteAddr indicates the direct peer address cannot be parsed;
	// no header-derived identity may be used in that case.
	ErrInvalidRemoteAddr = errors.New("clientidentity: invalid direct peer RemoteAddr")
	// ErrUntrustedForwarded indicates an X-Forwarded-For header was received
	// from a direct peer that is not a trusted proxy, so the whole header is
	// attacker controlled and was discarded.
	ErrUntrustedForwarded = errors.New("clientidentity: X-Forwarded-For from untrusted direct peer discarded")
	// ErrInvalidForwardedHop indicates an X-Forwarded-For entry is not a valid
	// IP address, so trusted-chain traversal stops at that entry.
	ErrInvalidForwardedHop = errors.New("clientidentity: invalid X-Forwarded-For entry stops trusted chain")
	// ErrUntrustedHop indicates the chain reaches a hop that is not a trusted
	// proxy, so every entry further to the left is unattested.
	ErrUntrustedHop = errors.New("clientidentity: untrusted hop stops X-Forwarded-For chain")
)

// Identity is the immutable, resolved security identity of a request.
type Identity struct {
	// DirectAddr is the host:port of the direct TCP/TLS peer (Request.RemoteAddr).
	DirectAddr string
	// DirectIP is the parsed address of the direct peer. It is nil when the
	// direct address cannot be parsed, in which case no identity is asserted.
	DirectIP net.IP
	// ClientIP is the resolved real client address. It equals DirectIP unless
	// a fully trusted proxy chain attests a more distant client.
	ClientIP net.IP
	// ForwardedFor holds the trusted-attested chain entries in client-first
	// order, excluding the direct peer. It is empty for direct clients.
	ForwardedFor []net.IP
	// TrustedChain reports whether at least one trusted proxy hop attested
	// the identity.
	TrustedChain bool
	// TLS carries the TLS connection evidence for the direct connection, if any.
	TLS *tls.ConnectionState
	// Errs records every reason why part or all of a forwarded chain was
	// rejected. Identity resolution always fails closed regardless of Errs.
	Errs []error
}

// ForwardedHeaderValue returns the sanitized, authoritative X-Forwarded-For
// value to send upstream: the attested chain followed by the direct peer.
func (id *Identity) ForwardedHeaderValue() string {
	if id.DirectIP == nil {
		return ""
	}
	parts := make([]string, 0, len(id.ForwardedFor)+1)
	for _, ip := range id.ForwardedFor {
		parts = append(parts, ip.String())
	}
	parts = append(parts, id.DirectIP.String())
	return strings.Join(parts, ", ")
}

// Resolver resolves client identities against a fixed set of trusted proxies.
type Resolver struct {
	trusted []*net.IPNet
}

// NewResolver builds a Resolver whose trusted proxies are the given networks.
// With a nil or empty trust set every X-Forwarded-For header is treated as
// attacker controlled.
func NewResolver(trusted []*net.IPNet) *Resolver {
	cp := make([]*net.IPNet, len(trusted))
	copy(cp, trusted)
	return &Resolver{trusted: cp}
}

// ParseTrustedProxies parses a list of bare IP addresses or CIDR ranges into
// networks suitable for NewResolver. Bare IPs are matched as host routes.
func ParseTrustedProxies(values []string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("clientidentity: invalid trusted proxy %q", value)
			}
			prefixLen := 32
			if ip.To4() == nil {
				prefixLen = 128
			}
			value = fmt.Sprintf("%s/%d", ip.String(), prefixLen)
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("clientidentity: invalid trusted proxy %q: %w", value, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// IsTrusted reports whether ip is a configured trusted proxy.
func (r *Resolver) IsTrusted(ip net.IP) bool {
	for _, network := range r.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve derives the authoritative Identity for req. It never panics on
// malformed input: any chain segment that cannot be validated is discarded and
// recorded in Identity.Errs, and the identity falls back to the direct peer.
func (r *Resolver) Resolve(req *http.Request) *Identity {
	identity := &Identity{
		DirectAddr: req.RemoteAddr,
		TLS:        req.TLS,
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		identity.Errs = append(identity.Errs, fmt.Errorf("%w: %q", ErrInvalidRemoteAddr, req.RemoteAddr))
		return identity
	}
	directIP := net.ParseIP(host)
	if directIP == nil {
		identity.Errs = append(identity.Errs, fmt.Errorf("%w: %q", ErrInvalidRemoteAddr, req.RemoteAddr))
		return identity
	}
	identity.DirectIP = directIP
	identity.ClientIP = directIP

	entries, parseErrs := parseForwardedFor(req.Header.Values(HeaderXForwardedFor))
	identity.Errs = append(identity.Errs, parseErrs...)

	// The direct peer is the only fact the client cannot control. If it is not
	// a trusted proxy, every forwarding header is attacker supplied and the
	// identity fails closed to the direct address.
	if !r.IsTrusted(directIP) {
		if len(entries) > 0 || len(parseErrs) > 0 {
			identity.Errs = append(identity.Errs, ErrUntrustedForwarded)
		}
		return identity
	}

	// Walk the chain right to left. Entry i was added by hop i+1, where the
	// final hop is the direct peer. An entry is accepted only while the hop
	// that added it is trusted; the first untrusted or invalid entry stops the
	// traversal so unattested left-hand entries can never influence identity.
	hop := directIP
	for i := len(entries) - 1; i >= 0; i-- {
		if !r.IsTrusted(hop) {
			identity.Errs = append(identity.Errs, fmt.Errorf("%w: %s", ErrUntrustedHop, hop))
			break
		}
		identity.ForwardedFor = append([]net.IP{entries[i]}, identity.ForwardedFor...)
		hop = entries[i]
	}

	if len(identity.ForwardedFor) > 0 {
		identity.ClientIP = identity.ForwardedFor[0]
		identity.TrustedChain = true
	}
	return identity
}

// parseForwardedFor flattens and trims all X-Forwarded-For header lines and
// parses each entry right up to the first invalid one, which is reported and
// causes every remaining left-hand entry to be ignored.
func parseForwardedFor(headerLines []string) ([]net.IP, []error) {
	var raw []string
	for _, line := range headerLines {
		for _, entry := range strings.Split(line, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				raw = append(raw, entry)
			}
		}
	}

	var entries []net.IP
	var errs []error
	for _, entry := range raw {
		ip := net.ParseIP(entry)
		if ip == nil {
			errs = append(errs, fmt.Errorf("%w: %q", ErrInvalidForwardedHop, entry))
			break
		}
		entries = append(entries, ip)
	}
	return entries, errs
}

type identityContextKey struct{}

// WithIdentity returns a context carrying the resolved identity.
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

// FromContext returns the identity stored in ctx, if any.
func FromContext(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(*Identity)
	return identity, ok
}

// FromRequest returns the identity attached to req's context, if any.
func FromRequest(req *http.Request) (*Identity, bool) {
	return FromContext(req.Context())
}

// Middleware resolves the identity once per request, attaches it to the
// request context and then invokes next. All downstream layers must obtain
// the client identity through FromRequest rather than touching headers.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		identity := r.Resolve(req)
		next.ServeHTTP(w, req.WithContext(WithIdentity(req.Context(), identity)))
	})
}
