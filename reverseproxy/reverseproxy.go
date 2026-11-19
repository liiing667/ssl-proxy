package reverseproxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/suyashkumar/ssl-proxy/clientidentity"
)

// Build initializes and returns a new ReverseProxy instance suitable for SSL proxying
func Build(toURL *url.URL) *httputil.ReverseProxy {
	return BuildWithIdentity(toURL, clientidentity.NewResolver(nil))
}

// BuildWithIdentity initializes a ReverseProxy that derives every
// client-facing decision (forwarded headers, error attribution, upstream
// identity evidence) from the single Identity resolved by resolver.
func BuildWithIdentity(toURL *url.URL, resolver *clientidentity.Resolver) *httputil.ReverseProxy {
	if resolver == nil {
		resolver = clientidentity.NewResolver(nil)
	}
	localProxy := &httputil.ReverseProxy{}
	localProxy.ErrorLog = log.Default()
	localProxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		identity, _ := clientidentity.FromRequest(req)
		logger := localProxy.ErrorLog
		if logger == nil {
			logger = log.Default()
		}
		logger.Printf("upstream error client_identity=%q direct_addr=%q: %v",
			clientLabel(identity), directLabel(identity), err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
	addProxyHeaders := func(req *http.Request) {
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), "443") // TODO: inherit another port if needed
		applyClientIdentity(req, resolver)
	}
	// Rewrite mode strips every client-supplied forwarding header before our
	// logic runs and never appends RemoteAddr on its own, so the identity
	// derived by applyClientIdentity is the single source of truth upstream.
	director := newDirector(toURL, addProxyHeaders)
	localProxy.Rewrite = func(pr *httputil.ProxyRequest) {
		director(pr.Out)
	}

	return localProxy
}

// applyClientIdentity rewrites the identity-bearing headers of the upstream
// request so they can contain only values derived from the resolved
// Identity. Client-supplied X-Forwarded-For and X-Real-Ip headers are always
// removed first, which makes a direct connection with a forged
// X-Forwarded-For unable to influence the upstream (or any origin policy).
func applyClientIdentity(req *http.Request, resolver *clientidentity.Resolver) {
	identity, ok := clientidentity.FromRequest(req)
	if !ok {
		// The Director may also be invoked directly (or in tests) without the
		// identity middleware. Resolve on demand with the same fail-closed
		// rules so header handling never silently trusts client input.
		identity = resolver.Resolve(req)
		req = req.WithContext(clientidentity.WithIdentity(req.Context(), identity))
	}

	req.Header.Del(clientidentity.HeaderXForwardedFor)
	req.Header.Del(clientidentity.HeaderXRealIP)
	// Forwarded (RFC 7239) is an alternate identity-bearing header. ssl-proxy
	// only emits an X-Forwarded-For identity it validated itself, so any
	// client-supplied value is dropped to keep a single identity channel.
	req.Header.Del(clientidentity.HeaderForwarded)

	if value := identity.ForwardedHeaderValue(); value != "" {
		req.Header.Set(clientidentity.HeaderXForwardedFor, value)
	}
	if identity.ClientIP != nil {
		req.Header.Set(clientidentity.HeaderXRealIP, identity.ClientIP.String())
	}
}

func clientLabel(identity *clientidentity.Identity) string {
	if identity == nil || identity.ClientIP == nil {
		return "unknown"
	}
	return identity.ClientIP.String()
}

func directLabel(identity *clientidentity.Identity) string {
	if identity == nil || identity.DirectAddr == "" {
		return "unknown"
	}
	return identity.DirectAddr
}

// newDirector creates a base director that should be exactly what http.NewSingleHostReverseProxy() creates, but allows
// for the caller to supply and extraDirector function to decorate to request to the downstream server
func newDirector(target *url.URL, extraDirector func(*http.Request)) func(*http.Request) {
	targetQuery := target.RawQuery
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if extraDirector != nil {
			extraDirector(req)
		}
	}
}

// singleJoiningSlash is a utility function that adds a single slash to a URL where appropriate, copied from
// the httputil package
// TODO: add test to ensure behavior does not diverge from httputil's implementation, as per Rob Pike's proverbs
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
