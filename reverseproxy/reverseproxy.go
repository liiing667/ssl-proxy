package reverseproxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Build initializes and returns a new ReverseProxy instance suitable for SSL proxying
func Build(toURL *url.URL) *httputil.ReverseProxy {
	localProxy := &httputil.ReverseProxy{}
	addProxyHeaders := func(req *http.Request) {
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), "443") // TODO: inherit another port if needed
	}
	localProxy.Director = newDirector(toURL, func(req *http.Request) {
		stripInboundIdentityHeaders(req)
		addProxyHeaders(req)
	})

	return localProxy
}

// ClientAuthMiddleware enforces client certificate authentication before the
// request reaches the reverse proxy. When authenticator is nil the middleware
// is a pass-through so existing deployments keep working unchanged.
func ClientAuthMiddleware(authenticator *ClientAuthenticator, next http.Handler) http.Handler {
	if authenticator == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "client certificate authentication required", http.StatusUnauthorized)
			return
		}
		identity, err := authenticator.Authenticate(*r.TLS)
		if err != nil {
			http.Error(w, "client certificate authentication failed: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := contextWithClientIdentity(r.Context(), identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// BuildWithClientAuth initializes a ReverseProxy that authenticates clients
// with authenticator and forwards their verified identity to the downstream
// service. A nil authenticator is equivalent to Build.
func BuildWithClientAuth(toURL *url.URL, authenticator *ClientAuthenticator) *httputil.ReverseProxy {
	localProxy := &httputil.ReverseProxy{}
	addProxyHeaders := func(req *http.Request) {
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), "443")
		if identity, ok := clientIdentityFromContext(req.Context()); ok {
			AddIdentityHeaders(req, identity)
		}
	}
	localProxy.Director = newDirector(toURL, func(req *http.Request) {
		stripInboundIdentityHeaders(req)
		addProxyHeaders(req)
	})

	return localProxy
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
