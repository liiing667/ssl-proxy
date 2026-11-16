package reverseproxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Build initializes and returns a new ReverseProxy instance suitable for SSL proxying
func Build(toURL *url.URL) *httputil.ReverseProxy {
	localProxy := &httputil.ReverseProxy{
		// Defense in depth: httputil.ReverseProxy already removes hop-by-hop
		// headers from backend responses, but pin the same policy here so the
		// response framing seen by clients stays fixed regardless of stdlib
		// internals. Backend Content-Length/Transfer-Encoding are generated
		// from the parsed response and are left untouched.
		ModifyResponse: func(res *http.Response) error {
			removeHopByHopHeaders(res.Header)
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Printf("reverseproxy: upstream error: %v", err)
			rw.Header().Set("Connection", "close")
			http.Error(rw, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
	}
	addProxyHeaders := func(req *http.Request) {
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), "443") // TODO: inherit another port if needed
	}
	localProxy.Director = newDirector(toURL, addProxyHeaders)

	return localProxy
}

// Handler wraps the built proxy so inbound requests with illegal or
// ambiguous message framing are rejected before any header normalization and
// forwarding happens.
func Handler(toURL *url.URL) http.Handler {
	proxy := Build(toURL)
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := validateRequestFraming(req); err != nil {
			log.Printf("reverseproxy: rejecting request: %v", err)
			rw.Header().Set("Connection", "close")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(rw, req)
	})
}

// newDirector creates a base director that should be exactly what http.NewSingleHostReverseProxy() creates, but allows
// for the caller to supply and extraDirector function to decorate to request to the downstream server
func newDirector(target *url.URL, extraDirector func(*http.Request)) func(*http.Request) {
	targetQuery := target.RawQuery
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		// Resolve any Host conflict in favor of the configured upstream: a
		// client-supplied Host must never be sent to a different origin than
		// the one the request line was rewritten to.
		req.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		normalizeRequestHeaders(req)
		appendVia(req.Header, req)
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
