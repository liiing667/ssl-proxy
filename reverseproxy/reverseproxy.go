package reverseproxy

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	// dialTimeout bounds the time spent establishing a TCP connection to the
	// upstream, including half-open or half-closed network paths.
	dialTimeout = 30 * time.Second
	// dialKeepAlive keeps TCP keepalive probes enabled so dead upstream
	// connections are detected instead of lingering in the pool.
	dialKeepAlive = 30 * time.Second
	// tlsHandshakeTimeout bounds the upstream TLS handshake.
	tlsHandshakeTimeout = 10 * time.Second
	// expectContinueTimeout bounds waiting for an upstream 100-continue.
	expectContinueTimeout = time.Second
	// idleConnTimeout bounds how long an upstream keep-alive connection may sit
	// idle in the pool before being closed, so stale connections cannot be
	// reused across requests.
	idleConnTimeout = 90 * time.Second
	// maxIdleConnsPerHost bounds pooled idle upstream connections.
	maxIdleConnsPerHost = 16
	// clientClosedStatus mirrors nginx's 499 status used when the downstream
	// client cancels or times out before the upstream response completes.
	clientClosedStatus = 499
)

// Build initializes and returns a new ReverseProxy instance suitable for SSL proxying
func Build(toURL *url.URL) *httputil.ReverseProxy {
	localProxy := &httputil.ReverseProxy{
		// A dedicated, bounded Transport ensures canceled or half-closed
		// upstream connections are reaped and never leak between requests.
		Transport: NewTransport(),
		// ErrorHandler distinguishes downstream cancellation from real
		// upstream failures so connection state and cancellation reason stay
		// consistent, while preserving the historical 502 output otherwise.
		ErrorHandler: proxyErrorHandler,
	}
	addProxyHeaders := func(req *http.Request) {
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), "443") // TODO: inherit another port if needed
	}
	localProxy.Director = newDirector(toURL, addProxyHeaders)

	return localProxy
}

// NewTransport returns the http.Transport used for upstream connections. It is
// equivalent in spirit to http.DefaultTransport but with explicit dial,
// handshake, and idle timeouts so a canceled, timed-out, or half-closed
// upstream connection cannot outlive its request or be handed to another
// request. The http.Transport's built-in retry remains safe: it only retries
// idempotent requests on reused connections whose request bytes were never
// written, using rewindable request bodies.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: dialKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxIdleConnsPerHost * 2,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
		// ResponseHeaderTimeout is intentionally left unset so long-lived,
		// streamed, or upgraded responses remain supported.
	}
}

// proxyErrorHandler maps a RoundTrip failure to a response consistent with why
// the connection ended. When the downstream request context is done (client
// cancellation or deadline), the connection is already abandoned, so no
// upstream error is logged and a 499 is reported instead of a misleading 502.
// Writing to an already-closed downstream connection is a harmless no-op.
// All other failures preserve the historical "http: proxy error" log line and
// 502 Bad Gateway response.
func proxyErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	if isClientClosed(req, err) {
		rw.WriteHeader(clientClosedStatus)
		return
	}
	log.Printf("http: proxy error: %v", err)
	rw.WriteHeader(http.StatusBadGateway)
}

// isClientClosed reports whether the RoundTrip failure was caused by the
// downstream client canceling or timing out, rather than by the upstream. The
// downstream request context is the only authoritative signal for the client
// side: an error that merely wraps context.DeadlineExceeded (for example an
// upstream dial timeout) is an upstream failure and must stay a 502.
func isClientClosed(req *http.Request, err error) bool {
	if req != nil {
		switch req.Context().Err() {
		case context.Canceled, context.DeadlineExceeded:
			return true
		}
	}
	return false
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
