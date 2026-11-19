package reverseproxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/suyashkumar/ssl-proxy/securelog"
)

// Build initializes and returns a new ReverseProxy instance suitable for SSL proxying
func Build(toURL *url.URL) *httputil.ReverseProxy {
	return BuildWithOptions(toURL)
}

// Option customizes a ReverseProxy created via BuildWithOptions.
type Option func(*config)

type config struct {
	logger *securelog.Logger
}

// WithLogger wires a structured, fail-closed secure logger into the proxy.
// Without it, the proxy uses a package-default logger writing redacted events
// to stderr, so protection never depends on a caller supplying one.
func WithLogger(logger *securelog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// BuildWithOptions initializes a ReverseProxy with framework-level protection:
// the original proxy headers and director behavior are preserved, while TLS
// and upstream errors are routed through a redacting error handler, and each
// pipeline stage emits structured, redacted trace events.
func BuildWithOptions(toURL *url.URL, opts ...Option) *httputil.ReverseProxy {
	cfg := config{logger: securelog.DefaultLogger()}
	for _, opt := range opts {
		opt(&cfg)
	}

	localProxy := &httputil.ReverseProxy{}
	addProxyHeaders := func(req *http.Request) {
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), "443") // TODO: inherit another port if needed
	}

	logger := cfg.logger
	localProxy.Director = newDirector(toURL, func(req *http.Request) {
		addProxyHeaders(req)
		logger.Trace(req, "director", "request rewritten for upstream")
	})

	// All framework-internal errors (including TLS handshakes surfaced by
	// httputil) go through the scrubbing writer instead of the default logger.
	localProxy.ErrorLog = logger.Std()

	// ModifyResponse emits a redacted trace of the upstream response without
	// altering it, preserving existing proxy semantics.
	localProxy.ModifyResponse = func(resp *http.Response) error {
		logger.Trace(resp.Request, "upstream_response",
			fmt.Sprintf("status=%d", resp.StatusCode))
		return nil
	}

	// ErrorHandler preserves the historical response exactly (status 502 with
	// no body, matching httputil's default behavior) while the error detail is
	// emitted only through the redacting structured logger.
	localProxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		stage := "upstream"
		if isTLSError(err) {
			logger.TLSError(req, err)
			stage = "tls"
		} else {
			logger.ProxyError(req, stage, err)
		}
		logger.Audit(req, "request_failed_closed",
			"upstream request failed; error emitted only in redacted form",
			map[string]string{"stage": stage})
		rw.WriteHeader(http.StatusBadGateway)
	}

	return localProxy
}

// NewHandler returns the full protected handler chain: redacting access-log,
// trace and audit middleware in front of the reverse proxy. Deployments that
// previously passed Build(toURL) directly to a mux can replace it with
// NewHandler(toURL) without other changes.
func NewHandler(toURL *url.URL, opts ...Option) http.Handler {
	cfg := config{logger: securelog.DefaultLogger()}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg.logger.Middleware(BuildWithOptions(toURL, opts...))
}

// isTLSError reports whether err originates from the TLS layer. The standard
// library does not expose a dedicated sentinel, so classification is based on
// the stable error text prefixes used by crypto/tls and crypto/x509.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	msg := err.Error()
	return strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "remote error: tls:") ||
		strings.Contains(msg, "TLS handshake")
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
