package reverseproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

// Build initializes and returns a new ReverseProxy instance suitable for SSL proxying
//
// When toURL uses the https scheme, the returned proxy applies a single upstream
// TLS policy: the TLS ServerName (sent as SNI and used to verify the peer
// certificate's hostname) is pinned to the target host, and the certificate chain
// is verified against the system roots plus any PEM-encoded CA certificates in
// upstreamCAFile. Verification always fails closed--an untrusted or mismatched
// upstream certificate aborts the connection. An unreadable or invalid
// upstreamCAFile is reported as a startup error.
func Build(toURL *url.URL, upstreamCAFile string) (*httputil.ReverseProxy, error) {
	localProxy := &httputil.ReverseProxy{}
	addProxyHeaders := func(req *http.Request) {
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), "443") // TODO: inherit another port if needed
	}
	localProxy.Director = newDirector(toURL, addProxyHeaders)

	if toURL.Scheme == "https" {
		transport, err := newUpstreamTransport(toURL, upstreamCAFile)
		if err != nil {
			return nil, err
		}
		localProxy.Transport = transport
	}

	return localProxy, nil
}

// newUpstreamTransport returns an *http.Transport whose TLS configuration pins the
// ServerName to the target host and verifies upstream certificates against the
// system roots plus any CA certificates in caFile. Verification is never disabled.
func newUpstreamTransport(toURL *url.URL, caFile string) (*http.Transport, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		// Fall back to an empty pool; verification still fails closed, just
		// against fewer roots.
		rootCAs = x509.NewCertPool()
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read upstream CA file %q: %w", caFile, err)
		}
		if !rootCAs.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid PEM CA certificates found in upstream CA file %q", caFile)
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		// Pin the ServerName to the configured target host so that both SNI and
		// certificate hostname verification always use it.
		ServerName: toURL.Hostname(),
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}
	return transport, nil
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
