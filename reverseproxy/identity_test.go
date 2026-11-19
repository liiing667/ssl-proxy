package reverseproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/suyashkumar/ssl-proxy/clientidentity"
)

type upstreamObservation struct {
	xForwardedFor   string
	xRealIP         string
	xForwardedProto string
	xForwardedPort  string
	forwarded       string
	remoteAddr      string
}

func newUpstream(t *testing.T) (*httptest.Server, *upstreamObservation) {
	t.Helper()
	observation := &upstreamObservation{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		observation.xForwardedFor = req.Header.Get("X-Forwarded-For")
		observation.xRealIP = req.Header.Get("X-Real-Ip")
		observation.xForwardedProto = req.Header.Get("X-Forwarded-Proto")
		observation.xForwardedPort = req.Header.Get("X-Forwarded-Port")
		observation.forwarded = req.Header.Get("Forwarded")
		observation.remoteAddr = req.RemoteAddr
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, observation
}

func mustProxy(t *testing.T, upstream *httptest.Server, resolver *clientidentity.Resolver) *httptest.Server {
	t.Helper()
	toURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proxy := BuildWithIdentity(toURL, resolver)
	server := httptest.NewServer(resolver.Middleware(proxy))
	t.Cleanup(server.Close)
	return server
}

func doProxyRequest(t *testing.T, proxyURL string, headers map[string]string) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	var builder strings.Builder
	builder.WriteString("GET / HTTP/1.1\r\nHost: example.test\r\n")
	for key, value := range headers {
		builder.WriteString(key + ": " + value + "\r\n")
	}
	builder.WriteString("\r\n")
	if _, err := conn.Write([]byte(builder.String())); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// Headline end-to-end attack: a direct attacker forges X-Forwarded-For. The
// upstream must only ever see the attacker's real direct address.
func TestProxy_DirectConnectionForgedXFFCannotBypassOriginPolicy(t *testing.T) {
	upstream, observation := newUpstream(t)
	proxy := mustProxy(t, upstream, clientidentity.NewResolver(nil))

	doProxyRequest(t, proxy.URL, map[string]string{
		"X-Forwarded-For": "10.0.0.7, 192.0.2.200",
		"X-Real-Ip":       "10.0.0.7",
		"Forwarded":       "for=10.0.0.7;proto=https",
	})

	directPeer := observation.remoteAddr
	host, _, err := net.SplitHostPort(directPeer)
	if err != nil {
		t.Fatalf("upstream RemoteAddr %q: %v", directPeer, err)
	}
	if strings.Contains(observation.xForwardedFor, "10.0.0.7") ||
		strings.Contains(observation.xForwardedFor, "192.0.2.200") {
		t.Fatalf("forged XFF reached upstream: %q", observation.xForwardedFor)
	}
	if observation.xRealIP == "10.0.0.7" {
		t.Fatalf("forged X-Real-Ip reached upstream: %q", observation.xRealIP)
	}
	if observation.forwarded != "" {
		t.Fatalf("forged Forwarded header reached upstream: %q", observation.forwarded)
	}
	if !strings.HasSuffix(observation.xForwardedFor, host) {
		t.Fatalf("X-Forwarded-For must carry only the real peer %q, got %q", host, observation.xForwardedFor)
	}
	if observation.xRealIP != host {
		t.Fatalf("X-Real-Ip: got %q, want real peer %q", observation.xRealIP, host)
	}
}

// Legitimate deployment behind a trusted proxy keeps real client attribution.
func TestProxy_TrustedProxyChainReachesUpstream(t *testing.T) {
	upstream, observation := newUpstream(t)
	trusted := clientidentity.NewResolver(mustTrustedNetworks(t, "127.0.0.0/8"))
	proxy := mustProxy(t, upstream, trusted)

	doProxyRequest(t, proxy.URL, map[string]string{
		"X-Forwarded-For": "203.0.113.50",
	})

	host, _, err := net.SplitHostPort(observation.remoteAddr)
	if err != nil {
		t.Fatalf("upstream RemoteAddr %q: %v", observation.remoteAddr, err)
	}
	if got, want := observation.xForwardedFor, "203.0.113.50, "+host; got != want {
		t.Fatalf("X-Forwarded-For: got %q, want %q", got, want)
	}
	if got := observation.xRealIP; got != "203.0.113.50" {
		t.Fatalf("X-Real-Ip: got %q, want 203.0.113.50", got)
	}
}

// Existing header behavior stays compatible for ordinary direct clients.
func TestProxy_CompatibilityHeadersForDirectClient(t *testing.T) {
	upstream, observation := newUpstream(t)
	proxy := mustProxy(t, upstream, clientidentity.NewResolver(nil))

	doProxyRequest(t, proxy.URL, nil)

	if observation.xForwardedProto != "https" {
		t.Fatalf("X-Forwarded-Proto: got %q, want https", observation.xForwardedProto)
	}
	if observation.xForwardedPort != "443" {
		t.Fatalf("X-Forwarded-Port: got %q, want 443", observation.xForwardedPort)
	}
	host, _, err := net.SplitHostPort(observation.remoteAddr)
	if err != nil {
		t.Fatalf("upstream RemoteAddr %q: %v", observation.remoteAddr, err)
	}
	if observation.xForwardedFor != host {
		t.Fatalf("X-Forwarded-For: got %q, want %q", observation.xForwardedFor, host)
	}
	if observation.xRealIP != host {
		t.Fatalf("X-Real-Ip: got %q, want %q", observation.xRealIP, host)
	}
}

// An unreachable upstream still yields the historical 502 error output.
func TestProxy_UpstreamFailureKeeps502ErrorOutput(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	toURL, err := url.Parse(closed.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proxy := BuildWithIdentity(toURL, clientidentity.NewResolver(nil))
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.66:9"

	var buffer bytes.Buffer
	proxy.ErrorLog = log.New(&buffer, "", 0)
	clientidentity.NewResolver(nil).Middleware(proxy).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want %d", recorder.Code, http.StatusBadGateway)
	}
	if body := recorder.Body.String(); !strings.Contains(body, http.StatusText(http.StatusBadGateway)) {
		t.Fatalf("body %q must keep Bad Gateway error output", body)
	}
	if !strings.Contains(buffer.String(), `client_identity="198.51.100.66"`) {
		t.Fatalf("error log must attribute the resolved identity: %q", buffer.String())
	}
}

// TLS evidence on the inbound connection is preserved inside the identity.
func TestProxy_TLSEvidencePreserved(t *testing.T) {
	resolver := clientidentity.NewResolver(nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.66:9"
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS12}

	identity := resolver.Resolve(req)
	if identity.TLS == nil || identity.TLS.Version != tls.VersionTLS12 {
		t.Fatalf("TLS evidence lost: %#v", identity.TLS)
	}
}

func mustTrustedNetworks(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()
	networks, err := clientidentity.ParseTrustedProxies(values)
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	return networks
}
