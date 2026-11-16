package reverseproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBuild_AddHeaders tests that Build's returned ReverseProxy Director adds the proper request headers
func TestBuild_AddHeaders(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	proxy, err := Build(u, "")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if proxy == nil {
		t.Fatal("got nil, want non-nil proxy")
	}

	req := httptest.NewRequest("GET", "/test", nil)
	proxy.Director(req)

	// Check that headers were added to req
	if got := req.Header.Get(http.CanonicalHeaderKey("X-Forwarded-Proto")); got != "https" {
		t.Errorf("X-Forwarded-Proto: got %q, want %q", got, "https")
	}
	if got := req.Header.Get(http.CanonicalHeaderKey("X-Forwarded-Port")); got != "443" {
		t.Errorf("X-Forwarded-Port: got %q, want %q", got, "443")
	}
}

// TestBuild_HTTPUpstream tests that Build leaves the Transport untouched for plain http upstreams
func TestBuild_HTTPUpstream(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	proxy, err := Build(u, "")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if proxy.Transport != nil {
		t.Errorf("Transport: got %v, want nil (default transport)", proxy.Transport)
	}
}

// TestBuild_PinsServerNameToTargetHost tests that for https upstreams the TLS ServerName is pinned
// to the target host and verification is never disabled
func TestBuild_PinsServerNameToTargetHost(t *testing.T) {
	u, err := url.Parse("https://example.com:8443")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	proxy, err := Build(u, "")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport: got %T, want *http.Transport", proxy.Transport)
	}
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		t.Fatal("TLSClientConfig: got nil, want non-nil")
	}
	if got, want := tlsConfig.ServerName, "example.com"; got != want {
		t.Errorf("ServerName: got %q, want %q", got, want)
	}
	if tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify: got true, want false (verification must fail closed)")
	}
	if got, want := tlsConfig.MinVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("MinVersion: got %d, want %d", got, want)
	}
}

// TestBuild_BadCAFile tests that an unreadable or invalid upstream CA file is a startup error
func TestBuild_BadCAFile(t *testing.T) {
	u, err := url.Parse("https://127.0.0.1:8443")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if _, err := Build(u, filepath.Join(t.TempDir(), "does-not-exist.pem")); err == nil {
		t.Error("got nil error for missing CA file, want non-nil")
	}

	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(u, garbage); err == nil {
		t.Error("got nil error for invalid CA file, want non-nil")
	}
}

// TestBuild_TrustedUpstreamWithCAFile tests that a self-signed upstream whose CA is supplied via
// the CA file is trusted (single-certificate deployments can migrate)
func TestBuild_TrustedUpstreamWithCAFile(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	proxy, err := Build(u, caFile)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if got, want := recorder.Code, http.StatusOK; got != want {
		t.Errorf("status: got %d, want %d", got, want)
	}
}

// TestBuild_FailsClosedWithoutTrust tests that an upstream with an untrusted (self-signed)
// certificate is rejected when no CA file is supplied
func TestBuild_FailsClosedWithoutTrust(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	proxy, err := Build(u, "")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if got, want := recorder.Code, http.StatusBadGateway; got != want {
		t.Errorf("status: got %d, want %d (untrusted upstream must fail closed)", got, want)
	}
}

// TestBuild_FailsClosedOnHostnameMismatch tests that an upstream presenting a trusted certificate
// for the wrong hostname is rejected
func TestBuild_FailsClosedOnHostnameMismatch(t *testing.T) {
	// Start a TLS upstream presenting a certificate for "example.test" (not an IP SAN)
	cert, caPEM := newTestCertificate(t, []string{"example.test"}, nil)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	upstream.StartTLS()
	defer upstream.Close()

	// Trust the upstream's CA, so only the hostname mismatch can fail the handshake
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(upstream.URL) // https://127.0.0.1:port
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	proxy, err := Build(u, caFile)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if got, want := recorder.Code, http.StatusBadGateway; got != want {
		t.Errorf("status: got %d, want %d (hostname mismatch must fail closed)", got, want)
	}
}

// newTestCertificate generates a self-signed CA and a server certificate signed by it with the
// given DNS names and IP addresses as SANs. It returns the server certificate and the CA's PEM.
func newTestCertificate(t *testing.T, dnsNames []string, ipAddresses []net.IP) (tls.Certificate, []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"ssl-proxy test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"ssl-proxy test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return cert, caPEM
}

func TestNewDirector(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	director := newDirector(u, nil)

	defaultProxy := httputil.NewSingleHostReverseProxy(u)
	defaultDirector := defaultProxy.Director

	expectedReq := httptest.NewRequest("GET", "/test", nil)
	testReq := httptest.NewRequest("GET", "/test", nil)

	defaultDirector(expectedReq)
	director(testReq)

	// Compare relevant fields of the requests
	if got, want := testReq.URL.String(), expectedReq.URL.String(); got != want {
		t.Errorf("URL: got %q, want %q", got, want)
	}
	if got, want := testReq.Host, expectedReq.Host; got != want {
		t.Errorf("Host: got %q, want %q", got, want)
	}
	if got, want := testReq.RemoteAddr, expectedReq.RemoteAddr; got != want {
		t.Errorf("RemoteAddr: got %q, want %q", got, want)
	}
	// TODO: add more test cases
}
