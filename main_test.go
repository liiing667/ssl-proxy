package main

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
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert generates a self-signed certificate for dnsNames and writes it
// plus its key to a temporary directory.
func writeTestCert(t *testing.T, dnsNames ...string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"ssl-proxy test"}},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// handshake attempts a full TLS handshake against a server using config,
// offering the given SNI server name, and returns the server-side error.
func handshake(config *tls.Config, serverName string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		server := tls.Server(conn, config)
		serverErr <- server.Handshake()
	}()
	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	if err != nil {
		return err
	}
	client.Close()
	return <-serverErr
}

// TestServerTLSConfig_MismatchedSNI_FailsClosed is an attack test: a client
// offering an SNI that does not match the served identity is rejected.
func TestServerTLSConfig_MismatchedSNI_FailsClosed(t *testing.T) {
	certFile, keyFile := writeTestCert(t, "example.com")
	config, err := serverTLSConfig(certFile, keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(config, "evil.com"); err == nil {
		t.Fatal("got nil error, want handshake rejection for mismatched SNI")
	}
}

// TestServerTLSConfig_MatchingAndEmptySNI_Accepted is a compatibility test:
// legitimate clients offering the correct SNI (or no SNI at all, e.g.
// IP-based clients) keep working.
func TestServerTLSConfig_MatchingAndEmptySNI_Accepted(t *testing.T) {
	certFile, keyFile := writeTestCert(t, "example.com")
	config, err := serverTLSConfig(certFile, keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(config, "example.com"); err != nil {
		t.Errorf("matching SNI: got error %v, want nil", err)
	}
	if err := handshake(config, ""); err != nil {
		t.Errorf("empty SNI: got error %v, want nil", err)
	}
}

// TestServerTLSConfig_ExpectedHostEnforced checks that an explicitly expected
// host (e.g. -domain) is enforced at the ingress even if the certificate does
// not list it.
func TestServerTLSConfig_ExpectedHostEnforced(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	config, err := serverTLSConfig(certFile, keyFile, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(config, "example.com"); err != nil {
		t.Errorf("expected host SNI: got error %v, want nil", err)
	}
	if err := handshake(config, "evil.com"); err == nil {
		t.Error("got nil error, want handshake rejection for unexpected SNI")
	}
}

// TestServerTLSConfig_MinVersion checks TLS 1.2 is the floor.
func TestServerTLSConfig_MinVersion(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	config, err := serverTLSConfig(certFile, keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %x, want %x (TLS 1.2)", config.MinVersion, tls.VersionTLS12)
	}
}

// TestRedirectHandler_NormalRequest is a compatibility test: normal
// origin-form requests redirect exactly as before.
func TestRedirectHandler_NormalRequest(t *testing.T) {
	handler := redirectHandler("example.com")
	req := &http.Request{
		Method:     "GET",
		Host:       "example.com",
		RequestURI: "/foo/bar?a=b",
		URL:        &url.URL{Path: "/foo/bar", RawQuery: "a=b"},
	}
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusMovedPermanently {
		t.Errorf("status: got %d, want %d", recorder.Code, http.StatusMovedPermanently)
	}
	if got, want := recorder.Header().Get("Location"), "https://example.com/foo/bar?a=b"; got != want {
		t.Errorf("Location: got %q, want %q", got, want)
	}
}

// TestRedirectHandler_ProtocolRelativeTarget_FailsClosed is an attack test: a
// "//evil.com" request target must not become an open redirect to evil.com.
func TestRedirectHandler_ProtocolRelativeTarget_FailsClosed(t *testing.T) {
	handler := redirectHandler("example.com")
	req := &http.Request{
		Method:     "GET",
		Host:       "example.com",
		RequestURI: "//evil.com/phish",
		URL:        &url.URL{Path: "//evil.com/phish"},
	}
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if location := recorder.Header().Get("Location"); location != "" {
		t.Errorf("Location: got %q, want no redirect", location)
	}
}

// TestRedirectHandler_CrossHostAbsoluteForm_FailsClosed is an attack test: an
// absolute-form request target pointing at another host fails closed.
func TestRedirectHandler_CrossHostAbsoluteForm_FailsClosed(t *testing.T) {
	handler := redirectHandler("example.com")
	req := &http.Request{
		Method:     "GET",
		Host:       "example.com",
		RequestURI: "http://evil.com/phish",
		URL:        &url.URL{Scheme: "http", Host: "evil.com", Path: "/phish"},
	}
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if location := recorder.Header().Get("Location"); location != "" {
		t.Errorf("Location: got %q, want no redirect", location)
	}
}

// TestRedirectHandler_SameHostAbsoluteForm_Redirects is a compatibility test:
// absolute-form targets for this very host still redirect to https.
func TestRedirectHandler_SameHostAbsoluteForm_Redirects(t *testing.T) {
	handler := redirectHandler("example.com")
	req := &http.Request{
		Method:     "GET",
		Host:       "example.com",
		RequestURI: "http://example.com/foo?a=b",
		URL:        &url.URL{Scheme: "http", Host: "example.com", Path: "/foo", RawQuery: "a=b"},
	}
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusMovedPermanently {
		t.Errorf("status: got %d, want %d", recorder.Code, http.StatusMovedPermanently)
	}
	if got, want := recorder.Header().Get("Location"), "https://example.com/foo?a=b"; got != want {
		t.Errorf("Location: got %q, want %q", got, want)
	}
}

// TestRequireHost_MismatchedHost_FailsClosed is an attack test: requests
// carrying a foreign Host header are rejected instead of being served under
// this proxy's trust context.
func TestRequireHost_MismatchedHost_FailsClosed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireHost("example.com", next)
	req := httptest.NewRequest("GET", "https://evil.com/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusMisdirectedRequest {
		t.Errorf("status: got %d, want %d", recorder.Code, http.StatusMisdirectedRequest)
	}
}

// TestRequireHost_MatchingHost_Accepted is a compatibility test.
func TestRequireHost_MatchingHost_Accepted(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requireHost("example.com", next)
	for _, host := range []string{"example.com", "EXAMPLE.com", "example.com:443"} {
		req := httptest.NewRequest("GET", "https://"+host+"/", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Errorf("host %q: got status %d, want %d", host, recorder.Code, http.StatusOK)
		}
	}
}

func TestParseCertPin(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := parseCertPin(valid); err != nil {
		t.Errorf("hex pin: got error %v, want nil", err)
	}
	spaced := "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"
	if _, err := parseCertPin(spaced); err != nil {
		t.Errorf("spaced pin: got error %v, want nil", err)
	}
	if _, err := parseCertPin("not-hex"); err == nil {
		t.Error("got nil error, want failure for non-hex pin")
	}
	if _, err := parseCertPin("0123"); err == nil {
		t.Error("got nil error, want failure for wrong-length pin")
	}
}
