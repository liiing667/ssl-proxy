package reverseproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testUpstreamHost = "upstream.example"

// makeTestCA creates a throwaway CA for tests.
func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ssl-proxy test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

// issueServerCert issues a server certificate for dnsNames signed by the CA.
func issueServerCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames ...string) (tls.Certificate, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, sha256.Sum256(der)
}

// startUpstream starts a TLS test server presenting cert and returns it along
// with a dial function that routes any address to the server (simulating DNS).
func startUpstream(t *testing.T, cert tls.Certificate) (*httptest.Server, func(ctx context.Context, network, addr string) (net.Conn, error)) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	dialer := &net.Dialer{}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	return server, dial
}

func getViaTransport(transport *http.Transport, rawURL string) (string, error) {
	client := &http.Client{Transport: transport}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// newTestTransport builds a secure transport wired to the test upstream's dial
// function, with proxying disabled so requests reach the test server directly.
func newTestTransport(pins CertPins, rootCAs *x509.CertPool, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	transport := newSecureTransport(pins, rootCAs)
	transport.Proxy = nil
	transport.DialContext = dial
	return transport
}

// TestSecureTransport_CorrectPin_Succeeds is a compatibility test: a properly
// pinned, CA-valid upstream keeps working.
func TestSecureTransport_CorrectPin_Succeeds(t *testing.T) {
	ca, caKey, pool := makeTestCA(t)
	cert, fingerprint := issueServerCert(t, ca, caKey, testUpstreamHost)
	_, dial := startUpstream(t, cert)
	transport := newTestTransport(CertPins{testUpstreamHost: fingerprint}, pool, dial)
	body, err := getViaTransport(transport, "https://"+testUpstreamHost+"/")
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if body != "ok" {
		t.Errorf("body: got %q, want %q", body, "ok")
	}
}

// TestSecureTransport_NoPins_KeepsDefaultVerification is a compatibility test:
// without pins, verification behaves like the default transport (CA + hostname).
func TestSecureTransport_NoPins_KeepsDefaultVerification(t *testing.T) {
	ca, caKey, pool := makeTestCA(t)
	cert, _ := issueServerCert(t, ca, caKey, testUpstreamHost)
	_, dial := startUpstream(t, cert)
	transport := newTestTransport(nil, pool, dial)
	if _, err := getViaTransport(transport, "https://"+testUpstreamHost+"/"); err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	// Hostname mismatch must still fail, exactly like the default transport.
	transport = newTestTransport(nil, pool, dial)
	if _, err := getViaTransport(transport, "https://other.example/"); err == nil {
		t.Fatal("got nil error, want hostname verification failure")
	}
}

// TestSecureTransport_PinMismatch_FailsClosed is an attack test: an upstream
// presenting a certificate that does not match the configured pin is rejected.
func TestSecureTransport_PinMismatch_FailsClosed(t *testing.T) {
	ca, caKey, pool := makeTestCA(t)
	cert, _ := issueServerCert(t, ca, caKey, testUpstreamHost)
	_, dial := startUpstream(t, cert)
	wrongPin := sha256.Sum256([]byte("attacker controlled certificate"))
	transport := newTestTransport(CertPins{testUpstreamHost: wrongPin}, pool, dial)
	_, err := getViaTransport(transport, "https://"+testUpstreamHost+"/")
	if err == nil {
		t.Fatal("got nil error, want pin mismatch failure")
	}
	if !strings.Contains(err.Error(), "pin mismatch") {
		t.Errorf("error: got %v, want pin mismatch", err)
	}
}

// TestSecureTransport_CrossHostMigration_FailsClosed is an attack test: a pin
// configured for one host must not be reused as the trust policy for a
// connection to a different host.
func TestSecureTransport_CrossHostMigration_FailsClosed(t *testing.T) {
	ca, caKey, pool := makeTestCA(t)
	cert, fingerprint := issueServerCert(t, ca, caKey, testUpstreamHost)
	_, dial := startUpstream(t, cert)
	// The real fingerprint is pinned, but under a different host name.
	transport := newTestTransport(CertPins{"other.example": fingerprint}, pool, dial)
	_, err := getViaTransport(transport, "https://"+testUpstreamHost+"/")
	if err == nil {
		t.Fatal("got nil error, want fail-closed rejection for unpinned host")
	}
	if !strings.Contains(err.Error(), "no certificate pin configured") {
		t.Errorf("error: got %v, want missing-pin rejection", err)
	}
}

// TestBuildSecureTransport_EndToEnd exercises the full proxy: egress to an
// https upstream succeeds with the right pin and fails closed (502) with a
// wrong one, matching the proxy's existing upstream-error output.
func TestBuildSecureTransport_EndToEnd(t *testing.T) {
	ca, caKey, pool := makeTestCA(t)
	cert, fingerprint := issueServerCert(t, ca, caKey, testUpstreamHost)
	_, dial := startUpstream(t, cert)
	newProxy := func(pins CertPins) *httputil.ReverseProxy {
		u, err := url.Parse("https://" + testUpstreamHost)
		if err != nil {
			t.Fatal(err)
		}
		proxy := Build(u)
		proxy.Transport = newTestTransport(pins, pool, dial)
		return proxy
	}
	// Compatibility: correct pin proxies the request through.
	proxy := newProxy(CertPins{testUpstreamHost: fingerprint})
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest("GET", "https://proxy.example/", nil))
	if recorder.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", recorder.Code, http.StatusOK)
	}
	// Attack: wrong pin fails closed with the standard 502 upstream error.
	wrongPin := sha256.Sum256([]byte("attacker controlled certificate"))
	proxy = newProxy(CertPins{testUpstreamHost: wrongPin})
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest("GET", "https://proxy.example/", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Errorf("status: got %d, want %d", recorder.Code, http.StatusBadGateway)
	}
}
