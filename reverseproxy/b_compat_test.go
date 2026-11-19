package reverseproxy

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Compatibility 1: a valid client certificate chaining to the trusted CA is
// authenticated and its identity reaches the downstream service.
func TestCompat_TrustedClientAuthenticated(t *testing.T) {
	pki := newTestPKI()
	authenticator, err := NewClientAuthenticator(pki.caPEM)
	if err != nil {
		t.Fatalf("NewClientAuthenticator: %v", err)
	}
	clientCert := pki.issueLeaf("legit.example", nil, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil)

	state, handshakeErr := dialHandshake(t, pki.serverTLSConfig(tls.RequireAnyClientCert, nil), clientTLSConfig(clientCert, nil))
	if handshakeErr != nil {
		t.Fatalf("handshake with trusted client failed: %v", handshakeErr)
	}

	identity, err := authenticator.Authenticate(state)
	if err != nil {
		t.Fatalf("trusted client rejected: %v", err)
	}
	if identity.CommonName != "legit.example" {
		t.Fatalf("CommonName: got %q, want %q", identity.CommonName, "legit.example")
	}
	if identity.Certificate == nil || len(identity.RawDER) == 0 {
		t.Fatal("identity is missing the verified certificate material")
	}
}

// Compatibility 2: an intermediate-CA chain is accepted when it terminates
// in the trusted root, and the leaf subject is the authenticated subject.
func TestCompat_IntermediateChainVerified(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)

	intermediate := pki.issueIntermediateCA("Intermediate CA")

	leaf := pki.issueLeaf("chained.example", intermediate.cert, intermediate.key,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil)

	clientConfig := clientTLSConfig(leaf, nil)
	clientConfig.Certificates[0].Certificate = [][]byte{leaf.cert.Raw, intermediate.cert.Raw}

	state, handshakeErr := dialHandshake(t, pki.serverTLSConfig(tls.RequireAnyClientCert, nil), clientConfig)
	if handshakeErr != nil {
		t.Fatalf("handshake failed: %v", handshakeErr)
	}
	identity, err := authenticator.Authenticate(state)
	if err != nil {
		t.Fatalf("intermediate chain rejected: %v", err)
	}
	if identity.CommonName != "chained.example" {
		t.Fatalf("CommonName: got %q, want chained.example", identity.CommonName)
	}
}

// Compatibility 3: end-to-end proxy flow keeps existing X-Forwarded headers
// and adds verified identity headers only for the authenticated subject.
func TestCompat_ProxyFlowPreservesHeadersAndIdentity(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)
	clientCert := pki.issueLeaf("legit.example", nil, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil)

	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("X-Forwarded-Proto: got %q, want https", got)
		}
		if got := r.Header.Get("X-Forwarded-Port"); got != "443" {
			t.Errorf("X-Forwarded-Port: got %q, want 443", got)
		}
		if got := r.Header.Get(HeaderForwardedClientCN); got != "legit.example" {
			t.Errorf("%s: got %q, want legit.example", HeaderForwardedClientCN, got)
		}
		if got := r.Header.Get(HeaderForwardedSubjectDN); got == "" {
			t.Error("subject DN header missing")
		}
		der, err := base64.StdEncoding.DecodeString(r.Header.Get(HeaderForwardedClientCert))
		if err != nil || len(der) == 0 {
			t.Errorf("client cert header is not base64 DER: %v", err)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer downstream.Close()

	handler := ClientAuthMiddleware(authenticator, BuildWithClientAuth(mustParseURL(t, downstream.URL), authenticator))
	proxyServer := httptest.NewUnstartedServer(handler)
	proxyServer.TLS = pki.serverTLSConfig(tls.RequireAndVerifyClientCert, authenticator.RootPool())
	proxyServer.StartTLS()
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLSConfig(clientCert, nil)}}
	response, err := client.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status: got %d, want 200 (body: %s)", response.StatusCode, body)
	}
}

// Compatibility 4: the original Build behavior is unchanged -- no
// authentication requirement, same X-Forwarded headers.
func TestCompat_LegacyBuildUnchanged(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("X-Forwarded-Proto: got %q, want https", got)
		}
		if got := r.Header.Get("X-Forwarded-Port"); got != "443" {
			t.Errorf("X-Forwarded-Port: got %q, want 443", got)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer downstream.Close()

	proxyServer := httptest.NewServer(Build(mustParseURL(t, downstream.URL)))
	defer proxyServer.Close()

	response, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", response.StatusCode)
	}
}

// Compatibility 4b: the legacy Build path also strips inbound identity
// headers so a client cannot inject an authenticated context, while keeping
// the standard X-Forwarded headers intact.
func TestCompat_LegacyBuildStripsSpoofedIdentityHeaders(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range spoofableIdentityHeaders {
			if got := r.Header.Get(http.CanonicalHeaderKey(header)); got != "" {
				t.Errorf("spoofed header %s=%q reached downstream via legacy Build", header, got)
			}
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("X-Forwarded-Proto: got %q, want https", got)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer downstream.Close()

	proxyServer := httptest.NewServer(Build(mustParseURL(t, downstream.URL)))
	defer proxyServer.Close()

	request, err := http.NewRequest(http.MethodGet, proxyServer.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range spoofableIdentityHeaders {
		request.Header.Set(header, "spoofed-identity")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", response.StatusCode)
	}
}

// Compatibility 5: nil authenticator keeps the middleware as a pass-through.
func TestCompat_NilAuthenticatorPassThrough(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	recorder := httptest.NewRecorder()
	ClientAuthMiddleware(nil, inner).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("next handler was not invoked with nil authenticator")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", recorder.Code)
	}
}

// Compatibility 6: invalid CA PEM keeps returning a construction error rather
// than silently trusting nothing or everything.
func TestCompat_InvalidCAPEMErrors(t *testing.T) {
	if _, err := NewClientAuthenticator([]byte("not a certificate")); err == nil {
		t.Fatal("invalid CA PEM accepted; want error")
	}
}

// Compatibility 7: TLS config stays at TLS 1.2+ and requests the client
// certificate without forcing legacy protocols.
func TestCompat_TLSConfigBaseline(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)
	config := authenticator.TLSConfig()
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion: got %x, want %x", config.MinVersion, tls.VersionTLS12)
	}
	if config.ClientAuth == tls.NoClientCert {
		t.Fatal("client certificates are not requested")
	}
}
