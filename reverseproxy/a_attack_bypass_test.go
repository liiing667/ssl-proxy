package reverseproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// dialHandshake performs a TLS handshake over an in-memory pipe and returns
// the server-side connection state.
func dialHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)

	type result struct {
		state tls.ConnectionState
		err   error
	}
	resultCh := make(chan result, 1)

	go func() {
		srv := tls.Server(serverConn, serverConfig)
		err := srv.Handshake()
		res := result{err: err}
		if err == nil {
			res.state = srv.ConnectionState()
		}
		resultCh <- res
	}()

	cli := tls.Client(clientConn, clientConfig)
	err := cli.Handshake()
	if err != nil {
		state := <-resultCh
		_ = serverConn.Close()
		_ = clientConn.Close()
		return state.state, state.err
	}
	state := <-resultCh
	_ = serverConn.Close()
	_ = clientConn.Close()
	return state.state, state.err
}

func clientTLSConfig(tc *tlsCert, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{tc.cert.Raw},
			PrivateKey:  tc.key,
			Leaf:        tc.cert,
		}},
		RootCAs: roots,
	}
}

// Attack 1: a certificate issued by an untrusted foreign CA must never be
// accepted as an authenticated subject.
func TestAttack_UntrustedChainRejected(t *testing.T) {
	pki := newTestPKI()
	authenticator, err := NewClientAuthenticator(pki.caPEM)
	if err != nil {
		t.Fatalf("NewClientAuthenticator: %v", err)
	}
	foreign := pki.issueLeaf("attacker.example", pki.otherCA, pki.otherKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil)

	serverConfig := pki.serverTLSConfig(tls.RequireAnyClientCert, nil)
	state, _ := dialHandshake(t, serverConfig, clientTLSConfig(foreign, nil))

	if _, err := authenticator.Authenticate(state); err == nil {
		t.Fatal("foreign-CA client certificate was accepted as authenticated; want rejection")
	}
}

// Attack 2: a self-signed client certificate not anchored in the trusted pool
// must be rejected even when the peer sends no chain.
func TestAttack_SelfSignedCertificateRejected(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)
	rogue := pki.selfSignedLeaf("trusted-admin")

	serverConfig := pki.serverTLSConfig(tls.RequireAnyClientCert, nil)
	state, _ := dialHandshake(t, serverConfig, clientTLSConfig(rogue, nil))

	if _, err := authenticator.Authenticate(state); err == nil {
		t.Fatal("self-signed client certificate was accepted as authenticated; want rejection")
	}
}

// Attack 3: an expired certificate chaining to the trusted CA must be
// rejected (time validity is part of chain constraints).
func TestAttack_ExpiredCertificateRejected(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)
	expired := pki.issueLeaf("expired.example", nil, nil, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), nil)

	serverConfig := pki.serverTLSConfig(tls.RequireAnyClientCert, nil)
	state, _ := dialHandshake(t, serverConfig, clientTLSConfig(expired, nil))

	if _, err := authenticator.Authenticate(state); err == nil {
		t.Fatal("expired client certificate was accepted; want rejection")
	}
}

// Attack 4: a certificate without the clientAuth EKU must not authenticate a
// TLS client even when it chains to the trusted CA.
func TestAttack_WrongExtKeyUsageRejected(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)
	serverOnly := pki.issueLeaf("server-only.example", nil, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	serverConfig := pki.serverTLSConfig(tls.RequireAnyClientCert, nil)
	state, _ := dialHandshake(t, serverConfig, clientTLSConfig(serverOnly, nil))

	if _, err := authenticator.Authenticate(state); err == nil {
		t.Fatal("serverAuth-only client certificate was accepted; want rejection")
	}
}

// Attack 5: a connection presenting no certificate cannot yield an identity.
func TestAttack_NoCertificateRejected(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)

	serverConfig := pki.serverTLSConfig(tls.RequireAnyClientCert, nil)
	state, _ := dialHandshake(t, serverConfig, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	if _, err := authenticator.Authenticate(state); !errors.Is(err, errNoClientCertificate) {
		t.Fatalf("got %v, want errNoClientCertificate", err)
	}
}

// Attack 6: inbound spoofed identity headers must be stripped instead of
// being forwarded to the downstream service as authenticated context.
func TestAttack_InboundSpoofedIdentityHeadersStripped(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)

	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range spoofableIdentityHeaders {
			if got := r.Header.Get(http.CanonicalHeaderKey(header)); got != "" {
				t.Errorf("spoofed header %s=%q reached downstream", header, got)
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer downstream.Close()

	target := mustParseURL(t, downstream.URL)
	proxy := BuildWithClientAuth(target, authenticator)
	handler := ClientAuthMiddleware(authenticator, proxy)
	proxyServer := httptest.NewUnstartedServer(handler)
	proxyServer.TLS = pki.serverTLSConfig(tls.RequireAndVerifyClientCert, authenticator.RootPool())
	proxyServer.StartTLS()
	defer proxyServer.Close()

	request, err := http.NewRequest(http.MethodGet, proxyServer.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range spoofableIdentityHeaders {
		request.Header.Set(header, "spoofed-identity")
	}
	// Request carries no client certificate: authentication must fail closed.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := client.Do(request)
	if err != nil {
		// Rejecting at the TLS handshake ("certificate required") is also a
		// secure failure: the spoofed headers never reached the downstream.
		if !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

// Attack 7: when authentication is configured but the request has no TLS
// connection state, the proxy must fail closed rather than forward context.
func TestAttack_PlaintextWithContextRejected(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)

	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached downstream without client authentication")
	}))
	defer downstream.Close()

	handler := ClientAuthMiddleware(authenticator, BuildWithClientAuth(mustParseURL(t, downstream.URL), authenticator))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", strings.NewReader(""))
	request.Header.Set(HeaderForwardedClientCN, "spoofed-admin")
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(recorder.Body.String(), "client certificate") {
		t.Fatalf("body %q does not explain the client certificate failure", recorder.Body.String())
	}
}

// Defense in depth: a forged context value must not be treated as identity.
func TestAttack_ForgedContextNotTrusted(t *testing.T) {
	pki := newTestPKI()
	authenticator, _ := NewClientAuthenticator(pki.caPEM)
	rogue := pki.selfSignedLeaf("forged-admin")
	forgedState := tls.ConnectionState{PeerCertificates: []*x509.Certificate{rogue.cert}}

	if _, err := authenticator.Authenticate(forgedState); err == nil {
		t.Fatal("forged connection state accepted without chain verification")
	}
	if _, ok := clientIdentityFromContext(context.Background()); ok {
		t.Fatal("identity leaked from an empty context")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return parsed
}
