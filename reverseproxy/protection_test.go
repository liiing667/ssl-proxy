package reverseproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/suyashkumar/ssl-proxy/securelog"
)

const secret = "ATTACKER-SECRET-abcdef987654"

func closedUpstream(t *testing.T) *url.URL {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse closed upstream url: %v", err)
	}
	return target
}

func newCapturingLogger() (*securelog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return securelog.NewLogger(&buf, securelog.DefaultRules()), &buf
}

func attackRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		target+"/v1/resource?token="+secret+"&api_key="+secret+"&ok=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Proxy-Authorization", "Basic "+secret)
	req.Header.Set("Cookie", "session="+secret)
	req.Header.Set("X-Api-Key", secret)
	req.Header.Set("Accept", "application/json")
	return req
}

// TestProtectedProxy_Attack_NoSecretInAnyLogStage drives the full proxy
// pipeline (middleware, director trace, access log, audit) against a healthy
// upstream and proves the attacker secret cannot be recovered by splicing any
// combination of log outputs.
func TestProtectedProxy_Attack_NoSecretInAnyLogStage(t *testing.T) {
	var upstreamSawSecret bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The proxy must still deliver legitimate auth material to the
		// upstream; only logging is redacted.
		if r.Header.Get("Authorization") == "Bearer "+secret {
			upstreamSawSecret = true
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("X-Forwarded-Proto: got %q, want https", got)
		}
		if got := r.Header.Get("X-Forwarded-Port"); got != "443" {
			t.Errorf("X-Forwarded-Port: got %q, want 443", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	logger, logBuf := newCapturingLogger()
	handler := logger.Middleware(BuildWithOptions(target, WithLogger(logger)))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, attackRequest(t, ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if !upstreamSawSecret {
		t.Fatal("upstream did not receive the original Authorization header")
	}
	logger.Writer().Flush()
	out := logBuf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked across spliced log stages:\n%s", out)
	}
	for _, want := range []string{
		`"kind":"access"`, `"kind":"trace"`, `"kind":"audit"`,
		`sensitive_header_redacted`, `sensitive_query_param_redacted`,
		`"status":200`, `ok=1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing attributable evidence %q in logs:\n%s", want, out)
		}
	}
}

// TestProtectedProxy_Attack_UpstreamFailureRedacted points the proxy at a
// closed upstream and verifies the error response stays byte-compatible with
// the historical httputil behavior while the secret embedded in the request
// never appears in any error/trace/audit output.
func TestProtectedProxy_Attack_UpstreamFailureRedacted(t *testing.T) {
	dead := closedUpstream(t)
	logger, logBuf := newCapturingLogger()
	proxy := BuildWithOptions(dead, WithLogger(logger))

	req := attackRequest(t, "http://proxy.example.test")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	logger.Writer().Flush()

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502", rec.Code)
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("compat: expected empty 502 body, got %q", body)
	}
	out := logBuf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked through upstream error logs:\n%s", out)
	}
	if !strings.Contains(out, `"kind":"proxy_error"`) {
		t.Fatalf("expected structured proxy_error event:\n%s", out)
	}
	if !strings.Contains(out, `"reason":"upstream_unreachable"`) {
		t.Fatalf("expected locatable error category:\n%s", out)
	}
}

// TestProtectedProxy_Attack_StdLoggerScrubbed forces a raw standard-library
// log line (the path used by http.Server.ErrorLog for TLS handshake errors and
// by httputil internals) containing the secret, and verifies it is scrubbed.
func TestProtectedProxy_Attack_StdLoggerScrubbed(t *testing.T) {
	logger, logBuf := newCapturingLogger()
	std := logger.Std()
	std.Printf("http: TLS handshake error from 203.0.113.7: tls: bad certificate token=%s", secret)
	logger.Writer().Flush()
	if strings.Contains(logBuf.String(), secret) {
		t.Fatalf("secret leaked through std logger: %q", logBuf.String())
	}

	// Chunked emulation of a secret split across two log writes.
	logBuf.Reset()
	w := logger.Writer()
	_, _ = w.Write([]byte("partial token=" + secret[:6]))
	_, _ = w.Write([]byte(secret[6:] + " end\n"))
	_ = w.Flush()
	if strings.Contains(logBuf.String(), secret) {
		t.Fatalf("secret reassembled across split writes: %q", logBuf.String())
	}
}

// TestProtectedProxy_Compat_DefaultErrorHandlerParity proves the custom error
// handler preserves the exact user-visible behavior of httputil's default.
func TestProtectedProxy_Compat_DefaultErrorHandlerParity(t *testing.T) {
	dead := closedUpstream(t)
	logger, _ := newCapturingLogger()

	customRec := httptest.NewRecorder()
	BuildWithOptions(dead, WithLogger(logger)).
		ServeHTTP(customRec, httptest.NewRequest(http.MethodGet, "/", nil))

	defaultProxy := httputil.NewSingleHostReverseProxy(dead)
	defaultRec := httptest.NewRecorder()
	defaultProxy.ServeHTTP(defaultRec, httptest.NewRequest(http.MethodGet, "/", nil))

	if customRec.Code != defaultRec.Code {
		t.Fatalf("status: custom=%d default=%d", customRec.Code, defaultRec.Code)
	}
	if customRec.Body.String() != defaultRec.Body.String() {
		t.Fatalf("body: custom=%q default=%q", customRec.Body.String(), defaultRec.Body.String())
	}
	if customRec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", customRec.Code)
	}
}

// TestProtectedProxy_Compat_BuildSignatureAndHeaders verifies the original
// Build API, director semantics and proxy headers all remain intact.
func TestProtectedProxy_Compat_BuildSignatureAndHeaders(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:8080/base")
	proxy := Build(target)
	if proxy == nil {
		t.Fatal("Build returned nil")
	}
	req := httptest.NewRequest(http.MethodGet, "/item?x=1", nil)
	proxy.Director(req)

	if req.URL.Scheme != "http" || req.URL.Host != "127.0.0.1:8080" {
		t.Fatalf("director target wrong: %s", req.URL.String())
	}
	if req.URL.Path != "/base/item" {
		t.Fatalf("director path wrong: %q", req.URL.Path)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("X-Forwarded-Proto: got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Port"); got != "443" {
		t.Fatalf("X-Forwarded-Port: got %q", got)
	}
}

// TestProtectedProxy_Compat_LegitimateTLSClient is an end-to-end check that a
// legitimate HTTPS client still completes a proxied request with its
// Authorization header delivered upstream and normal response content
// returned, while logs stay redacted.
func TestProtectedProxy_Compat_LegitimateTLSClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer legit-token" {
			t.Errorf("upstream Authorization: got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)

	logger, logBuf := newCapturingLogger()
	handler := NewHandler(target, WithLogger(logger))

	front := httptest.NewUnstartedServer(handler)
	front.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	front.StartTLS()
	defer front.Close()

	pool := x509.NewCertPool()
	pool.AddCert(front.Certificate())
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, MinVersion: tls.VersionTLS12,
		}},
	}

	req, err := http.NewRequest(http.MethodGet, front.URL+"/health?format=json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer legit-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("legitimate TLS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, body)
	}
	logger.Writer().Flush()
	if strings.Contains(logBuf.String(), "legit-token") {
		t.Fatalf("legitimate credential leaked into logs:\n%s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), `"status":200`) {
		t.Fatalf("missing success access event:\n%s", logBuf.String())
	}
}

// TestProtectedProxy_Attack_TLSErrorCategory verifies TLS-class failures are
// classified and redacted while remaining diagnosable.
func TestProtectedProxy_Attack_TLSErrorCategory(t *testing.T) {
	logger, logBuf := newCapturingLogger()
	req := attackRequest(t, "https://proxy.test")
	logger.TLSError(req, &url.Error{
		Op:  "Get",
		URL: req.URL.String(),
		Err: errors.New("remote error: tls: handshake failure token=" + secret),
	})
	logger.Writer().Flush()
	out := logBuf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked in TLS error event: %s", out)
	}
	if !strings.Contains(out, `"reason":"tls_failure"`) {
		t.Fatalf("missing TLS classification: %s", out)
	}
}
