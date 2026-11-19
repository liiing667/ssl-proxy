package clientidentity

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Logs must attribute the request to the same identity the proxy enforces
// upstream: the real direct peer, not a forged X-Forwarded-For value.
func TestLogMiddleware_AttributesResolvedIdentity(t *testing.T) {
	resolver := NewResolver(nil)
	var buffer bytes.Buffer
	logger := log.New(&buffer, "", 0)
	handler := resolver.Middleware(LogMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))

	req := newRequest("198.51.100.66:443", "10.0.0.7")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	line := buffer.String()
	for _, want := range []string{
		`client_identity="198.51.100.66"`,
		`direct_addr="198.51.100.66:443"`,
		"trusted_chain=false",
		"status=418",
		ErrUntrustedForwarded.Error(),
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "10.0.0.7") {
		t.Fatalf("forged XFF value must never appear as log identity: %q", line)
	}
}

func TestLogMiddleware_TrustedChainAttribution(t *testing.T) {
	resolver := NewResolver(mustNetworks(t, "10.0.0.0/8"))
	var buffer bytes.Buffer
	logger := log.New(&buffer, "", 0)
	handler := resolver.Middleware(LogMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})))

	handler.ServeHTTP(httptest.NewRecorder(), newRequest("10.0.0.2:443", "203.0.113.50"))

	line := buffer.String()
	for _, want := range []string{
		`client_identity="203.0.113.50"`,
		`direct_addr="10.0.0.2:443"`,
		"trusted_chain=true",
		"status=200",
		"bytes=2",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line %q missing %q", line, want)
		}
	}
}

func TestLogMiddleware_DefaultLoggerDoesNotPanic(t *testing.T) {
	resolver := NewResolver(nil)
	handler := resolver.Middleware(LogMiddleware(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	handler.ServeHTTP(httptest.NewRecorder(), newRequest("198.51.100.66:443"))
}
