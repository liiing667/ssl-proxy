package securelog

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const attackSecret = "super-secret-credential-123456"

func attackRequest(t *testing.T) *http.Request {
	t.Helper()
	req := &http.Request{
		Method:     http.MethodGet,
		RemoteAddr: "203.0.113.7:51000",
		Header: http.Header{
			"Authorization":       {"Bearer " + attackSecret},
			"Proxy-Authorization": {"Basic " + attackSecret},
			"Cookie":              {"session=" + attackSecret},
			"X-Api-Key":           {attackSecret},
			"Accept":              {"application/json"},
		},
	}
	u, err := url.Parse("https://proxy.example.test/path?token=" + attackSecret +
		"&api_key=" + attackSecret + "&safe=keep-me")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	req.URL = u
	req.RequestURI = u.RequestURI()
	return req
}

// TestRedactHeader_AttackSecretsRemoved verifies no credential value survives
// structured header redaction while the auth scheme stays usable for
// diagnostics.
func TestRedactHeader_AttackSecretsRemoved(t *testing.T) {
	rules := DefaultRules()
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"bearer", "Bearer " + attackSecret, "Bearer " + RedactionToken},
		{"basic", "Basic " + attackSecret, "Basic " + RedactionToken},
		{"raw", attackSecret, RedactionToken},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rules.RedactHeader("Authorization", tc.value)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if strings.Contains(got, attackSecret) {
				t.Fatalf("secret leaked through redacted header: %q", got)
			}
		})
	}

	redacted := rules.RedactHeaderMap(attackRequest(t).Header)
	for name, values := range redacted {
		for _, v := range values {
			if strings.Contains(v, attackSecret) {
				t.Fatalf("secret leaked in header %s: %q", name, v)
			}
		}
	}
	if got := redacted.Get("Accept"); got != "application/json" {
		t.Fatalf("non-sensitive header altered: %q", got)
	}
}

// TestRedactURL_AttackParamsRemoved verifies sensitive query parameters are
// stripped while legitimate parameters and paths remain attributable.
func TestRedactURL_AttackParamsRemoved(t *testing.T) {
	rules := DefaultRules()
	safe := rules.RedactURL(attackRequest(t).URL).String()
	if strings.Contains(safe, attackSecret) {
		t.Fatalf("secret leaked through redacted URL: %q", safe)
	}
	if !strings.Contains(safe, "safe=keep-me") {
		t.Fatalf("legitimate query parameter lost: %q", safe)
	}
	if !strings.Contains(safe, "/path") {
		t.Fatalf("path attribution lost: %q", safe)
	}

	raw := rules.RedactRawQuery("token=" + attackSecret + "&page=2")
	if strings.Contains(raw, attackSecret) {
		t.Fatalf("secret leaked through raw query: %q", raw)
	}
	if !strings.Contains(raw, "page=2") {
		t.Fatalf("legitimate raw parameter lost: %q", raw)
	}
}

// TestScrubString_FreeFormEmbeddings covers every free-form rendering an
// attacker might force into TLS/proxy error strings, including
// percent-encoded and multi-line forms.
func TestScrubString_FreeFormEmbeddings(t *testing.T) {
	rules := DefaultRules()
	inputs := []string{
		"Authorization: Bearer " + attackSecret,
		"authorization: " + attackSecret,
		"upstream dial failed token=" + attackSecret + " retrying",
		"redirect token%3D" + attackSecret + " observed",
		"url https://user:" + attackSecret + "@upstream.test/x",
		"header line\nX-Api-Key: " + attackSecret + "\nend",
		"TOKEN:" + attackSecret,
	}
	for _, in := range inputs {
		got := rules.ScrubString(in)
		if strings.Contains(got, attackSecret) {
			t.Fatalf("secret survived ScrubString\ninput: %q\nout:   %q", in, got)
		}
	}
}

// TestSafeWriter_ChunkedSplicing simulates multi-stage log splicing: the
// secret is split across arbitrary write boundaries, including a split
// directly inside the credential. No fragment may be reassembled downstream.
func TestSafeWriter_ChunkedSplicing(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSafeWriter(&buf, DefaultRules())
	line := "tls handshake rejected token=" + attackSecret + "\n"

	// Emit one byte at a time, the worst case for boundary-based bypasses.
	for i := 0; i < len(line); i++ {
		if _, err := writer.Write([]byte{line[i]}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, attackSecret) {
		t.Fatalf("secret reassembled from chunked writes: %q", out)
	}

	// And again with arbitrary mid-secret chunking across separate lines.
	buf.Reset()
	first := "error token=" + attackSecret[:7]
	second := attackSecret[7:] + " done\n"
	writer.Write([]byte(first))
	writer.Write([]byte(second))
	writer.Flush()
	if strings.Contains(buf.String(), attackSecret) {
		t.Fatalf("secret reassembled across two writes: %q", buf.String())
	}
}

// TestSafeWriter_FailClosed forces the redactor to panic and asserts the raw
// payload is replaced by the suppression marker instead of being emitted.
func TestSafeWriter_FailClosed(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSafeWriter(&buf, DefaultRules())
	writer.scrub = func(string) string { panic("redactor unavailable") }
	if _, err := writer.Write([]byte("token=" + attackSecret + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, attackSecret) {
		t.Fatalf("raw secret emitted after redaction failure: %q", out)
	}
	if !strings.Contains(out, "suppressed") {
		t.Fatalf("expected suppression marker, got %q", out)
	}
}

// TestLogger_Events_RedactedAndAttributable verifies the shared structured
// envelope across access, trace, audit and error events: secrets never appear,
// while request attribution (id, method, path, category) is preserved.
func TestLogger_Events_RedactedAndAttributable(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DefaultRules())
	req := attackRequest(t)
	req = req.WithContext(ContextWithRequestID(req.Context(), "req-123"))

	logger.Access(req, http.StatusBadGateway, 0)
	logger.Trace(req, "director", "rewrote token="+attackSecret)
	logger.Audit(req, "sensitive_header_redacted", "token="+attackSecret,
		map[string]string{"header": "Authorization"})
	logger.TLSError(req, &url.Error{Op: "Get", URL: req.URL.String(),
		Err: errors.New("tls: handshake failure token=" + attackSecret)})
	logger.ProxyError(req, "upstream", &url.Error{Op: "Get", URL: req.URL.String(),
		Err: errors.New("connection refused token=" + attackSecret)})
	logger.Writer().Flush()

	out := buf.String()
	if strings.Contains(out, attackSecret) {
		t.Fatalf("secret leaked into structured events:\n%s", out)
	}
	for _, want := range []string{
		`"kind":"access"`, `"kind":"trace"`, `"kind":"audit"`,
		`"kind":"tls_error"`, `"kind":"proxy_error"`,
		`"request_id":"req-123"`, `"reason":"tls_failure"`,
		`"reason":"upstream_unreachable"`, `"/path"`,
		`"action":"sensitive_header_redacted"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected event output to contain %s\n%s", want, out)
		}
	}
}

// TestMiddleware_AuditAndAccess verifies the framework middleware audits each
// sensitive input and emits an access event without any secret leakage.
func TestMiddleware_AuditAndAccess(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, DefaultRules())
	handler := logger.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := newResponseRecorder()
	handler.ServeHTTP(rec, attackRequest(t))
	logger.Writer().Flush()

	out := buf.String()
	if strings.Contains(out, attackSecret) {
		t.Fatalf("secret leaked through middleware logs:\n%s", out)
	}
	for _, want := range []string{
		`sensitive_header_redacted`, `sensitive_query_param_redacted`,
		`"kind":"access"`, `"status":418`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in:\n%s", want, out)
		}
	}
	if rec.header.Get("X-Request-Id") == "" {
		t.Fatal("expected X-Request-Id correlation header on response")
	}
}

type responseRecorder struct {
	header http.Header
	status int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: http.Header{}}
}

func (r *responseRecorder) Header() http.Header { return r.header }
func (r *responseRecorder) WriteHeader(s int)   { r.status = s }
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(b), nil
}
