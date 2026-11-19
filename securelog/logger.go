package securelog

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Event kinds. Every output of the proxy (access log, trace, audit, TLS or
// proxy error) is emitted as one of these structured events so all stages
// share one schema and one redaction rule set.
const (
	KindAccess     = "access"
	KindTrace      = "trace"
	KindAudit      = "audit"
	KindTLSFailure = "tls_error"
	KindProxyError = "proxy_error"
)

// Event is the single structured envelope for all proxy log output. Field
// values are populated from pre-redacted inputs, and the serialized form is
// additionally scrubbed by the backing SafeWriter (defense in depth).
type Event struct {
	Kind       string            `json:"kind"`
	Time       string            `json:"time"`
	RequestID  string            `json:"request_id,omitempty"`
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	URL        string            `json:"url,omitempty"`
	Status     int               `json:"status,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Stage      string            `json:"stage,omitempty"`
	Action     string            `json:"action,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Error      string            `json:"error,omitempty"`
	DurationMS int64             `json:"duration_ms,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Attrs      map[string]string `json:"attrs,omitempty"`
}

// Logger emits structured, redacted events through a fail-closed SafeWriter.
type Logger struct {
	writer *SafeWriter
	rules  Rules
	std    *log.Logger
}

// NewLogger builds a Logger whose events are scrubbed under rules and written
// to dest.
func NewLogger(dest io.Writer, rules Rules) *Logger {
	writer := NewSafeWriter(dest, rules)
	return &Logger{
		writer: writer,
		rules:  rules,
		std:    log.New(writer, "", log.LstdFlags),
	}
}

// DefaultLogger returns a Logger writing redacted JSON events to stderr.
func DefaultLogger() *Logger {
	return NewLogger(os.Stderr, DefaultRules())
}

// Rules exposes the configured redaction rules.
func (l *Logger) Rules() Rules { return l.rules }

// Std returns a standard library *log.Logger whose output is scrubbed. It is
// suitable for http.Server.ErrorLog, autocert managers and any code that only
// speaks the standard log interface (including TLS handshake errors).
func (l *Logger) Std() *log.Logger { return l.std }

// Writer exposes the backing fail-closed writer.
func (l *Logger) Writer() *SafeWriter { return l.writer }

// Emit serializes ev as a single JSON line. All free-form fields are scrubbed
// once more at the byte level; if serialization fails the event is replaced
// by a minimal safe marker rather than emitted verbatim.
func (l *Logger) Emit(ev Event) {
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// HTML escaping is disabled so query separators ("&") keep their literal
	// form and the redaction patterns can delimit parameter values correctly.
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(ev)
	if err != nil {
		// Fail closed: a struct we cannot serialize must not reach the log raw.
		l.emitFallback(ev.Kind, "event serialization failed")
		return
	}
	if _, err := l.writer.Write(buf.Bytes()); err != nil {
		l.emitFallback(ev.Kind, "event write failed")
	}
}

func (l *Logger) emitFallback(kind, reason string) {
	fallback, err := json.Marshal(Event{Kind: kind, Time: time.Now().UTC().Format(time.RFC3339Nano), Reason: reason})
	if err != nil {
		// Last-resort constant message; contains no caller-controlled data.
		io.WriteString(l.writer, SuppressedLine)
		return
	}
	fallback = append(fallback, '\n')
	l.writer.Write(fallback)
}

// Access emits an access-log event for a completed request. The URL and
// headers are redacted before serialization.
func (l *Logger) Access(req *http.Request, status int, duration time.Duration) {
	l.Emit(Event{
		Kind:       KindAccess,
		RequestID:  RequestIDFromContext(req.Context()),
		Method:     req.Method,
		URL:        l.safeURL(req.URL),
		Path:       l.rules.ScrubString(req.URL.Path),
		Status:     status,
		RemoteAddr: req.RemoteAddr,
		DurationMS: duration.Milliseconds(),
	})
}

// Trace emits a trace event for a pipeline stage. Any sensitive material in
// detail is removed by the shared scrubber before output.
func (l *Logger) Trace(req *http.Request, stage, detail string) {
	l.Emit(Event{
		Kind:      KindTrace,
		RequestID: RequestIDFromContext(req.Context()),
		Method:    req.Method,
		URL:       l.safeURL(req.URL),
		Stage:     stage,
		Reason:    l.rules.ScrubString(detail),
	})
}

// Audit emits a security audit event. action describes the framework decision
// (for example "sensitive_header_redacted") and attrs carry non-secret
// attribution evidence such as header names or parameter names.
func (l *Logger) Audit(req *http.Request, action, reason string, attrs map[string]string) {
	safeAttrs := make(map[string]string, len(attrs))
	for k, v := range attrs {
		safeAttrs[k] = l.rules.ScrubString(v)
	}
	l.Emit(Event{
		Kind:      KindAudit,
		RequestID: RequestIDFromContext(req.Context()),
		Method:    req.Method,
		URL:       l.safeURL(req.URL),
		Action:    action,
		Reason:    l.rules.ScrubString(reason),
		Attrs:     safeAttrs,
	})
}

// TLSError emits a redacted TLS failure event while preserving the failure
// category and request attribution needed for security diagnostics.
func (l *Logger) TLSError(req *http.Request, err error) {
	ev := Event{
		Kind:   KindTLSFailure,
		Reason: classifyError(err),
		Error:  l.rules.ScrubString(errString(err)),
	}
	if req != nil {
		ev.RequestID = RequestIDFromContext(req.Context())
		ev.Method = req.Method
		ev.URL = l.safeURL(req.URL)
		ev.RemoteAddr = req.RemoteAddr
	}
	l.Emit(ev)
}

// ProxyError emits a redacted upstream/proxy failure event.
func (l *Logger) ProxyError(req *http.Request, stage string, err error) {
	l.Emit(Event{
		Kind:      KindProxyError,
		RequestID: requestIDOrEmpty(req),
		Method:    methodOrEmpty(req),
		URL:       l.safeURLOfRequest(req),
		Stage:     stage,
		Reason:    classifyError(err),
		Error:     l.rules.ScrubString(errString(err)),
	})
}

func (l *Logger) safeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return l.rules.RedactURL(u).String()
}

func (l *Logger) safeURLOfRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	return l.safeURL(req.URL)
}

func requestIDOrEmpty(req *http.Request) string {
	if req == nil {
		return ""
	}
	return RequestIDFromContext(req.Context())
}

func methodOrEmpty(req *http.Request) string {
	if req == nil {
		return ""
	}
	return req.Method
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// classifyError maps an error to a stable, non-secret diagnostic category so
// failures remain locatable without echoing attacker-controlled strings.
func classifyError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := err.Error()
	switch {
	case containsAny(msg, "certificate", "x509", "tls:", "handshake"):
		return "tls_failure"
	case containsAny(msg, "connection refused", "dial"):
		return "upstream_unreachable"
	case containsAny(msg, "timeout", "deadline exceeded"):
		return "timeout"
	case containsAny(msg, "context canceled"):
		return "canceled"
	default:
		return "proxy_error"
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if len(n) > 0 && stringContainsFold(haystack, n) {
			return true
		}
	}
	return false
}

func stringContainsFold(s, substr string) bool {
	return len(s) >= len(substr) && indexFold(s, substr) >= 0
}

func indexFold(s, substr string) int {
	ls, lsub := len(s), len(substr)
	for i := 0; i+lsub <= ls; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// requestIDKey is the context key for per-request correlation IDs.
type requestIDKey struct{}

// NewRequestID returns a 128-bit hex correlation identifier.
func NewRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// rand.Read should not fail; fall back to a time-derived value so the
		// request still gets a non-secret, unique-ish identifier.
		return time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b)
}

// ContextWithRequestID attaches id to ctx.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the correlation ID stored in ctx, if any.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// statusRecorder captures the status code written by downstream handlers.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Middleware wraps handler so every request receives a correlation ID, an
// access-log event and audit events for any redacted headers or query
// parameters. It is the framework entry point that makes protection
// independent of individual call sites.
func (l *Logger) Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := NewRequestID()
		ctx := ContextWithRequestID(r.Context(), requestID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-Id", requestID)

		l.auditSensitiveInput(r)

		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: 0}
		handler.ServeHTTP(recorder, r)
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		l.Access(r, recorder.status, time.Since(start))
	})
}

// auditSensitiveInput emits one audit event per detected sensitive header or
// query parameter, recording only names and counts so the evidence is
// attributable without revealing the secret itself.
func (l *Logger) auditSensitiveInput(r *http.Request) {
	for name, values := range r.Header {
		if l.rules.IsSensitiveHeader(name) && len(values) > 0 {
			l.Audit(r, "sensitive_header_redacted",
				"credential-bearing header removed from structured logs",
				map[string]string{
					"header": http.CanonicalHeaderKey(name),
					"count":  itoa(len(values)),
				})
		}
	}
	for name, values := range r.URL.Query() {
		if l.rules.IsSensitiveParam(name) && len(values) > 0 {
			l.Audit(r, "sensitive_query_param_redacted",
				"credential-bearing query parameter removed from structured logs",
				map[string]string{
					"param": name,
					"count": itoa(len(values)),
				})
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
