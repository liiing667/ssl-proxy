package clientidentity

import (
	"log"
	"net/http"
	"time"
)

// statusRecorder captures the response status and body size so connection
// lifecycle logging can be attributed to the resolved client identity.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

// LogMiddleware emits one lifecycle log line per request. Every field
// describing the client (resolved identity, direct peer, trusted chain,
// rejected header evidence) comes from the single Identity resolved by
// Middleware, so logs can never attribute a request to an identity different
// from the one enforced upstream.
func LogMiddleware(logger *log.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = log.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}

		next.ServeHTTP(recorder, req)

		identity, _ := FromRequest(req)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		logger.Printf(
			"client_identity=%q direct_addr=%q tls=%t trusted_chain=%t method=%s host=%s uri=%q status=%d bytes=%d duration=%s rejected=%q",
			clientLabel(identity),
			directLabel(identity),
			tlsUsed(identity),
			identity != nil && identity.TrustedChain,
			req.Method,
			req.Host,
			req.RequestURI,
			status,
			recorder.bytes,
			time.Since(start),
			rejectedLabel(identity),
		)
	})
}

func clientLabel(identity *Identity) string {
	if identity == nil || identity.ClientIP == nil {
		return "unknown"
	}
	return identity.ClientIP.String()
}

func directLabel(identity *Identity) string {
	if identity == nil || identity.DirectAddr == "" {
		return "unknown"
	}
	return identity.DirectAddr
}

func tlsUsed(identity *Identity) bool {
	return identity != nil && identity.TLS != nil
}

func rejectedLabel(identity *Identity) string {
	if identity == nil || len(identity.Errs) == 0 {
		return ""
	}
	return joinErrors(identity.Errs)
}

func joinErrors(errs []error) string {
	out := ""
	for i, err := range errs {
		if i > 0 {
			out += "; "
		}
		out += err.Error()
	}
	return out
}
