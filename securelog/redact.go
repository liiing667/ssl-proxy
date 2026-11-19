// Package securelog provides framework-level, fail-closed redaction of
// sensitive material (authentication headers, credential-bearing query
// parameters and embedded secrets) across every logging output of the proxy:
// TLS errors, access logs, traces and audit events.
//
// All log paths in ssl-proxy must route through a Logger (or its underlying
// SafeWriter). Every structured event is built from already-redacted fields,
// and the SafeWriter additionally scrubs the raw serialized bytes, so an
// attacker cannot recover a secret by splicing fragments emitted across
// multiple log stages. If redaction itself ever fails, the output is
// suppressed rather than emitted verbatim (fail-closed).
package securelog

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// RedactionToken replaces every redacted secret. It is constant-width and
// carries no information about the original value.
const RedactionToken = "[REDACTED]"

// DefaultSensitiveHeaders is the framework-level set of request headers that
// may carry attacker credentials. Matching is case-insensitive, as required
// by RFC 7230 for HTTP header names.
var DefaultSensitiveHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"Set-Cookie",
	"X-Api-Key",
	"X-Auth-Token",
	"X-Access-Token",
}

// DefaultSensitiveParams is the framework-level set of URL query parameter
// names that may carry credentials. Matching is case-insensitive.
var DefaultSensitiveParams = []string{
	"access_token",
	"api_key",
	"apikey",
	"auth",
	"credential",
	"password",
	"pwd",
	"refresh_token",
	"secret",
	"session",
	"sessionid",
	"sid",
	"token",
}

// Rules configures which headers and query parameters are treated as
// sensitive. The zero value is not valid; use DefaultRules.
type Rules struct {
	headers map[string]struct{}
	params  map[string]struct{}
	// fuzzy matches embedded credential patterns in free-form strings.
	fuzzy *regexp.Regexp
}

// DefaultRules returns Rules populated with the built-in sensitive header and
// query-parameter sets.
func DefaultRules() Rules {
	return NewRules(DefaultSensitiveHeaders, DefaultSensitiveParams)
}

// NewRules builds Rules from caller-supplied sensitive header and parameter
// names. Names are matched case-insensitively.
func NewRules(headers, params []string) Rules {
	r := Rules{
		headers: make(map[string]struct{}, len(headers)),
		params:  make(map[string]struct{}, len(params)),
	}
	for _, h := range headers {
		r.headers[http.CanonicalHeaderKey(h)] = struct{}{}
	}
	for _, p := range params {
		r.params[strings.ToLower(p)] = struct{}{}
	}
	r.fuzzy = buildFuzzyPattern(params)
	return r
}

// IsSensitiveHeader reports whether name is a credential-bearing header.
func (r Rules) IsSensitiveHeader(name string) bool {
	_, ok := r.headers[http.CanonicalHeaderKey(name)]
	return ok
}

// IsSensitiveParam reports whether name is a credential-bearing query
// parameter.
func (r Rules) IsSensitiveParam(name string) bool {
	_, ok := r.params[strings.ToLower(name)]
	return ok
}

// RedactHeader returns a safe representation of a sensitive header value: the
// scheme (e.g. "Bearer", "Basic") is preserved for diagnostics while the
// actual credential is replaced. Non-sensitive values are returned unchanged.
func (r Rules) RedactHeader(name, value string) string {
	if !r.IsSensitiveHeader(name) || value == "" {
		return value
	}
	if scheme, rest, ok := strings.Cut(value, " "); ok && isAuthScheme(scheme) && rest != "" {
		return scheme + " " + RedactionToken
	}
	return RedactionToken
}

// RedactHeaderMap returns a copy of headers with every sensitive header value
// replaced. The original map is never mutated.
func (r Rules) RedactHeaderMap(headers http.Header) http.Header {
	out := make(http.Header, len(headers))
	for name, values := range headers {
		if r.IsSensitiveHeader(name) {
			redacted := make([]string, len(values))
			for i, v := range values {
				redacted[i] = r.RedactHeader(name, v)
			}
			out[http.CanonicalHeaderKey(name)] = redacted
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		out[http.CanonicalHeaderKey(name)] = copied
	}
	return out
}

// RedactURL returns a copy of u with sensitive query parameters stripped and
// any embedded userinfo removed. Non-sensitive query parameters are retained
// so legitimate request attribution stays intact.
func (r Rules) RedactURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	safe := *u
	if u.User != nil {
		safe.User = url.User(RedactionToken)
	}
	query := u.Query()
	redacted := false
	for name := range query {
		if r.IsSensitiveParam(name) {
			query.Set(name, RedactionToken)
			redacted = true
		}
	}
	if redacted {
		safe.RawQuery = query.Encode()
	}
	return &safe
}

// RedactRawQuery redacts sensitive parameters inside a raw query string
// without fully parsing it, preserving parameter order and any odd encoding.
func (r Rules) RedactRawQuery(rawQuery string) string {
	if rawQuery == "" {
		return rawQuery
	}
	parts := strings.Split(rawQuery, "&")
	for i, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(name)
		if err != nil {
			key = name
		}
		if r.IsSensitiveParam(key) {
			parts[i] = name + "=" + RedactionToken
		}
	}
	return strings.Join(parts, "&")
}

var (
	// Explicit "Header: value" rendering, e.g. in httputil error output.
	headerPattern = regexp.MustCompile(`(?im)^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token|X-Access-Token)\s*:\s*\S+.*$`)
	// RFC 7235 credentials embedded in prose or error messages.
	bearerPattern = regexp.MustCompile(`(?i)\b(Bearer|Basic|Digest|Token|Negotiate)\s+[A-Za-z0-9._~+/=-]+`)
	// Credentials embedded in a URL's userinfo component.
	userInfoPattern = regexp.MustCompile(`(?i)[a-z][a-z0-9+.\-]*://[^/\s@?#]*:[^/\s@?#]*@`)
)

func isAuthScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "basic", "bearer", "digest", "token", "negotiate", "mutual", "oauth":
		return true
	}
	return false
}

// buildFuzzyPattern builds a pattern that catches sensitive query parameters
// inside free-form strings, including percent-encoded forms such as
// "token%3Dsecret" or "api_key=secret".
func buildFuzzyPattern(params []string) *regexp.Regexp {
	alts := make([]string, 0, len(params))
	for _, p := range params {
		alts = append(alts, regexp.QuoteMeta(p))
	}
	// Only explicit value separators ("=", ":" or percent-encoded "%3D")
	// start a credential match, so a URL's "?" boundary cannot cause the
	// remainder of an innocent query string to be swallowed. The value runs
	// until the next delimiter, quote or whitespace.
	return regexp.MustCompile(`(?i)(?:` + strings.Join(alts, "|") +
		`)(?:%3[Dd]|[=:])[^\s"'&;,\]]+`)
}

// ScrubString removes every form of sensitive material from a free-form log
// line. It is the shared, deterministic redaction rule applied by SafeWriter
// to all serialized output, so every logging stage enforces identical rules.
func (r Rules) ScrubString(in string) string {
	out := headerPattern.ReplaceAllString(in, "${1}: "+RedactionToken)
	out = bearerPattern.ReplaceAllString(out, "${1} "+RedactionToken)
	out = userInfoPattern.ReplaceAllString(out, RedactionToken+"@")
	out = r.fuzzy.ReplaceAllString(out, RedactionToken)
	return out
}
