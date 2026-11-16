package reverseproxy

import (
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// viaPseudonym is the token ssl-proxy appends to the Via header chain. It
// identifies this proxy alone and is generated here rather than trusting any
// Via value supplied by the client.
const viaPseudonym = "ssl-proxy"

// hopByHopHeaders are the connection-scoped header fields defined by
// RFC 9110 section 7.6.1 (and the obsoleted RFC 2616 section 13.5.1). They
// describe a single transport hop and must never be forwarded as-is, since
// replaying them against the upstream connection can desynchronize framing
// and connection state.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders strips every header listed in the Connection header
// along with the well-known hop-by-hop header fields, matching the cleanup
// httputil.ReverseProxy applies to both proxied requests and responses.
func removeHopByHopHeaders(header http.Header) {
	for _, field := range header["Connection"] {
		for _, part := range strings.Split(field, ",") {
			if name := textproto.TrimString(part); name != "" {
				header.Del(name)
			}
		}
	}
	for _, field := range hopByHopHeaders {
		header.Del(field)
	}
}

// normalizeRequestHeaders collapses any duplicated framing headers into a
// single canonical value after validateRequestFraming has proven the
// duplicates are not conflicting, and removes all hop-by-hop headers. The
// parsed request fields (ContentLength, TransferEncoding) stay authoritative
// for the wire framing, so legitimate fixed-length and chunked requests
// stream unchanged.
func normalizeRequestHeaders(req *http.Request) {
	if values, ok := req.Header["Content-Length"]; ok && len(values) > 1 {
		req.Header.Set("Content-Length", textproto.TrimString(values[0]))
	}
	removeHopByHopHeaders(req.Header)
}

// appendVia adds this proxy's own, independently generated Via entry to any
// existing chain. The client-supplied Via values are preserved, while the
// new entry is always derived from the request protocol and viaPseudonym.
func appendVia(header http.Header, req *http.Request) {
	received := header.Values("Via")
	entry := viaEntry(req)
	if len(received) == 0 {
		header.Set("Via", entry)
		return
	}
	header.Set("Via", strings.Join(append(received, entry), ", "))
}

// viaEntry renders the RFC 9110 Via received-protocol/pseudonym pair, for
// example "1.1 ssl-proxy" or "2.0 ssl-proxy".
func viaEntry(req *http.Request) string {
	major, minor := req.ProtoMajor, req.ProtoMinor
	if major == 0 && minor == 0 {
		major, minor = 1, 1
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor) + " " + viaPseudonym
}
