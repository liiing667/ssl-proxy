package reverseproxy

import (
	"errors"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// errAmbiguousFraming is returned by validateRequestFraming when an inbound
// request carries conflicting or duplicated message framing that could be
// interpreted differently by two HTTP implementations (request smuggling).
var errAmbiguousFraming = errors.New("reverseproxy: ambiguous or invalid request message framing")

// validateRequestFraming enforces a single, unambiguous framing for the
// inbound request before it is normalized and forwarded. Requests that are
// valid per RFC 9112 (a single Content-Length, or a single chunked
// Transfer-Encoding) are accepted unchanged so that legitimate fixed-length
// and streaming requests keep working; ambiguous or otherwise illegal
// framing is rejected so the proxy never has to guess how the next hop will
// parse the message.
func validateRequestFraming(req *http.Request) error {
	rawTE, hasTE := req.Header["Transfer-Encoding"]
	rawCL, hasCL := req.Header["Content-Length"]

	// Prefer the unnormalized framing observed on the wire when the
	// connection was wrapped by NewFramingListener. net/http deletes the
	// Transfer-Encoding (and, for some smuggling patterns, the
	// Content-Length) from the parsed header map, so the raw values are the
	// only place every client-supplied field remains visible.
	if observed := rawFramingFromContext(req); observed != nil {
		return validateRawFraming(observed)
	}

	// RFC 9112 section 6.1: reject multiple Transfer-Encoding header
	// fields outright rather than folding them together. A single field
	// must contain exactly the "chunked" coding; a coding stack such as
	// "chunked, identity" or any other coding cannot be safely re-emitted.
	if hasTE {
		if len(rawTE) > 1 {
			return errAmbiguousFraming
		}
		codings := strings.Split(rawTE[0], ",")
		if len(codings) != 1 || !strings.EqualFold(textproto.TrimString(codings[0]), "chunked") {
			return errAmbiguousFraming
		}
	}

	// RFC 9112 section 6.3: multiple Content-Length header fields are only
	// safe when every value is identical; conflicting lengths (or a
	// non-numeric value) are an error, never a reason to pick one value.
	if hasCL {
		if len(rawCL) > 1 {
			first := textproto.TrimString(rawCL[0])
			for _, value := range rawCL[1:] {
				if textproto.TrimString(value) != first {
					return errAmbiguousFraming
				}
			}
		}
		for _, value := range rawCL {
			if _, err := strconv.ParseInt(textproto.TrimString(value), 10, 64); err != nil {
				return errAmbiguousFraming
			}
		}
	}

	// RFC 9112 section 6.2: a message with both Transfer-Encoding and
	// Content-Length is potentially smuggling. Check both the raw header
	// map and the server-parsed framing, since net/http removes the
	// Transfer-Encoding header from the map after parsing chunked requests.
	if (hasTE || len(req.TransferEncoding) > 0) && hasCL {
		return errAmbiguousFraming
	}

	// The parsed framing must agree with the raw headers: a chunked body
	// has to be backed by a Transfer-Encoding header, and a fixed-length
	// body has to be backed by a Content-Length header. A mismatch means the
	// message was accepted under framing the proxy cannot faithfully
	// reproduce.
	if len(req.TransferEncoding) > 0 {
		if len(req.TransferEncoding) != 1 || req.TransferEncoding[0] != "chunked" {
			return errAmbiguousFraming
		}
	} else if req.ContentLength > 0 && !hasCL {
		return errAmbiguousFraming
	}

	return nil
}

// validateRawFraming applies the same single-framing policy to the
// wire-level header fields.
func validateRawFraming(observed *rawFraming) error {
	if len(observed.transferEncoding) > 0 {
		if len(observed.transferEncoding) > 1 {
			return errAmbiguousFraming
		}
		codings := strings.Split(observed.transferEncoding[0], ",")
		if len(codings) != 1 || !strings.EqualFold(textproto.TrimString(codings[0]), "chunked") {
			return errAmbiguousFraming
		}
	}

	if len(observed.contentLength) > 0 {
		first := textproto.TrimString(observed.contentLength[0])
		for _, value := range observed.contentLength {
			value = textproto.TrimString(value)
			if value != first {
				return errAmbiguousFraming
			}
			if _, err := strconv.ParseInt(value, 10, 64); err != nil {
				return errAmbiguousFraming
			}
		}
	}

	// RFC 9112 section 6.2: never forward a message that declares both
	// framing mechanisms.
	if len(observed.transferEncoding) > 0 && len(observed.contentLength) > 0 {
		return errAmbiguousFraming
	}

	return nil
}
