package reverseproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startProxy wires the framing-validating proxy in front of a backend and
// returns the proxy base URL and the backend host:port.
func startProxy(t *testing.T, backendHandler http.HandlerFunc) (proxyURL, backendAddr string) {
	t.Helper()
	backend := httptest.NewServer(backendHandler)
	t.Cleanup(backend.Close)

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("url.Parse backend: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := NewServer("", target)
	go func() {
		if err := Serve(server, listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("proxy serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		server.Close()
	})
	return "http://" + listener.Addr().String(), strings.TrimPrefix(backend.URL, "http://")
}

// rawRoundTrip sends a hand-crafted HTTP/1.1 request to the proxy and returns
// the raw response so framing behavior can be asserted on the wire.
func rawRoundTrip(t *testing.T, proxyURL, raw string) string {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(response)
}

func statusLine(response string) string {
	if line, _, ok := strings.Cut(response, "\r\n"); ok {
		return line
	}
	return response
}

func TestHandlerStripsHopByHopHeadersAndNormalizesHost(t *testing.T) {
	var seen http.Header
	var seenHost string
	proxyURL, backendAddr := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seenHost = r.Host
		io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Backend", "kept")
		w.WriteHeader(http.StatusOK)
	})

	raw := "POST /path HTTP/1.1\r\n" +
		"Host: client.example\r\n" +
		"Connection: close, keep-alive, X-Conn-Scoped\r\n" +
		"Content-Length: 5\r\n" +
		"Content-Length: 5\r\n" +
		"X-Conn-Scoped: leaked\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"Proxy-Authorization: Basic abc\r\n" +
		"X-End-To-End: yes\r\n" +
		"\r\nhello"
	response := rawRoundTrip(t, proxyURL, raw)

	if !strings.HasPrefix(response, "HTTP/1.1 200") {
		t.Fatalf("status: got %q, want 200", statusLine(response))
	}
	if got := seenHost; got != backendAddr {
		t.Errorf("backend Host: got %q, want %q", got, backendAddr)
	}
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authorization", "Transfer-Encoding", "Upgrade"} {
		if got := seen.Get(name); got != "" {
			t.Errorf("hop-by-hop %q reached backend: %q", name, got)
		}
	}
	if got := seen.Get("X-Conn-Scoped"); got != "" {
		t.Errorf("Connection-listed header reached backend: %q", got)
	}
	if got, want := seen.Values("Content-Length"), []string{"5"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("backend Content-Length: got %v, want %v", got, want)
	}
	if got := seen.Get("X-End-To-End"); got != "yes" {
		t.Errorf("X-End-To-End: got %q, want yes", got)
	}
	if got := seen.Get("Via"); !strings.HasSuffix(got, " ssl-proxy") {
		t.Errorf("Via: got %q, want an ssl-proxy entry", got)
	}
	if got := seen.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto: got %q, want https", got)
	}
	if !strings.Contains(response, "X-Backend: kept") {
		t.Errorf("backend response header not forwarded to client:\n%s", response)
	}
}

func TestHandlerRejectsIllegalFraming(t *testing.T) {
	backendCalled := false
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
	})

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "conflicting duplicate content length",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
		},
		{
			name: "content length and chunked together",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		},
		{
			name: "stacked transfer encoding",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := rawRoundTrip(t, proxyURL, tc.raw)
			first := statusLine(response)
			if !strings.HasPrefix(response, "HTTP/1.1 400") && !strings.HasPrefix(response, "HTTP/1.1 501") {
				t.Fatalf("status: got %q, want 400 Bad Request or 501 Not Implemented", first)
			}
		})
	}
	if backendCalled {
		t.Fatal("backend must never receive an illegally framed request")
	}
}

func TestHandlerAllowsLegitimateChunkedStreaming(t *testing.T) {
	bodyChunks := make(chan string, 1)
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.TransferEncoding; len(got) != 1 || got[0] != "chunked" {
			t.Errorf("backend TransferEncoding: got %v, want [chunked]", got)
		}
		if got := r.Header.Get("Content-Length"); got != "" {
			t.Errorf("backend Content-Length: got %q, want absent for chunked", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		bodyChunks <- string(body)
		w.WriteHeader(http.StatusOK)
	})

	raw := "POST /stream HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Connection: close\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n"
	response := rawRoundTrip(t, proxyURL, raw)

	if !strings.HasPrefix(response, "HTTP/1.1 200") {
		t.Fatalf("status: got %q, want 200", statusLine(response))
	}
	select {
	case got := <-bodyChunks:
		if want := "hello!"; got != want {
			t.Errorf("decoded chunked body: got %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for streamed body")
	}
}

func TestHandlerEmitsSingleCanonicalFramingToBackend(t *testing.T) {
	var rawRequest string
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		dump, err := httputil.DumpRequest(r, false)
		if err != nil {
			t.Fatalf("DumpRequest: %v", err)
		}
		rawRequest = string(dump)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})

	t.Run("duplicate identical content length becomes a single header", func(t *testing.T) {
		raw := "POST / HTTP/1.1\r\n" +
			"Host: x\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 5\r\n" +
			"Content-Length: 5\r\n" +
			"\r\nhello"
		response := rawRoundTrip(t, proxyURL, raw)
		if !strings.HasPrefix(response, "HTTP/1.1 200") {
			t.Fatalf("status: got %q, want 200", statusLine(response))
		}
		if count := strings.Count(rawRequest, "Content-Length:"); count != 1 {
			t.Errorf("backend Content-Length header count: got %d, want 1\n%s", count, rawRequest)
		}
		if strings.Contains(rawRequest, "Transfer-Encoding:") {
			t.Errorf("fixed-length request must not send Transfer-Encoding:\n%s", rawRequest)
		}
	})

	t.Run("chunked request keeps exactly one transfer encoding and no content length", func(t *testing.T) {
		raw := "POST / HTTP/1.1\r\n" +
			"Host: x\r\n" +
			"Connection: close\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n5\r\nhello\r\n0\r\n\r\n"
		response := rawRoundTrip(t, proxyURL, raw)
		if !strings.HasPrefix(response, "HTTP/1.1 200") {
			t.Fatalf("status: got %q, want 200", statusLine(response))
		}
		if count := strings.Count(rawRequest, "Transfer-Encoding:"); count != 1 {
			t.Errorf("backend Transfer-Encoding header count: got %d, want 1\n%s", count, rawRequest)
		}
		if strings.Contains(rawRequest, "Content-Length:") {
			t.Errorf("chunked request must not send Content-Length:\n%s", rawRequest)
		}
	})
}

func TestHandlerStripsHopByHopResponseHeaders(t *testing.T) {
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Upgrade", "h2c")
		w.Header().Set("X-End-To-End", "kept")
		w.WriteHeader(http.StatusOK)
	})

	response := rawRoundTrip(t, proxyURL, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	for _, banned := range []string{"Keep-Alive:", "Upgrade:"} {
		if strings.Contains(response, banned) {
			t.Errorf("response contains hop-by-hop header %q:\n%s", banned, response)
		}
	}
	if !strings.Contains(response, "X-End-To-End: kept") {
		t.Errorf("end-to-end response header missing:\n%s", response)
	}
}

func TestHandlerPreservesFixedResponseFraming(t *testing.T) {
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		// A fixed-length response: net/http emits one Content-Length and no
		// Transfer-Encoding, which must survive the proxy unchanged.
		body := []byte("fixed-body")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	response := rawRoundTrip(t, proxyURL, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	if !strings.HasPrefix(response, "HTTP/1.1 200") {
		t.Fatalf("status: got %q, want 200", statusLine(response))
	}
	if count := strings.Count(response, "Content-Length:"); count != 1 {
		t.Errorf("response Content-Length count: got %d, want 1\n%s", count, response)
	}
	if strings.Contains(response, "Transfer-Encoding:") {
		t.Errorf("fixed-length response must not use chunked encoding:\n%s", response)
	}
	if !strings.Contains(response, "\r\nfixed-body") {
		t.Errorf("response body missing or altered:\n%s", response)
	}
}

func TestHandlerStreamsUnboundedResponses(t *testing.T) {
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		// Unknown length forces chunked streaming; the proxy must flush data
		// without buffering the whole body.
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support flushing")
		}
		for _, event := range []string{"one", "two", "three"} {
			fmt.Fprintf(w, "data: %s\n\n", event)
			flusher.Flush()
		}
	})

	response := rawRoundTrip(t, proxyURL, "GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	if !strings.HasPrefix(response, "HTTP/1.1 200") {
		t.Fatalf("status: got %q, want 200", statusLine(response))
	}
	for _, event := range []string{"data: one", "data: two", "data: three"} {
		if !strings.Contains(response, event) {
			t.Errorf("streaming event %q missing from response:\n%s", event, response)
		}
	}
	if !strings.Contains(response, "Content-Type: text/event-stream") {
		t.Errorf("SSE content type missing:\n%s", response)
	}
}

func TestHandlerFramingValidationAcrossKeepAlive(t *testing.T) {
	var requests int
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	// First request is a legal fixed-length message.
	if _, err := io.WriteString(conn,
		"POST /first HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"); err != nil {
		t.Fatalf("write first request: %v", err)
	}
	reader := bufio.NewReader(conn)
	first, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first response: got %d, want 200", first.StatusCode)
	}

	// The second pipelined request on the same connection carries a
	// smuggling pattern that must be rejected even though the connection was
	// already established.
	if _, err := io.WriteString(conn,
		"POST /second HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	second, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("second response: got %d, want 400", second.StatusCode)
	}
	if requests != 1 {
		t.Fatalf("backend requests: got %d, want exactly 1 (smuggled request must not arrive)", requests)
	}
}
