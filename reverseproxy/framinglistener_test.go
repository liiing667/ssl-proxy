package reverseproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseRawFraming(t *testing.T) {
	block := []byte("POST / HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"content-length: 5\r\n" +
		"Content-Length: 5\r\n" +
		"TRANSFER-ENCODING: chunked\r\n" +
		"X-Other: ignored\r\n" +
		"\r\n")

	framing := parseRawFraming(block)

	if got, want := framing.contentLength, []string{"5", "5"}; len(got) != len(want) {
		t.Fatalf("contentLength: got %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("contentLength[%d]: got %q, want %q", i, got[i], want[i])
			}
		}
	}
	if got, want := framing.transferEncoding, []string{"chunked"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("transferEncoding: got %v, want %v", got, want)
	}
}

func TestHeaderBlockEnd(t *testing.T) {
	tests := []struct {
		name string
		buf  string
		want int
	}{
		{"terminator present", "a\r\nb\r\n\r\nrest", 8},
		{"terminator absent", "a\r\nb\r\n", -1},
		{"empty", "", -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := headerBlockEnd([]byte(tc.buf)); got != tc.want {
				t.Errorf("headerBlockEnd: got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFramingConnHandlesLargeHeaderBlock(t *testing.T) {
	var seenHeader string
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get("X-Large")
		w.WriteHeader(http.StatusOK)
	})

	// A header value well beyond the initial 64KiB buffer forces the framing
	// connection to grow its peek window.
	largeValue := strings.Repeat("z", 2*initialFramingBufferSize)
	raw := "GET / HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Connection: close\r\n" +
		"X-Large: " + largeValue + "\r\n" +
		"\r\n"

	response := rawRoundTrip(t, proxyURL, raw)
	if !strings.HasPrefix(response, "HTTP/1.1 200") {
		t.Fatalf("status: got %q, want 200", statusLine(response))
	}
	if seenHeader != largeValue {
		t.Errorf("large header not forwarded intact: got length %d, want %d", len(seenHeader), len(largeValue))
	}
}

func TestFramingConnRejectsWithoutConsumingBody(t *testing.T) {
	// The rejected smuggling request must not stall even though the client
	// keeps the connection open with a body pending.
	backendCalled := false
	proxyURL, _ := startProxy(t, func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
	})

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := io.WriteString(conn,
		"POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read response: %v", err)
	}
	response := string(buf[:n])
	if !strings.HasPrefix(response, "HTTP/1.1 400") {
		t.Fatalf("status: got %q, want 400", statusLine(response))
	}
	if backendCalled {
		t.Fatal("backend must not be reached for an ambiguously framed request")
	}
}
