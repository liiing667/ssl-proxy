package reverseproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestRemoveHopByHopHeaders(t *testing.T) {
	header := http.Header{}
	for _, name := range hopByHopHeaders {
		header.Set(name, "present")
	}
	header.Set("Connection", "keep-alive, X-Connection-Scoped")
	header.Set("X-Connection-Scoped", "present")
	header.Set("X-End-To-End", "kept")

	removeHopByHopHeaders(header)

	for _, name := range hopByHopHeaders {
		if got := header.Get(name); got != "" {
			t.Errorf("hop-by-hop header %q: got %q, want removed", name, got)
		}
	}
	if got := header.Get("X-Connection-Scoped"); got != "" {
		t.Errorf("Connection-listed header: got %q, want removed", got)
	}
	if got := header.Get("X-End-To-End"); got != "kept" {
		t.Errorf("end-to-end header: got %q, want %q", got, "kept")
	}
}

func TestNormalizeRequestHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Add("Content-Length", "5")
	req.Header.Add("Content-Length", "5")
	req.Header.Set("Connection", "close, X-Hop")
	req.Header.Set("X-Hop", "v")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("X-Keep", "yes")

	normalizeRequestHeaders(req)

	if got, want := req.Header.Values("Content-Length"), []string{"5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Content-Length: got %v, want %v", got, want)
	}
	if got := req.Header.Get("Transfer-Encoding"); got != "" {
		t.Errorf("Transfer-Encoding: got %q, want removed", got)
	}
	if got := req.Header.Get("Connection"); got != "" {
		t.Errorf("Connection: got %q, want removed", got)
	}
	if got := req.Header.Get("Keep-Alive"); got != "" {
		t.Errorf("Keep-Alive: got %q, want removed", got)
	}
	if got := req.Header.Get("X-Hop"); got != "" {
		t.Errorf("Connection-listed X-Hop: got %q, want removed", got)
	}
	if got := req.Header.Get("X-Keep"); got != "yes" {
		t.Errorf("X-Keep: got %q, want %q", got, "yes")
	}
}

func TestAppendVia(t *testing.T) {
	t.Run("fresh via", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.ProtoMajor, req.ProtoMinor = 1, 1
		header := http.Header{}

		appendVia(header, req)

		if got, want := header.Get("Via"), "1.1 ssl-proxy"; got != want {
			t.Errorf("Via: got %q, want %q", got, want)
		}
	})

	t.Run("appends to existing chain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.ProtoMajor, req.ProtoMinor = 2, 0
		header := http.Header{}
		header.Set("Via", "1.1 edge")

		appendVia(header, req)

		if got, want := header.Get("Via"), "1.1 edge, 2.0 ssl-proxy"; got != want {
			t.Errorf("Via: got %q, want %q", got, want)
		}
	})

	t.Run("client via cannot spoof proxy token position", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		header := http.Header{}
		header.Set("Via", "1.1 ssl-proxy")

		appendVia(header, req)

		if got, want := header.Get("Via"), "1.1 ssl-proxy, 1.1 ssl-proxy"; got != want {
			t.Errorf("Via: got %q, want %q", got, want)
		}
	})
}

func TestDirectorNormalizesHeadersAndHost(t *testing.T) {
	target, err := url.Parse("http://upstream.example:8080/base")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	director := newDirector(target, nil)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Host = "client.example"
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("X-End-To-End", "kept")
	req.Header.Add("Content-Length", "5")
	req.Header.Add("Content-Length", "5")

	director(req)

	if got, want := req.Host, "upstream.example:8080"; got != want {
		t.Errorf("Host: got %q, want %q", got, want)
	}
	if got, want := req.URL.Host, "upstream.example:8080"; got != want {
		t.Errorf("URL.Host: got %q, want %q", got, want)
	}
	if got, want := req.URL.Path, "/base/test"; got != want {
		t.Errorf("URL.Path: got %q, want %q", got, want)
	}
	if got := req.Header.Get("Connection"); got != "" {
		t.Errorf("Connection: got %q, want removed", got)
	}
	if got := req.Header.Get("Keep-Alive"); got != "" {
		t.Errorf("Keep-Alive: got %q, want removed", got)
	}
	if got, want := req.Header.Values("Content-Length"), []string{"5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Content-Length: got %v, want %v", got, want)
	}
	if got := req.Header.Get("X-End-To-End"); got != "kept" {
		t.Errorf("X-End-To-End: got %q, want kept", got)
	}
	if got, want := req.Header.Get("Via"), "1.1 ssl-proxy"; got != want {
		t.Errorf("Via: got %q, want %q", got, want)
	}
}
