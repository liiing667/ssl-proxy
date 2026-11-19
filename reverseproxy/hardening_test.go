package reverseproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// TestNewTransport_BoundedTimeouts verifies the upstream Transport carries
// explicit boundaries so canceled, timed-out, or half-closed upstream
// connections cannot outlive their request or be pooled indefinitely.
func TestNewTransport_BoundedTimeouts(t *testing.T) {
	tr := NewTransport()

	if tr.IdleConnTimeout != idleConnTimeout {
		t.Errorf("IdleConnTimeout: got %v, want %v", tr.IdleConnTimeout, idleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != tlsHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout: got %v, want %v", tr.TLSHandshakeTimeout, tlsHandshakeTimeout)
	}
	if tr.ExpectContinueTimeout != expectContinueTimeout {
		t.Errorf("ExpectContinueTimeout: got %v, want %v", tr.ExpectContinueTimeout, expectContinueTimeout)
	}
	if tr.MaxIdleConnsPerHost != maxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost: got %v, want %v", tr.MaxIdleConnsPerHost, maxIdleConnsPerHost)
	}
	if tr.MaxIdleConns < tr.MaxIdleConnsPerHost {
		t.Errorf("MaxIdleConns: got %v, want >= %v", tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil, want a bounded net.Dialer")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2: got false, want true")
	}
}

// TestIsClientClosed verifies cancellation reasons are classified from both
// the request context state and the returned error, so connection state and
// cancellation reason always agree.
func TestIsClientClosed(t *testing.T) {
	upstreamErr := errors.New("connection refused")

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer deadlineCancel()
	time.Sleep(2 * time.Millisecond)

	canceledReq := (&http.Request{}).WithContext(canceledCtx)
	deadlineReq := (&http.Request{}).WithContext(deadlineCtx)
	backgroundReq := (&http.Request{}).WithContext(context.Background())

	tests := []struct {
		name string
		req  *http.Request
		err  error
		want bool
	}{
		{"context canceled", canceledReq, upstreamErr, true},
		{"context deadline", deadlineReq, upstreamErr, true},
		{"upstream wrapped canceled error", backgroundReq, fmt.Errorf("roundtrip: %w", context.Canceled), false},
		{"upstream dial timeout wrapped deadline", backgroundReq, fmt.Errorf("dial tcp: %w", context.DeadlineExceeded), false},
		{"upstream failure", backgroundReq, upstreamErr, false},
		{"nil request", nil, upstreamErr, false},
		{"nil request upstream error", nil, upstreamErr, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isClientClosed(tt.req, tt.err); got != tt.want {
				t.Errorf("isClientClosed: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProxyErrorHandler_ClientClosed verifies downstream cancellation yields a
// 499 without masquerading as an upstream 502.
func TestProxyErrorHandler_ClientClosed(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	proxyErrorHandler(rec, req, context.Canceled)

	if got := rec.Code; got != clientClosedStatus {
		t.Errorf("status: got %v, want %v", got, clientClosedStatus)
	}
}

// TestProxyErrorHandler_UpstreamFailure preserves the historical 502 Bad
// Gateway output for genuine upstream errors.
func TestProxyErrorHandler_UpstreamFailure(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	proxyErrorHandler(rec, req, errors.New("dial tcp: connection refused"))

	if got := rec.Code; got != http.StatusBadGateway {
		t.Errorf("status: got %v, want %v", got, http.StatusBadGateway)
	}
}

// TestBuild_ProxyCancellationPropagates verifies that canceling the downstream
// request cancels the in-flight upstream request instead of letting the old
// connection keep sending.
func TestBuild_ProxyCancellationPropagates(t *testing.T) {
	upstreamStarted := make(chan struct{})
	upstreamReleased := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(upstreamStarted)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			t.Error("upstream request was not canceled")
		}
		close(upstreamReleased)
	}))
	defer upstream.Close()

	proxy := Build(mustParseURL(t, upstream.URL))
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyServer.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	roundTripErr := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		roundTripErr <- err
	}()

	<-upstreamStarted
	cancel()

	select {
	case <-upstreamReleased:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request outlived downstream cancellation")
	}

	select {
	case err := <-roundTripErr:
		if err == nil {
			t.Error("client Do: got nil error, want cancellation error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client Do did not return after cancellation")
	}
}

// TestBuild_RequestStateIsolation verifies that concurrent proxied requests
// never share or reuse per-request state: each request reaches the upstream
// with its own path, query, and forwarded headers.
func TestBuild_RequestStateIsolation(t *testing.T) {
	const requestCount = 25
	var mu sync.Mutex
	seen := make(map[string]string)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("X-Forwarded-Port") + "|" + r.Header.Get("X-Forwarded-Proto")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := Build(mustParseURL(t, upstream.URL))
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	var wg sync.WaitGroup
	errs := make(chan error, requestCount)
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/client-%d", i)
			resp, err := http.Get(proxyServer.URL + path)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("proxied request failed: %v", err)
	}

	if len(seen) != requestCount {
		t.Errorf("upstream saw %d distinct requests, want %d", len(seen), requestCount)
	}
	for i := 0; i < requestCount; i++ {
		path := fmt.Sprintf("/client-%d", i)
		got, ok := seen[path]
		if !ok {
			t.Errorf("upstream never observed %s", path)
			continue
		}
		if want := "443|https"; got != want {
			t.Errorf("%s forwarded headers: got %q, want %q", path, got, want)
		}
	}
}

// TestBuild_UpstreamUnreachable_Preserves502 verifies a genuine upstream
// failure still surfaces as 502 Bad Gateway.
func TestBuild_UpstreamUnreachable_Preserves502(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadURL := "http://" + listener.Addr().String()
	listener.Close() // nothing will accept connections

	proxy := Build(mustParseURL(t, deadURL))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	proxy.ServeHTTP(rec, req)

	if got := rec.Code; got != http.StatusBadGateway {
		t.Errorf("status: got %v, want %v", got, http.StatusBadGateway)
	}
}

// TestBuild_HalfClosedUpstream_RetriesSafely verifies that an upstream closing
// the connection after each response does not corrupt subsequent requests:
// each request completes exactly once with the right body and no state reuse.
func TestBuild_HalfClosedUpstream_RetriesSafely(t *testing.T) {
	var mu sync.Mutex
	requestCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Header().Set("Connection", "close")
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxy := Build(mustParseURL(t, upstream.URL))
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(proxyServer.URL + "/half-closed")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d read body: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d status: got %d, want %d", i, resp.StatusCode, http.StatusOK)
		}
		if string(body) != "ok" {
			t.Errorf("request %d body: got %q, want %q", i, body, "ok")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if requestCount != 3 {
		t.Errorf("upstream request count: got %d, want 3 (no state reuse or lost requests)", requestCount)
	}
}

// TestBuild_StaleIdleUpstreamIsReplaced exercises the half-closed race where a
// pooled connection dies while idle. A subsequent request must still complete
// successfully rather than inheriting the dead connection's state.
func TestBuild_StaleIdleUpstreamIsReplaced(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "fresh")
	}))
	defer upstream.Close()

	proxy := Build(mustParseURL(t, upstream.URL))
	// Aggressively age pooled connections so any stale idle connection is
	// closed rather than handed to the next request.
	proxy.Transport.(*http.Transport).IdleConnTimeout = 20 * time.Millisecond
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	first, err := http.Get(proxyServer.URL + "/one")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	io.Copy(io.Discard, first.Body)
	first.Body.Close()

	time.Sleep(40 * time.Millisecond)

	second, err := http.Get(proxyServer.URL + "/two")
	if err != nil {
		t.Fatalf("second request after idle expiry: %v", err)
	}
	body, err := io.ReadAll(second.Body)
	second.Body.Close()
	if err != nil {
		t.Fatalf("second request body: %v", err)
	}
	if second.StatusCode != http.StatusOK || string(body) != "fresh" {
		t.Errorf("second request: status=%d body=%q, want 200 %q", second.StatusCode, body, "fresh")
	}
}

// TestBuild_HeadersAndRouting verifies the director still rewrites the URL and
// appends forwarded headers as before the hardening, preserving compatibility.
func TestBuild_HeadersAndRouting(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/routing" {
			t.Errorf("path: got %q, want /routing", r.URL.Path)
		}
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("X-Forwarded-Proto: got %q, want https", r.Header.Get("X-Forwarded-Proto"))
		}
		if r.Header.Get("X-Forwarded-Port") != "443" {
			t.Errorf("X-Forwarded-Port: got %q, want 443", r.Header.Get("X-Forwarded-Port"))
		}
		io.WriteString(w, "routed")
	}))
	defer upstream.Close()

	proxy := Build(mustParseURL(t, upstream.URL))
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/routing")
	if err != nil {
		t.Fatalf("proxied request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "routed" {
		t.Errorf("body: got %q, want routed", body)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}
