package reverseproxy

import (
	"net"
	"net/http"
	"net/url"
)

// NewServer returns an http.Server that serves the reverse proxy against
// target with full request framing validation and header normalization. The
// server inspects raw HTTP/1.x framing headers, including smuggling patterns
// that net/http would otherwise normalize away before the handler runs, and
// rejects illegal or ambiguous requests before they reach the upstream.
func NewServer(addr string, target *url.URL) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/", Handler(target))

	server := &http.Server{
		Addr:        addr,
		Handler:     mux,
		ConnContext: FramingConnContext,
		ConnState: func(conn net.Conn, state http.ConnState) {
			// StateIdle fires after each response completes and before the
			// next request on a keep-alive connection is read, which is the
			// correct point to inspect another raw header block.
			if state == http.StateIdle {
				if framed, ok := conn.(*framingConn); ok {
					framed.armHeaderDetection()
				}
			}
		},
	}
	return server
}

// Serve runs server on listener after wrapping it with the framing-aware
// listener. Callers using ListenAndServe (which creates its own listener)
// should instead create a listener and call Serve so the raw framing
// inspection is active.
func Serve(server *http.Server, listener net.Listener) error {
	return server.Serve(NewFramingListener(listener))
}

// ServeTLS runs server over TLS on listener after wrapping it with the
// framing-aware listener. certFile and keyFile follow http.Server.ServeTLS
// semantics and may be empty when the server's TLSConfig supplies
// certificates (for example via an autocert.Manager).
func ServeTLS(server *http.Server, listener net.Listener, certFile, keyFile string) error {
	return server.ServeTLS(NewFramingListener(listener), certFile, keyFile)
}
