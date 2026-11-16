package reverseproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
)

// framingContextKey is the context key under which the wire-level framing
// connection observed for a request is stored.
type framingContextKey struct{}

// rawFraming holds the unparsed Content-Length and Transfer-Encoding header
// lines seen on the wire before net/http's parser normalizes the request.
type rawFraming struct {
	contentLength    []string
	transferEncoding []string
}

// initialFramingBufferSize is the starting buffer used while locating a
// request header block. It doubles on demand for unusually large headers.
const initialFramingBufferSize = 64 * 1024

// NewFramingListener wraps listener so every accepted connection inspects
// each HTTP/1.x request header block before net/http parses it. Pair it with
// FramingConnContext on an http.Server so the observed framing fields are
// attached to each request context and can be checked by
// validateRequestFraming.
//
// The wrapper exists because net/http silently normalizes some smuggling
// patterns (notably a request carrying both Content-Length and
// Transfer-Encoding) before the handler runs, which makes them invisible to
// handler-level validation.
func NewFramingListener(listener net.Listener) net.Listener {
	return &framingListener{Listener: listener}
}

// FramingConnContext is an http.Server.ConnContext hook: it attaches the
// framing connection so handlers can read the raw framing of each request.
func FramingConnContext(ctx context.Context, conn net.Conn) context.Context {
	if framed, ok := conn.(*framingConn); ok {
		return context.WithValue(ctx, framingContextKey{}, framed)
	}
	return ctx
}

type framingListener struct {
	net.Listener
}

func (l *framingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newFramingConn(conn), nil
}

type framingState int

const (
	// stateHeader: the next bytes form the next request header block.
	stateHeader framingState = iota
	// stateBody: the current header block was located and reads stream the
	// request body until the exchange completes.
	stateBody
)

// framingConn peeks each incoming request header block without consuming any
// bytes, so net/http's parser reads the exact wire message. The framing
// fields it records let the proxy reject smuggling patterns the standard
// library would otherwise normalize away before the handler runs.
type framingConn struct {
	net.Conn
	reader *bufio.Reader

	mu    sync.Mutex
	state framingState
	// current is the raw framing of the request most recently located and
	// stays in place until the next request starts.
	current *rawFraming
}

func newFramingConn(conn net.Conn) *framingConn {
	return &framingConn{
		Conn:   conn,
		reader: bufio.NewReaderSize(conn, initialFramingBufferSize),
		state:  stateHeader,
	}
}

func (c *framingConn) Read(p []byte) (int, error) {
	if c.state == stateHeader {
		block, err := c.peekHeaderBlock()
		if err != nil {
			return 0, err
		}
		c.mu.Lock()
		c.current = parseRawFraming(block)
		c.state = stateBody
		c.mu.Unlock()
	}
	return c.reader.Read(p)
}

// armHeaderDetection re-enables raw header inspection for the next request.
// It is driven by an http.Server ConnState hook (StateIdle), which fires
// after each response completes and before the next request is read, so it
// covers keep-alive and pipelined connections.
func (c *framingConn) armHeaderDetection() {
	c.mu.Lock()
	c.state = stateHeader
	c.current = nil
	c.mu.Unlock()
}

// snapshot returns a copy of the framing of the request currently being
// processed.
func (c *framingConn) snapshot() *rawFraming {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		return nil
	}
	clone := *c.current
	return &clone
}

// peekHeaderBlock returns the raw bytes of the next request header block
// (including its terminating CRLFCRLF) without consuming them. The peek
// window grows when a header block is larger than the current buffer.
func (c *framingConn) peekHeaderBlock() ([]byte, error) {
	var peeked []byte
	for {
		buf, err := c.reader.Peek(len(peeked) + 1)
		if len(buf) > len(peeked) {
			peeked = buf
		}
		if idx := headerBlockEnd(peeked); idx >= 0 {
			return peeked[:idx], nil
		}
		if err == bufio.ErrBufferFull {
			if growErr := c.growBuffer(); growErr != nil {
				return nil, growErr
			}
			continue
		}
		if err != nil {
			return nil, err
		}
	}
}

// growBuffer swaps in a bufio.Reader twice the current size, preserving the
// bytes already buffered so no wire data is lost.
func (c *framingConn) growBuffer() error {
	buffered := c.reader.Buffered()
	pending := make([]byte, buffered)
	if _, err := io.ReadFull(c.reader, pending); err != nil {
		return err
	}
	grown := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(pending), c.Conn), c.reader.Size()*2)
	c.reader = grown
	return nil
}

// headerBlockEnd returns the index just past the CRLFCRLF terminating the
// header block, or -1 when the terminator has not been observed yet.
func headerBlockEnd(buf []byte) int {
	idx := bytes.Index(buf, []byte("\r\n\r\n"))
	if idx < 0 {
		return -1
	}
	return idx + 4
}

// parseRawFraming scans the raw header block and collects every
// Content-Length and Transfer-Encoding field exactly as transmitted,
// including duplicates that an http.Header map would fold together.
func parseRawFraming(block []byte) *rawFraming {
	framing := &rawFraming{}
	lines := bytes.Split(block, []byte("\r\n"))
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		switch http.CanonicalHeaderKey(string(name)) {
		case "Content-Length":
			framing.contentLength = append(framing.contentLength, string(bytes.TrimSpace(value)))
		case "Transfer-Encoding":
			framing.transferEncoding = append(framing.transferEncoding, string(bytes.TrimSpace(value)))
		}
	}
	return framing
}

// rawFramingFromContext returns the raw framing attached to the request
// context, or nil when the connection did not provide any.
func rawFramingFromContext(req *http.Request) *rawFraming {
	conn, _ := req.Context().Value(framingContextKey{}).(*framingConn)
	if conn == nil {
		return nil
	}
	return conn.snapshot()
}
