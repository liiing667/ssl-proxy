package securelog

import (
	"io"
	"os"
	"strings"
	"sync"
)

// SafeWriter is an io.Writer that scrubs every byte with a shared Rules set
// before forwarding it to a destination writer.
//
// Defense against multi-stage log splicing: a secret can be split across
// several Write calls (or several log stages), and a pattern-based redactor
// cannot match a credential that has only partially arrived. SafeWriter
// therefore keeps raw, unscrubbed bytes in an in-memory buffer and only ever
// runs the redactor over a complete newline-delimited line (or over the full
// pending buffer on Flush). Scrubbed bytes are forwarded immediately; raw
// caller bytes never reach the destination writer.
//
// Fail-closed behavior: if redaction panics or otherwise cannot be guaranteed,
// the offending payload is replaced by SuppressedLine rather than emitted
// verbatim.
type SafeWriter struct {
	mu sync.Mutex

	dest  io.Writer
	rules Rules
	scrub func(string) string

	// pending holds raw, unscrubbed bytes for the not-yet-completed final
	// line. It never contains content already forwarded to dest.
	pending strings.Builder
}

// SuppressedLine is emitted in place of content whose safety cannot be
// guaranteed. It contains no caller-controlled data.
const SuppressedLine = "securelog: log line suppressed due to redaction failure\n"

// NewSafeWriter wraps dest so every write is scrubbed under rules.
func NewSafeWriter(dest io.Writer, rules Rules) *SafeWriter {
	return &SafeWriter{dest: dest, rules: rules, scrub: rules.ScrubString}
}

// Write appends p to the raw pending buffer, redacts and forwards every
// completed line, and retains the trailing partial line for a future write.
func (w *SafeWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending.Write(p)

	lastNL := strings.LastIndexByte(w.pending.String(), '\n')
	if lastNL < 0 {
		// No complete line yet: keep the raw bytes buffered; nothing leaves
		// the writer unredacted.
		return len(p), nil
	}

	complete := w.pending.String()[:lastNL+1]
	remainder := w.pending.String()[lastNL+1:]

	redacted, ok := w.scrubSafe(complete)
	if !ok {
		// Fail closed: drop the unprocessable payload entirely and emit a
		// constant marker instead of any caller-controlled bytes.
		w.pending.Reset()
		w.pending.WriteString(remainder)
		_, err := io.WriteString(w.dest, SuppressedLine)
		return len(p), err
	}

	w.pending.Reset()
	w.pending.WriteString(remainder)
	_, err := io.WriteString(w.dest, redacted)
	return len(p), err
}

// Flush redacts and forwards any buffered partial line.
func (w *SafeWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pending.Len() == 0 {
		return nil
	}
	redacted, ok := w.scrubSafe(w.pending.String())
	w.pending.Reset()
	if !ok {
		_, err := io.WriteString(w.dest, SuppressedLine)
		return err
	}
	_, err := io.WriteString(w.dest, redacted)
	return err
}

// scrubSafe runs the redactor under a panic guard so any redaction failure
// results in suppression rather than verbatim emission.
func (w *SafeWriter) scrubSafe(in string) (out string, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = "", false
		}
	}()
	return w.scrub(in), true
}

// DefaultWriter is the framework default destination for all proxy logging:
// stderr behind the fail-closed scrubber using DefaultRules.
func DefaultWriter() *SafeWriter {
	return NewSafeWriter(os.Stderr, DefaultRules())
}
