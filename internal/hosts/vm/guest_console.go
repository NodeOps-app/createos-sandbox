package vm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

const guestConsoleCapacity = 64 << 10

const journalStreamPath = "/run/systemd/journal/stdout"

type guestConsoleCapture struct {
	id       string
	journal  *os.File
	fallback *guestConsoleRing
}

// newGuestConsoleCapture gives Firecracker a direct journald stream. Unlike an
// io.Pipe owned by createos-serve, the inherited socket remains valid while
// serve restarts, so guest output produced in that gap is still attributable
// to the sandbox. Hosts without systemd-journald retain the in-memory fallback.
func newGuestConsoleCapture(id string) *guestConsoleCapture {
	c := &guestConsoleCapture{id: id}
	if stream, err := openJournalStream(guestConsoleIdentifier(id)); err == nil {
		c.journal = stream
	} else {
		c.fallback = newGuestConsoleRing()
	}
	return c
}

// rehydratedGuestConsole does not open another writer: the surviving
// Firecracker already owns the journald socket inherited at its original
// launch. It only gives the new serve process a way to query that history.
func rehydratedGuestConsole(id string) *guestConsoleCapture {
	return &guestConsoleCapture{id: id}
}

func guestConsoleIdentifier(id string) string { return "fc-console-" + id }

func openJournalStream(identifier string) (*os.File, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: journalStreamPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.CloseRead()

	// sd_journal_stream_fd protocol: identifier, empty unit id, priority,
	// level-prefix, forward-syslog, forward-kmsg, forward-console.
	header := fmt.Sprintf("%s\n\n6\n0\n0\n0\n0\n", identifier)
	if _, err := io.WriteString(conn, header); err != nil {
		return nil, err
	}
	return conn.File()
}

func (c *guestConsoleCapture) writer() io.Writer {
	if c != nil && c.journal != nil {
		return c.journal
	}
	if c != nil {
		return c.fallback
	}
	return nil
}

// releaseParent closes serve's copy after Firecracker has inherited the file
// descriptor. Firecracker's copy remains open independently across restarts.
func (c *guestConsoleCapture) releaseParent() {
	if c != nil && c.journal != nil {
		_ = c.journal.Close()
		c.journal = nil
	}
}

func (c *guestConsoleCapture) cause() string {
	if c == nil {
		return ""
	}
	if cause := GuestConsoleCause(c.id); cause != "" {
		return cause
	}
	return c.fallback.cause()
}

// GuestConsoleCause reads a bounded tail selected by journald's per-sandbox
// identifier. Output is written into a ring, never accumulated unboundedly and
// never returned to logs. This also works during startup reconciliation after
// the serve process that launched Firecracker has disappeared.
func GuestConsoleCause(id string) string {
	if id == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ring := newGuestConsoleRing()
	cmd := exec.CommandContext(ctx, "journalctl",
		"--identifier="+guestConsoleIdentifier(id),
		"--lines=512", "--output=cat", "--no-pager", "--quiet")
	cmd.Stdout = ring
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return ""
	}
	return ring.cause()
}

// guestConsoleRing retains only the tail of a VM's serial console. Firecracker
// still writes its output to the host journal; this copy exists solely so an
// unexpected VM death can be classified without logging tenant console data.
type guestConsoleRing struct {
	mu   sync.Mutex
	buf  []byte
	pos  int
	full bool
}

func newGuestConsoleRing() *guestConsoleRing {
	return &guestConsoleRing{buf: make([]byte, guestConsoleCapacity)}
}

func (r *guestConsoleRing) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(p) >= len(r.buf) {
		copy(r.buf, p[len(p)-len(r.buf):])
		r.pos = 0
		r.full = true
		return n, nil
	}

	first := copy(r.buf[r.pos:], p)
	copy(r.buf, p[first:])
	r.pos = (r.pos + len(p)) % len(r.buf)
	if first < len(p) || r.pos == 0 {
		r.full = true
	}
	return n, nil
}

func (r *guestConsoleRing) bytes() []byte {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]byte(nil), r.buf[:r.pos]...)
	}
	out := make([]byte, 0, len(r.buf))
	out = append(out, r.buf[r.pos:]...)
	out = append(out, r.buf[:r.pos]...)
	return out
}

// cause returns a low-cardinality classification only. It deliberately does
// not return or log raw console text, which may contain tenant data.
func (r *guestConsoleRing) cause() string {
	console := bytes.ToLower(r.bytes())
	switch {
	case bytes.Contains(console, []byte("attempted to kill init")):
		return "guest_init_exit"
	case bytes.Contains(console, []byte("kernel panic")):
		return "guest_kernel_panic"
	case bytes.Contains(console, []byte("out of memory:")),
		bytes.Contains(console, []byte("oom-kill:")),
		bytes.Contains(console, []byte("killed process ")):
		return "guest_oom"
	default:
		return ""
	}
}
