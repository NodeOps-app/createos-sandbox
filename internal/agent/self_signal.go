// Guest-side self-signal endpoints. Loopback-only bind is the security
// boundary: no AUTH gate because nothing outside this VM can reach it.
// Sandbox identity is derived host-side from the UDS path — payload
// carries only action + reason.
//
// Two surfaces, one dispatcher:
//   - HTTP on 127.0.0.1:1029  (`/self/pause`, `/self/delete`)
//   - FIFO at /run/self        (`echo park > /run/self`, `echo retire > /run/self`)
//
// The FIFO exists so a workload can end its own sandbox without curl.
package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	selfSignalPort = 1029
	selfFifoPath   = "/run/self"
)

func startSelfSignal() {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", selfSignalPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: self-signal listener disabled: %v\n", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/self/pause", handleSelfSignal("pause"))
	mux.HandleFunc("/self/delete", handleSelfSignal("delete"))
	go func() {
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 2 * time.Second,
		}
		fmt.Printf("agent: self-signal server on %s\n", l.Addr())
		_ = srv.Serve(l)
	}()
	// Note: serveSelfFifo runs in phase 2 (see agent.go). Phase 1's /run
	// is the initrd's tmpfs, which the rootfs overlay hides — a FIFO
	// created here would vanish on pivot.
}

// serveSelfFifo creates /run/self as a world-writable FIFO and dispatches
// one line at a time to sendSelfSignal. Vocabulary:
//
//	park | pause          → self-pause
//	retire | delete | rm  → self-delete
//
// Reopens the FIFO on every EOF so the agent keeps listening across
// multiple writers. Errors are logged but never fatal — the HTTP path
// stays available as a fallback.
func serveSelfFifo() {
	_ = os.MkdirAll("/run", 0o755)
	_ = os.Remove(selfFifoPath) // clean any stale non-FIFO leftover
	if err := syscall.Mkfifo(selfFifoPath, 0o666); err != nil {
		fmt.Fprintf(os.Stderr, "agent: self-fifo mkfifo: %v\n", err)
		return
	}
	// Chmod again: umask may have masked the world-writable bits.
	_ = os.Chmod(selfFifoPath, 0o666)
	fmt.Printf("agent: self-signal fifo at %s\n", selfFifoPath)

	for {
		f, err := os.OpenFile(selfFifoPath, os.O_RDONLY, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent: self-fifo open: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			action := ""
			switch strings.ToLower(strings.Fields(line)[0]) {
			case "park", "pause":
				action = "pause"
			case "retire", "delete", "rm", "destroy":
				action = "delete"
			default:
				fmt.Fprintf(os.Stderr, "agent: self-fifo unknown verb %q\n", line)
				continue
			}
			if err := sendSelfSignal(action, "fifo"); err != nil {
				fmt.Fprintf(os.Stderr, "agent: self-fifo dispatch %s: %v\n", action, err)
			}
		}
		_ = f.Close()
	}
}

func handleSelfSignal(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		reason := sanitizeReason(r.URL.Query().Get("reason"))
		if err := sendSelfSignal(action, reason); err != nil {
			fmt.Fprintf(os.Stderr, "agent: self-signal %s: %v\n", action, err)
			http.Error(w, "self-signal failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "accepted",
			"action": action,
		})
	}
}

// sanitizeReason strips control characters so the audit line the host
// eventually writes can't be smuggled with newlines.
func sanitizeReason(s string) string {
	const maxLen = 128
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(out) < maxLen; i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
