// Host side of guest→host self-signal. One UDS listener per VM at
// <VsockUDSPath>_1029, sandbox identity is the socket path (never the
// payload). Cross-tenant blocked by the per-VM runtime dir mode
// (0700 slot-uid); loopback bind in the guest keeps callers in-VM;
// action whitelist keeps payload from driving arbitrary code.
package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/sandbox/models"
)

const selfSignalPortSuffix = "_1029"

type SelfSignalWatchers struct {
	mu sync.Mutex
	m  map[string]context.CancelFunc
}

func NewSelfSignalWatchers() *SelfSignalWatchers {
	return &SelfSignalWatchers{m: make(map[string]context.CancelFunc)}
}

func (s *Service) StartSelfSignal(sb *vm.Sandbox) {
	if s.selfWatchers == nil || sb == nil || sb.VsockUDSPath == "" {
		return
	}
	s.selfWatchers.mu.Lock()
	defer s.selfWatchers.mu.Unlock()
	if _, running := s.selfWatchers.m[sb.ID]; running {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	udsPath := sb.VsockUDSPath + selfSignalPortSuffix
	if err := runSelfSignalListener(ctx, s, sb, udsPath); err != nil {
		cancel()
		log.Warnf("[self-signal] %s bind %s: %v — endpoint disabled for this VM", sb.ID, udsPath, err)
		return
	}
	s.selfWatchers.m[sb.ID] = cancel
}

func (s *Service) StopSelfSignal(id string) {
	if s.selfWatchers == nil {
		return
	}
	s.selfWatchers.mu.Lock()
	cancel, ok := s.selfWatchers.m[id]
	if ok {
		delete(s.selfWatchers.m, id)
	}
	s.selfWatchers.mu.Unlock()
	if ok {
		cancel()
	}
}

func runSelfSignalListener(ctx context.Context, svc *Service, sb *vm.Sandbox, udsPath string) error {
	_ = os.Remove(udsPath)
	l, err := net.Listen("unix", udsPath)
	if err != nil {
		return err
	}
	// Chown to slot-uid so firecracker (running as that uid) can open
	// the UDS when guest vsock fires. Directory ACL (0700 slot-uid)
	// blocks other tenants regardless of file mode.
	_ = os.Chmod(udsPath, 0600)
	if info, err := os.Stat(vm.SlotRuntimeDir(sb.ID)); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(udsPath, int(st.Uid), int(st.Gid))
		}
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
		_ = os.Remove(udsPath)
	}()
	go acceptSelfSignal(ctx, svc, sb.ID, l)
	return nil
}

// acceptSelfSignal rate-limits to 1 accept per 500ms so a runaway guest
// can't burn CPU on the dispatch path.
func acceptSelfSignal(ctx context.Context, svc *Service, sbID string, l net.Listener) {
	lastAccept := time.Time{}
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.WithContext(ctx).Debugf("[self-signal] %s accept: %v", sbID, err)
			return
		}
		if since := time.Since(lastAccept); since < 500*time.Millisecond {
			_ = conn.Close()
			continue
		}
		lastAccept = time.Now()
		go handleSelfSignalConn(context.Background(), svc, sbID, conn)
	}
}

func handleSelfSignalConn(ctx context.Context, svc *Service, sbID string, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// ReadSlice never grows its buffer: allow 200 raw payload bytes plus the
	// newline, and reject oversized input before trimming or decoding it.
	r := bufio.NewReaderSize(conn, 201)
	raw, err := r.ReadSlice('\n')
	if err != nil {
		log.WithContext(ctx).Debugf("[self-signal] %s read: %v", sbID, err)
		return
	}
	line := strings.TrimSpace(string(raw))
	if len(line) == 0 || len(line) > 200 {
		log.WithContext(ctx).Warnf("[self-signal] %s payload bounds: len=%d", sbID, len(line))
		return
	}
	var msg struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		log.WithContext(ctx).Warnf("[self-signal] %s json: %v", sbID, err)
		return
	}
	switch msg.Action {
	case "pause", "delete":
	default:
		log.WithContext(ctx).Warnf("[self-signal] %s unknown action=%q", sbID, msg.Action)
		return
	}

	// Fetch the row so we can pass the sandbox's CreatedBy to Pause/Destroy
	// as the caller. The socket-path→sandbox_id mapping is the security
	// anchor; the caller value here just satisfies the ownership gate for
	// a signal that originated inside the guest.
	rec, err := svc.Repo.Get(ctx, sbID)
	if err != nil {
		log.WithContext(ctx).Warnf("[self-signal] %s repo.Get: %v", sbID, err)
		return
	}
	if rec == nil {
		return
	}
	caller := rec.CreatedBy

	switch models.Status(rec.Status) {
	case models.StatusPaused, models.StatusPausing,
		models.StatusDestroyed, models.StatusDestroying:
		log.WithContext(ctx).Infof("[self-signal] %s ignored action=%s reason=%q — sandbox status=%s",
			sbID, msg.Action, msg.Reason, rec.Status)
		return
	}

	log.WithContext(ctx).Infof("[self-signal] %s action=%s reason=%q", sbID, msg.Action, msg.Reason)
	switch msg.Action {
	case "pause":
		if _, err := svc.Pause(ctx, sbID, caller); err != nil {
			log.WithContext(ctx).Warnf("[self-signal] %s pause: %v", sbID, err)
		}
	case "delete":
		if err := svc.Destroy(ctx, sbID, caller); err != nil {
			log.WithContext(ctx).Warnf("[self-signal] %s destroy: %v", sbID, err)
		}
	}
	_, _ = fmt.Fprintln(conn, `{"status":"accepted"}`)
}
