package agent

import (
	"encoding/json"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const vsockCIDHost uint32 = 2

// sendSelfSignal opens vsock to (CID=2, selfSignalPort) and writes one
// JSON line. Guest→host over firecracker's hybrid vsock is raw bytes —
// the CONNECT/OK handshake is only used host→guest.
func sendSelfSignal(action, reason string) error {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("vsock socket: %w", err)
	}
	defer syscall.Close(fd)

	sa := vsockSockaddr{Family: afVsock, Port: selfSignalPort, CID: vsockCIDHost}
	if _, _, e := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd),
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); e != 0 {
		return fmt.Errorf("vsock connect CID=2 port=%d: %v", selfSignalPort, e)
	}

	payload, err := json.Marshal(map[string]string{
		"action": action,
		"reason": reason,
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	payload = append(payload, '\n')
	return writeAllDeadline(fd, payload, 2*time.Second)
}

func writeAllDeadline(fd int, buf []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for len(buf) > 0 {
		if time.Now().After(deadline) {
			return fmt.Errorf("write deadline exceeded")
		}
		n, err := syscall.Write(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n <= 0 {
			return fmt.Errorf("short write")
		}
		buf = buf[n:]
	}
	return nil
}
