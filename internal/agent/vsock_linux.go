// Vsock readiness-probe listener. Lives alongside the TCP listeners
// (exec, files, tunnel, pty) which still carry real traffic. Vsock is
// used ONLY by the host's waitForAgent — its host→guest packet path
// bypasses virtio-net, so the dial isn't taxed by the L0 hypervisor's
// trap costs on nested-virt cloud hosts.
//
// Bound in phase 1 alongside the TCP listeners so the kernel accept
// queue survives the snapshot. Restored VMs reply to host probes from
// the queue without waiting for phase 2.
//
// Wire: any host connection accepted writes "ok\n" and closes. Used
// only as a "the agent process is alive" signal — not a real transport.
//
// Stdlib-only (raw syscall via the syscall package) — keeps
// `make check-agent` happy.
package agent

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	afVsock        = 40
	vsockProbePort = 1024
	vsockCIDAny    = uint32(0xFFFFFFFF)
)

// sockaddr_vm matches the kernel's struct sockaddr_vm — 16 bytes.
type vsockSockaddr struct {
	Family   uint16
	Reserved uint16
	Port     uint32
	CID      uint32
	Zero     [4]byte
}

// bindVsockProbe creates an AF_VSOCK SOCK_STREAM socket bound on
// vsockProbePort and returns the listener fd.
func bindVsockProbe() (int, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, fmt.Errorf("vsock socket: %w", err)
	}
	sa := vsockSockaddr{Family: afVsock, Port: vsockProbePort, CID: vsockCIDAny}
	if _, _, e := syscall.Syscall(syscall.SYS_BIND, uintptr(fd),
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); e != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("vsock bind port %d: %v", vsockProbePort, e)
	}
	if err := syscall.Listen(fd, 16); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("vsock listen: %w", err)
	}
	return fd, nil
}

// serveVsockProbe accepts forever, writes "ok\n", closes. Best-effort.
// EBADF means the snapshot teardown closed the fd — exit cleanly.
func serveVsockProbe(fd int) {
	for {
		cfd, _, err := syscall.Accept(fd)
		if err != nil {
			if err == syscall.EBADF {
				return
			}
			continue
		}
		syscall.Write(cfd, []byte("ok\n"))
		syscall.Close(cfd)
	}
}

// startVsockProbe wires bind + serve. Silently no-ops if vsock isn't
// available in this guest kernel — createos hosts may run guests with
// or without vsock; the agent falls back silently to TCP-only.
func startVsockProbe() {
	fd, err := bindVsockProbe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: vsock probe disabled: %v\n", err)
		return
	}
	go serveVsockProbe(fd)
}
