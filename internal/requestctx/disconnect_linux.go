package requestctx

import (
	"context"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// WithDisconnect watches Linux socket closure, peer write-half closure, and
// error events, checking immediately and then every 100 ms. It does not detect
// a silent network outage until the socket reports an event. Polling consumes
// no HTTP/TLS bytes. Unsupported connections retain only parent/manual
// cancellation. Call the returned stop function before keep-alive reuse to
// cancel the context and join the watcher.
func WithDisconnect(parent context.Context, conn net.Conn) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	for {
		wrapped, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		conn = wrapped.NetConn()
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		// Callers must handle I/O errors themselves for unsupported transports.
		return ctx, cancel
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		cancel()
		return ctx, cancel
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			closed := false
			err := raw.Control(func(fd uintptr) {
				// Linux pollfd ABI. Use a zero timeout while RawConn.Control
				// holds the descriptor, so closure/reuse cannot race this poll.
				const rdhup, hup, pollerr, invalid = 0x2000, 0x10, 0x08, 0x20
				poll := struct {
					fd              int32
					events, revents int16
				}{fd: int32(fd), events: rdhup}
				timeout := syscall.Timespec{}
				_, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&poll)), 1, uintptr(unsafe.Pointer(&timeout)), 0, 0, 0)
				closed = (errno != 0 && errno != syscall.EINTR) || poll.revents&(rdhup|hup|pollerr|invalid) != 0
			})
			if err != nil || closed {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return ctx, func() { cancel(); <-done }
}
