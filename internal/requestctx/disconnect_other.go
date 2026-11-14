//go:build !linux

package requestctx

import (
	"context"
	"net"
)

// WithDisconnect retains context cancellation on non-Linux clients. Operational
// control, machine and guest services run on Linux and observe socket closure.
func WithDisconnect(parent context.Context, _ net.Conn) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
