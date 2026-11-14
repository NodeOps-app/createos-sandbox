package gateway

import (
	"context"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	maxSandboxChannels = 64
	maxGatewayChannels = 1024
)

// directTCPIPPayload mirrors the wire format of RFC 4254 §7.2 for
// direct-tcpip channel requests.
type directTCPIPPayload struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// handleChannels dispatches SSH channels for one authenticated session.
// Only direct-tcpip channels are accepted; everything else is rejected
// with ssh.Prohibited.
func (g *Gateway) handleChannels(conn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for nc := range chans {
		switch nc.ChannelType() {
		case "direct-tcpip":
			release, ok := g.acquireChannel(extSandboxID(conn))
			if !ok {
				_ = nc.Reject(ssh.ResourceShortage, "channel capacity busy")
				continue
			}
			go func(nc ssh.NewChannel) {
				defer release()
				g.handleDirectTCPIP(conn, nc)
			}(nc)
		default:
			log.Infof("[gateway] channel-reject sandbox=%s type=%s reason=prohibited",
				extSandboxID(conn), nc.ChannelType())
			_ = nc.Reject(ssh.Prohibited, nc.ChannelType()+" not allowed")
		}
	}
}

// handleDirectTCPIP validates the request target, opens a direct mTLS
// tunnel to the host that owns this sandbox, and splices the SSH channel
// onto it. The host address was resolved at SSH auth time and stashed in
// Permissions.Extensions["host_addr"] so this path needs no extra round
// trip to control.
func (g *Gateway) handleDirectTCPIP(conn *ssh.ServerConn, nc ssh.NewChannel) {
	var req directTCPIPPayload
	if err := ssh.Unmarshal(nc.ExtraData(), &req); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
		return
	}

	sbID := extSandboxID(conn)
	sbIP := ""
	hostAddr := ""
	if conn.Permissions != nil {
		sbIP = conn.Permissions.Extensions["sandbox_ip"]
		hostAddr = conn.Permissions.Extensions["host_addr"]
	}
	if hostAddr == "" {
		log.Warnf("[gateway] channel-reject sandbox=%s reason=%q",
			sbID, "no host_addr in session extensions (auth path bug?)")
		_ = nc.Reject(ssh.ConnectionFailed, "tunnel open failed")
		return
	}

	target := strings.ToLower(strings.TrimSpace(req.DestHost))
	if target != "localhost" && target != "127.0.0.1" && (sbIP == "" || target != sbIP) {
		log.Infof("[gateway] channel-reject sandbox=%s type=direct-tcpip target=%s:%d reason=%q",
			sbID, req.DestHost, req.DestPort, "target must be sandbox itself")
		_ = nc.Reject(ssh.Prohibited, "target must be sandbox itself")
		return
	}

	log.Infof("[gateway] channel-open sandbox=%s type=direct-tcpip target=%s:%d origin=%s:%d",
		sbID, req.DestHost, req.DestPort, req.OriginHost, req.OriginPort)

	tc, err := g.openTunnel(context.Background(), hostAddr, sbID, int(req.DestPort))
	if err != nil {
		log.Warnf("[gateway] tunnel-open-failed sandbox=%s port=%d err=%v",
			sbID, req.DestPort, err)
		_ = nc.Reject(ssh.ConnectionFailed, "tunnel open failed")
		return
	}
	defer tc.Close()

	ch, chReqs, err := nc.Accept()
	if err != nil {
		log.Warnf("[gateway] channel-accept-failed sandbox=%s err=%v", sbID, err)
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(chReqs)

	// Splice. Close the opposite side on EOF so the peer can see it.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(tc, ch)
		if cw, ok := tc.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(ch, tc)
		_ = ch.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	log.Infof("[gateway] channel-close sandbox=%s target=%s:%d",
		sbID, req.DestHost, req.DestPort)
}

func extSandboxID(conn *ssh.ServerConn) string {
	if conn.Permissions == nil {
		return ""
	}
	return conn.Permissions.Extensions["sandbox_id"]
}

// Counts are shared across SSH sessions, so reconnecting cannot bypass the
// sandbox limit. Reject before starting a goroutine or opening a host tunnel.
func (g *Gateway) acquireChannel(id string) (func(), bool) {
	g.channelMu.Lock()
	defer g.channelMu.Unlock()
	if id == "" || g.channelCount >= maxGatewayChannels || g.channels[id] >= maxSandboxChannels {
		return nil, false
	}
	if g.channels == nil {
		g.channels = make(map[string]int)
	}
	id = strings.Clone(id)
	g.channels[id]++
	g.channelCount++
	return func() {
		g.channelMu.Lock()
		defer g.channelMu.Unlock()
		g.channels[id]--
		g.channelCount--
		if g.channels[id] == 0 {
			delete(g.channels, id)
		}
	}, true
}
