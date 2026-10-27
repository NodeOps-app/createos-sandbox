package agent

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// tunnelPort is the TCP port the agent's tunnel accepts on. Separate from
// exec (1024) and files (1025). Traffic is routed through this listener so
// services bound to 127.0.0.1 inside the VM are reachable — the dial
// originates inside the VM's netns, which is the only thing a loopback
// socket will accept from.
//
// Protocol: first line is ASCII decimal target port + '\n' (e.g. "8000\n").
// After that the connection carries raw bidirectional bytes spliced to
// 127.0.0.1:<port>.
const tunnelPort = 1026

const (
	computerVNCFirstPort = 5900
	computerVNCLastPort  = 5907
)

func bindTunnel() (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tunnelPort))
}

func serveTunnelOn(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent: tunnel accept: %v\n", err)
			continue
		}
		go handleTunnelConn(c)
	}
}

func handleTunnelConn(c net.Conn) {
	defer c.Close()
	r := authenticateConn(c)
	if r == nil {
		return
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || port < 1 || port > 65535 {
		return
	}
	// Refuse the complete agent-reserved range. In particular, 1029 is the
	// loopback-only self-signal service: allowing a tunnel to reach it would
	// let public ingress invoke /self/pause or /self/delete. Include the
	// phase-1 probe on 1023 so future lifetime changes cannot expose it either.
	if port >= phase1ProbePort && port <= selfSignalPort {
		return
	}
	// x11vnc is deliberately unauthenticated because its only intended
	// caller is the per-screen, token-gated websockify process in the guest.
	// The ingress tunnel can otherwise turn a loopback-only VNC socket into a
	// public service, bypassing the noVNC bearer token entirely.
	if port >= computerVNCFirstPort && port <= computerVNCLastPort {
		return
	}
	up, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, r); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}
