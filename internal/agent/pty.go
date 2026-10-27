package agent

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
)

// ptyPort is the TCP port the agent's interactive-shell listener accepts
// on. Separate from exec (1024), files (1025), and tunnel (1026).
//
// A connection here gets a real PTY-backed login shell — the keyless,
// API-key-authenticated alternative to reaching sshd through the gateway.
//
// Wire protocol, after the standard "AUTH <token>\n" line:
//   - client → agent: framed messages — [type:1][len:4 BE][payload:len]
//     type 0 (data)   → payload is raw stdin, written to the pty master
//     type 1 (resize) → payload is rows:uint16 + cols:uint16 (BE)
//   - agent → client: raw, unframed — whatever the shell writes to the pty.
const ptyPort = 1027

const (
	ptyFrameData   = 0
	ptyFrameResize = 1
	ptyMaxFrame    = 1 << 20 // 1 MiB — sanity cap on a single frame
)

func bindPTY() (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", ptyPort))
}

func servePTYOn(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent: pty accept: %v\n", err)
			continue
		}
		go handlePTYConn(c)
	}
}

func handlePTYConn(c net.Conn) {
	defer c.Close()

	r := authenticateConn(c)
	if r == nil {
		return
	}

	master, slave, err := openPTY()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: pty alloc: %v\n", err)
		return
	}
	defer master.Close()

	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-l")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.Dir = "/root"
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	// Setsid: new session so the shell is a session leader.
	// Setctty: make the slave (child fd 0) the controlling terminal —
	// that's what makes job control and Ctrl-C work.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "agent: pty shell start: %v\n", err)
		_ = slave.Close()
		return
	}
	// The slave is now the child's controlling terminal; the parent holds
	// only the master from here on.
	_ = slave.Close()

	// agent → client: raw pty output. When the shell exits, the master
	// read hits EOF; closing c unblocks the client→agent loop below.
	go func() {
		_, _ = io.Copy(c, master)
		_ = c.Close()
	}()

	// client → agent: framed stdin + resize control messages.
	var hdr [5]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			break
		}
		typ := hdr[0]
		n := binary.BigEndian.Uint32(hdr[1:5])
		if n > ptyMaxFrame {
			break
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		if typ == ptyFrameResize {
			if len(payload) >= 4 {
				_ = setWinsize(master,
					binary.BigEndian.Uint16(payload[0:2]),
					binary.BigEndian.Uint16(payload[2:4]))
			}
			continue
		}
		if _, err := master.Write(payload); err != nil {
			break
		}
	}

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
