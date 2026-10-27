package agent

import (
	"bufio"
	"crypto/subtle"
	"net"
	"sync"
	"time"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

// authReadDeadline bounds how long a connection has to deliver its
// "AUTH <token>\n" line before we close it. Short enough that a stalled
// peer can't pin a goroutine; long enough that the very first connection
// after snapshot restore has time to wait for the MMDS-delivered token.
const authReadDeadline = 1 * time.Second

var (
	tokenMu     sync.RWMutex
	secretToken string
	tokenReady  = make(chan struct{})
)

// setToken stores the per-VM secret on first delivery via MMDS. First
// non-empty token wins; later pushes are ignored (token never rotates
// within a VM lifetime).
func setToken(t string) {
	if t == "" {
		return
	}
	tokenMu.Lock()
	defer tokenMu.Unlock()
	if secretToken != "" {
		return
	}
	secretToken = t
	close(tokenReady)
}

// checkToken constant-time compares against the stored secret. Returns
// false if the secret hasn't been set yet (caller is responsible for
// gating on tokenReady before calling).
func checkToken(got string) bool {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	if secretToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(secretToken), []byte(got)) == 1
}

// authenticateConn reads the AUTH line from c, validates it, and returns
// the buffered reader (with any post-line bytes preserved) on success.
// On failure it closes c and returns nil.
//
// Blocks on tokenReady so a connection that arrives between accept and
// the first MMDS push waits up to authReadDeadline for the token to
// land. In normal operation the agent's 2 ms MMDS poll has already
// stored the token long before any host-side dial.
func authenticateConn(c net.Conn) *bufio.Reader {
	deadline := time.Now().Add(authReadDeadline)
	_ = c.SetReadDeadline(deadline)

	select {
	case <-tokenReady:
	case <-time.After(time.Until(deadline)):
		c.Close()
		return nil
	}

	br := bufio.NewReader(c)
	tok, err := proto.ReadAuthLine(br)
	if err != nil || !checkToken(tok) {
		c.Close()
		return nil
	}
	_ = c.SetReadDeadline(time.Time{}) // clear; subsequent reads are unbounded
	return br
}
