package proto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// AuthPrefix is the constant prefix every authenticated agent connection
// must send before its real payload. Wire form: "AUTH <token>\n".
const AuthPrefix = "AUTH "

// MaxAuthLine bounds auth-line memory consumption. Callers must also set a
// read deadline to bound how long a peer can stall the handshake.
const MaxAuthLine = 256

// MaxFileUploadBytes is enforced at every hop of the streaming file API.
const MaxFileUploadBytes int64 = 10 * 1024 * 1024 * 1024

// WriteAuthLine writes "AUTH <token>\n" to w. Host dialers call this as
// the first write on connections using the agent's AUTH-line protocol.
func WriteAuthLine(w io.Writer, token string) error {
	_, err := fmt.Fprintf(w, "%s%s\n", AuthPrefix, token)
	return err
}

// ReadAuthLine reads one line from r, validates the AUTH prefix, and
// returns the token. The returned token is not validated — the caller
// must constant-time-compare it against the expected value.
func ReadAuthLine(r *bufio.Reader) (string, error) {
	line, err := readLineCapped(r, MaxAuthLine)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(line, AuthPrefix) {
		return "", errors.New("missing AUTH prefix")
	}
	return strings.TrimSuffix(strings.TrimPrefix(line, AuthPrefix), "\n"), nil
}

// readLineCapped reads from r until '\n' or max bytes, whichever comes
// first. The trailing '\n' is included; '\r' is not stripped. Returns
// io.ErrUnexpectedEOF if the cap is hit without a newline.
func readLineCapped(r *bufio.Reader, max int) (string, error) {
	var b strings.Builder
	for i := 0; i < max; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		b.WriteByte(c)
		if c == '\n' {
			return b.String(), nil
		}
	}
	return "", io.ErrUnexpectedEOF
}
