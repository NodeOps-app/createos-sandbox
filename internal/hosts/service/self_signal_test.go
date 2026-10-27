package service

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
)

type countedSignalConn struct {
	net.Conn
	bytesRead int
}

func (c *countedSignalConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.bytesRead += n
	return n, e
}
func TestSelfSignalReadBound(t *testing.T) {
	for _, payload := range []string{strings.Repeat("x", 1<<20) + "\n", strings.Repeat(" ", 1<<20) + "\n", strings.Repeat("x", 1<<20)} {
		server, client := net.Pipe()
		counted := &countedSignalConn{Conn: server}
		done := make(chan struct{})
		go func() { defer close(done); defer client.Close(); _, _ = io.Copy(client, strings.NewReader(payload)) }()
		handleSelfSignalConn(context.Background(), nil, "test", counted)
		<-done
		if counted.bytesRead > 201 {
			t.Errorf("read %d guest bytes before rejecting; want at most 201", counted.bytesRead)
		}
	}
}
