package gateway

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type admissionTestChannel struct {
	entered  chan struct{}
	rejected chan struct{}
	gate     <-chan struct{}
}

func (c *admissionTestChannel) ChannelType() string { return "direct-tcpip" }
func (c *admissionTestChannel) ExtraData() []byte   { c.entered <- struct{}{}; <-c.gate; return nil }
func (c *admissionTestChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("test channel")
}
func (c *admissionTestChannel) Reject(ssh.RejectionReason, string) error {
	c.rejected <- struct{}{}
	return nil
}
func TestChannelAdmissionBeforeDispatch(t *testing.T) {
	entered, rejected, gate := make(chan struct{}, 130), make(chan struct{}, 130), make(chan struct{})
	defer close(gate)
	g := New(Config{})
	conn := &ssh.ServerConn{Permissions: &ssh.Permissions{Extensions: map[string]string{"sandbox_id": "sb-audit"}}}
	channels := make(chan ssh.NewChannel, 65)
	for i := 0; i < 65; i++ {
		channels <- &admissionTestChannel{entered, rejected, gate}
	}
	close(channels)
	g.handleChannels(conn, channels)
	admitted, denied := 0, 0
	for i := 0; i < 65; i++ {
		select {
		case <-entered:
			admitted++
		case <-rejected:
			denied++
		case <-time.After(2 * time.Second):
			t.Fatal("dispatch stalled")
		}
	}
	t.Logf("attempts=65 admitted=%d denied=%d", admitted, denied)
	if admitted > 64 || denied != 1 {
		t.Fatal("no effective per-sandbox channel admission bound")
	}
}

func TestChannelLimitsAndRelease(t *testing.T) {
	g := New(Config{})
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for i := 0; i < maxGatewayChannels; i++ {
		id := fmt.Sprintf("sandbox-%d", i/maxSandboxChannels)
		release, ok := g.acquireChannel(id)
		if !ok {
			t.Fatalf("capacity rejected early at %d", i)
		}
		releases = append(releases, release)
		if i == maxSandboxChannels-1 {
			if release, ok := g.acquireChannel(id); ok {
				release()
				t.Fatal("sandbox limit bypassed")
			}
		}
	}
	if release, ok := g.acquireChannel("another-sandbox"); ok {
		release()
		t.Fatal("gateway limit bypassed")
	}
	releases[0]()
	releases = releases[1:]
	release, ok := g.acquireChannel("sandbox-0")
	if !ok {
		t.Fatal("released capacity not reusable")
	}
	release()
}
