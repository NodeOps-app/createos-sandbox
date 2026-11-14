package vm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

func TestGuestLineBounds(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		wantErr       bool
	}{
		{"boundary", strings.Repeat("x", maxGuestExecFrameBytes-1) + "\n", false},
		{"oversized", strings.Repeat("x", maxGuestExecFrameBytes) + "\n", true},
		{"unterminated", strings.Repeat("x", maxGuestExecFrameBytes+1), true},
		{"partial", "partial", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := readGuestLine(bufio.NewReader(strings.NewReader(tc.payload)), maxGuestExecFrameBytes)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
			if tc.wantErr && len(line) != 0 {
				t.Fatal("partial frame leaked")
			}
			if !tc.wantErr && string(line) != tc.payload {
				t.Fatal("frame changed")
			}
		})
	}
	// Existing buffered output limits must still fit even at maximum JSON expansion.
	payload, err := json.Marshal(proto.ExecResponse{Stdout: strings.Repeat("\x00", 1<<20), Stderr: strings.Repeat("\x00", 1<<20)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readGuestLine(bufio.NewReader(bytes.NewReader(append(payload, '\n'))), maxGuestExecResponseBytes); err != nil {
		t.Fatal(err)
	}
}

// Infinite input must stop at a byte bound, without waiting for EOF/newline.
type endlessGuestInput struct{ read int }

func (r *endlessGuestInput) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.read += len(p)
	return len(p), nil
}
func TestGuestReadsStopWithoutEOF(t *testing.T) {
	r := &endlessGuestInput{}
	if _, err := readGuestLine(bufio.NewReader(r), maxGuestExecFrameBytes); err == nil {
		t.Fatal("accepted endless line")
	}
	if r.read > maxGuestExecFrameBytes+4096 {
		t.Fatalf("read %d bytes", r.read)
	}
	r = &endlessGuestInput{}
	var v any
	if err := decodeGuestProbe(r, &v); err == nil {
		t.Fatal("accepted endless probe")
	}
	if r.read != maxGuestProbeResponseBytes+1 {
		t.Fatalf("read %d bytes", r.read)
	}
}

// Use actual guest-facing methods so each call site must enforce its limit.
func TestGuestResponseBounds(t *testing.T) {
	const ip = "127.0.0.4"
	for _, kind := range []string{"exec", "stream", "memory", "storage", "disks"} {
		for _, large := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/large=%v", kind, large), func(t *testing.T) {
				isExec := kind == "exec" || kind == "stream"
				port := 1025
				if isExec {
					port = 1024
				}
				l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					c, err := l.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					r := bufio.NewReader(c)
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
					if isExec {
						if _, err := r.ReadString('\n'); err != nil {
							return
						}
						if large {
							limit := maxGuestExecResponseBytes
							if kind == "stream" {
								limit = maxGuestExecFrameBytes
							}
							_, _ = io.WriteString(c, strings.Repeat("x", limit+1)+"\n")
							return
						}
						if kind == "stream" {
							for i := 0; i < 100; i++ {
								_, _ = fmt.Fprintf(c, "{\"stdout\":\"%s\"}\n", strings.Repeat("x", 1024))
							}
						} else {
							_, _ = io.WriteString(c, "{\"stdout\":\"ok\",\"exit_code\":0}\n")
						}
						return
					}
					req, err := http.ReadRequest(r)
					if err != nil {
						return
					}
					req.Body.Close()
					payload := `{"used_bytes":12,"total_bytes":24,"disks":[]}`
					if large {
						payload = `{"ignored":"` + strings.Repeat("x", maxGuestProbeResponseBytes) + `"}`
					}
					// Chunked responses ensure the limit does not depend on Content-Length.
					resp := http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), ContentLength: -1, TransferEncoding: []string{"chunked"}, Close: true}
					_ = resp.Write(c)
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				sb := Sandbox{IP: ip, SecretToken: "test"}
				switch kind {
				case "exec":
					var out *proto.ExecResponse
					out, _, err = sb.ExecTimed(ctx, proto.ExecRequest{})
					if err == nil && out.Stdout != "ok" {
						t.Fatal("bad output")
					}
				case "stream":
					var out bytes.Buffer
					err = sb.ExecStream(ctx, proto.ExecRequest{}, &out, nil)
					if large && out.Len() != 0 {
						t.Fatal("oversized frame forwarded")
					}
					if !large && out.Len() <= maxGuestExecFrameBytes {
						t.Fatal("stream total incorrectly capped")
					}
				case "memory":
					var used uint64
					used, err = dialGuestMeminfo(ip, "test")
					if err == nil && used != 12 {
						t.Fatal("bad memory")
					}
				case "storage":
					var used, total uint64
					used, total, err = dialGuestStorage(ip, "test")
					if err == nil && (used != 12 || total != 24) {
						t.Fatal("bad storage")
					}
				case "disks":
					_, err = fetchDiskStatus(ctx, ip, "test")
				}
				<-done
				if (err != nil) != large {
					t.Fatalf("large=%v err=%v", large, err)
				}
			})
		}
	}
}

func TestGuestProbeBoundary(t *testing.T) {
	for _, size := range []int{maxGuestProbeResponseBytes, maxGuestProbeResponseBytes + 1} {
		payload := `{"used_bytes":12}`
		payload += strings.Repeat(" ", size-len(payload))
		var out guestMemResp
		err := decodeGuestProbe(strings.NewReader(payload), &out)
		if size == maxGuestProbeResponseBytes {
			if err != nil || out.UsedBytes != 12 {
				t.Fatalf("boundary rejected: %v", err)
			}
		} else if err == nil {
			t.Fatal("oversized trailing whitespace accepted")
		}
	}
}

func TestGuestExecCancellation(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.4:1024")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				r := bufio.NewReader(c)
				r.ReadString('\n')
				r.ReadString('\n')
				cancel()
				_, _ = io.Copy(io.Discard, r)
			}()
			sb := Sandbox{IP: "127.0.0.4", SecretToken: "test"}
			start := time.Now()
			if stream {
				err = sb.ExecStream(ctx, proto.ExecRequest{}, io.Discard, nil)
			} else {
				_, _, err = sb.ExecTimed(ctx, proto.ExecRequest{})
			}
			<-done
			if err == nil {
				t.Fatal("canceled read succeeded")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("cancellation did not unblock read promptly")
			}
		})
	}
}

// Teardown must cancel the old incarnation even when the same sandbox ID is
// later resumed, and a late transfer registration must inherit cancellation.
func TestFileTransfersFollowVMTeardown(t *testing.T) {
	sb := &Sandbox{ID: "test"}
	mgr := &Manager{Sandboxes: map[string]*Sandbox{"test": sb}}
	ctx, stop := sb.FileTransferContext(context.Background())
	defer stop()
	unlock, ok := mgr.BeginTeardown(sb)
	if !ok {
		t.Fatal("teardown rejected")
	}
	unlock()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("transfer survived teardown")
	}
	late, stopLate := sb.FileTransferContext(context.Background())
	defer stopLate()
	if late.Err() == nil {
		t.Fatal("late transfer accepted on removed incarnation")
	}
	fresh := &Sandbox{ID: "test"}
	next, stopNext := fresh.FileTransferContext(context.Background())
	defer stopNext()
	if next.Err() != nil {
		t.Fatal("new incarnation inherited cancellation")
	}
}
