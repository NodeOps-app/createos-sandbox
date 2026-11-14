package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

type responseTestService struct{ Service }

func (responseTestService) Get(context.Context, string, string) (*SandboxView, error) {
	ip := "127.0.0.2"
	return &SandboxView{IP: &ip}, nil
}
func (responseTestService) SecretToken(context.Context, string) (string, error) {
	return "test-token", nil
}

func (responseTestService) OpenFileTransfer(ctx context.Context, _, _ string) (*FileTransferTarget, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &FileTransferTarget{IP: "127.0.0.2", Token: "test-token", Context: ctx, Cancel: cancel}, nil
}

// Exercise the real handlers against a guest that sends normal or oversized
// JSON. The guest consumes the AUTH preface just like the agent listener.
func TestGuestResponseBounds(t *testing.T) {
	for _, kind := range []string{"process", "connect-error", "upload"} {
		for _, chunked := range []bool{false, true} {
			for _, large := range []bool{false, true} {
				t.Run(kind+"/chunked="+strconv.FormatBool(chunked)+"/large="+strconv.FormatBool(large), func(t *testing.T) {
					port := agentProcessPort
					if kind == "upload" {
						port = agentFilePort
					}
					l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
					if err != nil {
						t.Fatal(err)
					}
					defer l.Close()
					done := make(chan struct{})
					payload := `{"ok":true}`
					if large {
						payload = `{"data":"` + strings.Repeat("x", 5<<20) + `"}`
					}
					status := 200
					if kind == "connect-error" {
						status = 400
					}
					go func() {
						defer close(done)
						c, e := l.Accept()
						if e != nil {
							return
						}
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						r := bufio.NewReader(c)
						if _, e = r.ReadString('\n'); e != nil {
							return
						}
						req, e := http.ReadRequest(r)
						if e != nil {
							return
						}
						io.Copy(io.Discard, req.Body)
						req.Body.Close()
						resp := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), ContentLength: int64(len(payload)), Close: true}
						resp.Header.Set("Content-Type", "application/json")
						if chunked {
							resp.ContentLength = -1
							resp.TransferEncoding = []string{"chunked"}
						}
						_ = resp.Write(c)
					}()
					server := &Server{Svc: responseTestService{}}
					app := fiber.New()
					method := http.MethodGet
					path := "/v1/sandboxes/test/processes"
					switch kind {
					case "process":
						app.Get(path, server.handleProcessProxy)
					case "connect-error":
						app.Get(path, server.handleProcessConnect)
					case "upload":
						method = http.MethodPut
						path = "/v1/sandboxes/test/files"
						app.Put(path, server.handleFileUpload)
						path += "?path=/tmp/test"
					}
					resp, err := app.Test(httptest.NewRequest(method, path, nil), 5000)
					if err != nil {
						t.Fatal(err)
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					<-done
					want := status
					if large {
						want = http.StatusBadGateway
					}
					if resp.StatusCode != want {
						t.Fatalf("status=%d want=%d; guest payload bytes=%d", resp.StatusCode, want, len(payload))
					}
				})
			}
		}
	}
}

// An endless sender must be stopped by the byte limit, without waiting for EOF.
type endlessGuestResponse struct{ bytesRead int }

func (r *endlessGuestResponse) Read(p []byte) (int, error) {
	clear(p)
	r.bytesRead += len(p)
	return len(p), nil
}

func TestReadGuestResponseLimit(t *testing.T) {
	for _, size := range []int{maxGuestResponseBytes - 1, maxGuestResponseBytes, maxGuestResponseBytes + 1} {
		body, err := readGuestResponse(strings.NewReader(strings.Repeat("x", size)))
		if size <= maxGuestResponseBytes {
			if err != nil || len(body) != size {
				t.Fatalf("size=%d: bytes=%d err=%v", size, len(body), err)
			}
		} else if err == nil {
			t.Fatal("oversized response accepted")
		}
	}
	r := &endlessGuestResponse{}
	if _, err := readGuestResponse(r); err == nil {
		t.Fatal("endless response accepted")
	}
	if r.bytesRead != maxGuestResponseBytes+1 {
		t.Fatalf("read %d bytes from endless response", r.bytesRead)
	}
}

func TestFileClientRejectsRedirect(t *testing.T) {
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	guest, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer guest.Close()
	reached := make(chan bool, 1)
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		c, e := target.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(c)
		a, _ := r.ReadString('\n')
		q, e := http.ReadRequest(r)
		reached <- e == nil && a == "AUTH review-only-token\n" && q.URL.Path == "/redirect-target"
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	go func() {
		c, e := guest.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(c)
		r.ReadString('\n')
		q, e := http.ReadRequest(r)
		if e != nil {
			return
		}
		io.Copy(io.Discard, q.Body)
		q.Body.Close()
		fmt.Fprintf(c, "HTTP/1.1 302 Found\r\nLocation: http://%s/redirect-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target.Addr())
	}()
	client := newFileClient("review-only-token")
	client.Timeout = 3 * time.Second
	q, _ := http.NewRequest("PUT", "http://"+guest.Addr().String()+"/files/tmp/test", strings.NewReader("x"))
	resp, e := client.Do(q)
	if e == nil {
		resp.Body.Close()
		t.Fatal("guest redirect accepted")
	}
	target.Close()
	<-targetDone
	select {
	case <-reached:
		t.Fatal("redirect destination received sandbox credentials")
	default:
	}
}

type fileLifetimeTestService struct {
	responseTestService
	lifetime context.Context
}

func (s fileLifetimeTestService) OpenFileTransfer(parent context.Context, _, _ string) (*FileTransferTarget, error) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.lifetime, cancel)
	return &FileTransferTarget{IP: "127.0.0.2", Token: "test-token", Context: ctx, Cancel: func() { stop(); cancel() }}, nil
}

// Real TCP is required: Fiber's in-memory app.Test does not observe closure.
// Exercise cancellation both before headers and while reading the guest body.
func TestFileTransferCancellation(t *testing.T) {
	for _, method := range []string{"PUT", "GET"} {
		for _, phase := range []string{"headers", "response-body", "upload-body"} {
			if method == "GET" && phase == "upload-body" {
				continue
			}
			for _, cause := range []string{"disconnect", "teardown", "upstream-close"} {
				if cause == "upstream-close" && phase != "upload-body" {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%s", method, phase, cause), func(t *testing.T) {
					guest, e := net.Listen("tcp", "127.0.0.2:1025")
					if e != nil {
						t.Fatal(e)
					}
					defer guest.Close()
					accepted := make(chan net.Conn, 1)
					go func() {
						c, e := guest.Accept()
						if e != nil {
							return
						}
						c.SetDeadline(time.Now().Add(5 * time.Second))
						r := bufio.NewReader(c)
						r.ReadString('\n')
						q, e := http.ReadRequest(r)
						if e != nil {
							c.Close()
							return
						}
						if phase != "upload-body" {
							io.Copy(io.Discard, q.Body)
							q.Body.Close()
						} else {
							io.CopyN(io.Discard, q.Body, 300*1024)
						}
						if phase == "response-body" {
							fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nx")
						}
						accepted <- c
					}()
					lifetime, stopLifetime := context.WithCancel(context.Background())
					defer stopLifetime()
					s := &Server{Svc: fileLifetimeTestService{responseTestService{}, lifetime}}
					app := fiber.New(fiber.Config{DisableStartupMessage: true, StreamRequestBody: true, BodyLimit: 256 * 1024})
					if method == "PUT" {
						app.Put("/v1/sandboxes/:id/files", s.handleFileUpload)
					} else {
						app.Get("/v1/sandboxes/:id/files", s.handleFileDownload)
					}
					l, e := net.Listen("tcp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					defer l.Close()
					go app.Listener(l)
					defer app.ShutdownWithTimeout(time.Second)
					client, e := net.Dial("tcp", l.Addr().String())
					if e != nil {
						t.Fatal(e)
					}
					defer client.Close()
					body, length := "x", 1
					if phase == "upload-body" {
						body, length = strings.Repeat("x", 300*1024), 1024*1024
					}
					fmt.Fprintf(client, "%s /v1/sandboxes/test/files?path=/tmp/test HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n%s", method, length, body)
					var upstream net.Conn
					select {
					case upstream = <-accepted:
					case <-time.After(3 * time.Second):
						t.Fatal("guest not reached")
					}
					defer upstream.Close()
					if cause == "disconnect" {
						client.Close()
					} else if cause == "upstream-close" {
						upstream.Close()
					} else {
						stopLifetime()
					}
					upstream.SetReadDeadline(time.Now().Add(time.Second))
					_, e = io.Copy(io.Discard, upstream)
					if ne, ok := e.(net.Error); ok && ne.Timeout() {
						t.Fatal("guest connection not cancelled")
					}
					deadline := time.Now().Add(time.Second)
					for {
						s.fileMu.Lock()
						n := s.fileCount
						s.fileMu.Unlock()
						if n == 0 {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("transfer slot leaked")
						}
						time.Sleep(time.Millisecond)
					}
				})
			}
		}
	}
}

func TestFileTransferAdmission(t *testing.T) {
	s := &Server{}
	var releases []func()
	for i := 0; i < 64; i++ {
		release, ok := s.acquireFileTransfer(strconv.Itoa(i / 8))
		if !ok {
			t.Fatalf("transfer %d rejected", i)
		}
		releases = append(releases, release)
	}
	if _, ok := s.acquireFileTransfer("another"); ok {
		t.Fatal("host limit not enforced")
	}
	releases[63]()
	releases = releases[:63]
	if _, ok := s.acquireFileTransfer("0"); ok {
		t.Fatal("sandbox limit not enforced")
	}
	for _, release := range releases {
		release()
	}
	if s.fileCount != 0 || len(s.fileTransfers) != 0 {
		t.Fatal("transfer bookkeeping leaked")
	}
}
