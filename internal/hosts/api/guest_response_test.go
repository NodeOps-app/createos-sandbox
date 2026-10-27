package api

import (
	"bufio"
	"context"
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
