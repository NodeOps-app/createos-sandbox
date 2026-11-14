package api

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func TestProcessAndComputerDisconnect(t *testing.T) {
	for _, kind := range []string{"process", "connect", "computer"} {
		for _, phase := range []string{"headers", "body"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				guest, err := net.Listen("tcp", "127.0.0.2:1028")
				if err != nil {
					t.Fatal(err)
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
					io.Copy(io.Discard, q.Body)
					q.Body.Close()
					if phase == "body" {
						fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nx")
					}
					accepted <- c
				}()
				s := &Server{Svc: responseTestService{}}
				app := fiber.New(fiber.Config{DisableStartupMessage: true, Immutable: true})
				path := "/v1/sandboxes/test/processes"
				switch kind {
				case "process":
					app.Get("/v1/sandboxes/:id/processes", s.handleProcessProxy)
				case "connect":
					app.Get("/v1/sandboxes/:id/processes", s.handleProcessConnect)
				case "computer":
					path = "/v1/sandboxes/test/computer/cursor"
					app.Get("/v1/sandboxes/:id/computer/cursor", s.handleComputerProxy)
				}
				listener, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer listener.Close()
				go app.Listener(listener)
				defer app.ShutdownWithTimeout(time.Second)
				client, e := net.Dial("tcp", listener.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
				fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", path)
				var upstream net.Conn
				select {
				case upstream = <-accepted:
				case <-time.After(2 * time.Second):
					t.Fatal("guest not reached")
				}
				defer upstream.Close()
				client.Close()
				upstream.SetReadDeadline(time.Now().Add(time.Second))
				_, e = io.Copy(io.Discard, upstream)
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					t.Fatal("guest request still open after downstream disconnected")
				}
				deadline := time.Now().Add(time.Second)
				for {
					s.processMu.Lock()
					remaining := s.processCount
					s.processMu.Unlock()
					if remaining == 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("request admission leaked")
					}
					time.Sleep(time.Millisecond)
				}
				t.Log("guest connection and request slot released after disconnect")
			})
		}
	}
}

func TestProcessRequestAdmission(t *testing.T) {
	s := &Server{}
	var stops []func()
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()
	app := fiber.New()
	app.Get("/:id", func(c *fiber.Ctx) error {
		ctx, stop, ok := s.beginProcessRequest(c, false)
		if !ok {
			return c.SendStatus(http.StatusTooManyRequests)
		}
		stops = append(stops, stop)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > processRequestTimeout || time.Until(deadline) < 30*time.Second {
			t.Error("buffered request lacks bounded deadline allowing guest wait")
		}
		return c.SendStatus(http.StatusOK)
	})
	check := func(id string, want int) {
		t.Helper()
		resp, err := app.Test(httptest.NewRequest("GET", "/"+id, nil))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("status=%d want=%d", resp.StatusCode, want)
		}
	}
	for i := 0; i < maxHostProcessRequests; i++ {
		check(fmt.Sprintf("sandbox-%d", i/maxSandboxProcessRequests), 200)
		if i == maxSandboxProcessRequests-1 {
			check("sandbox-0", 429)
		}
	}
	check("another", 429)
	stops[0]()
	stops[0]() // Cleanup is idempotent across handler and stream paths.
	stops = stops[1:]
	check("sandbox-0", 200)
	for _, stop := range stops {
		stop()
	}
	stops = nil
	if s.processCount != 0 || len(s.processRequests) != 0 {
		t.Fatal("idle admission state retained")
	}
}

func TestProcessConnectPreservesStreaming(t *testing.T) {
	guest, err := net.Listen("tcp", "127.0.0.2:1028")
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := guest.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(conn)
		if _, err = r.ReadString('\n'); err != nil {
			return
		}
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		req.Body.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\none\n")
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(conn, "two")
	}()
	server := &Server{Svc: responseTestService{}}
	app := fiber.New(fiber.Config{DisableStartupMessage: true, Immutable: true})
	app.Get("/v1/sandboxes/:id/processes", server.handleProcessConnect)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go app.Listener(listener)
	defer app.ShutdownWithTimeout(time.Second)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + listener.Addr().String() + "/v1/sandboxes/test/processes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "one\ntwo" {
		t.Fatalf("stream was interrupted: %q %v", body, err)
	}
	<-done
}
