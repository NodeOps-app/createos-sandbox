package agent

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/NodeOps-app/sandbox/internal/agent/computer"
	agentprocess "github.com/NodeOps-app/sandbox/internal/agent/process"
)

// processPort is the guest-internal HTTP API for managed pipe and PTY
// processes. It uses the same per-VM AUTH handshake as the other agent APIs.
const processPort = 1028

// bindProcesses reserves the listener during phase 1 so the socket and its
// accept queue survive in the template snapshot. No requests are accepted
// until phase 2 has mounted the sandbox rootfs and initialized cgroup v2.
func bindProcesses() (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", processPort))
}

// serveProcessesOn starts the managed-process HTTP API after restore. The
// shared authListener requires AUTH <token> before any bytes reach net/http.
// There is intentionally no server-wide read or write deadline: process output
// streams and waits may live for the sandbox's lifetime.
func serveProcessesOn(listener net.Listener, manager *agentprocess.Manager) {
	handler, err := agentprocess.NewHTTPHandler(manager)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: initialize process HTTP handler: %v\n", err)
		return
	}

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/v1/processes", handler)
		mux.Handle("/v1/processes/", handler)
		mux.Handle("/v1/computer/", computer.NewHTTPHandler())
		server := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 2 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		fmt.Printf("agent: process server on %s\n", listener.Addr())
		if err := server.Serve(&authListener{Listener: listener}); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "agent: process server: %v\n", err)
		}
	}()
}
