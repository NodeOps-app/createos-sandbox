package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

// SYS_OPENAT2 is 437 on every Linux arch we ship for (amd64, arm64) — stable
// since 5.6. Go's stdlib doesn't expose the constant so we hardcode the
// number rather than pull in golang.org/x/sys (the agent is stdlib-only).
const sysOpenat2 = 437

// resolveNoSymlinks refuses to follow ANY symlink in the resolved path —
// including intermediate directory components. Closes the "guest plants
// /var/log/symdir → /etc and waits for an upload to /var/log/symdir/x" attack
// that plain O_NOFOLLOW (only checks the final component) does not.
const resolveNoSymlinks = 0x04

// openHow is the argument layout for openat2(2). Three little-endian
// uint64 fields with no padding — sizeof(struct open_how)=24.
type openHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

// openat2NoSymlinks opens an absolute path with RESOLVE_NO_SYMLINKS so a
// symlink at ANY component of the resolved path returns ELOOP. Falls back
// to the caller's O_NOFOLLOW path when openat2 isn't available (kernel
// pre-5.6 — we don't ship those but be defensive).
func openat2NoSymlinks(path string, flags int, mode uint32) (int, error) {
	how := openHow{
		Flags:   uint64(flags),
		Mode:    uint64(mode),
		Resolve: resolveNoSymlinks,
	}
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	atFDCWD := int64(-100)
	r1, _, errno := syscall.Syscall6(
		sysOpenat2,
		uintptr(atFDCWD),
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&how)),
		unsafe.Sizeof(how),
		0, 0,
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

// forbiddenPathPrefixes are kernel/device pseudo-filesystems the file API
// must never reach. The agent runs as PID 1 (root) inside the guest, so
// without this guard a `PUT /files/proc/self/mem` or
// `PUT /files/sys/kernel/sysrq` would actually work. None of these paths
// have any legitimate use through the file API — code uploads land under
// /workspace, /tmp, /home, /root, /etc/createos (hooks), etc.
var forbiddenPathPrefixes = []string{
	"/proc/",
	"/sys/",
	"/dev/",
	"/boot/",
	"/run/createos/", // agent-internal sockets / runtime state
}

// filePort is the TCP port the agent's file server listens on. Separate from
// the exec port (1024) so the exec protocol stays pure JSON framing.
const filePort = 1025

// bindFiles creates the listener for the file server without starting the
// accept loop. Called in phase 1 so the bound socket is captured in the
// snapshot — on restore, SYNs from the host get SYN-ACK'd immediately even
// while phase 2 is still mounting the overlay.
func bindFiles() (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", filePort))
}

// serveFilesOn runs the HTTP file server on a pre-bound listener. Called in
// phase 2 after the overlay is mounted (we need a writable fs before handling
// PUTs). Routes:
//
//	PUT  /files/<abs-path>   — write request body to <abs-path>, mkdir -p parents
//	GET  /files/<abs-path>   — stream the file contents
//	HEAD /files/<abs-path>   — return Content-Length + X-File-Mode for metadata
func serveFilesOn(l net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("/files/", handleFile)
	mux.HandleFunc("/disks/status", handleDiskStatus)
	mux.HandleFunc("/meminfo", handleMeminfo)
	mux.HandleFunc("/storage", handleStorage)
	go func() {
		// ReadHeaderTimeout bounds a client that opens a conn and dribbles
		// headers forever — the guest agent has no other request timeout.
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}
		fmt.Printf("agent: file server on %s\n", l.Addr())
		// authListener wraps every accepted conn with the AUTH-line
		// handshake before handing it to the HTTP server. Failed auth
		// closes the conn silently and Accept loops to the next inbound.
		if err := srv.Serve(&authListener{Listener: l}); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "agent: file server: %v\n", err)
		}
	}()
}

// authListener wraps a net.Listener so each accepted connection must
// present a valid "AUTH <token>\n" line before its bytes reach the HTTP
// server. Failed handshakes close the conn and the listener loops to the
// next Accept — http.Server never sees them.
type authListener struct {
	net.Listener
}

func (a *authListener) Accept() (net.Conn, error) {
	for {
		c, err := a.Listener.Accept()
		if err != nil {
			return nil, err
		}
		br := authenticateConn(c)
		if br == nil {
			continue // closed inside authenticateConn; try the next inbound
		}
		return &bufConn{Conn: c, r: br}, nil
	}
}

// bufConn wraps a net.Conn so that bytes already buffered by the auth
// handshake's bufio.Reader are surfaced through Read. Without this the
// HTTP server would re-read directly from the underlying socket and lose
// the request bytes that came right after the AUTH line.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func handleFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/files")
	if path == "" || !strings.HasPrefix(path, "/") || filepath.Clean(path) != path {
		http.Error(w, "path must be absolute and canonical", http.StatusBadRequest)
		return
	}
	for _, prefix := range forbiddenPathPrefixes {
		if strings.HasPrefix(path, prefix) || path == strings.TrimSuffix(prefix, "/") {
			http.Error(w, "path under kernel/device pseudo-fs is not writable via file API", http.StatusForbidden)
			return
		}
	}

	// openat2(RESOLVE_NO_SYMLINKS) refuses to follow ANY symlink in the
	// resolved path — including intermediate components. Plain O_NOFOLLOW
	// only checks the final element, so a guest workload could plant
	// `ln -s /etc /var/log/sym` and an upload to `/var/log/sym/passwd`
	// would land in /etc/passwd. The agent runs as PID 1 (root) inside
	// the VM; we want every file API write to land where the URL says.
	switch r.Method {
	case http.MethodPut:
		if r.ContentLength > proto.MaxFileUploadBytes {
			http.Error(w, "file exceeds 10 GiB limit", http.StatusRequestEntityTooLarge)
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			http.Error(w, "mkdir: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 0644 (rw for owner, r for group/world). Single-tenant guest
		// today, but use a sensible explicit mode rather than relying on
		// umask — a future change to multi-user images doesn't want
		// every uploaded file world-writable.
		fd, err := openat2NoSymlinks(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				http.Error(w, "refuse to write through symlink", http.StatusBadRequest)
				return
			}
			http.Error(w, "create: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f := os.NewFile(uintptr(fd), path)
		defer f.Close()
		limitedBody := http.MaxBytesReader(w, r.Body, proto.MaxFileUploadBytes)
		n, err := io.Copy(f, limitedBody)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "file exceeds 10 GiB limit", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "write: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"bytes":%d,"path":%q}}`+"\n", n, path)

	case http.MethodGet:
		fd, err := openat2NoSymlinks(path, os.O_RDONLY, 0)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, syscall.ELOOP) {
				http.Error(w, "refuse to read through symlink", http.StatusBadRequest)
				return
			}
			http.Error(w, "open: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f := os.NewFile(uintptr(fd), path)
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.Error(w, "stat: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if st.IsDir() {
			http.Error(w, "is a directory", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		w.Header().Set("X-File-Mode", fmt.Sprintf("%o", st.Mode().Perm()))
		_, _ = io.Copy(w, f)

	case http.MethodHead:
		// Lstat — report on the symlink itself, not its target. Matches
		// the GET path's O_NOFOLLOW semantics.
		st, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "stat: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if st.Mode()&os.ModeSymlink != 0 {
			http.Error(w, "refuse to stat symlink target", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		w.Header().Set("X-File-Mode", fmt.Sprintf("%o", st.Mode().Perm()))

	default:
		w.Header().Set("Allow", "GET, PUT, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
