package hostproxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// SO_ORIGINAL_DST is the Linux IPv4 getsockopt used to recover the pre-DNAT
// destination of a REDIRECT'd connection.
const SO_ORIGINAL_DST = 80

// Proxy is a transparent egress proxy that inspects TLS SNI / HTTP Host on
// REDIRECT'd connections and enforces a per-source-IP egress allowlist.
type Proxy struct {
	HTTPAddr  string
	HTTPSAddr string
	Cache     *Cache
	Logger    *log.Logger

	// SniffTimeout bounds how long the ClientHello/Host peek may take.
	// Zero means use the default (500ms).
	SniffTimeout time.Duration

	domains *domainResolver
}

// New wires a Proxy with an APIClient + Cache. apiClient must already
// carry the mTLS bundle the by-ip route needs — control's route is
// gated on a verified SPIFFE-URI client cert.
func New(httpAddr, httpsAddr, apiURL string, apiClient *http.Client, cacheTTL time.Duration) *Proxy {
	api := NewAPIClient(apiURL, apiClient)
	cache := NewCache(cacheTTL, api.FetchEgress)
	return &Proxy{
		HTTPAddr:     httpAddr,
		HTTPSAddr:    httpsAddr,
		Cache:        cache,
		Logger:       log.New(os.Stderr, "proxy ", log.LstdFlags|log.Lmicroseconds),
		SniffTimeout: 500 * time.Millisecond,
		domains:      newDomainResolver(net.DefaultResolver, 30*time.Second),
	}
}

// Run starts both listeners and blocks until ctx is cancelled.
func (p *Proxy) Run(ctx context.Context) error {
	var lc net.ListenConfig
	httpLn, err := lc.Listen(ctx, "tcp", p.HTTPAddr)
	if err != nil {
		return err
	}
	httpsLn, err := lc.Listen(ctx, "tcp", p.HTTPSAddr)
	if err != nil {
		httpLn.Close()
		return err
	}

	// Inbound :8443 is intentionally plain TCP — the proxy peeks at the
	// TLS ClientHello bytes to extract SNI then forwards bytes verbatim
	// to the original destination. VMs aren't part of the mTLS mesh,
	// so we never terminate TLS here. (The TLSCert/Key/CA paths are
	// only used for the OUTBOUND proxy→control mTLS client.)
	p.Logger.Printf("listening http=%s https=%s (transparent SNI sniff)",
		p.HTTPAddr, p.HTTPSAddr)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.acceptLoop(ctx, httpLn, false) }()
	go func() { defer wg.Done(); p.acceptLoop(ctx, httpsLn, true) }()

	<-ctx.Done()
	httpLn.Close()
	httpsLn.Close()
	wg.Wait()
	return ctx.Err()
}

func (p *Proxy) acceptLoop(ctx context.Context, ln net.Listener, isTLS bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			p.Logger.Printf("accept error: %v", err)
			continue
		}
		go p.handle(ctx, conn, isTLS)
	}
}

func (p *Proxy) handle(ctx context.Context, conn net.Conn, isTLS bool) {
	start := time.Now()
	defer conn.Close()

	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		p.Logger.Printf("non-tcp conn rejected")
		return
	}

	srcIP, _, _ := net.SplitHostPort(tcp.RemoteAddr().String())

	origIP, origPort, err := originalDst(tcp)
	if err != nil {
		p.Logger.Printf("src=%s so_original_dst error: %v", srcIP, err)
		return
	}

	entry, err := p.Cache.Lookup(ctx, srcIP)
	if err != nil {
		p.Logger.Printf("src=%s dst=%s:%d verdict=api-error err=%v", srcIP, origIP, origPort, err)
		return
	}
	if entry == nil || entry.Negative {
		p.Logger.Printf("src=%s dst=%s:%d verdict=unknown-src", srcIP, origIP, origPort)
		return
	}

	var (
		host         string
		peeked       []byte
		verdict      = "deny"
		domainTarget bool
	)

	allowAll := AllowAll(entry.Rules)
	if !allowAll {
		host, peeked, _ = SniffHostname(tcp, p.SniffTimeout)
		switch {
		case host != "" && MatchDomain(entry.Rules, host, origPort):
			verdict = "allow"
			domainTarget = true
		case MatchIP(entry.Rules, origIP, origPort):
			verdict = "allow"
		}
	} else {
		verdict = "allow"
	}

	if verdict != "allow" {
		p.Logger.Printf("src=%s sandbox=%s dst=%s (%s:%d) verdict=deny dur=%s",
			srcIP, entry.SandboxID, displayHost(host), origIP, origPort, time.Since(start))
		return
	}

	var (
		upstream net.Conn
		dialIP   = origIP
	)
	if domainTarget {
		// SNI and HTTP Host are assertions made by the untrusted VM. Never
		// combine an allowed asserted hostname with the VM-selected original
		// destination: a client that disables TLS verification could otherwise
		// put an allowlisted name in SNI while connecting to any IP. Resolve and
		// select the destination in the trusted host namespace instead.
		upstream, dialIP, err = p.domains.Dial(ctx, host, origPort)
	} else {
		upstream, err = net.DialTimeout("tcp", net.JoinHostPort(origIP.String(), itoa(origPort)), 5*time.Second)
	}
	if err != nil {
		p.Logger.Printf("src=%s sandbox=%s dst=%s (%s:%d) verdict=dial-fail err=%v",
			srcIP, entry.SandboxID, displayHost(host), origIP, origPort, err)
		return
	}
	defer upstream.Close()

	if len(peeked) > 0 {
		if _, err := upstream.Write(peeked); err != nil {
			p.Logger.Printf("src=%s sandbox=%s dst=%s:%d verdict=replay-fail err=%v",
				srcIP, entry.SandboxID, origIP, origPort, err)
			return
		}
	}

	nUp, nDown := splice(tcp, upstream)

	p.Logger.Printf("src=%s sandbox=%s dst=%s (%s:%d) dial_ip=%s verdict=allow bytes=%d/%d dur=%s",
		srcIP, entry.SandboxID, displayHost(host), origIP, origPort, dialIP, nUp, nDown, time.Since(start))
}

func displayHost(h string) string {
	if h == "" {
		return "-"
	}
	return h
}

// splice copies bytes bidirectionally between client and upstream until
// either side closes. Returns (client->upstream bytes, upstream->client bytes).
func splice(client, upstream net.Conn) (int64, int64) {
	var (
		up, down int64
		wg       sync.WaitGroup
	)
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, client)
		atomic.StoreInt64(&up, n)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // half-close is best-effort; the peer may already be gone
		} else {
			upstream.Close()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, upstream)
		atomic.StoreInt64(&down, n)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // half-close is best-effort; the peer may already be gone
		} else {
			client.Close()
		}
	}()
	wg.Wait()
	return atomic.LoadInt64(&up), atomic.LoadInt64(&down)
}

// originalDst returns the pre-DNAT destination of a REDIRECT'd TCP connection.
func originalDst(conn *net.TCPConn) (net.IP, int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var addr syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		_, _, e := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_IP),
			uintptr(SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if e != 0 {
			sockErr = e
		}
	})
	if ctrlErr != nil {
		return nil, 0, ctrlErr
	}
	if sockErr != nil {
		return nil, 0, sockErr
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	// Port is stored big-endian in sockaddr.
	port := int(addr.Port>>8) | int(addr.Port&0xff)<<8
	return ip, port, nil
}

// itoa avoids strconv for a tiny hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
