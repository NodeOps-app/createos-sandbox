// Package gateway implements the SSH port-forwarding gateway for createos.
//
// Users SSH into this gateway with `-L` flags, authenticate via SSH public
// keys registered at sandbox-create time, and the gateway splices TCP
// traffic directly through the owning host's tunnel endpoint. Control
// supplies the sandbox's authorized keys and host address during authentication.
//
// Only `direct-tcpip` channels are permitted — no shells, no exec, no
// remote port forwarding (`-R`), no agent forwarding. The target of each
// `direct-tcpip` request is validated to be the authenticated sandbox
// itself (`localhost`, `127.0.0.1`, or the sandbox IP).
package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/NodeOps-app/createos-sandbox/internal/ca/crl"
	"github.com/NodeOps-app/createos-sandbox/internal/mtlsclient"
)

// Config configures a Gateway.
type Config struct {
	// Addr is the TCP listen address (e.g. ":2222").
	Addr string
	// HostKey is the gateway's SSH host key. If nil, Run generates an
	// ephemeral ed25519 key at startup and logs the fingerprint.
	HostKey ssh.Signer
	// ControlURL is the base URL of the control plane, e.g.
	// "http://localhost:8080". Gateway uses this for pubkey lookup and
	// for opening the host->guest tunnel via HTTP Upgrade. Outbound auth
	// is mTLS via TLS* below; no JWT path remains.
	ControlURL string
	// HTTP is the HTTP client used for JSON control-plane calls
	// (not the tunnel dial). Nil = default 10s timeout.
	HTTP *http.Client

	// mTLS outbound config. When all three paths are set, New() wires
	// the gateway's outbound http.Client + raw-TCP tunnel dial to present
	// the gateway's actor cert and verify control's TLS cert against the
	// CA bundle.
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string
}

// Gateway is the SSH port-forwarding gateway.
type Gateway struct {
	cfg Config

	wg       sync.WaitGroup
	listener net.Listener

	// outboundTLS is the client-side mTLS config used by openTunnel's
	// raw-TCP dial. A nil config makes host tunnel opens fail. Built in New().
	outboundTLS *tls.Config

	// crlFetcher supplies revocation checks for host tunnels and the default
	// HTTP client. Its bootstrap transport uses normal TLS verification.
	crlFetcher *crl.Fetcher

	// authLimiter throttles ssh public-key auth attempts per source IP
	// before control-plane lookup. This bounds repeated lookup attempts
	// from a source; it does not make authentication paths equal-time.
	authLimiter *connRateLimiter

	// Include channels still opening their upstream tunnel in admission counts.
	channelMu    sync.Mutex
	channels     map[string]int
	channelCount int
}

// New builds a Gateway. Call Run to start serving.
func New(cfg Config) *Gateway {
	g := &Gateway{}
	mtls := cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" && cfg.TLSCAPath != ""
	if mtls {
		tr, err := mtlsclient.NewTransport(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath, nil)
		if err != nil {
			// Host tunnels fail closed when their TLS configuration cannot load.
			log.Errorf("[gateway] outbound mTLS disabled: %v", err)
		} else {
			// Bootstrap CRL fetches verify TLS normally but cannot depend on
			// the revocation cache they populate. Keep that transport separate.
			g.crlFetcher = crl.New(cfg.ControlURL, &http.Client{Timeout: 10 * time.Second, Transport: tr})
			g.crlFetcher.Logger = log.WithField("component", "crl")
			g.outboundTLS = tr.TLSClientConfig.Clone()
			g.outboundTLS.VerifyPeerCertificate = g.crlFetcher.VerifyPeerCertificate
			g.outboundTLS.VerifyConnection = crl.VerifyConnectionFunc(g.crlFetcher.VerifyPeerCertificate)
			if cfg.HTTP == nil {
				httpTR := tr.Clone()
				httpTR.TLSClientConfig = g.outboundTLS.Clone()
				cfg.HTTP = &http.Client{Timeout: 10 * time.Second, Transport: httpTR}
			}
		}
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	g.cfg = cfg
	g.authLimiter = newConnRateLimiter()
	return g
}

// SetHostKey replaces the gateway's SSH host signer. Call before Run.
func (g *Gateway) SetHostKey(s ssh.Signer) { g.cfg.HostKey = s }

// SetHostKeyFromFile loads (or creates) an ed25519 host key at path.
// If path does not exist, a new key is generated and persisted. The key
// file is a raw ed25519 seed (32 bytes).
func (g *Gateway) SetHostKeyFromFile(path string) error {
	seed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return gerr
		}
		seed = priv.Seed()
		if werr := os.WriteFile(path, seed, 0o600); werr != nil {
			return werr
		}
		log.Infof("[gateway] generated new host key at %s", path)
	} else if err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return errors.New("gateway: host key file must contain a 32-byte ed25519 seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	g.cfg.HostKey = signer
	log.Infof("[gateway] host key loaded from %s fingerprint=%s",
		path, ssh.FingerprintSHA256(signer.PublicKey()))
	return nil
}

// Run starts the SSH listener and blocks until ctx is cancelled.
func (g *Gateway) Run(ctx context.Context) error {
	if g.crlFetcher != nil {
		go g.crlFetcher.Run(ctx)
	}

	if g.cfg.HostKey == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return err
		}
		g.cfg.HostKey = signer
		log.WithContext(ctx).Warnf("[gateway] host key is ephemeral fingerprint=%s "+
			"(set GATEWAY_HOST_KEY for a stable key)",
			ssh.FingerprintSHA256(signer.PublicKey()))
	}

	// Restrict negotiation to the explicit key-exchange, cipher, MAC,
	// and public-key algorithms below. Curve25519 is classical ECDH,
	// not a post-quantum key exchange.
	srvCfg := &ssh.ServerConfig{
		PublicKeyCallback: g.authPublicKey,
		// This compatibility banner is not the implementation version and
		// must not be used to identify the deployed gateway build.
		ServerVersion: "SSH-2.0-OpenSSH_9.6",
		// Cap auth attempts per connection (default is 6). Even though
		// every attempt has to go through PublicKeyCallback → fetchSandbox
		// → control plane, lowering the cap reduces request fan-out under
		// scan / brute attempts.
		MaxAuthTries: 3,
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
			},
			Ciphers: []string{
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
				"aes128-gcm@openssh.com",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
			},
		},
		// Only accept Ed25519 user pubkeys. We already store every
		// authorized key as Ed25519 (`ssh-keygen -t ed25519`); accepting
		// ssh-rsa (SHA-1 sig) or ssh-dss broadens the attack surface for
		// no operational gain.
		PublicKeyAuthAlgorithms: []string{
			ssh.KeyAlgoED25519,
		},
	}
	srvCfg.AddHostKey(g.cfg.HostKey)

	l, err := net.Listen("tcp", g.cfg.Addr)
	if err != nil {
		return err
	}
	g.listener = l
	log.WithContext(ctx).Infof("[gateway] listening on %s control=%s", g.cfg.Addr, g.cfg.ControlURL)

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.WithContext(ctx).Warnf("[gateway] accept: %v", err)
			continue
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.handleConn(ctx, c, srvCfg)
		}()
	}

	g.wg.Wait()
	return nil
}

// sessionMaxDuration is this gateway's 24-hour cap on an authenticated SSH
// connection. Expiry closes its TCP socket and all active forwards.
const sessionMaxDuration = 24 * time.Hour

// tcpKeepAlivePeriod is the TCP keepalive interval. With this set, an
// idle connection that the peer has silently lost (NAT timeout, peer
// reboot, network split) gets reaped by the kernel within roughly
// keepalivePeriod × probe_count instead of staying half-open forever.
const tcpKeepAlivePeriod = 60 * time.Second

// handleConn performs the SSH handshake for one TCP connection and
// dispatches channels for the lifetime of the SSH session.
func (g *Gateway) handleConn(_ context.Context, nc net.Conn, cfg *ssh.ServerConfig) {
	remote := nc.RemoteAddr().String()
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))

	// TCP keepalive on the underlying socket so a peer that vanishes
	// (NAT timeout, host reboot, network split) is reaped by the kernel
	// rather than held indefinitely as a half-open session. SSH itself
	// doesn't send keepalives — without this an attacker (or a bug) that
	// authenticates and then goes quiet ties up gateway resources forever.
	if tc, ok := nc.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	}

	sconn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Infof("[gateway] handshake remote=%s err=%v", remote, err)
		_ = nc.Close()
		return
	}
	_ = nc.SetDeadline(time.Time{})
	defer sconn.Close()

	// Hard cap on session lifetime. Spawn a watcher that closes the
	// underlying TCP after sessionMaxDuration; this in turn fails every
	// pending Read/Write on the SSH channels and unwinds the handler
	// loop. Defense against a privileged-but-buggy/compromised client
	// that authenticates and then squats on the session indefinitely.
	expiry := time.AfterFunc(sessionMaxDuration, func() {
		log.Infof("[gateway] session-max-duration reached, closing remote=%s", remote)
		_ = nc.Close()
	})
	defer expiry.Stop()

	sbID := ""
	if sconn.Permissions != nil {
		sbID = sconn.Permissions.Extensions["sandbox_id"]
	}
	log.Infof("[gateway] session-open remote=%s user=%s sandbox=%s",
		remote, sconn.User(), sbID)

	// Drop all global (connection-level) requests silently.
	go ssh.DiscardRequests(reqs)

	// Delegate channel handling.
	g.handleChannels(sconn, chans)

	log.Infof("[gateway] session-close remote=%s sandbox=%s", remote, sbID)
}
