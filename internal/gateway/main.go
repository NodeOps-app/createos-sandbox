// Package gateway implements the SSH port-forwarding gateway for createos.
//
// Users SSH into this gateway with `-L` flags, authenticate via SSH public
// keys registered at sandbox-create time, and the gateway splices TCP
// traffic through the control plane's tunnel endpoint to the sandbox on
// its owning host.
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

	"github.com/NodeOps-app/sandbox/internal/ca/crl"
	"github.com/NodeOps-app/sandbox/internal/mtlsclient"
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
	// raw-TCP dial. nil = plaintext. Built once at New() time.
	outboundTLS *tls.Config

	// crlFetcher polls control's CRL endpoint and gates outbound dials
	// in its VerifyPeerCertificate. nil when outbound mTLS is off.
	crlFetcher *crl.Fetcher

	// authLimiter throttles ssh public-key auth attempts per source IP
	// before the control-plane lookup runs. Defends against timing-based
	// sandbox-id enumeration (one DB read on hit vs O(µs) reject on miss).
	authLimiter *connRateLimiter
}

// New builds a Gateway. Call Run to start serving.
func New(cfg Config) *Gateway {
	g := &Gateway{}
	mtls := cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" && cfg.TLSCAPath != ""
	if mtls {
		tlsCfg, err := mtlsclient.NewTLSConfig(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath)
		if err != nil {
			// Fail loud at startup over latent: log and fall through
			// to plain HTTP. Internal control routes are mTLS-only in
			// production; this branch is for local-dev configs.
			log.Errorf("[gateway] outbound mTLS disabled: %v", err)
		} else {
			g.outboundTLS = tlsCfg
		}
	}
	if cfg.HTTP == nil {
		if g.outboundTLS != nil {
			// CRL fetcher uses a no-verify transport (otherwise it
			// can't bootstrap its own revocation cache). The main
			// transport then enforces revocation on every dial.
			crlTR, err := mtlsclient.NewTransport(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath, nil)
			if err != nil {
				log.Errorf("[gateway] crl http transport: %v", err)
				cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
			} else {
				g.crlFetcher = crl.New(cfg.ControlURL, &http.Client{Timeout: 10 * time.Second, Transport: crlTR})
				g.crlFetcher.Logger = log.WithField("component", "crl")
				tr, err := mtlsclient.NewTransportWithVerify(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath, nil, g.crlFetcher.VerifyPeerCertificate)
				if err != nil {
					log.Errorf("[gateway] outbound mTLS http transport: %v", err)
					cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
				} else {
					cfg.HTTP = &http.Client{Timeout: 10 * time.Second, Transport: tr}
				}
			}
		} else {
			cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
		}
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

	// Restrict every negotiable algorithm to a small modern set. The
	// x/crypto default accepts ssh-rsa / hmac-sha1 / dh-group14-sha1 etc.
	// for compatibility; we don't need that — createos-cli, OpenSSH 7.7+, every
	// modern client supports the post-quantum-ready curve25519 + AES-GCM /
	// ChaCha20 + HMAC-SHA2-ETM / Ed25519 stack.
	srvCfg := &ssh.ServerConfig{
		PublicKeyCallback: g.authPublicKey,
		// Banner masks the gateway's actual implementation. Banner-only
		// spoofing buys little against a determined adversary (the kex
		// algorithm list, error-message phrasing, and channel-open
		// rejection codes still fingerprint x/crypto/ssh in seconds via
		// nmap/ssh-audit), but it does drop us off the radar of casual
		// service-banner scans.
		//
		// IMPORTANT for operators: any internal log search filtering on
		// the banner string (e.g. "find gateway by SSH banner") must
		// now use the listener port or createos-cli's mTLS metadata instead —
		// this banner is intentionally not a unique identifier.
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

// sessionMaxDuration caps the lifetime of any single SSH session. After
// this window the gateway force-closes the underlying TCP, dropping every
// active port-forward through it. 24h is the standard SSH server default
// (compatible with overnight `createos-cli shell` workflows but bounded against
// indefinite resource hold). Made package-level so it's discoverable from
// future config knobs.
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
