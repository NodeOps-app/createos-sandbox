package relay

// bootstrap.go — relay's bring-up flow onto the wg-hosts mesh.
//
// Lifecycle of bootstrap(ctx, cfg):
//
//  1. Detect underlay IP (UDP-connect probe to control URL).
//  2. Load (or generate) the host's WireGuard keypair from disk.
//  3. POST /v1/internal/hosts/register with our pubkey + region + role.
//     Control allocates a wg-hosts /32 (the /22 VM subnet allocator
//     fires too but relays never use it).
//  4. Bring up the `wg-hosts` kernel iface with the assigned IP.
//  5. Start the wg-hosts peer reconciler (60s tick).
//  6. Start the heartbeat loop (5s tick).
//
// Owned by the relay binary — compute hosts (machine host) have their
// own inline bring-up and DO NOT share this code path.

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/NodeOps-app/sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/sandbox/internal/hosts/wg"
	authjwt "github.com/NodeOps-app/sandbox/internal/jwt"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/models"
)

// bootstrapConfig is everything bootstrap() needs from the caller.
type bootstrapConfig struct {
	// Identity — who we are on the mesh.
	HostID string
	Region string
	Addr   string // host:port advertised on hosts.addr for peers to dial

	// Control plane.
	ControlURL     string
	BootstrapToken string                // for register only
	Client         *controlclient.Client // pre-built mTLS client

	// Disk-persisted identity material. Created at mode 0600 on first call.
	SigningKeyPath string // ed25519 host signing key
	WGSigningKey   string // WG mesh private key (wg-hosts)
	WGPort         int    // UDP port wg-hosts listens on (defaults to 51820)

	// wg-devices pubkey, sent on register so the session-create handler
	// can hand it to clients in their wg-quick configs.
	RelayDevicesPubkey []byte
}

// bootstrapHandle is what the caller holds after bootstrap returns —
// trimmed to the two things we actually use.
type bootstrapHandle struct {
	WGIP  string
	close context.CancelFunc
}

// Close cancels the peer reconciler + heartbeat goroutines. The
// wg-hosts iface itself is left up — Linux WG ifaces survive process
// exit and the next process reconciles them back into shape.
func (h *bootstrapHandle) Close() {
	if h != nil && h.close != nil {
		h.close()
	}
}

// bootstrap runs the bring-up and returns once register + iface up have
// completed. Background goroutines run until handle.Close() or the
// parent ctx is cancelled.
func bootstrap(ctx context.Context, cfg bootstrapConfig) (*bootstrapHandle, error) {
	if cfg.HostID == "" {
		return nil, fmt.Errorf("bootstrap: HostID required")
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("bootstrap: Region required")
	}
	if cfg.ControlURL == "" {
		return nil, fmt.Errorf("bootstrap: ControlURL required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("bootstrap: Client required")
	}
	if cfg.WGPort == 0 {
		cfg.WGPort = 51820
	}

	underlayIP := detectOutboundIP(cfg.ControlURL)

	hostPriv, err := authjwt.LoadOrGenerateSeed(cfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load host signing key: %w", err)
	}
	hostPub := hostPriv.Public().(ed25519.PublicKey)

	wgPriv, err := wg.LoadOrCreateKey(cfg.WGSigningKey)
	if err != nil {
		return nil, fmt.Errorf("load WG key: %w", err)
	}
	wgPub := wgPriv.PublicKey()

	resp, err := cfg.Client.Register(ctx, proto.ControlHostRegisterReq{
		ID:                 cfg.HostID,
		Addr:               cfg.Addr,
		Rootfses:           []string{},
		PublicKey:          hostPub,
		UnderlayIP:         underlayIP,
		Region:             cfg.Region,
		WGPublicKey:        wgPub[:],
		Role:               models.HostRoleRelay,
		RelayDevicesPubkey: cfg.RelayDevicesPubkey,
	}, cfg.BootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	if resp.WGIP == "" {
		return nil, fmt.Errorf("register: control returned empty wg_ip — allocator exhausted?")
	}

	wgIP := net.ParseIP(resp.WGIP)
	if wgIP == nil {
		return nil, fmt.Errorf("control returned malformed wg_ip %q", resp.WGIP)
	}
	wgAddr := &net.IPNet{IP: wgIP, Mask: net.CIDRMask(16, 32)}
	if err := wg.EnsureInterface("wg-hosts", cfg.WGPort, wgPriv, wgAddr); err != nil {
		return nil, fmt.Errorf("bring up wg-hosts: %w", err)
	}
	log.WithContext(ctx).Infof("[relay-bootstrap] %s registered as role=relay wg=%s", cfg.HostID, resp.WGIP)

	loopCtx, cancel := context.WithCancel(ctx)
	go runPeerReconciler(loopCtx, cfg)
	go runHeartbeat(loopCtx, cfg)

	return &bootstrapHandle{WGIP: resp.WGIP, close: cancel}, nil
}

func runPeerReconciler(ctx context.Context, cfg bootstrapConfig) {
	err := wg.Run(ctx, wg.Config{
		IfaceName: "wg-hosts",
		PeerSource: func(ctx context.Context) ([]wg.Peer, error) {
			return buildWGPeers(ctx, cfg.Client, cfg.HostID, cfg.WGPort)
		},
		Interval: 60 * time.Second,
		OnEnforce: func(peers []wg.Peer) {
			if err := wg.Enforce("wg-hosts", cfg.WGPort, peers); err != nil {
				log.WithContext(ctx).Warnf("[relay-bootstrap] iptables: %v", err)
			}
		},
	})
	if err != nil && ctx.Err() == nil {
		log.WithContext(ctx).Errorf("[relay-bootstrap] peer reconciler exited: %v", err)
	}
}

func runHeartbeat(ctx context.Context, cfg bootstrapConfig) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := cfg.Client.Heartbeat(ctx, proto.ControlHostHeartbeatReq{
				ID:     cfg.HostID,
				Status: "active",
			}); err != nil {
				log.WithContext(ctx).Debugf("[relay-bootstrap] heartbeat: %v", err)
			}
		}
	}
}

// buildWGPeers reads the fleet host list from control and turns it into
// a wg.Peer set. Self, dead hosts, and any not-yet-fully-registered peer are
// skipped. Draining hosts remain reachable until their existing VMs are gone.
// Sorted output keeps wgctrl diffs stable across ticks.
func buildWGPeers(ctx context.Context, client *controlclient.Client, selfID string, port int) ([]wg.Peer, error) {
	hosts, err := client.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].ID < hosts[j].ID })

	out := make([]wg.Peer, 0, len(hosts))
	for _, h := range hosts {
		if h.ID == selfID {
			continue
		}
		if h.Status == models.HostStatusDead {
			continue
		}
		if len(h.WGPublicKey) != wgtypes.KeyLen || h.WGIP == "" {
			continue
		}
		if h.UnderlayIP == nil || *h.UnderlayIP == "" {
			continue
		}
		var pk wgtypes.Key
		copy(pk[:], h.WGPublicKey)
		endpointIP := net.ParseIP(*h.UnderlayIP)
		if endpointIP == nil {
			continue
		}
		wgIP := net.ParseIP(h.WGIP)
		if wgIP == nil {
			continue
		}
		var subnet *net.IPNet
		if h.SubnetCIDR != nil && *h.SubnetCIDR != "" {
			if _, sn, err := net.ParseCIDR(*h.SubnetCIDR); err == nil {
				subnet = sn
			}
		}
		var extra []net.IPNet
		if h.Role == models.HostRoleRelay {
			// Relays carry device traffic with src in 100.64.0.0/10 —
			// add to AllowedIPs so WG accepts decrypted device packets.
			_, devicePool, _ := net.ParseCIDR("100.64.0.0/10")
			if devicePool != nil {
				extra = append(extra, *devicePool)
			}
		}
		out = append(out, wg.Peer{
			PublicKey:       pk,
			Endpoint:        &net.UDPAddr{IP: endpointIP, Port: port},
			WGIP:            wgIP,
			VMSubnet:        subnet,
			ExtraAllowedIPs: extra,
		})
	}
	return out, nil
}

// detectOutboundIP returns the local IP the kernel would use to reach
// controlURL. UDP-connect-only — no packet leaves the box. Falls back
// to the first non-loopback IPv4 if the dial fails.
func detectOutboundIP(controlURL string) string {
	host := stripHostPort(controlURL)
	if host == "" {
		host = "8.8.8.8"
	}
	conn, err := net.Dial("udp", host+":80")
	if err == nil {
		defer conn.Close()
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && !ua.IP.IsLoopback() {
			return ua.IP.String()
		}
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		return ip.String()
	}
	return ""
}

func stripHostPort(controlURL string) string {
	for _, p := range []string{"https://", "http://"} {
		if len(controlURL) > len(p) && controlURL[:len(p)] == p {
			controlURL = controlURL[len(p):]
			break
		}
	}
	for i := 0; i < len(controlURL); i++ {
		if controlURL[i] == ':' || controlURL[i] == '/' {
			return controlURL[:i]
		}
	}
	return controlURL
}
