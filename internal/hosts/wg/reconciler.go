package wg

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer describes one mesh peer. Built by the caller from the hosts table.
type Peer struct {
	PublicKey wgtypes.Key
	Endpoint  *net.UDPAddr // peer's underlay:51820 — where to send WG handshakes
	WGIP      net.IP       // peer's 172.30.0.X — used for AllowedIPs and as next-hop for VM-subnet routes
	// VMSubnet is the peer's /22 of VM overlay IPs. Required so:
	//   1. WG AllowedIPs includes it — incoming packets sourced from any
	//      VM in that range are accepted; outgoing packets destined there
	//      are encrypted via this peer's session.
	//   2. EnsureRoutes installs `ip route <VMSubnet> via <WGIP> dev wg-hosts`
	//      so kernel-routed cross-host traffic finds the tunnel.
	VMSubnet *net.IPNet

	// ExtraAllowedIPs is additional CIDRs to include in this peer's
	// WG AllowedIPs filter. Used by relay peers to allow the CGNAT
	// device range (100.64.0.0/10) — without this, WG drops decrypted
	// packets whose source is a device IP because the source isn't
	// covered by VMSubnet or WGIP.
	ExtraAllowedIPs []net.IPNet
}

// PersistentKeepaliveSeconds is the canonical "stay alive through any
// reasonable NAT" interval. 25s is what WireGuard's own docs recommend.
const PersistentKeepaliveSeconds = 25

// ReconcilePeers diffs the kernel's current WG peer set against `desired`
// and applies add/remove with one wgctrl.ConfigureDevice call. Idempotent.
//
// Peers with an empty pubkey or nil endpoint are silently skipped (the
// host hasn't completed its registration yet — wait for the next tick).
func ReconcilePeers(ifaceName string, desired []Peer) error {
	cli, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl.New: %w", err)
	}
	defer cli.Close()

	dev, err := cli.Device(ifaceName)
	if err != nil {
		return fmt.Errorf("get device %s: %w", ifaceName, err)
	}

	// Index current peers by pubkey for fast membership tests.
	current := make(map[wgtypes.Key]wgtypes.Peer, len(dev.Peers))
	for _, p := range dev.Peers {
		current[p.PublicKey] = p
	}

	// Index desired by pubkey.
	want := make(map[wgtypes.Key]Peer, len(desired))
	for _, p := range desired {
		if p.Endpoint == nil || p.WGIP == nil {
			continue
		}
		want[p.PublicKey] = p
	}

	var cfg []wgtypes.PeerConfig
	keepalive := PersistentKeepaliveSeconds * time.Second

	// Adds + updates.
	for pubkey, p := range want {
		_, already := current[pubkey]
		allowed := []net.IPNet{
			{IP: p.WGIP, Mask: net.CIDRMask(32, 32)}, // peer's WG mesh IP
		}
		if p.VMSubnet != nil {
			// Path B: extend AllowedIPs to the peer's VM subnet so WG
			// (a) accepts decrypted packets sourced from any VM in that range
			// (b) directs outgoing packets destined for that range through
			//     this peer's session.
			allowed = append(allowed, *p.VMSubnet)
		}
		// Relay peers carry additional ranges (CGNAT device pool).
		allowed = append(allowed, p.ExtraAllowedIPs...)
		cfg = append(cfg, wgtypes.PeerConfig{
			PublicKey:                   pubkey,
			Endpoint:                    p.Endpoint,
			AllowedIPs:                  allowed,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &keepalive,
			// Force kernel state to match our config — wgctrl treats
			// UpdateOnly=false as upsert. Set Remove=false explicitly
			// for clarity.
			Remove:     false,
			UpdateOnly: already,
		})
	}

	// Removals: peers present in kernel that aren't in `want`.
	for pubkey := range current {
		if _, keep := want[pubkey]; keep {
			continue
		}
		cfg = append(cfg, wgtypes.PeerConfig{
			PublicKey: pubkey,
			Remove:    true,
		})
	}

	if len(cfg) == 0 {
		return nil
	}
	if err := cli.ConfigureDevice(ifaceName, wgtypes.Config{Peers: cfg}); err != nil {
		return fmt.Errorf("configure peers on %s: %w", ifaceName, err)
	}
	return nil
}

// EnsureRoutes installs `ip route <peer.VMSubnet> via <peer.WGIP> dev <iface>`
// for each peer with a non-empty VMSubnet. Idempotent — RouteReplace upserts.
// Also removes routes whose destination subnet is no longer in any peer's
// VMSubnet (cleanup on peer removal). The "createos-wg" protocol number
// identifies routes we own so we don't disturb other operator-owned routes.
const wgRouteProto = 0xFC // arbitrary, distinct from kernel/static/bgp/etc.

func EnsureRoutes(ifaceName string, peers []Peer) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", ifaceName, err)
	}

	// Desired: map subnet → next-hop WG IP.
	desired := make(map[string]net.IP, len(peers))
	for _, p := range peers {
		if p.VMSubnet == nil || p.WGIP == nil {
			continue
		}
		desired[p.VMSubnet.String()] = p.WGIP
	}

	// Apply desired.
	for cidr, gw := range desired {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Gw:        gw,
			Protocol:  wgRouteProto,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("route replace %s via %s: %w", cidr, gw, err)
		}
	}

	// Cleanup: list our existing routes on this iface and remove any not in desired.
	existing, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("route list %s: %w", ifaceName, err)
	}
	for _, r := range existing {
		if r.Protocol != wgRouteProto {
			continue // not ours
		}
		if r.Dst == nil {
			continue
		}
		if _, keep := desired[r.Dst.String()]; keep {
			continue
		}
		_ = netlink.RouteDel(&r)
	}
	return nil
}

// Config drives Run.
type Config struct {
	// IfaceName is the WG device to manage (e.g. "wg-hosts").
	IfaceName string
	// PeerSource returns the current desired peer set. Called every tick.
	PeerSource func(context.Context) ([]Peer, error)
	// Interval between ticks. Default 5s.
	Interval time.Duration
	// OnEnforce, if set, is invoked after a successful peer reconcile with
	// the same peer list. Used by the iptables enforcer so iptables and
	// peer state stay in sync from one source of truth.
	OnEnforce func([]Peer)
}

// Run starts the reconcile loop and blocks until ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()

	tick := func() {
		peers, err := cfg.PeerSource(ctx)
		if err != nil {
			log.WithContext(ctx).Warnf("[wg-reconciler] peer source: %v", err)
			return
		}
		if err := ReconcilePeers(cfg.IfaceName, peers); err != nil {
			log.WithContext(ctx).Warnf("[wg-reconciler] reconcile: %v", err)
			return
		}
		// Install per-peer kernel routes so cross-host VM traffic finds the
		// tunnel. Idempotent. Must come AFTER ReconcilePeers — installing a
		// route to a destination whose corresponding peer isn't configured
		// in WG would silently black-hole packets.
		if err := EnsureRoutes(cfg.IfaceName, peers); err != nil {
			log.WithContext(ctx).Warnf("[wg-reconciler] routes: %v", err)
			return
		}
		if cfg.OnEnforce != nil {
			cfg.OnEnforce(peers)
		}
	}

	tick() // sync first pass before sleeping
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			tick()
		}
	}
}
