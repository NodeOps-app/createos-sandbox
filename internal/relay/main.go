package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/wg"
)

// Relay is the runtime state for `control relay`. In-memory state is
// reconstructed on every boot using cfg and persisted identity files.
// Reconciliation data (sessions, BPF pairs) comes from control's
// /v1/internal/relay-state endpoint over mTLS, NOT a direct DB
// connection — keeps DB credentials off relay boxes.
type Relay struct {
	cfg config.RelayConfig

	// Control-plane client — reused across registration, heartbeat, and
	// per-tick relay-state polls. Same mTLS material as bootstrap.
	ctrl *controlclient.Client

	policy *vm.RelayPolicy
}

func New(cfg config.RelayConfig) *Relay { return &Relay{cfg: cfg} }

// Run blocks until ctx is cancelled. Joins the wg-hosts mesh via
// bootstrap (registers as role=relay), brings up wg-devices for
// user-side WG, and reconciles device-session peers every 5s.
func (r *Relay) Run(ctx context.Context) (runErr error) {
	// Kernel interfaces outlive the process. Remove old peers before any
	// startup work, and stop device traffic on every normal/error exit.
	if err := wg.RemoveInterface("wg-devices"); err != nil {
		return fmt.Errorf("reset wg-devices: %w", err)
	}
	defer func() {
		runErr = errors.Join(runErr, wg.RemoveInterface("wg-devices"))
		if r.policy != nil {
			r.policy.Close()
		}
	}()

	// Resolve bootstrap token: prefer file (mode 0600, off the cmdline)
	// over the literal flag value. The flag form leaks via
	// /proc/<pid>/cmdline and `ps`; the file form is mountable from a
	// k8s Secret or systemd LoadCredential.
	if r.cfg.BootstrapTokenFile != "" {
		b, err := os.ReadFile(r.cfg.BootstrapTokenFile)
		if err != nil {
			return fmt.Errorf("read bootstrap-token-file %s: %w", r.cfg.BootstrapTokenFile, err)
		}
		r.cfg.BootstrapToken = strings.TrimSpace(string(b))
	}

	// 1. First-issue mTLS leaf cert via bootstrap token. Idempotent —
	// no-op if cert already exists on disk. The relay's peer reconciler
	// needs mTLS to call /v1/internal/db/hosts; without it, the relay
	// can decrypt device packets but can't list compute hosts to peer
	// with, so cross-host traffic dies.
	if r.cfg.TLSCertPath != "" && r.cfg.BootstrapToken != "" {
		if err := firstIssueCert(ctx, csrConfig{
			HostID:         r.cfg.HostID,
			ControlURL:     r.cfg.ControlURL,
			BootstrapToken: r.cfg.BootstrapToken,
			CertPath:       r.cfg.TLSCertPath,
			KeyPath:        r.cfg.TLSKeyPath,
			CAPath:         r.cfg.TLSCAPath,
		}); err != nil {
			return fmt.Errorf("first-issue cert: %w", err)
		}
	}

	// 2. Load wg-devices key UP FRONT — its pubkey needs to be in the
	// register request so the API can hand it to clients in wg-quick
	// configs. (wg-hosts key is loaded separately by bootstrap.)
	devicesKey, err := loadOrCreateWGKey(r.cfg.WGDevicesPrivKey)
	if err != nil {
		return fmt.Errorf("wg-devices key: %w", err)
	}
	devicesPubkey := devicesKey.PublicKey()

	// 3. Bootstrap onto the wg-hosts mesh. Same dance as `machine host`:
	// register, allocate WG IP, bring up wg-hosts iface, start peer
	// reconciler + heartbeat. The DB calls require mTLS, so we point
	// the client at the internal mTLS URL (defaults to public if unset).
	internalURL := r.cfg.InternalControlURL
	if internalURL == "" {
		internalURL = r.cfg.ControlURL
	}
	ctrl, err := controlclient.NewClientWithTLSAndVerify(internalURL,
		r.cfg.TLSCertPath, r.cfg.TLSKeyPath, r.cfg.TLSCAPath, nil)
	if err != nil {
		return fmt.Errorf("controlclient: %w", err)
	}
	// Stash the client for per-tick relay-state polls. mTLS is already
	// wired; the first relay-state request fails fast on a misconfigured
	// CA bundle.
	r.ctrl = ctrl
	boot, err := bootstrap(ctx, bootstrapConfig{
		HostID:             r.cfg.HostID,
		Region:             r.cfg.Region,
		Addr:               r.cfg.PublicEndpoint,
		ControlURL:         r.cfg.ControlURL,
		BootstrapToken:     r.cfg.BootstrapToken,
		Client:             ctrl,
		SigningKeyPath:     r.cfg.WGHostsPrivKey + ".ed25519",
		WGSigningKey:       r.cfg.WGHostsPrivKey,
		WGPort:             51820,
		RelayDevicesPubkey: devicesPubkey[:],
	})
	if err != nil {
		return fmt.Errorf("hostbootstrap: %w", err)
	}
	defer boot.Close()
	log.WithContext(ctx).Infof("[relay] joined wg-hosts mesh at %s", boot.WGIP)

	// 4. wg-devices: faces the public internet. Clients hit this iface.
	// MUST be a different UDP port than wg-hosts (51820) since both
	// can't bind the same port on hostNetwork.
	addr := &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(32, 32)}
	if err := wg.EnsureInterface("wg-devices", r.cfg.WGDevicesPort, devicesKey, addr); err != nil {
		return fmt.Errorf("ensure wg-devices: %w", err)
	}
	log.WithContext(ctx).Infof("[relay] wg-devices up on UDP/%d (pubkey=%s)",
		r.cfg.WGDevicesPort, devicesKey.PublicKey().String())

	// A dedicated pair map keeps relay reconciliation separate from any
	// compute-host policy maps. No device peer is installed before this succeeds.
	r.policy, err = vm.AttachRelayPolicy("wg-devices")
	if err != nil {
		return fmt.Errorf("relay BPF protection: %w", err)
	}

	// Keep the last successful snapshot, including session expiries. A failed
	// fetch must not renew access or prevent local expiry enforcement.
	state := &relayState{}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	tick := func() error {
		// Bound control polling so an outage cannot stall local expiry checks
		// for the client's normal 30-second HTTP timeout.
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		wire, err := r.ctrl.RelayState(fetchCtx, r.cfg.HostID)
		cancel()
		if err != nil {
			log.WithContext(ctx).Warnf("[relay] fetch state: %v", err)
		} else {
			state = toLocalState(wire)
		}
		active := state.activeAt(time.Now())
		// Revoke stale permissions before admitting new WireGuard peers.
		// Any enforcement failure stops the relay and removes wg-devices.
		if err := r.reconcileDevicePolicy(active); err != nil {
			return fmt.Errorf("relay policy reconcile: %w", err)
		}
		if err := r.reconcileDevicePeers(active); err != nil {
			return fmt.Errorf("relay peer reconcile: %w", err)
		}
		return nil
	}
	if err := tick(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := tick(); err != nil {
				return err
			}
		}
	}
}

// reconcileDevicePolicy compares desired permissions with the kernel map,
// including entries left by an earlier process or a failed deletion.
func (r *Relay) reconcileDevicePolicy(state *relayState) error {
	desired := make(map[[2]uint32]struct{}, len(state.DevicePairs)+len(state.DeviceVMPairs))
	for _, pairs := range [][]devicePair{state.DevicePairs, state.DeviceVMPairs} {
		for _, p := range pairs {
			src, err := ipKeyU32(p.SrcIP)
			if err != nil {
				return err
			}
			dst, err := ipKeyU32(p.DstIP)
			if err != nil {
				return err
			}
			desired[[2]uint32{src, dst}] = struct{}{}
		}
	}
	return r.policy.Reconcile(desired)
}

// ipKeyU32 parses a dotted-quad IPv4 to network-byte-order u32 (matching
// what BPF maps expect — see internal/hosts/vm/bpf_policy_maps.go).
func ipKeyU32(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("not ipv4: %q", s)
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]), nil
}

// reconcileDevicePeers applies the active sessions from the control snapshot
// to the wg-devices peer set. Removed sessions
// → peer removed from kernel; new sessions → peer added.
func (r *Relay) reconcileDevicePeers(state *relayState) error {
	peers := state.Sessions

	cli, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer cli.Close()

	dev, err := cli.Device("wg-devices")
	if err != nil {
		return fmt.Errorf("get wg-devices: %w", err)
	}

	// Index existing kernel peers by pubkey.
	current := make(map[wgtypes.Key]wgtypes.Peer, len(dev.Peers))
	for _, p := range dev.Peers {
		current[p.PublicKey] = p
	}
	want := make(map[wgtypes.Key]struct{}, len(peers))

	keepalive := wg.PersistentKeepaliveSeconds * time.Second
	var cfg []wgtypes.PeerConfig

	for _, peer := range peers {
		var key wgtypes.Key
		if len(peer.Pubkey) != wgtypes.KeyLen {
			log.Warnf("[relay] session %s: bad pubkey len %d", peer.SessionID, len(peer.Pubkey))
			continue
		}
		copy(key[:], peer.Pubkey)
		want[key] = struct{}{}

		clientIP := net.ParseIP(peer.ClientIP)
		if clientIP == nil {
			log.Warnf("[relay] session %s: bad client_ip %q", peer.SessionID, peer.ClientIP)
			continue
		}
		_, already := current[key]
		cfg = append(cfg, wgtypes.PeerConfig{
			PublicKey: key,
			// Endpoint is NOT set — clients are behind NAT, kernel learns
			// their endpoint from the inbound handshake packet.
			AllowedIPs: []net.IPNet{
				{IP: clientIP.To4(), Mask: net.CIDRMask(32, 32)},
			},
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &keepalive,
			UpdateOnly:                  already,
		})
	}

	// Remove peers in kernel that aren't in `want`.
	for pubkey := range current {
		if _, keep := want[pubkey]; keep {
			continue
		}
		cfg = append(cfg, wgtypes.PeerConfig{
			PublicKey: pubkey,
			Remove:    true,
		})
	}

	if len(cfg) != 0 {
		if err := cli.ConfigureDevice("wg-devices", wgtypes.Config{
			Peers: cfg,
		}); err != nil {
			return fmt.Errorf("configure wg-devices: %w", err)
		}
	}

	// AllowedIPs on the WG peer is a POLICY filter, not a routing entry.
	// For the relay's kernel to actually deliver packets destined for a
	// device IP back into the wg-devices tunnel (reply path: VM →
	// compute-host → relay-wg-hosts → relay's kernel → relay-wg-devices),
	// we also need an explicit kernel route per peer.
	link, err := netlink.LinkByName("wg-devices")
	if err == nil {
		for _, peer := range peers {
			ip := net.ParseIP(peer.ClientIP)
			if ip == nil {
				continue
			}
			route := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)},
				Protocol:  unix.RTPROT_BOOT,
			}
			if rerr := netlink.RouteReplace(route); rerr != nil {
				log.Debugf("[relay] route add %s: %v", peer.ClientIP, rerr)
			}
		}
	}

	log.Infof("[relay] reconciled wg-devices: %d active sessions, %d kernel ops",
		len(peers), len(cfg))
	return nil
}

// loadOrCreateWGKey reads a base64 WG private key from disk or generates
// a fresh one if the file doesn't exist. The pubkey for the wg-devices
// iface is derived from this and surfaced via the hosts table's
// public_key column so the control API can include it in client configs.
func loadOrCreateWGKey(path string) (wgtypes.Key, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		k, perr := wgtypes.ParseKey(trim(string(b)))
		if perr != nil {
			return wgtypes.Key{}, fmt.Errorf("parse key from %s: %w", path, perr)
		}
		return k, nil
	}
	if !os.IsNotExist(err) {
		return wgtypes.Key{}, fmt.Errorf("read %s: %w", path, err)
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate key: %w", err)
	}
	if err := os.WriteFile(path, []byte(k.String()+"\n"), 0o600); err != nil {
		return wgtypes.Key{}, fmt.Errorf("write %s: %w", path, err)
	}
	log.Infof("[relay] generated new wg-devices key at %s", path)
	return k, nil
}

func trim(s string) string {
	for i := len(s); i > 0; i-- {
		if c := s[i-1]; c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			return s[:i]
		}
	}
	return ""
}
