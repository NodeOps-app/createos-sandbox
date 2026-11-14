package hosts

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// resolveRegisterAddr computes the "host:port" this serve process advertises
// to the control plane. Precedence:
//  1. cfg.Addr already carries a host part (e.g. "10.0.0.5:9090") → use verbatim.
//  2. User set cfg.Hostname explicitly (anything other than os.Hostname()) →
//     trust it and prepend to cfg.Addr.
//  3. Auto-detect: ask the kernel which local IP it would use to reach
//     cfg.ControlURL (UDP dial trick — no packet sent) and prepend that.
//  4. Fallback: cfg.Hostname (which at this point equals os.Hostname()).
//
// The auto-detect step is why an operator no longer needs to set `hostname:`
// in serve.yaml on multi-host setups — the right routable IP for control is
// whatever the kernel picks when dialing control, which is exactly what this
// returns.
func resolveRegisterAddr(cfg config.ServeConfig) string {
	addr := cfg.Addr
	if !strings.HasPrefix(addr, ":") {
		return addr
	}
	osHost, _ := os.Hostname()
	if cfg.Hostname != "" && cfg.Hostname != osHost {
		return cfg.Hostname + addr
	}
	if ip := detectOutboundIP(cfg.ControlURL); ip != "" {
		return ip + addr
	}
	return cfg.Hostname + addr
}

// detectOutboundIP returns the local IP the kernel would use to route toward
// controlURL. Uses a UDP socket (no packet actually leaves the host — UDP
// connect() just primes the routing table). Returns "" on any failure so
// callers can fall back gracefully.
func detectOutboundIP(controlURL string) string {
	if controlURL == "" {
		return ""
	}
	u, err := url.Parse(controlURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || la.IP == nil || la.IP.IsUnspecified() {
		return ""
	}
	return la.IP.String()
}

// registerHost sends the initial registration to control via the
// controlclient and returns the assigned /22 subnet + WG mesh IP + the
// resolved shape catalog the control plane wants this host to advertise.
// shapes is nil when control's shapes DB table is empty or unreachable;
// the caller logs once and continues with an empty catalog until a
// later heartbeat populates one.
// Bootstrap-token-authed (host pubkey isn't in the DB yet at first call).
func registerHost(ctx context.Context, repo *controlclient.Client, cfg config.ServeConfig, hostID, addr, underlayIP string, maxVMs int, pubkey, wgPubkey []byte) (subnetCIDR, wgIP string, shapes []proto.Shape, storage *proto.HostStorageInfo, err error) {
	hw := CollectHardware(cfg.SnapshotDir)
	rootfsNames := make([]string, 0, len(cfg.Rootfses))
	for name := range cfg.Rootfses {
		rootfsNames = append(rootfsNames, name)
	}
	sort.Strings(rootfsNames)
	resp, err := repo.Register(ctx, proto.ControlHostRegisterReq{
		ID:                hostID,
		Addr:              addr,
		MemCapacityMib:    cfg.MemCapacity,
		CPUCount:          hw.CPUCount,
		DiskTotalMib:      hw.DiskTotalMib,
		DiskUsedMib:       hw.DiskUsedMib,
		MaxVMs:            maxVMs,
		Rootfses:          rootfsNames,
		Labels:            cfg.Labels,
		PublicKey:         pubkey,
		UnderlayIP:        underlayIP,
		Region:            cfg.Region,
		CPUVendor:         hw.CPUVendor,
		CPUFamily:         hw.CPUFamily,
		WGPublicKey:       wgPubkey,
		CPUOvercommitX10:  cfg.CPUOvercommitX10,
		MemOvercommitX10:  cfg.MemOvercommitX10,
		DiskOvercommitX10: cfg.DiskOvercommitX10,
	}, cfg.BootstrapToken)
	if err != nil {
		return "", "", nil, nil, err
	}
	fmt.Fprintf(os.Stderr, "[hostagent] registered with %s\n", cfg.ControlURL)
	if resp.SubnetCIDR == "" {
		return "", "", nil, nil, fmt.Errorf("control plane returned empty subnet_cidr; overlay subnet is required")
	}
	if resp.WGIP == "" {
		return "", "", nil, nil, fmt.Errorf("control plane returned empty wg_ip; WG mesh allocator exhausted?")
	}
	return resp.SubnetCIDR, resp.WGIP, resp.Shapes, resp.Storage, nil
}
