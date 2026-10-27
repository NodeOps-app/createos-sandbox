package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
)

const persistedNetSlotVersion = 1

type persistedNetSlot struct {
	Version     int    `json:"version"`
	ContainerID string `json:"container_id"`
	VMCIDR      string `json:"vm_cidr"`
	Gateway     string `json:"gateway"`
	MAC         string `json:"mac"`
	VsockCID    uint32 `json:"vsock_cid"`
}

func netSlotStateDir() string {
	return filepath.Join(RuntimeDir(), "netpool-slots")
}

func netSlotStatePath(containerID string) string {
	return filepath.Join(netSlotStateDir(), containerID+".json")
}

// persistCleanNetSlot publishes the durable proof that a slot is idle and
// free of borrower-specific policy. Callers must do this only after cleanup.
func persistCleanNetSlot(pn *PooledNet) error {
	if pn == nil || !pn.permanent {
		return nil
	}
	state := persistedNetSlot{
		Version:     persistedNetSlotVersion,
		ContainerID: pn.ContainerID,
		VMCIDR:      pn.pair.VMCIDR,
		Gateway:     pn.pair.Gateway,
		MAC:         pn.MAC,
		VsockCID:    pn.VsockCID,
	}
	if err := os.MkdirAll(netSlotStateDir(), 0o700); err != nil {
		return fmt.Errorf("create netpool state dir: %w", err)
	}
	tmp, err := os.CreateTemp(netSlotStateDir(), ".slot-*.tmp")
	if err != nil {
		return fmt.Errorf("create netpool state: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := json.NewEncoder(tmp).Encode(state); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode netpool state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close netpool state: %w", err)
	}
	if err := os.Rename(tmpPath, netSlotStatePath(pn.ContainerID)); err != nil {
		return fmt.Errorf("publish netpool state: %w", err)
	}
	return nil
}

// claimPersistedNetSlot removes the clean marker before a slot can carry VM
// traffic. A marker must never coexist with an active borrower.
func claimPersistedNetSlot(containerID string) error {
	err := os.Remove(netSlotStatePath(containerID))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove clean netpool marker: %w", err)
	}
	return nil
}

func loadPersistedNetSlot(containerID string) (*persistedNetSlot, error) {
	data, err := os.ReadFile(netSlotStatePath(containerID))
	if err != nil {
		return nil, err
	}
	var state persistedNetSlot
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode marker: %w", err)
	}
	if state.Version != persistedNetSlotVersion || state.ContainerID != containerID {
		return nil, fmt.Errorf("marker identity/version mismatch")
	}
	n := parsePoolN(containerID)
	if n <= 0 || state.VsockCID != uint32(100+n) {
		return nil, fmt.Errorf("marker vsock CID mismatch")
	}
	return &state, nil
}

// validatePersistedNetSlot verifies the kernel objects whose identity cannot
// safely be inferred from a filename. The marker proves the previous process
// returned the slot clean; these checks prove that state still describes the
// live netns/veth topology.
func validatePersistedNetSlot(state *persistedNetSlot) (*PooledNet, error) {
	ip, ipNet, err := net.ParseCIDR(state.VMCIDR)
	if err != nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid VM CIDR %q", state.VMCIDR)
	}
	ipNet.IP = ip.To4()
	gw := net.ParseIP(state.Gateway).To4()
	if gw == nil {
		return nil, fmt.Errorf("invalid gateway %q", state.Gateway)
	}
	mac, err := net.ParseMAC(state.MAC)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC %q: %w", state.MAC, err)
	}

	hostVeth, err := netlink.LinkByName(vethNameFor(state.ContainerID))
	if err != nil {
		return nil, fmt.Errorf("host veth: %w", err)
	}
	if hostVeth.Attrs().Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("host veth is down")
	}
	hostAddrs, err := netlink.AddrList(hostVeth, netlink.FAMILY_V4)
	if err != nil || !hasExactAddress(hostAddrs, gw, ipNet.Mask) {
		return nil, fmt.Errorf("host gateway address mismatch")
	}

	nsHandle, err := vnetns.GetFromPath(NetnsPathRoot + state.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("open netns: %w", err)
	}
	defer nsHandle.Close()
	if err := validatePersistedGuestNet(nsHandle, ipNet, gw, mac); err != nil {
		return nil, err
	}

	return &PooledNet{
		NetNSPath:   NetnsPathRoot + state.ContainerID,
		TapName:     TapDevName,
		MAC:         mac.String(),
		IP:          *ipNet,
		Gateway:     gw,
		DNS:         []string{"1.1.1.1", "8.8.8.8"},
		VMIfName:    "eth0",
		ContainerID: state.ContainerID,
		VsockCID:    state.VsockCID,
		pair:        IPPair{VMCIDR: state.VMCIDR, Gateway: state.Gateway},
		permanent:   true,
	}, nil
}

func validatePersistedGuestNet(nsHandle vnetns.NsHandle, wantIP *net.IPNet, gateway net.IP, wantMAC net.HardwareAddr) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := vnetns.Get()
	if err != nil {
		return err
	}
	defer original.Close()
	if err := vnetns.Set(nsHandle); err != nil {
		return err
	}
	defer func() { _ = vnetns.Set(original) }()

	veth, err := netlink.LinkByName(VethGuestName)
	if err != nil || veth.Attrs().Flags&net.FlagUp == 0 {
		return fmt.Errorf("guest veth missing or down: %w", err)
	}
	if !bytes.Equal(veth.Attrs().HardwareAddr, wantMAC) {
		return fmt.Errorf("guest veth MAC mismatch")
	}
	addrs, err := netlink.AddrList(veth, netlink.FAMILY_V4)
	if err != nil || !hasExactAddress(addrs, wantIP.IP, wantIP.Mask) {
		return fmt.Errorf("guest address mismatch")
	}
	tap, err := netlink.LinkByName(TapDevName)
	if err != nil || tap.Attrs().Flags&net.FlagUp == 0 {
		return fmt.Errorf("tap missing or down: %w", err)
	}
	routes, err := netlink.RouteList(veth, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list guest routes: %w", err)
	}
	for _, route := range routes {
		isDefault := route.Dst == nil
		if route.Dst != nil {
			ones, bits := route.Dst.Mask.Size()
			isDefault = ones == 0 && bits == 32
		}
		if isDefault && route.LinkIndex == veth.Attrs().Index && route.Gw.Equal(gateway) {
			return nil
		}
	}
	return fmt.Errorf("guest default route mismatch")
}

func hasExactAddress(addrs []netlink.Addr, ip net.IP, mask net.IPMask) bool {
	wantOnes, wantBits := mask.Size()
	for _, addr := range addrs {
		if addr.IPNet == nil || !addr.IP.Equal(ip) {
			continue
		}
		ones, bits := addr.Mask.Size()
		if ones == wantOnes && bits == wantBits {
			return true
		}
	}
	return false
}

func removeStaleNetSlotMarkers(existing map[string]bool) {
	entries, err := os.ReadDir(netSlotStateDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			if filepath.Ext(name) == ".tmp" {
				_ = os.Remove(filepath.Join(netSlotStateDir(), name))
			}
			continue
		}
		containerID := name[:len(name)-len(".json")]
		if !existing[containerID] {
			_ = os.Remove(filepath.Join(netSlotStateDir(), name))
		}
	}
}
