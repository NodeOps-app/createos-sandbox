package wg

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wireguardLinkType is the netlink Type() returned by a WireGuard device.
const wireguardLinkType = "wireguard"

// genericLink is a minimal netlink.Link implementation that returns a
// specific Type(). The netlink package consults Type() in LinkAdd to
// pick the kernel module — we need "wireguard" to create a WG device.
type genericLink struct {
	attrs *netlink.LinkAttrs
	kind  string
}

func (g *genericLink) Attrs() *netlink.LinkAttrs { return g.attrs }
func (g *genericLink) Type() string              { return g.kind }

// EnsureInterface brings up (or recreates if state has drifted) the WG kernel
// device `name` with the given private key, listen port, and host address.
// Idempotent: safe to call on every reconcile tick.
//
// The route <addr.subnet> dev <name> is added so any traffic to a WG-mesh
// IP routes through the tunnel automatically — that's the kernel-routing
// substitution that makes vmip_to_remote.underlay_ip = peer.wg_ip work
// without touching BPF programs.
func EnsureInterface(name string, port int, priv wgtypes.Key, addr *net.IPNet) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, notFound := err.(netlink.LinkNotFoundError); !notFound {
			return fmt.Errorf("link lookup %s: %w", name, err)
		}
		// Create the WG device.
		la := netlink.NewLinkAttrs()
		la.Name = name
		newLink := &genericLink{attrs: &la, kind: wireguardLinkType}
		if err := netlink.LinkAdd(newLink); err != nil {
			return fmt.Errorf("link add %s (kernel WG module missing? `modprobe wireguard`): %w", name, err)
		}
		link, err = netlink.LinkByName(name)
		if err != nil {
			return fmt.Errorf("link re-lookup %s: %w", name, err)
		}
	}

	// Configure private key + listen port via wgctrl (genetlink).
	cli, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl.New: %w", err)
	}
	defer cli.Close()
	if err := cli.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &priv,
		ListenPort: &port,
	}); err != nil {
		return fmt.Errorf("configure device %s: %w", name, err)
	}

	// Assign the host's own address with the configured mask. Drop any
	// stale addresses on the interface that differ from the desired one
	// (e.g. a previous serve installed /24, this one wants /16) — without
	// the cleanup, AddrReplace just appends and both end up bound.
	desired := &netlink.Addr{IPNet: addr}
	existing, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("addr list %s: %w", name, err)
	}
	for _, a := range existing {
		if a.IP.Equal(desired.IP) && a.Mask.String() == desired.Mask.String() {
			continue // already the right address
		}
		_ = netlink.AddrDel(link, &a)
	}
	if err := netlink.AddrReplace(link, desired); err != nil {
		return fmt.Errorf("addr replace %s: %w", name, err)
	}

	// Bring up.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link set up %s: %w", name, err)
	}
	return nil
}

// RemoveInterface tears the device down. Idempotent — returns nil if absent.
func RemoveInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, notFound := err.(netlink.LinkNotFoundError); notFound {
			return nil
		}
		return fmt.Errorf("link lookup %s: %w", name, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("link del %s: %w", name, err)
	}
	return nil
}
