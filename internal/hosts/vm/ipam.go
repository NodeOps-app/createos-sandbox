package vm

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// IPPair is one allocation: a /31 point-to-point subnet where the lower
// address is the VM and the upper address is the host-side gateway. Each
// VM gets its own (vm, gw) pair so the host fcv interfaces never collide
// on a shared gateway IP — strict rp_filter on the host stays compatible
// because every gateway IP is reachable through exactly one interface.
type IPPair struct {
	VMCIDR  string // "a.b.c.d/31" — what the VM gets on eth0
	Gateway string // "a.b.c.e"     — what the host fcv gets on its /31 side
}

// StaticIPAM hands out /31 pairs from a /24 (or smaller) subnet pool.
// O(1) allocate/release via a buffered channel — lock-free on the hot
// path. Pre-computes every pair at startup.
type StaticIPAM struct {
	pool chan IPPair
}

// NewStaticIPAM enumerates /31 pairs in the given subnet, skipping the
// first pair (.0/.1) for cosmetic safety, and returns a ready pool.
//
//	gateway        — ignored (kept for compatibility); gateways are per-pair.
//	reservedVMIPs  — VM IPs (the lower half of each /31) that must NOT be
//	                 handed out — typically belonging to orphan VMs that
//	                 survived a host crash. Pairs containing these IPs are
//	                 omitted from the pool entirely.
func NewStaticIPAM(subnet, gateway string, reservedVMIPs []string) (*StaticIPAM, error) {
	_, cidr, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("static-ipam parse subnet %q: %w", subnet, err)
	}
	prefixBits, bits := cidr.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("static-ipam: only IPv4 supported (%s)", subnet)
	}
	if prefixBits > 30 {
		return nil, fmt.Errorf("static-ipam: subnet must be /30 or wider for /31 pairs (got /%d)", prefixBits)
	}

	reserved := make(map[string]struct{}, len(reservedVMIPs))
	for _, ip := range reservedVMIPs {
		reserved[ip] = struct{}{}
	}

	pairs := enumeratePairs(cidr)
	kept := pairs[:0]
	for _, p := range pairs {
		// VMCIDR is "a.b.c.d/31"; strip the prefix for the lookup.
		ip := p.VMCIDR[:len(p.VMCIDR)-3]
		if _, isReserved := reserved[ip]; isReserved {
			continue
		}
		kept = append(kept, p)
	}
	// Channel cap = full pair count, not kept. Reserved pairs are not
	// enqueued at startup, but Release of a previously-reserved pair
	// (e.g. when a startup-pinned `destroying` slot finally releases)
	// must succeed instead of silently dropping the IP back into a
	// channel that's already at cap.
	s := &StaticIPAM{pool: make(chan IPPair, len(pairs))}
	for _, p := range kept {
		s.pool <- p
	}
	skipped := len(pairs) - len(kept)
	if skipped > 0 {
		log.Infof("[static-ipam] %d /31 pairs in %s (%d reserved for surviving orphans)", len(kept), subnet, skipped)
	} else {
		log.Infof("[static-ipam] %d /31 pairs in %s", len(kept), subnet)
	}
	if gateway != "" {
		log.Warnf("[static-ipam] --gateway %q ignored (gateways are per-pair under /31 ptp)", gateway)
	}
	return s, nil
}

// Capacity returns the total number of /31 pairs the subnet supports
// (channel cap; includes pairs that were reserved at init time). Used
// to advertise the absolute max-VM count to the control plane.
func (s *StaticIPAM) Capacity() int { return cap(s.pool) }

// Allocate returns one (vm, gw) pair. Blocks if the pool is empty.
func (s *StaticIPAM) Allocate() IPPair { return <-s.pool }

// Reserve removes one exact pair from the available pool. It is used only
// while NetPool is starting, before any allocation goroutines exist, to
// reclaim a clean idle slot that survived the previous serve process.
func (s *StaticIPAM) Reserve(want IPPair) bool {
	n := len(s.pool)
	found := false
	for i := 0; i < n; i++ {
		pair := <-s.pool
		if !found && pair == want {
			found = true
			continue
		}
		s.pool <- pair
	}
	return found
}

// Release returns a pair to the pool. Best-effort (drops if full).
func (s *StaticIPAM) Release(p IPPair) {
	select {
	case s.pool <- p:
	default:
	}
}

// enumeratePairs returns every /31 pair inside cidr, skipping the very
// first pair so we don't hand out the .0 address (network address of the
// surrounding /24). For 192.168.127.0/24 this yields:
//
//	(192.168.127.2/31, 192.168.127.3),
//	(192.168.127.4/31, 192.168.127.5),
//	... up to ...
//	(192.168.127.252/31, 192.168.127.253)
//
// Net result: 126 pairs, i.e. 126 sandboxes per /24.
func enumeratePairs(cidr *net.IPNet) []IPPair {
	ones, bits := cidr.Mask.Size()
	if bits != 32 {
		return nil
	}
	hostBits := uint(bits - ones)
	total := uint32(1) << hostBits
	base := ipToUint32(cidr.IP.To4())

	var out []IPPair
	// Step by 2; start at base+2 (skip the first pair containing .0/.1).
	// Stop before base+total-1 so we don't include the broadcast (.255).
	for i := uint32(2); i+1 < total-1; i += 2 {
		vm := base + i
		gw := base + i + 1
		out = append(out, IPPair{
			VMCIDR:  fmt.Sprintf("%s/31", uint32ToIP(vm).String()),
			Gateway: uint32ToIP(gw).String(),
		})
	}
	return out
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(x uint32) net.IP {
	return net.IPv4(byte(x>>24), byte(x>>16), byte(x>>8), byte(x)).To4()
}
