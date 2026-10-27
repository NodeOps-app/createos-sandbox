package vm

import (
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var relayIsolatedBPFTest = flag.Bool("relay-isolated-bpf", false, "run relay attachment test in isolated namespaces with private bpffs")

// Run only inside isolated network and mount namespaces with a private bpffs.
func TestRelayPolicyAttachment(t *testing.T) {
	if !*relayIsolatedBPFTest {
		t.Skip("requires isolated network/mount namespaces and private bpffs")
	}
	if err := EnsureOverlayMaps(); err != nil {
		t.Fatal(err)
	}
	if err := SetVMIPPair(99, 100); err != nil {
		t.Fatal(err)
	}
	if p, err := AttachRelayPolicy("missing-relay"); err == nil {
		p.Close()
		t.Fatal("attachment to missing interface succeeded")
	}
	const name = "relay-test"
	for attempt := 0; attempt < 2; attempt++ {
		iface := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(iface); err != nil {
			t.Fatal(err)
		}
		p, err := AttachRelayPolicy(name)
		if err != nil {
			_ = netlink.LinkDel(iface)
			t.Fatal(err)
		}
		// On the second attachment, the first process's pinned rule exists.
		if err := p.Reconcile(nil); err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 20)
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], 20)
		binary.BigEndian.PutUint32(packet[12:16], 1)
		binary.BigEndian.PutUint32(packet[16:20], 2)
		check := func(want uint32) {
			t.Helper()
			got, _, err := p.collection.Programs[BPFProgWGIngress].Test(packet)
			if err != nil || got != want {
				t.Fatalf("packet decision=%d want=%d err=%v", got, want, err)
			}
		}
		check(2) // TC_ACT_SHOT: stale or absent permission must drop.
		if err := p.Reconcile(map[[2]uint32]struct{}{{1, 2}: {}}); err != nil {
			t.Fatal(err)
		}
		check(0) // TC_ACT_OK
		p.Close()
		if err := netlink.LinkDel(iface); err != nil {
			t.Fatal(err)
		}
	}
	var value uint8
	if err := globalOverlayMaps.vmipPair.Lookup(vmipPairBytes(99, 100), &value); err != nil || value != 1 {
		t.Fatalf("relay modified compute policy map: %v", err)
	}
}

func TestRelayPolicyReconcilesKernelState(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 8})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("kernel BPF permissions required: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	stale := vmipPairBytes(1, 2)
	if err := m.Put(stale, uint8(1)); err != nil {
		t.Fatal(err)
	}
	// A newly constructed reconciler has no history of this existing rule.
	policy := &RelayPolicy{pairs: m}
	desired := map[[2]uint32]struct{}{{3, 4}: {}}
	if err := policy.Reconcile(desired); err != nil {
		t.Fatal(err)
	}
	var value uint8
	if err := m.Lookup(stale, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale permission survived: %v", err)
	}
	if err := m.Lookup(vmipPairBytes(3, 4), &value); err != nil || value != 1 {
		t.Fatalf("desired permission missing: %v", err)
	}
	// Force deletion failure. Both attempts must report it; the second must
	// not forget the stale permission after an unsuccessful first attempt.
	if err := m.Freeze(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := policy.Reconcile(nil); err == nil {
			t.Fatal("failed permission deletion reported success")
		}
	}
}

// Uses the same explicit isolated-namespace opt-in as the relay test above.
func TestComputePolicyLinksSurviveClose(t *testing.T) {
	if !*relayIsolatedBPFTest {
		t.Skip("requires isolated network/mount namespaces and private bpffs")
	}
	iface := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "compute-test"}}
	if err := netlink.LinkAdd(iface); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(iface)
	program := func(action int32) *ebpf.Program {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "policy_test", Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, action), asm.Return()}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		return p
	}
	old, next := program(2), program(0)
	query := func(direction ebpf.AttachType) []link.AttachedProgram {
		r, err := link.QueryPrograms(link.QueryOptions{Target: iface.Attrs().Index, Attach: direction})
		if err != nil {
			t.Fatal(err)
		}
		return r.Programs
	}
	for _, direction := range []string{"ingress", "egress"} {
		attachType := ebpf.AttachTCXIngress
		if direction == "egress" {
			attachType = ebpf.AttachTCXEgress
		}
		a, err := attachTCPolicy(iface, old, direction)
		if err != nil {
			t.Fatal(err)
		}
		l := a.ingressLink
		if direction == "egress" {
			l = a.egressLink
		}
		if l == nil {
			t.Fatal("TCX required")
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		} // Simulate process descriptor closure.
		if got := len(query(attachType)); got != 1 {
			t.Fatalf("lost protection after close: %d", got)
		}
		a, err = attachTCPolicy(iface, next, direction)
		if err != nil {
			t.Fatal(err)
		}
		info, err := next.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := info.ID()
		attached := query(attachType)
		if len(attached) != 1 || attached[0].ID != id {
			t.Fatal("restart did not update the existing link")
		}
		a.detach()
		if len(query(attachType)) != 0 {
			t.Fatal("explicit teardown retained attachment")
		}
		if _, err := os.Stat(filepath.Join(policyLinkDir, iface.Attrs().Name+"_"+direction)); !os.IsNotExist(err) {
			t.Fatalf("pin survived teardown: %v", err)
		}
	}
	a, err := attachTCPolicy(iface, old, "ingress")
	if err != nil {
		t.Fatal(err)
	}
	a.ingressLink.Close()
	if err := netlink.LinkDel(iface); err != nil {
		t.Fatal(err)
	}
	if err := pruneDetachedPolicyLinks(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(policyLinkDir, "compute-test_ingress")); !os.IsNotExist(err) {
		t.Fatalf("orphan pin survived: %v", err)
	}
}
