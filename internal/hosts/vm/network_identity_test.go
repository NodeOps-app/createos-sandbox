package vm

// Run only in fresh private network/mount/PID namespaces with private bpffs and
// /run/netns. The explicit flag is shared with the existing BPF integration tests.
import (
	"context"
	"fmt"
	"github.com/vishvananda/netlink"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestComputeInFlightIdentityPackets(t *testing.T) {
	if !*relayIsolatedBPFTest {
		t.Skip("requires private mount/net/pid namespaces and bpffs")
	}
	// Never reconcile an empty desired state against a real host's maps.
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("requires fresh private network namespace")
	}
	entries, err := os.ReadDir("/sys/fs/bpf")
	if err != nil || len(entries) != 0 {
		t.Fatal("requires empty private bpffs")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %s %v", args, out, err)
		}
	}
	run("link", "set", "lo", "up")
	for _, n := range []struct{ name, host, peer, gw, addr string }{{"audit-a", "audit-ha", "audit-pa", "10.203.0.1/30", "10.203.0.2/30"}, {"audit-b", "audit-hb", "audit-pb", "10.203.0.5/30", "10.203.0.6/30"}} {
		run("netns", "add", n.name)
		defer exec.Command("ip", "netns", "del", n.name).Run()
		run("link", "add", n.host, "type", "veth", "peer", "name", n.peer)
		run("link", "set", n.peer, "netns", n.name)
		run("addr", "add", n.gw, "dev", n.host)
		run("link", "set", n.host, "up")
		run("-n", n.name, "link", "set", "lo", "up")
		run("-n", n.name, "addr", "add", n.addr, "dev", n.peer)
		run("-n", n.name, "link", "set", n.peer, "up")
		gw, _, _ := net.ParseCIDR(n.gw)
		run("-n", n.name, "route", "add", "default", "via", gw.String())
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureOverlayMaps(); err != nil {
		t.Fatal(err)
	}
	if err := LoadBPFPolicy(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"audit-ha", "audit-hb"} {
		if err := AttachBPFPolicyToVeth(name); err != nil {
			t.Fatal(err)
		}
	}
	server := exec.Command("ip", "netns", "exec", "audit-b", "python3", "-u", "-c", `import socket
s=socket.socket();s.bind(('0.0.0.0',18080));s.listen()
while True:
 c,a=s.accept();c.sendall(b'private-marker');c.close()
`)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	if out, err := exec.Command("ip", "netns", "exec", "audit-b", "python3", "-c", `import socket,time
for i in range(60):
 try:
  s=socket.create_connection(('127.0.0.1',18080),0.1);s.close();break
 except OSError: time.sleep(0.05)
else: raise RuntimeError('victim listener unavailable')
`).CombinedOutput(); err != nil {
		t.Fatalf("victim readiness: %s %v", out, err)
	}

	probe := func(stage string, want bool) {
		t.Helper()
		out, err := exec.Command("ip", "netns", "exec", "audit-a", "python3", "-c", `import socket
s=socket.create_connection(('10.203.0.6',18080),0.5);print(s.recv(100).decode());s.close()
`).CombinedOutput()
		allowed := err == nil
		t.Logf("%s: reached=%v", stage, allowed)
		if allowed != want {
			t.Errorf("%s: reached=%v want=%v (%s)", stage, allowed, want, out)
		}
	}
	probe("both identities absent", false)
	bind := func() {
		t.Helper()
		if e := BindVMIPToIface("audit-ha", "10.203.0.2"); e != nil {
			t.Fatal(e)
		}
		if e := BindVMIPToIface("audit-hb", "10.203.0.6"); e != nil {
			t.Fatal(e)
		}
	}
	bind()
	probe("identities bound without shared network", false)
	c, err := net.DialTimeout("tcp", "10.203.0.6:18080", time.Second)
	if err != nil {
		t.Fatal("bound guest unreachable from host", err)
	}
	c.Close()
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"success","data":{"members":[{"sandbox_id":"old-a","ip":"10.203.0.2","is_local":true,"vni":7},{"sandbox_id":"old-b","ip":"10.203.0.6","is_local":true,"vni":7}]}}`)
	}))
	defer control.Close()
	if err := reconcileOnce(context.Background(), NetReconcilerConfig{ControlURL: control.URL, Client: control.Client(), HostID: "audit", LocalSandboxIPs: func() []string { return nil }, LocalSandboxIDForIP: func(string) string { return "" }}); err != nil {
		t.Fatal(err)
	}
	probe("reconcile while creates not registered", false)
	for _, name := range []string{"audit-ha", "audit-hb"} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := iterU32U32(globalOverlayMaps.ifaceToIP)[uint32(link.Attrs().Index)]; !ok {
			t.Errorf("reconcile removed in-flight identity: %s", name)
		}
	}
	bind()
	a, _ := netlink.LinkByName("audit-ha")
	b, _ := netlink.LinkByName("audit-hb")
	aip, _ := ipKey("10.203.0.2")
	bip, _ := ipKey("10.203.0.6")
	for _, p := range [][2]uint32{{uint32(a.Attrs().Index), bip}, {uint32(b.Attrs().Index), aip}} {
		if err := SetIfacePair(p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range [][2]uint32{{aip, bip}, {bip, aip}} {
		if err := SetVMIPPair(p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	probe("explicit shared-network pairs", true)
	bind()
	probe("rebind removes previous tenant permissions", false)
	if err := DeleteVMIPVnis("10.203.0.2"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteIfaceVnis(uint32(a.Attrs().Index)); err != nil {
		t.Fatal(err)
	}
	probe("released source identity", false)
	if err := reconcileOnce(context.Background(), NetReconcilerConfig{ControlURL: control.URL, Client: control.Client(), HostID: "audit", LocalSandboxIPs: func() []string { return nil }, LocalSandboxIDForIP: func(string) string { return "" }}); err != nil {
		t.Fatal(err)
	}
	if _, ok := iterU32U32(globalOverlayMaps.ifaceToIP)[uint32(a.Attrs().Index)]; ok {
		t.Fatal("cleanup identity resurrected")
	}
	if _, ok := iterU32Set(globalOverlayMaps.knownVMIPs)[aip]; ok {
		t.Fatal("cleanup known IP resurrected")
	}
	// A failed map scan must never count as a clean handoff.
	original := globalOverlayMaps.ifacePair
	broken, err := original.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if err := broken.Close(); err != nil {
		t.Fatal(err)
	}
	globalOverlayMaps.ifacePair = broken
	err = BindVMIPToIface("audit-ha", "10.203.0.2")
	globalOverlayMaps.ifacePair = original
	if err == nil {
		t.Fatal("binding succeeded despite permission-map scan failure")
	}
	if _, ok := globalOverlayMaps.boundIfaces[uint32(a.Attrs().Index)]; ok {
		t.Fatal("failed handoff published a binding")
	}
	fmt.Println("private namespace packet checks complete")
}

func TestSlotProcessExitBarrier(t *testing.T) {
	pn := &PooledNet{}
	cmd := pn.trackProcess(exec.Command("sleep", "30"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err := pn.waitProcessExit(0); err == nil {
		t.Fatal("live process accepted as exited")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := pn.waitProcessExit(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	if len(pn.processes) != 0 {
		t.Fatal("exited process handle retained")
	}
	missing := pn.trackProcess(exec.Command("/nonexistent-createos-test-executable"))
	if err := missing.Start(); err == nil {
		t.Fatal("expected spawn failure")
	}
	if err := pn.waitProcessExit(0); err != nil {
		t.Fatal(err)
	}
}
