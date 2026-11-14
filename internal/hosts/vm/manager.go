package vm

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/singleflight"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/metrics"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm/dns"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// newSandboxID returns a new sandbox identifier of the form "sb-<ulid>".
// The id is deliberately a valid DNS label / RFC 1123 name: a "sb-"
// prefix (no underscore) plus a lower-cased 26-char Crockford-base32
// ULID. That makes it usable verbatim as a VM hostname, a Kubernetes
// node name, and a DNS label — no stripping or case-folding anywhere.
// ULIDs are time-prefixed and lexicographically sortable.
func newSandboxID() string {
	return "sb-" + strings.ToLower(ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String())
}

// NewSandboxID is the exported form of newSandboxID. Used by the control
// plane to mint sandbox IDs before inserting their durable rows.
func NewSandboxID() string { return newSandboxID() }

// ErrInvalidRequest wraps validation failures so callers (service/api layers)
// can distinguish client errors from infrastructure errors.
var ErrInvalidRequest = errors.New("invalid request")

// shapeKey identifies a snapshot by VM shape + base rootfs. DiskMib is
// intentionally excluded — overlay disks are per-VM-sized at mkfs and have
// no bearing on snapshot contents (memory + vmstate). Rootfs IS included
// because the snapshot's memory pages reflect that rootfs's libc/kernel
// version etc., so restoring against a different base rootfs is unsafe.
type shapeKey struct {
	VCPU   int
	MemMib int
	Rootfs string // catalog name, e.g. "python" or "node"
}

func (k shapeKey) String() string { return fmt.Sprintf("%s-%d-%d", k.Rootfs, k.VCPU, k.MemMib) }

// snapshotFiles holds the on-disk artifacts for a single (vcpu, mem) snapshot.
type snapshotFiles struct {
	FirecrackerBuild string
	VmStatePath      string
	MemFilePath      string
	BaseOverlay      string
	Ready            bool
	GuestMAC         string
}

// Manager owns the network/overlay pools and the map of running sandboxes.
type Manager struct {
	firecrackerRuntime firecrackerRuntime

	Pool        *NetPool
	OverlayPool *OverlayPools
	Sandboxes   map[string]*Sandbox
	// creating protects per-VM resources from orphan sweepers between the
	// beginning of Create and insertion into Sandboxes. Snapshot generation can
	// keep a create in this window for seconds; without this set the one-minute
	// runtime-dir sweep can delete the slot-owned directory underneath it.
	creating   map[string]int
	Mu         sync.RWMutex
	KernelPath string
	InitrdPath string
	// pendingRelease holds slots that have been torn down (firecracker
	// killed, BPF/iptables cleared, overlay removed) but whose owning
	// sandbox row hasn't yet reached `destroyed` in the DB. The slot
	// stays out of NetPool.ready until ReleaseSlot is called. Prevents
	// the slot's IP/container_id from being reused while a `destroying`
	// row still references it — closes a race where CleanupOrphan
	// (driven by the old row) would tear down a slot a fresh VM had
	// already grabbed.
	pendingRelease   map[string]*PooledNet
	pendingReleaseMu sync.Mutex
	// diskOpMu serialises every MMDS-disk push on this host. Held by
	// AttachDiskLive, DetachDiskLive, and the periodic reconciler so
	// the read-modify-write on firecracker's MMDS can't interleave —
	// without this a reconciler racing a live attach would push the
	// pre-attach disks set and silently undo the user's action.
	diskOpMu sync.Mutex
	// Rootfses maps catalog name → on-disk path of the base rootfs ext4.
	// Sandboxes pick one at create time; DefaultRootfs is used when the
	// request omits the field.
	Rootfses map[string]string
	// RootfsesMu protects all reads and writes after construction, including
	// reads of catalog entries while unrelated templates are added or evicted.
	RootfsesMu    sync.RWMutex
	DefaultRootfs string
	Subnet        string
	Gateway       string
	DiskSizeMB    int64
	ColdOnly      bool
	// SnapshotDir is the on-disk root for persisted snapshot files. Each
	// (shape, rootfs) lives under <SnapshotDir>/<key>/{vmstate,mem}.
	SnapshotDir string
	// Shapes is the lookup catalog used by Create / Prewarm. Constructed
	// from shapesList; both are swapped together under shapesMu when
	// control pushes a new catalog on heartbeat.
	Shapes *Catalog

	// shapesList is the live shape catalog the host currently advertises.
	// Heartbeat-driven swaps update this AND Shapes atomically under
	// shapesMu. The list is also what the host's /v1/shapes endpoint
	// serves so it reflects the same view as create-time validation.
	shapesList []Shape
	shapesMu   sync.RWMutex

	// Snapshots are keyed by (vcpu, mem). Each shape gets its own lazily-built
	// snapshot because Firecracker refuses to restore a snapshot into a VM
	// whose MachineConfiguration doesn't match.
	Snapshots      map[shapeKey]*snapshotFiles
	SnapshotsMu    sync.Mutex
	SnapshotFlight singleflight.Group

	prewarmAll bool
	uffdMode   string // "", "auto", "on", "off"

	// meterPersist / meterIngressPersist are captured when
	// StartMeterLoopWithIngress runs so Destroy can fire one final
	// read+persist before zeroing the BPF maps. Without this, up to
	// one meter interval's worth of consumed bytes is lost at destroy
	// — meaningful for billing event payloads.
	meterPersist        MeterPersister
	meterIngressPersist IngressMeterPersister

	// agentProbeTransport: "tcp" (default) or "vsock". When "vsock",
	// waitForAgent dials Sandbox.VsockUDSPath instead of VM IP:1024.
	agentProbeTransport string

	// MaxVMs is the local hard ceiling. 0 = unlimited (only IP space limits
	// you). Set by NewManager from cfg.MaxVMs or auto-derived from IPAM.
	MaxVMs int

	// firecrackerUIDBase, when > 0, runs each firecracker as a per-slot
	// unprivileged UID. 0 keeps today's root-mode behaviour. See
	// firecracker_uid.go.
	firecrackerUIDBase int
	// kvmGID is the gid of the kvm group; firecracker (post-drop) needs
	// it as a supplementary group to open /dev/kvm. Resolved once at
	// startup; 0 means "not configured" → caller falls back to root mode.
	kvmGID uint32

	// prewarmDone is closed once Prewarm() finishes building every
	// shape × rootfs snapshot (or immediately in cold-only mode). Hostagent
	// polls this to know when to flip its registered status from "warming"
	// to "active" — we don't want the control-plane scheduler to route
	// creates to a host whose snapshots are still building, because those
	// creates fall back to slow cold boot.
	prewarmDone chan struct{}

	// OnSandboxDeath is called when a firecracker process exits without
	// Manager.Destroy being invoked first (crash, SIGKILL, OOM, guest
	// kernel panic). The callback runs AFTER Manager has cleaned up the
	// sandbox's local resources, and is expected to update persistent
	// state (e.g. mark the DB row destroyed). Nil = no callback.
	OnSandboxDeath func(id, reason string)

	// overlayConfig holds the overlay networking parameters set at construction.
	// Used to wire the reconciler goroutine started externally via StartNetReconciler.
	overlayConfig ManagerConfig

	// netReconcilerTrigger wakes the reconciler immediately (instead of
	// waiting up to its 5s interval). Non-blocking: a missed send means
	// a reconcile is already queued. Initialised by StartNetReconciler.
	netReconcilerTrigger chan struct{}

	// DNSTable is the live name→IP map fed by the network reconciler and served
	// by the per-host DNS stub on 169.254.20.10:53. Non-nil only when BPFPolicy
	// is enabled (overlay networking active).
	DNSTable *dns.Table

	// diskStatusPersist is the callback the background StartDiskStatusLoop
	// uses to push mount-status updates into the DB. Stashed here so
	// PollDiskStatusOnce can reuse it for opportunistic per-sandbox polls
	// (e.g. immediately after a live attach so the UI flips quickly).
	diskStatusPersist DiskStatusPersister
}

// PrewarmReady reports whether Prewarm has completed (or was skipped in
// cold-only mode). Non-blocking.
func (m *Manager) PrewarmReady() bool {
	select {
	case <-m.prewarmDone:
		return true
	default:
		return false
	}
}

// ErrAtCapacity is returned by Create when the host has hit its MaxVMs cap.
// Callers (service layer / API) translate to 503 ("no capacity").
var ErrAtCapacity = errors.New("host at MaxVMs capacity")

// ManagerConfig is the constructor input for NewManager.
type ManagerConfig struct {
	KernelPath string
	InitrdPath string
	// Rootfses is the catalog of base rootfs images by name. Must be non-empty.
	Rootfses map[string]string
	// DefaultRootfs is the catalog name applied to creates that don't pick one.
	// Must be a key in Rootfses.
	DefaultRootfs string
	// Subnet is the IPv4 CIDR the VM pool draws from (e.g. "192.168.127.0/24").
	Subnet string
	// Gateway is the host-owned IP inside Subnet that the VMs route through.
	// Empty falls back to the .1 address of Subnet.
	Gateway        string
	PoolSize       int
	NetPoolWorkers int
	DiskSizeMB     int64
	ColdOnly       bool
	// SnapshotDir is where snapshot files are written and reloaded from.
	// Empty defers to the Manager default (./snapshots).
	SnapshotDir string
	// PrewarmAllRootfs, if true, prewarms snapshots for every (shape, rootfs)
	// combination. Default (false) prewarms only the default rootfs.
	PrewarmAllRootfs bool
	// MaxVMs caps concurrent VMs locally. 0 = derive from IPAM (whatever
	// the subnet allows). Set explicitly to enforce a smaller ceiling.
	MaxVMs int

	// FirecrackerUIDBase, when > 0, makes the manager run each
	// firecracker as a per-slot UID computed as base + (VsockCID-100).
	// 0 keeps today's root-mode behaviour. See config/host.go for the
	// security trade-off + host-onboard prerequisites.
	FirecrackerUIDBase int
	// SeccompFilterPath, when non-empty, passes --seccomp-filter <path>
	// to every firecracker child, restricting VMM-thread syscalls.
	SeccompFilterPath string
	// ReservedVMIPs are VM IPs that must NOT be re-allocated — typically
	// belong to orphan VMs that survived a host restart. Their /31 pairs
	// are pulled out of the IPAM before the pool starts.
	ReservedVMIPs []string

	// LiveContainerIDs are `fcpN` slot names currently owned by
	// rehydrated sandboxes (must survive the startup orphan sweep).
	LiveContainerIDs []string

	// PendingDestroyingRecords are sandbox rows in `destroying` state
	// at startup whose slot we want to pin until MarkDestroyed lands.
	// NewManager reconstructs a synthetic PooledNet for each (using
	// ContainerID + IP from the row) and stashes it in pendingRelease.
	// The periodic reconcile tick then drives MarkDestroyed + Release.
	// On Release, the slot's netns/veth/IP are torn down rather than
	// recycled — these slots have unknown internal state (no live
	// firecracker, no TapName/MAC bookkeeping), so the safe thing is
	// to throw the slot away and let NetPool's replenish make a new
	// one with a fresh container_id.
	PendingDestroyingRecords []models.Sandbox

	// UFFDMode controls snapshot restore backing:
	//   "" or "auto" — default: UFFD on for VMs ≥ 512 MiB, file-backed below
	//   "on"         — force UFFD regardless of size
	//   "off"        — force file-backed (required for restart-survivable VMs,
	//                  since the UFFD page server lives in this process and
	//                  dies with it)
	UFFDMode string

	// Overlay networking — Phase 3/4.
	// HostID is this host's registered identifier, used by the net reconciler.
	HostID string
	// UnderlayIP is this host's public IP (auto-detected from outbound
	// routing toward ControlURL). Peers use it as the WireGuard endpoint
	// when sending encrypted overlay traffic here. Empty disables overlay.
	UnderlayIP string
	// UnderlayMTU is the physical interface MTU. The per-VM veth MTU is
	// derived from this minus the per-packet overhead of the WG host-mesh
	// wrap (~60 bytes: outer IP+UDP+WG+Poly1305 MAC). Zero uses the
	// default.
	UnderlayMTU int
	// ControlURL is the base URL of the control plane the net reconciler
	// hits for GET /v1/internal/networks/host-state. Empty ControlURL
	// disables the reconciler. Should be the mTLS-only internal URL
	// (https://...:8443) when TLS is wired — that's the only listener
	// that mounts the internal routes.
	ControlURL string
	// ControlHTTPClient is the *http.Client used by the net reconciler.
	// Must carry the host's mTLS client cert when ControlURL is the
	// internal mTLS endpoint; otherwise the gate 401s.
	ControlHTTPClient *http.Client

	// AgentLivenessProbe enables guest connectivity probes. Five continuous
	// minutes of failed probes trigger VM cleanup; recovery, snapshot freezing,
	// or bandwidth capping resets the timer. This bounds hung-guest resource
	// usage, but a timeout does not prove the guest halted. WatchDeath separately
	// handles an actual Firecracker process exit. Enabled by default.
	AgentLivenessProbe bool

	// Shapes is the Manager's initial catalog, installed by the host
	// startup path from whatever control returned at register time.
	// Empty until both register and at least one heartbeat have landed;
	// updated atomically by SetShapes on subsequent heartbeats.
	Shapes []Shape

	// AgentProbeTransport selects "tcp" or "vsock" for waitForAgent's
	// dial path. See config/host.go for the wider note. Defaults to
	// "tcp" when empty.
	AgentProbeTransport string
}

// CreateRequest describes the shape of a sandbox to create.
type CreateRequest struct {
	// RestoreOverlay is a private, verified disk copy prepared by the host
	// service. Never decoded from a public request or shared between VMs.
	RestoreOverlay string

	// ID is optional. When supplied (typically by the control plane after
	// it has INSERTed the durable row and reserved capacity), the manager
	// uses it verbatim. When empty, the manager generates a fresh ULID-
	// backed id. Never populated from a user-supplied request body.
	ID string
	// CreatedBy is the owner user_id. Cached on the Sandbox so the host's
	// ownership check on hot-path calls (exec, bandwidth) skips a DB
	// round-trip. Set by the service layer from the request context.
	CreatedBy string
	// Name is the user-facing VM name (e.g. "brave-otter"). Pushed into
	// the guest via MMDS as `hostname`; the agent calls Sethostname with
	// it. Also used by the per-host DNS stub to resolve peer names.
	Name    string
	Shape   string   // required, a catalog ID like "s-1vcpu-1gb"
	Rootfs  string   // optional rootfs catalog name; empty = Manager.DefaultRootfs
	DiskMib int64    // optional, caller override; 0 = use shape's default
	Egress  []string // allowlist; empty = allow all

	// BandwidthQuotaBytes is the cap on total VM traffic (bytes). 0 means
	// "apply the server default" (DefaultBandwidthQuotaBytes). Must be >=
	// 0 — the API rejects negative values, so unmetered is not user-
	// reachable.
	BandwidthQuotaBytes int64

	// SecretToken is the per-VM shared secret to push via MMDS. The
	// service layer mints this before calling Manager.Create. Required —
	// Create returns ErrInvalidRequest on empty.
	SecretToken string

	// Envs is the persistent server-side env-var map. Copied verbatim
	// onto the new Sandbox so the host's exec handler can inject these
	// vars into every /exec without re-reading the DB. Validation
	// happens upstream in the control plane.
	Envs map[string]string

	// Disks is the set of decrypted disk attachments to push into MMDS
	// at boot. Each entry tells the guest agent what to mount where.
	// Populated by the host service from req.DisksResolved (control's
	// decrypted form). Empty = no disks, MMDS omits the `disks` field.
	Disks []proto.MMDSDisk

	// Resolved from Shape at Manager.Create time — callers don't set these.
	VCPU        int
	MemMib      int
	CPUQuotaPct int // 0 = unlimited; see Shape.CPUQuotaPct
}

// DefaultBandwidthQuotaBytes is the per-sandbox bandwidth quota applied when
// the caller doesn't specify one. 50 GiB — covers typical interactive use
// (apt install, pip install, cloning a few repos) without letting a
// single sandbox monopolise host egress. Users who want a different
// budget pass an explicit positive `bandwidth_quota_bytes` at create or
// top up via `/bandwidth/recharge`.
const DefaultBandwidthQuotaBytes int64 = 50 * 1024 * 1024 * 1024

// Validate checks that the resolved fields are within accepted bounds. Called
// after shape resolution. Kept for defense-in-depth against a malformed catalog.
func (r CreateRequest) Validate() error {
	if r.VCPU < 1 || r.VCPU > 8 {
		return fmt.Errorf("%w: vcpu out of range [1,8]: %d", ErrInvalidRequest, r.VCPU)
	}
	if r.MemMib < 128 || r.MemMib > 16384 {
		return fmt.Errorf("%w: mem_mib out of range [128,16384]: %d", ErrInvalidRequest, r.MemMib)
	}
	if !IsAllowedDiskMib(r.DiskMib) {
		allowed := make([]string, 0, len(AllowedDiskSizesMib))
		for _, v := range AllowedDiskSizesMib {
			allowed = append(allowed, fmt.Sprintf("%dgb", v/1024))
		}
		return fmt.Errorf("%w: disk_mib %d not allowed; choose one of %v", ErrInvalidRequest, r.DiskMib, allowed)
	}
	return nil
}

// CreateResult describes how a sandbox was created and how long it took.
type CreateResult struct {
	Sandbox *Sandbox
	Mode    string
	SpawnMs float64
}

// NewManager constructs a Manager and pre-creates the network and overlay pools.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	runtime, err := currentFirecrackerRuntime(cfg.SeccompFilterPath)
	if err != nil {
		return nil, fmt.Errorf("Firecracker runtime: %w", err)
	}
	log.WithField("firecracker_build", runtime.Build).WithField("seccomp", runtime.Seccomp).Info("[runtime] pinned default Firecracker")

	if len(cfg.Rootfses) == 0 {
		return nil, fmt.Errorf("rootfs catalog is empty")
	}
	if cfg.DefaultRootfs == "" {
		return nil, fmt.Errorf("default rootfs is required")
	}
	if _, ok := cfg.Rootfses[cfg.DefaultRootfs]; !ok {
		return nil, fmt.Errorf("default rootfs %q not in catalog", cfg.DefaultRootfs)
	}

	if cfg.Subnet == "" {
		return nil, fmt.Errorf("subnet is required")
	}
	log.Infof("[server] pre-creating %d network slots in %s...", cfg.PoolSize, cfg.Subnet)
	// Resolve kvm GID before pool creation: NetPool stamps it on each
	// slot's tap.Group, so the per-slot UID firecracker can pass the
	// kernel's in_egroup_p check on TUNSETIFF.
	var kvmGID uint32
	if cfg.FirecrackerUIDBase > 0 {
		if g, err := lookupKVMGID(); err == nil {
			kvmGID = g
		}
		// If kvm group is missing the per-slot path will fall back to
		// root-mode in NewManager below; tap.Group = 0 is fine in
		// root mode since firecracker has CAP_NET_ADMIN anyway.
	}
	SetNetPoolWorkers(cfg.NetPoolWorkers)
	pool, err := NewNetPool(cfg.PoolSize, cfg.Subnet, cfg.Gateway, cfg.ReservedVMIPs, cfg.LiveContainerIDs, cfg.FirecrackerUIDBase, kvmGID)
	if err != nil {
		return nil, fmt.Errorf("network pool: %w", err)
	}

	log.Infof("[server] pre-creating %d overlay disks per size (seeding %dMB)...", cfg.PoolSize, int64(10*1024))
	overlayPool := NewOverlayPools(cfg.PoolSize, []int64{10 * 1024})

	snapshotDir := cfg.SnapshotDir
	if snapshotDir == "" {
		snapshotDir = "snapshots"
	}
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		return nil, fmt.Errorf("snapshot dir: %w", err)
	}

	// Reap any prewarm-template firecrackers orphaned by a previous
	// serve generation. createBaseSnapshot's deferred cleanup runs
	// only on return; a SIGTERM during the multi-second
	// PauseVM/CreateSnapshot for a big shape (8 GiB+ memfile) leaves
	// the firecracker child re-parented to init, holding vCPUs + RAM
	// forever. Without this sweep, every restart-during-prewarm
	// accumulates one orphan per leaked shape, eventually saturating
	// host load and slowing every subsequent spawn.
	ReapOrphanedPrewarmTemplates()

	m := &Manager{
		firecrackerRuntime:  runtime,
		Pool:                pool,
		OverlayPool:         overlayPool,
		Sandboxes:           make(map[string]*Sandbox),
		creating:            make(map[string]int),
		pendingRelease:      make(map[string]*PooledNet),
		KernelPath:          cfg.KernelPath,
		InitrdPath:          cfg.InitrdPath,
		Rootfses:            maps.Clone(cfg.Rootfses),
		DefaultRootfs:       cfg.DefaultRootfs,
		Subnet:              cfg.Subnet,
		Gateway:             cfg.Gateway,
		DiskSizeMB:          cfg.DiskSizeMB,
		ColdOnly:            cfg.ColdOnly,
		SnapshotDir:         snapshotDir,
		Snapshots:           make(map[shapeKey]*snapshotFiles),
		Shapes:              NewCatalog(pickShapes(cfg.Shapes)),
		shapesList:          pickShapes(cfg.Shapes),
		prewarmAll:          cfg.PrewarmAllRootfs,
		uffdMode:            cfg.UFFDMode,
		agentProbeTransport: cfg.AgentProbeTransport,
		prewarmDone:         make(chan struct{}),
		firecrackerUIDBase:  cfg.FirecrackerUIDBase,
	}
	// Resolve kvm group GID once so the Credential drop can include it
	// as a supplementary group. Required for /dev/kvm access post-drop.
	if cfg.FirecrackerUIDBase > 0 {
		if g, err := lookupKVMGID(); err != nil {
			log.Warnf("[manager] firecracker-uid-base set but no kvm group: %v (staying in root mode)", err)
			m.firecrackerUIDBase = 0
		} else {
			m.kvmGID = g
			log.Infof("[manager] per-slot firecracker UIDs enabled (base=%d, kvm gid=%d)",
				cfg.FirecrackerUIDBase, g)
		}
	}
	// Resolve effective MaxVMs:
	//   cfg.MaxVMs == 0  → derive from IPAM pair count
	//   cfg.MaxVMs > 0   → user-requested cap
	// Then clamp to the IPAM capacity (the absolute ceiling — you can't
	// run more VMs than there are /31 pairs in the subnet). Warn loudly
	// if the user asked for more than the subnet allows so they know to
	// bump the subnet.
	requested := cfg.MaxVMs
	capacity := pool.IPAMCapacity()
	switch {
	case requested == 0:
		m.MaxVMs = capacity
	case requested <= capacity:
		m.MaxVMs = requested
	default:
		log.Warnf("[server] requested max_vms=%d exceeds IPAM capacity %d (subnet=%s); clamping to %d",
			requested, capacity, cfg.Subnet, capacity)
		m.MaxVMs = capacity
	}
	if m.MaxVMs > 0 {
		log.Infof("[server] max VMs on this host: %d (subnet capacity %d)", m.MaxVMs, capacity)
	}

	log.Infof("[server] rootfs catalog: %d image(s), default=%q", len(cfg.Rootfses), cfg.DefaultRootfs)

	// Phase 3: overlay policy BPF programs + maps. No host-wide tunnel
	// device anymore — cross-host traffic flows raw over the WG mesh
	// (wg-hosts), and BPF's job is purely the VNI gate (no encap, no MAC
	// rewrites). The wg-hosts device itself is brought up earlier in
	// internal/hosts/main.go before NewManager runs.
	//
	// One-time legacy cleanup: tear down leftover state from the
	// pre-Path-B install (fcvxlan0 device + dead pinned BPF maps).
	// No-op once it's been cleaned.
	removeLegacyOverlayArtifacts()

	if err := EnsureOverlayMaps(); err != nil {
		pool.Abort()
		return nil, fmt.Errorf("initialize overlay policy maps: %w", err)
	}
	if err := LoadBPFPolicy(); err != nil {
		pool.Abort()
		return nil, fmt.Errorf("load overlay policy: %w", err)
	}
	if cfg.Subnet != "" {
		if err := SetVMSubnet(cfg.Subnet); err != nil {
			pool.Abort()
			return nil, fmt.Errorf("configure overlay policy subnet: %w", err)
		}
		log.Infof("[overlay] SetVMSubnet %s", cfg.Subnet)
	}
	// fc_wg_ingress is the only mandatory membership check for packets
	// arriving from another compute host. Continuing without it would leave
	// the broad `-i wg-hosts -j ACCEPT` forwarding rule without its tenant-
	// isolation gate. Refuse to serve rather than operating unprotected.
	if err := AttachBPFPolicyToWGIface(WGHostsDevName); err != nil {
		pool.Abort()
		return nil, fmt.Errorf("attach cross-host network policy to %s: %w", WGHostsDevName, err)
	}

	// Store overlay config on the manager so it can be used by the reconciler.
	m.overlayConfig = cfg

	// Phase 5: allocate the DNS table. The reconciler populates it on every
	// tick; StartNetReconciler starts the stub.
	m.DNSTable = dns.NewTable()

	// Phase 6: re-pin slots of `destroying` rows we kept alive across
	// startup. Build a synthetic PooledNet for each — minimal fields
	// (NetNSPath, ContainerID, IPAM pair, permanent=false). On Release
	// the slot tears down rather than recycles, so TapName/MAC don't
	// need to be reconstructed accurately.
	for _, r := range cfg.PendingDestroyingRecords {
		if r.ContainerID == nil || *r.ContainerID == "" || r.IP == nil || *r.IP == "" {
			continue
		}
		gw, err := adjacentIP(*r.IP)
		if err != nil {
			log.Warnf("[manager] pendingRelease pre-populate %s: %v (skipping)", r.ID, err)
			continue
		}
		cidr := *r.IP + "/31"
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warnf("[manager] pendingRelease pre-populate %s: parse %s: %v (skipping)", r.ID, cidr, err)
			continue
		}
		ipNet.IP = net.ParseIP(*r.IP).To4()
		pn := &PooledNet{
			NetNSPath:   NetnsPathRoot + *r.ContainerID,
			ContainerID: *r.ContainerID,
			IP:          *ipNet,
			Gateway:     net.ParseIP(gw).To4(),
			pair:        IPPair{VMCIDR: cidr, Gateway: gw},
			ipam:        m.Pool.ipam,
			permanent:   false, // tear down on Release, do not recycle
		}
		pn.trackExistingProcess(r.FCPid)
		m.pendingRelease[r.ID] = pn
	}
	if len(m.pendingRelease) > 0 {
		log.Infof("[manager] pinned %d destroying-row slot(s) across startup", len(m.pendingRelease))
	}

	log.Info("[server] ready (snapshot on first create, fallback to cold boot)")
	return m, nil
}

// RootfsPathFor returns the on-disk path for the given catalog name. If name
// is empty it falls back to DefaultRootfs.
func (m *Manager) RootfsPathFor(name string) (string, error) {
	if name == "" {
		name = m.DefaultRootfs
	}
	path, ok := m.LookupRootfs(name)
	if !ok {
		return "", fmt.Errorf("%w: rootfs %q not in catalog", ErrInvalidRequest, name)
	}
	return path, nil
}

// RootfsNames returns the catalog names sorted ascending.
func (m *Manager) RootfsNames() []string {
	m.RootfsesMu.RLock()
	defer m.RootfsesMu.RUnlock()
	names := make([]string, 0, len(m.Rootfses))
	for k := range m.Rootfses {
		names = append(names, k)
	}
	// not sorted to avoid pulling sort dep here; callers can sort if needed
	return names
}

// LookupRootfs returns the on-disk path for a catalog rootfs name or
// (if a template was previously fetched and registered) for a tpl_id.
// The lock makes this safe against concurrent template add/remove.
func (m *Manager) LookupRootfs(name string) (string, bool) {
	m.RootfsesMu.RLock()
	defer m.RootfsesMu.RUnlock()
	p, ok := m.Rootfses[name]
	return p, ok
}

// RootfsCatalog returns an independent snapshot safe to iterate after unlocking.
func (m *Manager) RootfsCatalog() map[string]string {
	m.RootfsesMu.RLock()
	defer m.RootfsesMu.RUnlock()
	return maps.Clone(m.Rootfses)
}

// AddRootfs registers a new (name → path) entry. Used by the template
// fetch path; idempotent for the common case where the path didn't change.
func (m *Manager) AddRootfs(name, path string) {
	m.RootfsesMu.Lock()
	m.Rootfses[name] = path
	m.RootfsesMu.Unlock()
}

// RemoveRootfs drops a catalog entry. Caller is responsible for ensuring
// no active sandbox references it (the template reaper does this check
// against the DB before evicting).
func (m *Manager) RemoveRootfs(name string) {
	m.RootfsesMu.Lock()
	delete(m.Rootfses, name)
	m.RootfsesMu.Unlock()
}

// getOverlay returns an overlay path sized for diskMib. OverlayPools hits the
// right per-size pool (lazy-created if the size is new) or mkfs's fresh as a
// fallback.
func (m *Manager) getOverlay(diskMib int64) (string, error) {
	return m.OverlayPool.GetOverlay(diskMib)
}

// Create creates a new sandbox with the requested shape.
func (m *Manager) Create(ctx context.Context, req CreateRequest) (*CreateResult, error) {
	// Resolve shape → concrete sizing. Disk can be overridden per-request;
	// if unset we take the shape's default.
	if req.Shape == "" {
		return nil, fmt.Errorf("%w: shape is required (valid: %v)", ErrInvalidRequest, m.shapeCatalog().IDs())
	}
	vcpu, mem, defaultDisk, cpuQuotaPct, err := m.shapeCatalog().Resolve(req.Shape)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	req.VCPU, req.MemMib = vcpu, mem
	req.CPUQuotaPct = cpuQuotaPct
	if req.DiskMib == 0 {
		req.DiskMib = defaultDisk
	}
	if req.Rootfs == "" {
		req.Rootfs = m.DefaultRootfs
	}
	rootfsPath, ok := m.LookupRootfs(req.Rootfs)
	if !ok {
		return nil, fmt.Errorf("%w: rootfs %q not in catalog", ErrInvalidRequest, req.Rootfs)
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	restrictedEgress := len(req.Egress) > 0
	if restrictedEgress {
		parsed, ok := parseEgressRules(req.Egress)
		if !ok {
			return nil, fmt.Errorf("%w: invalid egress rules", ErrInvalidRequest)
		}
		restrictedEgress = !parsed.allowAll
	}
	if req.SecretToken == "" {
		return nil, fmt.Errorf("%w: secret_token is required", ErrInvalidRequest)
	}

	start := time.Now()
	var tPool, tOverlay, tBoot, tAgent, tNet time.Duration

	m.Mu.Lock()
	if m.MaxVMs > 0 && len(m.Sandboxes) >= m.MaxVMs {
		m.Mu.Unlock()
		return nil, fmt.Errorf("%w (running=%d, max=%d)", ErrAtCapacity, len(m.Sandboxes), m.MaxVMs)
	}
	m.Mu.Unlock()
	id := req.ID
	if id == "" {
		id = newSandboxID()
	}

	// Grab pre-pooled network
	t0 := time.Now()
	pn, poolDepth := m.Pool.GetWithDepth()
	tPool = time.Since(t0)
	if err := BindVMIPToIface(vethNameFor(pn.ContainerID), pn.IP.IP.String()); err != nil {
		// Return performs the same fail-closed cleanup used after a normal
		// borrower. If the map itself is unhealthy, the slot is discarded
		// and replaced instead of being exposed to a tenant without policy.
		m.Pool.Return(pn)
		return nil, fmt.Errorf("bind network policy: %w", err)
	}
	uid := m.SlotUID(pn.VsockCID)
	leaseGranted := false
	keepLease := false
	if err := m.grantTemplateAccess(req.Rootfs, rootfsPath, uid); err != nil {
		m.Pool.Return(pn)
		return nil, err
	}
	leaseGranted = uid > 0 && isTemplateRootfs(req.Rootfs)
	defer func() {
		if leaseGranted && !keepLease {
			_ = revokeTemplateAccess(req.Rootfs, rootfsPath, uid)
		}
	}()

	// Register only after the potentially blocking pool wait, but before any
	// per-VM filesystem work. From this point until insertion into Sandboxes (or
	// failure cleanup), the runtime-dir sweeper must treat this ID as owned.
	// Registering before GetWithDepth would let a request waiting indefinitely
	// for a slot protect an ID even though it has not created any runtime dir.
	releaseRuntime := m.HoldRuntime(id)
	defer releaseRuntime()

	// Grab overlay (from pool if sized like the pool, else on-demand)
	t0 = time.Now()
	overlayPath := req.RestoreOverlay
	if overlayPath == "" {
		overlayPath, err = m.getOverlay(req.DiskMib)
	}
	tOverlay = time.Since(t0)
	if err != nil {
		m.Pool.Return(pn)
		return nil, fmt.Errorf("overlay: %w", err)
	}

	// Per-VM runtime dir: contains the API socket, vsock UDS, and UFFD
	// sock. Created mode 0700 owned by root; ChownForSlot transfers
	// ownership to the per-slot UID right before launch when
	// firecracker_uid_base is set, so the post-drop firecracker can
	// bind sockets inside.
	socketPath := slotRuntimePath(id, "fc.sock")
	if pn != nil {
		// Chown the runtime dir to the slot UID so firecracker can bind
		// its API socket post-drop. No-op when uid base is 0.
		m.ChownForSlot(SlotRuntimeDir(id), pn.VsockCID)
	}

	key := shapeKey{VCPU: req.VCPU, MemMib: req.MemMib, Rootfs: req.Rootfs}

	// Try snapshot path first (singleflight keyed by shape ensures only one
	// snapshot build per unique (vcpu, mem) pair).
	var sb *Sandbox
	mode := "cold"
	snapAvailable := false
	if !m.ColdOnly {
		if err := m.ensureSnapshot(key); err != nil {
			log.WithContext(ctx).Warnf("[sandbox] snapshot not available for %s (%v), falling back to cold boot", key, err)
		} else {
			snapAvailable = m.snapshotReady(key)
		}
	}

	t0 = time.Now()
	if snapAvailable {
		sb, err = m.createFromSnapshot(id, req.Name, pn, overlayPath, socketPath, key, req.SecretToken, req.Disks)
		if err != nil {
			log.WithContext(ctx).Warnf("[sandbox] snapshot restore failed (%v), falling back to cold boot", err)
			// Drop the snapshot from the in-memory registry so the
			// next create doesn't try the same broken snapshot. The
			// next prewarm tick rebuilds.
			//
			// NOTE: do NOT async-RemoveAll the snapDir here. Under
			// 100-way concurrent creates against a broken snapshot,
			// every failing goroutine raced to RemoveAll the same
			// dir while OTHER goroutines were still reading vmstate +
			// memfile from it — producing spurious "snapshot file
			// not found" errors for creates that would have succeeded.
			// The orphan dir gets reclaimed on the next prewarm cycle
			// when it rebuilds in place; disk leak is one dir per
			// (vcpu, mem, rootfs) combo, bounded.
			m.SnapshotsMu.Lock()
			delete(m.Snapshots, key)
			m.SnapshotsMu.Unlock()
			os.Remove(socketPath)
			socketPath = slotRuntimePath(id, "fc.sock")
			sb, err = m.createColdBoot(id, pn, overlayPath, socketPath, req)
		} else {
			mode = "snapshot"
		}
	} else {
		sb, err = m.createColdBoot(id, pn, overlayPath, socketPath, req)
	}
	tBoot = time.Since(t0)

	if err != nil {
		os.Remove(overlayPath)
		os.Remove(socketPath)
		// Same as the agent_not_ready branch below: if firecracker bound
		// vsock.uds before failing, the runtime dir would otherwise
		// linger forever. RemoveAll is a no-op when the dir doesn't
		// exist yet (early-StartVMM failures).
		_ = os.RemoveAll(SlotRuntimeDir(id))
		m.Pool.Return(pn)
		return nil, fmt.Errorf("create sandbox: %w", err)
	}

	// Verify agent is ready. 5s is a firm liveness cap — p99 is ~120ms,
	// and under 50-way burst a guest that hasn't answered in 5s is wedged
	// (confirmed empirically: extending to 15s only recovers ~3 extra VMs
	// per 1000 while adding 40s of wall clock on the slow-path cycles).
	// Callers should retry on the rare 500 rather than block the deadline.
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	t0 = time.Now()
	err = waitForAgentByTransport(readyCtx, sb, m.agentProbeTransport)
	tAgent = time.Since(t0)
	if err != nil {
		// SYN black-hole diagnostic: capture host-side veth + iptables
		// before we tear the VM down, so the failure isn't observation-
		// less. Best-effort — never blocks teardown for more than ~1s.
		captureBlackholeDiag(sb.ID, sb.IP, pn.ContainerID)
		// A failed readiness probe means this VM was never registered, so the
		// normal Destroy path cannot reap it. Never wait without a deadline:
		// StopVMM may not terminate a wedged Firecracker process, which used to
		// hold the create request open until control's one-hour timeout.
		stopFailedVM(sb)
		os.Remove(overlayPath)
		os.Remove(socketPath)
		// Wipe the slot's runtime dir — it carries the vsock.uds socket
		// file firecracker just bound. Without this the dir accumulates
		// one entry per agent_not_ready failure (slot-uid owned, parent
		// 0700 root) until serve restart, growing a graveyard of zero-
		// byte sockets that's both noisy in `ls runtime/` and a real
		// inode leak on the locality cache filesystem.
		_ = os.RemoveAll(SlotRuntimeDir(id))
		// Don't recycle a slot that just produced a 5s SYN black-hole —
		// the failure is per-slot and persistent (same fcpN keeps
		// re-failing on every borrow until serve restart). Discard
		// teardowns the netns/veth/tap; replenish() rebuilds a fresh
		// slot to keep pool depth at the configured target.
		m.Pool.Discard(pn)
		return nil, fmt.Errorf("agent not ready: %w", err)
	}

	// Resolve bandwidth quota. 0 = apply default; positive = honor.
	// Negative values are rejected at the API; defense-in-depth here
	// folds any leftover negative onto the default rather than turning
	// the cap off.
	if req.BandwidthQuotaBytes <= 0 {
		sb.BandwidthQuota = DefaultBandwidthQuotaBytes
	} else {
		sb.BandwidthQuota = req.BandwidthQuotaBytes
	}

	// Stash the egress rules and install iptables rules for this VM.
	sb.Egress = req.Egress
	// Persist the persistent env-var map onto the in-memory sandbox so
	// the host's exec handler can inject them on every /exec call.
	sb.Envs = req.Envs
	// Cache owner id so authOwnedFast can shortcut per-call ownership
	// verification. Empty on legacy paths — falls back to DB.
	sb.SetCachedOwner(req.CreatedBy)
	t0 = time.Now()
	if veth, err := HostVethFor(sb.IP); err != nil {
		if restrictedEgress {
			stopFailedVM(sb)
			_ = os.Remove(overlayPath)
			_ = os.Remove(socketPath)
			_ = os.RemoveAll(SlotRuntimeDir(id))
			m.Pool.Return(pn)
			return nil, fmt.Errorf("resolve egress interface: %w", err)
		}
		log.WithContext(ctx).Warnf("[egress] could not resolve veth for unrestricted sandbox %s: %v", id, err)
	} else {
		sb.HostVeth = veth
		// Batched install: coalesces concurrent xt_lock acquisitions.
		// Single spawns behave like a direct InstallEgress; N-parallel
		// spawns converge on ~2 iptables-restore invocations regardless
		// of N.
		if err := EnqueueInstall(id, sb.IP, veth, req.Egress); err != nil {
			stopFailedVM(sb)
			RemoveSandboxIPTables(id, veth)
			_ = os.Remove(overlayPath)
			_ = os.Remove(socketPath)
			_ = os.RemoveAll(SlotRuntimeDir(id))
			m.Pool.Return(pn)
			return nil, fmt.Errorf("install egress policy: %w", err)
		}
		// Meter is always installed (even when unmetered) so a later
		// recharge/quota change can take effect without reinstall.
		if err := m.installMeterFor(id, veth); err != nil {
			log.WithContext(ctx).Warnf("[meter] install failed for %s: %v", id, err)
		}
	}
	tNet = time.Since(t0)

	if pid, err := sb.Machine.PID(); err == nil {
		sb.FCPid = pid
		// CPU throttle for fractional-vCPU shapes. Async: cgroup mkdir +
		// kernel thread-walk on cgroup.procs write costs 21–28ms per VM
		// on prod, which would dominate the post-tNet spawn tail. Doing
		// it off the hot path lets spawn return in ~18ms. Trade: the
		// guest runs unthrottled for ~25ms after spawn before the
		// cgroup attaches — bounded, one-time-per-VM, irrelevant for
		// VMs that live more than a second. No-op for full-CPU shapes
		// (CPUQuotaPct == 0), the current catalog.
		// Hard memory cap protects the host from a runaway guest: without
		// it, the host's global OOM killer can take out createos itself
		// when a tenant's VM grows past its allocated size. Always pass
		// req.MemMib so cgroup-scoped OOM (CONSTRAINT_MEMCG) fires
		// INSIDE the VM's cgroup, not globally. cpu.max stays opt-in
		// per shape via CPUQuotaPct.
		if req.CPUQuotaPct > 0 || req.MemMib > 0 || CPULanesActive() {
			go EnsureVMCgroup(id, req.Shape, pid, req.CPUQuotaPct, req.MemMib)
		}
		// Per-process rlimits (NOFILE, NPROC, FSIZE). Belt-and-braces with
		// the cgroup pids.max; NOFILE has no cgroup equivalent. FSIZE caps
		// the largest writable file at the VM's disk size + slop so an
		// escaped firecracker can't balloon the overlay and ENOSPC the
		// host.
		if m.firecrackerUIDBase > 0 {
			go ApplyRlimits(pid, int64(req.DiskMib))
		}
	} else {
		log.WithContext(ctx).Warnf("[sandbox] %s: PID() failed: %v (rehydrate after restart won't find this VM)", id, err)
	}

	m.Mu.Lock()
	m.Sandboxes[id] = sb
	m.Mu.Unlock()

	// Per-VM death watcher: notices unexpected firecracker exits and
	// invokes the OnSandboxDeath callback so the DB can be updated in
	// real time (rather than waiting for the next serve restart's
	// reconcile pass).
	m.WatchDeath(sb)
	// Liveness watcher: catches a guest that halted its own vCPU (the
	// firecracker process stays alive — no ACPI to power it off). No-op
	// unless AgentLivenessProbe is enabled.
	m.WatchLiveness(sb)
	if len(req.Disks) > 0 {
		m.settleDiskStatus(id)
	}

	spawnDur := time.Since(start)
	log.WithContext(ctx).Infof("[sandbox] rid=%s %s created via %s in %s (ip=%s, vcpu=%d, mem=%d, disk=%d) phases: pool=%s(depth=%d) overlay=%s boot=%s agent=%s net=%s",
		httpx.RequestID(ctx), id, mode, spawnDur, sb.IP, sb.VCPU, sb.MemMib, sb.DiskMib,
		tPool.Round(time.Millisecond), poolDepth, tOverlay.Round(time.Millisecond),
		tBoot.Round(time.Millisecond), tAgent.Round(time.Millisecond),
		tNet.Round(time.Millisecond))

	// Emit prometheus phase histograms + lifecycle counter. Mirror the
	// same phase set the [sandbox] log line uses so log + graph agree.
	metrics.SandboxOps.WithLabelValues("created").Inc()
	metrics.SpawnPhaseSeconds.WithLabelValues("pool").Observe(tPool.Seconds())
	metrics.SpawnPhaseSeconds.WithLabelValues("boot").Observe(tBoot.Seconds())
	metrics.SpawnPhaseSeconds.WithLabelValues("agent").Observe(tAgent.Seconds())
	metrics.SpawnPhaseSeconds.WithLabelValues("net").Observe(tNet.Seconds())
	metrics.SpawnPhaseSeconds.WithLabelValues("total").Observe(spawnDur.Seconds())
	metrics.NetPoolDepth.Set(float64(poolDepth))
	keepLease = true

	return &CreateResult{
		Sandbox: sb,
		Mode:    mode,
		SpawnMs: float64(spawnDur.Microseconds()) / 1000.0,
	}, nil
}

// stopFailedVM terminates a machine that never became visible in Sandboxes.
// Destroy cannot handle it because registration deliberately happens only
// after all create-time policy is installed. Use SIGKILL and a bounded reap:
// StopVMM can fail before registration, while Wait(context.Background()) can
// then hold the create request open forever and leave an unrestricted VM live.
func stopFailedVM(sb *Sandbox) {
	if sb == nil {
		return
	}
	pid := sb.FCPid
	if pid <= 0 && sb.Machine != nil {
		pid, _ = sb.Machine.PID()
	}
	KillFirecrackerFast(pid)
	if sb.Machine != nil {
		waitCtx, cancelWait := context.WithTimeout(context.Background(), 3*time.Second)
		_ = sb.Machine.Wait(waitCtx)
		cancelWait()
	}
	if sb.cancel != nil {
		sb.cancel()
	}
}

// snapshotReady reports whether a snapshot for the given shape is built.
func (m *Manager) snapshotReady(key shapeKey) bool {
	m.SnapshotsMu.Lock()
	defer m.SnapshotsMu.Unlock()
	s, ok := m.Snapshots[key]
	return ok && s.Ready
}

// UpdateEgress atomically replaces the sandbox's egress allowlist.
// Restricted-to-restricted changes retain the existing jump and replace its
// target chain through iptables-restore. Empty/nil rules = allow-all.
func (m *Manager) UpdateEgress(id string, rules []string) error {
	m.Mu.RLock()
	sb, ok := m.Sandboxes[id]
	m.Mu.RUnlock()
	if !ok {
		return fmt.Errorf("sandbox not found")
	}
	if sb.HostVeth == "" {
		return fmt.Errorf("sandbox has no host veth — egress unmanaged")
	}
	sb.egressMu.Lock()
	defer sb.egressMu.Unlock()
	// Destroy/pause removes the sandbox from the manager while holding the
	// same lock. Re-check after acquiring it: UpdateEgress may have obtained
	// sb just before teardown won the race and then waited here.
	m.Mu.RLock()
	current, stillRunning := m.Sandboxes[id]
	m.Mu.RUnlock()
	if !stillRunning || current != sb {
		return fmt.Errorf("sandbox not found")
	}
	if err := ReplaceEgress(id, sb.IP, sb.HostVeth, sb.Egress, rules); err != nil {
		return err
	}
	// Update the in-memory sandbox so subsequent reads (List, Info, etc.)
	// reflect the new state.
	m.Mu.Lock()
	sb.Egress = rules
	m.Mu.Unlock()
	return nil
}

// BeginTeardown serialises pause/destroy teardown with live egress updates.
// It removes sb from the running set while holding its egress lock, so no
// update can install policy after teardown has started. The caller must invoke
// the returned unlock function after it has queued iptables cleanup.
func (m *Manager) BeginTeardown(sb *Sandbox) (unlock func(), ok bool) {
	if sb == nil {
		return nil, false
	}
	sb.egressMu.Lock()
	m.Mu.Lock()
	current, ok := m.Sandboxes[sb.ID]
	if ok && current == sb {
		delete(m.Sandboxes, sb.ID)
	} else {
		ok = false
	}
	m.Mu.Unlock()
	if !ok {
		sb.egressMu.Unlock()
		return nil, false
	}
	sb.cancelFileTransfers()
	return sb.egressMu.Unlock, true
}

// Lookup returns the sandbox with the given id.
func (m *Manager) Lookup(id string) (*Sandbox, bool) {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	sb, ok := m.Sandboxes[id]
	return sb, ok
}

// SandboxVCPU returns the guest vCPU count for a tracked sandbox.
// Used by the metrics package as a fallback denominator when the
// cgroup has no CPU quota (full-vcpu shapes set cpu.max=max).
func (m *Manager) SandboxVCPU(id string) (int, bool) {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	sb, ok := m.Sandboxes[id]
	if !ok {
		return 0, false
	}
	return sb.VCPU, true
}

// SandboxNetTotals returns cumulative host→VM and VM→host byte counts
// tracked by the BPF veth meter. The metrics scraper converts these
// into per-second rates for the ring buffer and Prometheus counters.
func (m *Manager) SandboxNetTotals(id string) (uint64, uint64, bool) {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	sb, ok := m.Sandboxes[id]
	if !ok {
		return 0, 0, false
	}
	return uint64(sb.BandwidthIngressBytes), uint64(sb.BandwidthUsed), true
}

// SandboxDiskMib returns the shape's disk_mib ceiling and the current
// overlay file path. Metrics scraper stats the overlay to derive the
// storage-used gauge.
func (m *Manager) SandboxDiskMib(id string) (int64, string, bool) {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	sb, ok := m.Sandboxes[id]
	if !ok {
		return 0, "", false
	}
	return sb.DiskMib, sb.OverlayPath, true
}

// LiveIDs returns the ids of every sandbox currently tracked by the
// manager. Snapshot under RLock so callers can iterate without
// worrying about map mutation mid-walk.
func (m *Manager) LiveIDs() []string {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	ids := make([]string, 0, len(m.Sandboxes))
	for id := range m.Sandboxes {
		ids = append(ids, id)
	}
	return ids
}

// RuntimeIDs returns every sandbox ID whose runtime directory is currently
// owned by the manager, including creates that have not booted far enough to
// enter Sandboxes. It is intentionally narrower than LiveIDs' callers: only
// the runtime-directory orphan sweep should treat an in-progress create as
// live; DB reconciliation must continue to see running VMs only.
func (m *Manager) RuntimeIDs() []string {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	ids := make([]string, 0, len(m.Sandboxes)+len(m.creating))
	for id := range m.Sandboxes {
		ids = append(ids, id)
	}
	for id := range m.creating {
		if _, running := m.Sandboxes[id]; !running {
			ids = append(ids, id)
		}
	}
	return ids
}

// Destroy stops the VM with the given id and reclaims its resources.
func (m *Manager) Destroy(id string) error {
	m.Mu.RLock()
	sb, ok := m.Sandboxes[id]
	m.Mu.RUnlock()
	if !ok {
		return fmt.Errorf("sandbox not found")
	}
	unlockEgress, ok := m.BeginTeardown(sb)
	if !ok {
		return fmt.Errorf("sandbox not found")
	}
	defer unlockEgress()
	metrics.SandboxOps.WithLabelValues("destroyed").Inc()

	// Mark destroyed BEFORE teardown so the watcher goroutine knows this
	// exit was deliberate and doesn't re-invoke Destroy / OnSandboxDeath.
	sb.Destroyed.Store(true)

	teardownFailed := false
	if sb.HostVeth != "" {
		// One last meter read + persist before the maps get zeroed so
		// the DB's bandwidth_used_bytes reflects the final byte count at
		// destroy time. The 5s meter tick may have missed the last few
		// seconds of traffic; this closes that window.
		if m.meterPersist != nil {
			if bytes, err := m.readMeterBytesFor(id); err == nil {
				m.meterPersist(id, sb.BandwidthBaseline+int64(bytes), sb.BandwidthCapped)
			}
		}
		if m.meterIngressPersist != nil {
			if ib, err := m.readIngressMeterBytesFor(id); err == nil {
				m.meterIngressPersist(id, sb.BandwidthIngressBaseline+int64(ib))
			}
		}
		// Detach per-veth BPF programs + clear per-VM map entries. The
		// shared programs + maps stay loaded.
		DetachBPFMeter(id, sb.HostVeth)
		ResetBPFMeter(id)
		// Batched teardown: coalesces concurrent destroys into one
		// iptables-restore per xt_lock cycle. Single destroys behave
		// like a direct call; N-parallel destroys converge on 2
		// iptables-restore invocations regardless of N.
		if err := EnqueueTeardown(id, sb.HostVeth); err != nil {
			teardownFailed = true
			log.Warnf("[sandbox] iptables teardown failed sandbox=%s veth=%s: %v; discarding slot",
				id, sb.HostVeth, err)
		}
	}
	// Fast path: SIGKILL + fire-and-forget. The old SIGTERM + 50ms poll
	// + 3s grace never trips below a ~100ms floor even when firecracker
	// exits in <5ms. We're intentionally destroying the VM — overlay is
	// disposable, guest has no state to flush — so graceful shutdown is
	// wasted time.
	KillFirecrackerFast(sb.FCPid)
	if err := m.RevokeTemplateAccess(sb); err != nil {
		log.Warnf("[template-acl] revoke sandbox=%s: %v", id, err)
	}
	// rmdir per-VM cgroup leaf. Best-effort; cgroup v2 refuses rmdir
	// while any process is still attached, but KillFirecrackerFast
	// above sends SIGKILL so the leaf is empty by the time we get here
	// in practice. Any stragglers just leave a directory behind until
	// the next serve restart.
	RemoveVMCgroup(id)
	if sb.cancel != nil {
		sb.cancel()
	}
	if sb.Uffd != nil {
		sb.Uffd.Close()
	}
	os.Remove(sb.OverlayPath)
	os.Remove(sb.ApiSocket)
	if sb.VsockUDSPath != "" {
		// firecracker creates both the bare path and a per-port "_PORT"
		// peer for guest-initiated connections. Clean both.
		os.Remove(sb.VsockUDSPath)
		os.Remove(sb.VsockUDSPath + "_1024")
	}
	// Per-VM runtime subdir holds fc.sock, vsock.uds, uffd.sock — the
	// individual file removes above clear those, but the empty subdir
	// itself lingers. RemoveAll catches both the dir and any sockets we
	// missed (e.g. extra vsock peer fds firecracker created at exec).
	_ = os.RemoveAll(SlotRuntimeDir(id))
	// Slot stays out of NetPool.ready until ReleaseSlot(id) is called,
	// which must wait until the sandbox row is durably `destroyed`.
	// Without this pin, a fresh create could grab this slot before the
	// DB has caught up, causing the dying sandbox's reconcile path to
	// tear down the new VM's network state.
	if sb.Net != nil && teardownFailed {
		// Preserve the veth as a discovery marker until the reaper retries the
		// sandbox-specific iptables teardown. It must never return to rotation
		// while stale rules still reference its interface name.
		m.Pool.QuarantineAfterTeardownFailure(sb.Net, id)
	} else if sb.Net != nil {
		m.pendingReleaseMu.Lock()
		m.pendingRelease[id] = sb.Net
		m.pendingReleaseMu.Unlock()
	}

	log.Infof("[sandbox] %s destroyed (slot pending release)", id)
	return nil
}

// ReleaseSlot returns the slot bound to sandbox id back to NetPool.
// Called by the caller of Destroy once the durable sandbox row has
// reached the `destroyed` state. Idempotent: unknown ids are no-ops.
func (m *Manager) ReleaseSlot(id string) {
	m.pendingReleaseMu.Lock()
	pn, ok := m.pendingRelease[id]
	if ok {
		delete(m.pendingRelease, id)
	}
	m.pendingReleaseMu.Unlock()
	if ok && pn != nil {
		m.Pool.Return(pn)
	}
}

// PendingReleaseIDs returns a snapshot of sandbox ids whose slots are
// torn down but not yet returned to the pool. Used by the reconcile
// tick to walk pending releases and drive them to completion once the
// DB confirms `destroyed`.
func (m *Manager) PendingReleaseIDs() []string {
	m.pendingReleaseMu.Lock()
	defer m.pendingReleaseMu.Unlock()
	out := make([]string, 0, len(m.pendingRelease))
	for id := range m.pendingRelease {
		out = append(out, id)
	}
	return out
}

// IsPendingRelease reports whether the slot for sandbox id is held in
// the pending-release map. Callers use this before invoking
// CleanupOrphan so they don't double-tear-down a slot the Manager has
// already stashed for orderly release.
func (m *Manager) IsPendingRelease(id string) bool {
	m.pendingReleaseMu.Lock()
	defer m.pendingReleaseMu.Unlock()
	_, ok := m.pendingRelease[id]
	return ok
}

// PendingReleaseContainerID returns the container_id of the slot
// stashed for sandbox id in pendingRelease. Reconcile sweeps use this
// to extend their keep-set so orphan-netns reapers don't tear down a
// pinned slot.
func (m *Manager) PendingReleaseContainerID(id string) (string, bool) {
	m.pendingReleaseMu.Lock()
	defer m.pendingReleaseMu.Unlock()
	pn, ok := m.pendingRelease[id]
	if !ok || pn == nil {
		return "", false
	}
	return pn.ContainerID, true
}

// WatchDeath starts a goroutine that notices when the sandbox's firecracker
// process exits WITHOUT Destroy being called first, reclaims the VM's
// resources, and invokes m.OnSandboxDeath. Safe to call once per sandbox;
// no-op if the watcher can't establish a way to observe the process.
//
// Two detection paths:
//   - Sandboxes created in-process have an SDK *Machine; we block on
//     Machine.Wait() which returns when firecracker exits.
//   - Rehydrated sandboxes (Machine == nil) have only the recorded
//     fc_pid; we poll /proc/<pid> every few seconds.
func (m *Manager) WatchDeath(sb *Sandbox) {
	if sb == nil {
		return
	}
	if sb.Machine != nil {
		go m.waitSDK(sb)
		return
	}
	if sb.FCPid > 0 {
		go m.pollPID(sb)
	}
}

func (m *Manager) waitSDK(sb *Sandbox) {
	_ = sb.Machine.Wait(context.Background())
	m.handleDeath(sb, "firecracker exited (SDK Wait returned)")
}

func (m *Manager) pollPID(sb *Sandbox) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for range t.C {
		if sb.Destroyed.Load() {
			return
		}
		if !pidAlive(sb.FCPid) {
			m.handleDeath(sb, fmt.Sprintf("firecracker pid %d not alive (rehydrated VM)", sb.FCPid))
			return
		}
	}
}

// WatchLiveness bounds how long an unreachable guest can retain VM resources.
// It allows five continuous minutes of failed probes before cleanup, since
// transient load or networking failures do not establish that the guest halted.
// No-op unless ManagerConfig.AgentLivenessProbe is set.
func (m *Manager) WatchLiveness(sb *Sandbox) {
	if sb == nil || !m.overlayConfig.AgentLivenessProbe || sb.IP == "" {
		return
	}
	go m.pollLiveness(sb)
}

func (m *Manager) pollLiveness(sb *Sandbox) {
	const (
		bootGrace    = 30 * time.Second // suppress probes for this long after boot
		interval     = 5 * time.Second
		dialBudget   = 1 * time.Second
		failureGrace = 5 * time.Minute // measured from the first failed probe
	)
	// Boot-grace: during a host-wide burst (e.g. 100+ VMs spawning at
	// once), the agent process inside each guest may not get a CPU
	// slice fast enough to answer the first probe within 1s. Without a
	// grace window the watchdog reaps VMs that are alive but starving,
	// not actually wedged. 30s is well above typical agent-ready
	// timings (single-digit ms on a quiet host) but below any
	// reasonable "guest is really dead" expectation.
	time.Sleep(bootGrace)
	if sb.Destroyed.Load() {
		return
	}
	addr := net.JoinHostPort(sb.IP, strconv.Itoa(agentPort))
	t := time.NewTicker(interval)
	defer t.Stop()
	var failedSince time.Time
	for range t.C {
		if sb.Destroyed.Load() {
			return
		}
		// While the pause path has the guest frozen, the agent on :1024
		// can't accept connections — every probe is going to time out.
		// Stand down until pause either completes (teardown removes the
		// sandbox) or fails (resume + clearing of Freezing).
		if sb.Freezing.Load() {
			failedSince = time.Time{}
			continue
		}
		// When the bandwidth cap is engaged, the BPF program drops every
		// packet egressing from the VM except those destined for the
		// per-VM veth gateway IP. The agent's reply to our probe goes
		// back to the host's main IP (which is NOT the veth gateway), so
		// it gets dropped → probe times out → without this exemption the
		// VM gets reaped as "self-halted" even though it's just being
		// rate-limited. Stand down until the cap is lifted via recharge.
		m.Mu.RLock()
		capped := false
		if live, ok := m.Sandboxes[sb.ID]; ok {
			capped = live.BandwidthCapped
		}
		m.Mu.RUnlock()
		if capped {
			failedSince = time.Time{}
			continue
		}
		// A live firecracker PID is the gate: if the process is already
		// gone, WatchDeath handles it — don't double-fire. If the PID is
		// 0 (not yet captured), skip this tick.
		if sb.FCPid > 0 && !pidAlive(sb.FCPid) {
			return
		}
		d := net.Dialer{Timeout: dialBudget}
		conn, err := d.Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
			failedSince = time.Time{}
			continue
		}
		// Measure the recovery window from the first failure rather than a
		// probe count; any successful probe clears the accumulated failure time.
		now := time.Now()
		if failedSince.IsZero() {
			failedSince = now
		}
		if elapsed := now.Sub(failedSince); elapsed >= failureGrace {
			m.handleDeath(sb, fmt.Sprintf("guest agent unresponsive on %s for %s — liveness timeout", addr, elapsed.Round(time.Second)))
			return
		}
	}
}

// handleDeath is the common cleanup path for unexpected firecracker exits.
// It first checks `destroyed` to skip the work that Manager.Destroy is
// already doing (the watcher fires on BOTH deliberate stops and crashes —
// we distinguish via the flag, which Destroy sets before stopping the VM).
func (m *Manager) handleDeath(sb *Sandbox, reason string) {
	if sb.Destroyed.Load() {
		return
	}
	if cause := sb.guestConsole.cause(); cause != "" {
		// Persist only the classification in the death reason. The console
		// itself can contain tenant secrets and must never enter host logs.
		log.WithFields(log.Fields{"sandbox_id": sb.ID, "guest_cause": cause}).Warn("guest death classified from serial console")
		reason += "; guest_cause=" + cause
	}
	log.Warnf("[watch] sandbox %s: %s — reclaiming resources", sb.ID, reason)
	// Destroy drops the sandbox from m.Sandboxes and tears down net/meter/
	// overlay. It also sets destroyed=true, so a redundant later call is
	// safe if something else noticed first.
	if err := m.Destroy(sb.ID); err != nil {
		log.Warnf("[watch] destroy %s: %v", sb.ID, err)
	}
	if m.OnSandboxDeath != nil {
		m.OnSandboxDeath(sb.ID, reason)
	}
}

// pidAlive returns true iff /proc/<pid> is a live process. Cheap enough
// for a 3-second polling loop: one stat syscall.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d/status", pid))
	return err == nil
}

// List returns info on all running sandboxes.
func (m *Manager) List() []proto.SandboxInfo {
	m.Mu.RLock()
	defer m.Mu.RUnlock()

	var list []proto.SandboxInfo
	for _, sb := range m.Sandboxes {
		list = append(list, proto.SandboxInfo{ID: sb.ID, IP: sb.IP, Status: "running"})
	}
	return list
}

// Prewarm builds snapshots for every catalog shape, one at a time, in the
// background. Safe to call once on server start; each shape takes ~2s.
// Errors are logged, not returned — prewarm is best-effort; missing shapes
// fall back to lazy-build on first request.
func (m *Manager) Prewarm(ctx context.Context) {
	if m.ColdOnly {
		log.WithContext(ctx).Info("[prewarm] cold-only mode, skipping")
		close(m.prewarmDone) // nothing to prewarm — report ready immediately
		return
	}
	go func() {
		defer close(m.prewarmDone)
		// Decide which rootfs catalog entries to prewarm.
		rootfsNames := []string{m.DefaultRootfs}
		if m.prewarmAll {
			rootfsNames = m.RootfsNames()
		}
		shapesNow := m.GetShapes()
		log.WithContext(ctx).Infof("[prewarm] building %d shape × %d rootfs snapshots...", len(shapesNow), len(rootfsNames))
		for _, s := range shapesNow {
			for _, rfs := range rootfsNames {
				if ctx.Err() != nil {
					return
				}
				key := shapeKey{VCPU: s.VCPU, MemMib: s.MemMib, Rootfs: rfs}
				t0 := time.Now()
				if err := m.ensureSnapshot(key); err != nil {
					log.WithContext(ctx).Warnf("[prewarm] %s failed: %v", key, err)
					continue
				}
				log.WithContext(ctx).Infof("[prewarm] %s ready in %s", key, time.Since(t0))
			}
		}
		log.WithContext(ctx).Info("[prewarm] complete")
	}()
}

// BandwidthStatus is a read-only view of a sandbox's bandwidth accounting.
type BandwidthStatus struct {
	ID           string
	QuotaBytes   int64
	UsedBytes    int64 // egress (VM-initiated) — what counts against the quota
	IngressBytes int64 // inbound — observation only, never billed
	Capped       bool
}

// Bandwidth returns the current accounting for a sandbox. Returns false if
// the sandbox isn't tracked on this host.
func (m *Manager) Bandwidth(id string) (BandwidthStatus, bool) {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	sb, ok := m.Sandboxes[id]
	if !ok {
		return BandwidthStatus{}, false
	}
	return BandwidthStatus{
		ID:           sb.ID,
		QuotaBytes:   sb.BandwidthQuota,
		UsedBytes:    sb.BandwidthUsed,
		IngressBytes: sb.BandwidthIngressBytes,
		Capped:       sb.BandwidthCapped,
	}, true
}

// Recharge adds bytes to a sandbox's quota and lifts the cap if it was set
// and the new quota exceeds usage. Returns the new status.
func (m *Manager) Recharge(id string, addBytes int64) (BandwidthStatus, error) {
	if addBytes <= 0 {
		return BandwidthStatus{}, fmt.Errorf("%w: add_bytes must be > 0", ErrInvalidRequest)
	}
	m.Mu.Lock()
	defer m.Mu.Unlock()
	sb, ok := m.Sandboxes[id]
	if !ok {
		return BandwidthStatus{}, fmt.Errorf("sandbox not found")
	}
	sb.BandwidthQuota += addBytes
	if sb.BandwidthCapped && sb.BandwidthUsed < sb.BandwidthQuota {
		m.removeCapFor(id)
		sb.BandwidthCapped = false
	}
	return BandwidthStatus{
		ID:         sb.ID,
		QuotaBytes: sb.BandwidthQuota,
		UsedBytes:  sb.BandwidthUsed,
		Capped:     sb.BandwidthCapped,
	}, nil
}

// MeterPersister is invoked by the meter loop to persist updates.
// Implementations should be cheap and non-blocking on error.
type MeterPersister func(id string, used int64, capped bool)

// IngressMeterPersister is the same idea for the ingress observation
// chain. Cumulative byte counter, no cap.
type IngressMeterPersister func(id string, ingressBytes int64)

// StartMetricsLoop refreshes the gauges that aren't naturally
// incremented at lifecycle hooks (running count, mem accounting,
// snapshot readiness, netpool depth). Cheap — just reads in-memory
// maps. Stops when ctx is cancelled.
//
// capacityMiB is the operator-configured advertised capacity for this
// host (cfg.MemCapacity), exposed as a constant gauge for reference.
func (m *Manager) StartMetricsLoop(ctx context.Context, capacityMiB int, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	metrics.MemCapacityMiB.Set(float64(capacityMiB))
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Mu.RLock()
				n := len(m.Sandboxes)
				var used int
				for _, sb := range m.Sandboxes {
					used += sb.MemMib
				}
				m.Mu.RUnlock()
				metrics.SandboxRunning.Set(float64(n))
				metrics.MemInUseMiB.Set(float64(used))
				metrics.NetPoolDepth.Set(float64(m.Pool.Depth()))

				m.SnapshotsMu.Lock()
				for key, sf := range m.Snapshots {
					var v float64
					if sf.Ready {
						v = 1
					}
					metrics.SnapshotReady.WithLabelValues(
						fmt.Sprintf("%dvcpu-%dmib", key.VCPU, key.MemMib),
						key.Rootfs,
					).Set(v)
				}
				m.SnapshotsMu.Unlock()
			}
		}
	}()
}

// StartMeterLoop runs a background goroutine that reads each sandbox's
// meter counters, updates in-memory state, enforces the cap when quota is
// exceeded, and calls persist() to durably record usage. Stops when ctx
// is cancelled.
func (m *Manager) StartMeterLoop(ctx context.Context, persist MeterPersister, interval time.Duration) {
	m.StartMeterLoopWithIngress(ctx, persist, nil, interval)
}

// StartMeterLoopWithIngress is the meter loop that ALSO polls the ingress
// observation chain and calls ingressPersist with the cumulative byte
// count for each sandbox. Pass nil to skip the ingress side.
func (m *Manager) StartMeterLoopWithIngress(ctx context.Context, persist MeterPersister, ingressPersist IngressMeterPersister, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	m.meterPersist = persist
	m.meterIngressPersist = ingressPersist
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.meterTick(persist, ingressPersist)
			}
		}
	}()
}

func (m *Manager) meterTick(persist MeterPersister, ingressPersist IngressMeterPersister) {
	// Snapshot sandbox ids under read lock to minimise iptables time under lock.
	m.Mu.RLock()
	ids := make([]string, 0, len(m.Sandboxes))
	for id := range m.Sandboxes {
		ids = append(ids, id)
	}
	m.Mu.RUnlock()

	for _, id := range ids {
		bytes, err := m.readMeterBytesFor(id)
		if err != nil {
			// chain might not exist yet (race with create) — skip quietly
			continue
		}
		m.Mu.Lock()
		sb, ok := m.Sandboxes[id]
		if !ok {
			m.Mu.Unlock()
			continue
		}
		// chain counter is per-host (resets to 0 on each resume's
		// fresh InstallMeter); add the carried-over baseline so the
		// reported total is lifetime-cumulative across migrations.
		sb.BandwidthUsed = sb.BandwidthBaseline + int64(bytes)
		// Enforce cap.
		if sb.BandwidthQuota > 0 && sb.BandwidthUsed >= sb.BandwidthQuota && !sb.BandwidthCapped {
			if err := m.installCapFor(id); err == nil {
				sb.BandwidthCapped = true
			} else {
				log.Warnf("[meter] install cap for %s failed: %v", id, err)
			}
		}
		used, capped := sb.BandwidthUsed, sb.BandwidthCapped
		m.Mu.Unlock()

		if persist != nil {
			persist(id, used, capped)
		}
		if ib, err := m.readIngressMeterBytesFor(id); err == nil {
			// Apply baseline so cross-host pause/resume keeps a true
			// lifetime ingress total. Rehydrate restores the carried-over
			// baseline separately from this incarnation's pinned counters.
			m.Mu.Lock()
			var total int64
			if sb, ok := m.Sandboxes[id]; ok {
				total = sb.BandwidthIngressBaseline + int64(ib)
				sb.BandwidthIngressBytes = total
			} else {
				total = int64(ib)
			}
			m.Mu.Unlock()
			if ingressPersist != nil {
				ingressPersist(id, total)
			}
		}
	}
}

// ReapOrphanedPrewarmTemplates kills firecracker processes that were
// spawned as prewarm-template VMs but never received the matching
// fm.StopVMM(). This happens when createos-serve is SIGTERM'd or
// crashes mid-prewarm: the template firecracker (which lives in its
// own cgroup, NOT the systemd unit's slice) gets re-parented to init
// and survives indefinitely, occupying vCPUs + RAM forever.
//
// Detection is unambiguous: only createBaseSnapshot ever uses an api
// socket under /var/lib/createos/runtime/fc-template-*.sock, and that
// path is unlinked when the function returns. So any live firecracker
// whose cmdline references that path is by definition an orphan from
// a previous serve generation.
//
// Called once during NewManager. Safe and cheap (single /proc walk).
func ReapOrphanedPrewarmTemplates() int {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	killed := 0
	myPID := os.Getpid()
	for _, e := range procs {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == myPID {
			continue
		}
		// Cheap exec name probe before reading the full cmdline.
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil || !strings.HasPrefix(string(comm), "firecracker") {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		cmdline := string(raw)
		if !strings.Contains(cmdline, "/fc-template-") {
			continue
		}
		log.Warnf("[reaper] killing orphan prewarm template pid=%d (cmdline=%q)", pid, strings.ReplaceAll(cmdline, "\x00", " "))
		KillFirecrackerFast(pid)
		killed++
	}
	if killed > 0 {
		log.Infof("[reaper] killed %d orphan prewarm template firecracker(s)", killed)
	}
	return killed
}

// ReapOrphanTenantFirecrackers kills any firecracker process whose
// --id sb-<ulid> sandbox id is NOT in the Manager's live Sandboxes map.
// MUST be called AFTER rehydrate has finished so legitimate survivors
// are already adopted. Closes the equivalent of the prewarm-template
// leak window for the tenant-create path: if createos-serve dies
// between fm.Start (firecracker spawned) and the DB write of fc_pid,
// the firecracker is alive but no record points to it. Tenant VMs
// intentionally don't use Pdeathsig (would break the rehydrate model),
// so this post-rehydrate sweep is the catch-net.
//
// Prewarm templates (--id template-...) are skipped here — they're
// handled by ReapOrphanedPrewarmTemplates which runs earlier, before
// NewManager.
func (m *Manager) ReapOrphanTenantFirecrackers() int {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	// Snapshot the live set under lock so we don't race against
	// concurrent destroys / creates while we're scanning.
	m.Mu.RLock()
	known := make(map[string]struct{}, len(m.Sandboxes))
	for id := range m.Sandboxes {
		known[id] = struct{}{}
	}
	m.Mu.RUnlock()

	myPID := os.Getpid()
	killed := 0
	for _, e := range procs {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == myPID {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil || !strings.HasPrefix(string(comm), "firecracker") {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		// cmdline is NUL-separated. Parse out --id <value>.
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		var vmid string
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "--id" {
				vmid = args[i+1]
				break
			}
		}
		if vmid == "" || !strings.HasPrefix(vmid, "sb-") {
			// Skip prewarm templates (handled by ReapOrphanedPrewarmTemplates)
			// and anything without an extractable sandbox id.
			continue
		}
		if _, ok := known[vmid]; ok {
			// Legitimate rehydrated VM — leave it alone.
			continue
		}
		log.Warnf("[reaper] killing orphan tenant firecracker pid=%d vmid=%s (no DB record)", pid, vmid)
		KillFirecrackerFast(pid)
		killed++
	}
	if killed > 0 {
		log.Infof("[reaper] killed %d orphan tenant firecracker(s)", killed)
	}
	return killed
}

// KillFirecrackerFast SIGKILLs the given PID and returns without polling.
// Sending SIGKILL requests exit; it does not confirm that the process has
// released its resources. Newly launched slot borrowers are tracked by pidfd,
// and NetPool.Return / fallback startup enforce exit before reuse.
func KillFirecrackerFast(pid int) {
	if pid <= 0 {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

// Shutdown stops host background work but leaves every
// running firecracker VM, netns, overlay, and iptables chain in place so
// the next host process can rehydrate them (see Rehydrate). This is service
// shutdown, not the sweeper's sandbox migration/drain operation.
//
// This is the behaviour you want for a rolling code deploy: users' VMs
// survive the restart.
//
// Net pool replenishment is still halted (m.Pool.Close) so no new slots
// are created during the drain window. IPAM state and the in-memory
// Sandboxes map are discarded along with the process, but everything
// needed to reconstruct them is already persisted in the sandbox row
// (see store.Record.{APISock,ContainerID,FCPid,OverlayPath}).
//
// For a hard teardown (e.g. decommissioning a host), iterate the
// Sandboxes map and call Destroy(id) before calling Shutdown.
func (m *Manager) Shutdown() {
	m.Pool.Close()
	log.Infof("[sandbox] drain: leaving %d VM(s) running for rehydrate on next startup", len(m.Sandboxes))
}

// LocalSandboxIPs returns the IPv4 addresses of every live sandbox the
// manager knows about. The net reconciler includes unnetworked VMs in
// fc_known_vmips without granting allow pairs, so policy rejects VM-to-VM
// traffic between sandboxes that share no overlay membership.
func (m *Manager) LocalSandboxIPs() []string {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	out := make([]string, 0, len(m.Sandboxes))
	for _, sb := range m.Sandboxes {
		if sb.Net == nil {
			continue
		}
		ip := sb.Net.IP.IP.String()
		if ip == "" {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// LocalSandboxIDForIP returns the immutable sandbox ID currently associated
// with a local VM IP, or "" when the host has no live sandbox at that IP.
// The net reconciler uses this alongside control's sandbox ID so a cached
// pre-destroy membership cannot be applied to a new VM that recycled the IP.
func (m *Manager) LocalSandboxIDForIP(ip string) string {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	for id, sb := range m.Sandboxes {
		if sb.Net != nil && sb.Net.IP.IP.String() == ip {
			return id
		}
	}
	return ""
}

// IFIndexForIP returns the host-side veth ifindex for a VM with the given IP,
// or 0 if no such VM is currently running on this host.
func (m *Manager) IFIndexForIP(ip string) uint32 {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	for _, sb := range m.Sandboxes {
		if sb.Net == nil {
			continue
		}
		vmIP := sb.Net.IP.IP.String()
		if vmIP != ip {
			continue
		}
		// Derive the host-side veth name from the slot's container ID.
		vethName := vethNameFor(sb.Net.ContainerID)
		link, err := netlink.LinkByName(vethName)
		if err != nil {
			return 0
		}
		return uint32(link.Attrs().Index)
	}
	return 0
}

// vmDNS returns the DNS server list to push to a VM. The per-host stub
// (169.254.20.10) is prepended so VMs resolve overlay hostnames before
// falling through to any external DNS.
func (m *Manager) vmDNS(pn *PooledNet) []string {
	return append([]string{"169.254.20.10"}, pn.DNS...)
}

// StartNetReconciler launches the overlay network reconciler and the DNS stub
// goroutines using the overlay config set at construction. No-op if ControlURL
// is empty.
func (m *Manager) StartNetReconciler(ctx context.Context) {
	cfg := m.overlayConfig
	if cfg.ControlURL == "" {
		return
	}

	// Start the DNS stub if the table was initialised. Two host-side
	// preconditions must hold for VMs to actually reach it:
	//   1. 169.254.20.10/32 must be on `lo` so the listen() succeeds.
	//   2. iptables INPUT must accept UDP/53 to that IP — otherwise VM
	//      packets reach the host fcv but get dropped before the socket.
	// Both are idempotent; ignore "exists" errors.
	if m.DNSTable != nil {
		ensureDNSStubReachable()
		// The DNS stub's host-wide INPUT accept is installed first. Rebuild
		// every live IP-only sandbox policy afterwards so its per-veth DNS
		// guard is ahead of that accept. This also migrates VMs rehydrated
		// from a pre-guard binary without requiring them to be recreated.
		m.reinstallRestrictedDNSGuards()
		go func() {
			if err := dns.Run(ctx, m.DNSTable, dns.DefaultUpstreams); err != nil {
				log.WithContext(ctx).Warnf("[dns-stub] %v", err)
			}
		}()
		log.WithContext(ctx).Infof("[dns-stub] started on %s (zone %s)", dns.StubAddr, dns.Zone)
	}

	m.netReconcilerTrigger = make(chan struct{}, 1)
	go RunNetReconciler(ctx, NetReconcilerConfig{
		ControlURL:          cfg.ControlURL,
		Client:              cfg.ControlHTTPClient,
		HostID:              cfg.HostID,
		IFIndexForIP:        m.IFIndexForIP,
		LocalSandboxIDForIP: m.LocalSandboxIDForIP,
		LocalSandboxIPs:     m.LocalSandboxIPs,
		DNSTable:            m.DNSTable,
		Trigger:             m.netReconcilerTrigger,
	})
	log.WithContext(ctx).Infof("[overlay] net-reconciler started (interval=5s control=%s)", cfg.ControlURL)
}

// reinstallRestrictedDNSGuards closes the host-restart gap for IP-only
// restrictive sandboxes. Their Firecracker processes and iptables rules
// survive createos-serve restarts, but ensureDNSStubReachable deliberately
// refreshes the host-wide resolver ACCEPT. Reinstalling the affected policy
// puts its interface-specific DROP back before that ACCEPT and upgrades live
// sandboxes created by older binaries.
func (m *Manager) reinstallRestrictedDNSGuards() {
	type policy struct {
		id    string
		ip    string
		veth  string
		rules []string
	}

	m.Mu.RLock()
	policies := make([]policy, 0, len(m.Sandboxes))
	for id, sb := range m.Sandboxes {
		parsed, ok := parseEgressRules(sb.Egress)
		if len(sb.Egress) == 0 || !ok || parsed.allowAll || len(parsed.domains) != 0 || sb.HostVeth == "" {
			continue
		}
		policies = append(policies, policy{id: id, ip: sb.IP, veth: sb.HostVeth, rules: sb.Egress})
	}
	m.Mu.RUnlock()

	for _, p := range policies {
		if err := InstallEgress(p.id, p.ip, p.veth, p.rules); err != nil {
			log.Errorf("[egress] restore DNS guard sandbox=%s veth=%s: %v", p.id, p.veth, err)
		}
	}
}

// KickNetReconciler wakes the overlay reconciler immediately. Used by
// the Create path so a new sandbox's overlay membership is published
// to BPF maps without waiting up to one full tick. Non-blocking: if
// a kick is already pending the second call is a no-op.
func (m *Manager) KickNetReconciler() {
	if m.netReconcilerTrigger == nil {
		return
	}
	select {
	case m.netReconcilerTrigger <- struct{}{}:
	default:
	}
}

// ensureDNSStubReachable makes the per-host DNS stub addressable from VMs
// after a fresh boot:
//   - assigns the stub IP /32 to `lo` so the listen() bind succeeds
//   - inserts an iptables INPUT ACCEPT for UDP at the stub port so
//     a default-DROP INPUT policy doesn't black-hole VM queries
//
// Both ops are idempotent — repeated calls are silent no-ops. The IP and
// port are derived from dns.StubAddr (single source of truth).
func ensureDNSStubReachable() {
	host, port, err := net.SplitHostPort(dns.StubAddr)
	if err != nil {
		log.Warnf("[dns-stub] parse StubAddr %q: %v", dns.StubAddr, err)
		return
	}
	if out, err := exec.Command("ip", "addr", "add", host+"/32", "dev", "lo").CombinedOutput(); err != nil {
		s := string(out)
		if !strings.Contains(s, "File exists") && !strings.Contains(s, "Address already assigned") {
			log.Warnf("[dns-stub] ip addr add %s/32 dev lo: %v: %s", host, err, strings.TrimSpace(s))
		}
	}
	// The rule we maintain (including comment match — iptables' rule
	// equality compares the full spec, so the check MUST match what
	// install uses or `-C` will always miss and `-I` keeps duplicating).
	spec := []string{
		"-w", "2", "INPUT",
		"-p", "udp", "--dport", port, "-d", host,
		"-m", "comment", "--comment", "createos-dns-stub",
		"-j", "ACCEPT",
	}
	// Sweep any accumulated dups from the old buggy installer (a pre-fix
	// build appended a fresh rule on every call when `-C` looked for the
	// rule without its comment match). Drain to zero, then fall through
	// to the regular check+insert. MUST keep `-w 2` on every call —
	// startup is concurrent with bpf-meter / netpool iptables activity
	// and a lock-not-held failure would otherwise abort the sweep early.
	cmd := func(verb string) *exec.Cmd {
		args := append([]string{"-w", "2", verb}, spec[2:]...)
		return exec.Command("iptables", args...)
	}
	for i := 0; i < 200; i++ {
		if err := cmd("-D").Run(); err != nil {
			break // 1 = "no such rule" → done draining
		}
	}
	if cmd("-C").Run() == nil {
		return // already present, idempotent no-op
	}
	if out, err := cmd("-I").CombinedOutput(); err != nil {
		log.Warnf("[dns-stub] iptables INPUT ACCEPT: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

// removeLegacyOverlayArtifacts tears down state from the pre-Path-B install:
//   - the host-wide `fcvxlan0` VXLAN device
//   - pinned BPF maps that no live program reads anymore
//     (vmip_to_remote, vmip_to_ifindex, vmip_to_mac, overlay_config)
//   - stale `INPUT -p udp --dport 4789 -j ACCEPT` rules tagged with the old
//     `createos-vxlan-underlay` comment (accumulated across restarts on
//     pre-Path-B hosts; harmless because nothing listens on 4789 but
//     misrepresents the security posture)
//
// Idempotent — silently no-ops once each artifact is gone. Called at startup;
// after one successful run on each host this function does nothing.
func removeLegacyOverlayArtifacts() {
	if link, err := netlink.LinkByName("fcvxlan0"); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			log.Warnf("[overlay] remove legacy fcvxlan0: %v", err)
		} else {
			log.Infof("[overlay] removed legacy fcvxlan0 device")
		}
	}
	for _, name := range []string{
		"fc_vmip_to_remote",
		"fc_vmip_to_ifindex",
		"fc_vmip_to_mac",
		"fc_overlay_config",
	} {
		path := bpfPinDir + "/" + name
		if err := os.Remove(path); err == nil {
			log.Infof("[overlay] removed legacy pinned map %s", name)
		}
	}
	// Sweep stale createos-vxlan-underlay ACCEPT rules. `iptables -D` matches
	// one rule per call, so loop until it returns non-zero (no match left).
	swept := 0
	for {
		cmd := exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", "4789",
			"-j", "ACCEPT", "-m", "comment", "--comment", "createos-vxlan-underlay")
		if err := cmd.Run(); err != nil {
			break
		}
		swept++
	}
	if swept > 0 {
		log.Infof("[overlay] removed %d stale createos-vxlan-underlay iptables rule(s)", swept)
	}
}

// pickShapes returns the configured shape list, or an empty slice when
// nothing was wired (e.g. tests that pass a nil ManagerConfig.Shapes, or
// a host that registered against a control plane whose shapes table is
// empty). The prewarm loop and Resolve both tolerate an empty catalog.
func pickShapes(override []Shape) []Shape {
	if len(override) > 0 {
		return override
	}
	return []Shape{}
}

// GetShapes returns the host's current shape catalog. Reads under the
// shapesMu RLock so a heartbeat-driven swap can race read-only callers
// safely. The returned slice is the live backing array — callers MUST
// treat it as read-only.
func (m *Manager) GetShapes() []Shape {
	m.shapesMu.RLock()
	defer m.shapesMu.RUnlock()
	return m.shapesList
}

// shapeCatalog returns the immutable catalog under its publication lock.
func (m *Manager) shapeCatalog() *Catalog {
	m.shapesMu.RLock()
	defer m.shapesMu.RUnlock()
	return m.Shapes
}

// SetShapes installs a new shape catalog atomically. The replacement
// covers both the lookup catalog (Shapes) and the live slice
// (shapesList). Returns true if the catalog actually changed (caller
// uses the return to decide whether to kick prewarm).
func (m *Manager) SetShapes(s []Shape) bool {
	if len(s) == 0 {
		return false
	}
	m.shapesMu.Lock()
	defer m.shapesMu.Unlock()
	if shapesEqual(m.shapesList, s) {
		return false
	}
	m.shapesList = s
	m.Shapes = NewCatalog(s)
	return true
}

// shapesEqual reports whether two shape lists are identical (same length,
// same elements in the same order). Used on every heartbeat to decide
// whether to swap in a new catalog returned by control.
func shapesEqual(a, b []Shape) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// KickPrewarm fires the Prewarm() goroutine again so any shapes added by
// a heartbeat-driven catalog swap get their snapshots built. Best-effort
// — Prewarm logs and skips shapes whose snapshots already exist, so
// calling this when nothing changed is cheap. A pending prewarm tracked
// via prewarmDone is left alone; we never close that channel twice.
//
// Concurrency note: Prewarm builds snapshots serially through
// ensureSnapshot, which is guarded by SnapshotFlight (singleflight). So
// two overlapping kicks just coalesce on already-in-flight builds — no
// stampede.
func (m *Manager) KickPrewarm(ctx context.Context) {
	if m.ColdOnly {
		return
	}
	go func() {
		shapesNow := m.GetShapes()
		rootfsNames := []string{m.DefaultRootfs}
		if m.prewarmAll {
			rootfsNames = m.RootfsNames()
		}
		for _, s := range shapesNow {
			for _, rfs := range rootfsNames {
				if ctx.Err() != nil {
					return
				}
				key := shapeKey{VCPU: s.VCPU, MemMib: s.MemMib, Rootfs: rfs}
				if err := m.ensureSnapshot(key); err != nil {
					log.WithContext(ctx).Warnf("[prewarm.kick] %s failed: %v", key, err)
				}
			}
		}
	}()
}
