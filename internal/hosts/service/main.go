package service

import (
	"context"
	"crypto/ed25519"
	"sync"

	"github.com/NodeOps-app/sandbox/internal/hosts/api"
	"github.com/NodeOps-app/sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/sandbox/internal/storage"
	"github.com/NodeOps-app/sandbox/models"
)

// requireOwner is the central ownership check. Returns api.ErrNotFound
// if the caller's user_id doesn't match the record's CreatedBy.
//
// FAIL-CLOSED on empty caller. Control forwards the authenticated user_id;
// the host's mTLS role gate accepts it from control peers and handlers pass
// it down as an explicit parameter. An empty caller here means a code path skipped that
// middleware — treat it as "no identity, no access" rather than the
// old silent allow-all (which would mask any future routing bug).
func requireOwner(rec *models.Sandbox, caller string) error {
	if rec == nil {
		return api.ErrNotFound
	}
	if caller == "" {
		return api.ErrNotFound
	}
	if rec.CreatedBy != caller {
		return api.ErrNotFound
	}
	return nil
}

// Service implements api.Service by wiring the vm.Manager (the live Firecracker
// state) and the durable repository (lifecycle history).
type Service struct {
	Mgr    *vm.Manager
	Repo   *controlclient.Client
	Host   string
	Region string // set at construction; passed to DB-proxy calls that need region scoping

	// CPUVendor / CPUFamily are stamped from this host's /proc/cpuinfo at
	// startup. Persisted onto every sandbox row at create time so the
	// scheduler's cpu_compat filter has a stable
	// source-vendor lookup on resume without joining hosts → cached_host_id
	// (which can dangle when the original host is decommissioned).
	CPUVendor string
	CPUFamily string

	// HostPriv is the host's registered Ed25519 identity key.
	// We reuse it (converted to X25519 on demand) to decrypt cryptobox
	// envelopes sealed to this host's pubkey by control — currently the
	// S3-disk credentials in ResolvedDisk.Credentials.
	HostPriv ed25519.PrivateKey

	// Storage is the cluster's S3-compatible object-storage client.
	// Nil = pause/resume/fork + templates disabled (handlers return 501).
	Storage storage.Storage

	// PauseCfg holds the orchestrator's resolved tunables.
	PauseCfg PauseConfig

	// TplCfg holds the template ext4 cache config.
	TplCfg TemplateConfig

	// Internal coordination state for the pause/templates workflows.
	tplMu       sync.Mutex
	tplInflight map[string]chan struct{}

	// transitionInflight gates runPause/runResume against double-trigger
	// from HTTP and the reconcile poll. Key = sandbox id. tryClaim
	// atomically inserts; if the id was already present, the caller
	// returns no-op. Both code paths land in the same goroutine; one
	// wins, the other is a 10µs no-op.
	transitionInflight sync.Map // map[id]struct{}

	// bootSlots bounds how many firecracker.Start calls run concurrently
	// on this host. Mitigates the nested-virt PCI MMIO race observed on
	// cloud-VM hosts (where firecracker runs as L2 on
	// L1 KVM): under burst, L1's hypervisor occasionally hands a stale
	// MMIO range to L2 → guest kernel sees `bus_error: MissingAddressRange`
	// → boot crashes. Serializing the firecracker spawn step to N at a
	// time keeps L1's KVM ioctl queue uncontended.
	//
	// Buffer capacity is the concurrency cap. Acquire by sending into the
	// channel; release by receiving. Nil channel disables gating (used
	// before SetMaxConcurrentBoots is called or for tests). Only the
	// firecracker.Start step is gated — pause/resume/destroy/exec are
	// not affected.
	bootSlots chan struct{}

	selfWatchers *SelfSignalWatchers
}

// SetMaxConcurrentBoots installs (or replaces) the boot-concurrency
// semaphore. N <= 0 disables gating. Called once at service
// construction from the host's main(); not safe to change at runtime.
func (s *Service) SetMaxConcurrentBoots(n int) {
	if n <= 0 {
		s.bootSlots = nil
		return
	}
	s.bootSlots = make(chan struct{}, n)
}

// acquireBootSlot blocks until a firecracker boot slot is available
// (or the context fires). Returns a release function — call it once
// after firecracker.Start returns. nil bootSlots means no gating; the
// returned release is a no-op.
func (s *Service) acquireBootSlot(ctx context.Context) (release func(), err error) {
	if s.bootSlots == nil {
		return func() {}, nil
	}
	select {
	case s.bootSlots <- struct{}{}:
		return func() { <-s.bootSlots }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// tryClaimTransition adds id to the in-flight set. Returns true if the
// caller now owns the transition; false if another goroutine is already
// driving it. Caller must defer release on true.
func (s *Service) tryClaimTransition(id string) bool {
	_, loaded := s.transitionInflight.LoadOrStore(id, struct{}{})
	return !loaded
}

func (s *Service) releaseTransition(id string) {
	s.transitionInflight.Delete(id)
}

// Assert Service satisfies api.Service at compile time.
var _ api.Service = (*Service)(nil)

// SecretToken returns the per-VM shared secret stored on the in-memory
// Sandbox. Internal — used by host-side handlers (tunnel, file proxy)
// to inject "AUTH <token>\n" on dials to the guest agent. Never exposed
// to user-facing API responses.
func (s *Service) SecretToken(ctx context.Context, id string) (string, error) {
	sb, ok := s.Mgr.Lookup(id)
	if !ok {
		return "", api.ErrNotFound
	}
	return sb.SecretToken, nil
}

// LookupIP returns the live VM IP without per-user owner scoping. See
// the Service interface comment for the rationale.
func (s *Service) LookupIP(id string) (string, error) {
	sb, ok := s.Mgr.Lookup(id)
	if !ok {
		return "", api.ErrNotFound
	}
	if sb.IP == "" {
		return "", api.ErrNotFound
	}
	return sb.IP, nil
}

// New constructs a Service. Orphan reconciliation now happens upstream
// in hosts.reconcile, which inspects the host's actual process and network
// state to distinguish surviving VMs from truly dead rows. This constructor
// used to run a bulk reconciliation unconditionally, which marked surviving
// sandboxes destroyed during an ordinary service restart.
func New(ctx context.Context, mgr *vm.Manager, repo *controlclient.Client, host, region string) (*Service, error) {
	return &Service{
		Mgr:          mgr,
		Repo:         repo,
		Host:         host,
		Region:       region,
		selfWatchers: NewSelfSignalWatchers(),
	}, nil
}
