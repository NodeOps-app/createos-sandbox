package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/cryptobox"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/api"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/metrics"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/trace"
	"github.com/NodeOps-app/createos-sandbox/models"
)

func (s *Service) Create(ctx context.Context, caller string, req api.CreateReq) (*api.CreateResp, error) {
	t := trace.Start("host.create").WithObserver(func(name string, d time.Duration) {
		metrics.HostCreatePhaseSeconds.WithLabelValues(name).Observe(d.Seconds())
	})
	defer t.End()
	t.Attr("rid", httpx.RequestID(ctx))
	t.Attr("shape", req.Shape)

	if req.Shape == "" {
		return nil, fmt.Errorf("%w: shape is required", api.ErrInvalidRequest)
	}
	// If the request names a template (tpl_<ulid>), make sure the ext4
	// is on local disk and registered in Manager.Rootfses BEFORE
	// Manager.Create looks it up. A cold miss downloads, decompresses,
	// and verifies the artifact before creation can continue.
	reqRootfs := ""
	if req.Rootfs != nil {
		reqRootfs = *req.Rootfs
	}
	reqName := ""
	if req.Name != nil {
		reqName = *req.Name
	}
	if strings.HasPrefix(reqRootfs, models.TemplateIDPrefix) {
		if s.Storage == nil {
			return nil, fmt.Errorf("%w: templates feature not configured on this host", api.ErrInfrastructure)
		}
		release, err := s.useTemplate(ctx, reqRootfs)
		if err != nil {
			return nil, err
		}
		defer release()
		if _, err := s.EnsureTemplate(ctx, reqRootfs, api.SuppliedSandboxIDFromContext(ctx)); err != nil {
			return nil, fmt.Errorf("%w: ensure template: %v", api.ErrInfrastructure, err)
		}
	}
	// Mint the per-VM shared secret BEFORE Manager.Create so it can be
	// pushed via MMDS in the boot path. Stored on the durable row below.
	secretToken := vm.NewSecretToken()

	// Translate control's disk bundle into the agent-bound MMDS shape.
	// Credentials arrive sealed (cryptobox envelope keyed to this host's
	// pubkey); we open them with the matching private key. The plaintext
	// only ever lives in MMDS memory + this stack frame — never on host
	// disk.
	if err := s.UnsealResolvedDiskCreds(req.DisksResolved); err != nil {
		return nil, fmt.Errorf("%w: disk creds unseal: %v", api.ErrInvalidRequest, err)
	}
	var mmdsDisks []proto.MMDSDisk
	if len(req.DisksResolved) > 0 {
		mmdsDisks = make([]proto.MMDSDisk, 0, len(req.DisksResolved))
		for _, rd := range req.DisksResolved {
			d := proto.MMDSDisk{
				ID:        rd.DiskID,
				Kind:      rd.Kind,
				MountPath: rd.MountPath,
				SubPath:   rd.SubPath,
			}
			_ = proto.DecodeS3Config(rd.Config, &d.Config)
			_ = proto.DecodeS3Creds(rd.Credentials, &d.Credentials)
			mmdsDisks = append(mmdsDisks, d)
		}
	}

	vmReq := vm.CreateRequest{
		// Pre-supplied id from control's X-Sandbox-ID header. Empty means
		// "manager generates one" (legacy / direct host calls).
		ID:                  api.SuppliedSandboxIDFromContext(ctx),
		CreatedBy:           caller,
		Name:                reqName,
		Shape:               req.Shape,
		Rootfs:              reqRootfs,   // empty = manager's default
		DiskMib:             req.DiskMib, // 0 = use shape's default
		Egress:              req.Egress,
		BandwidthQuotaBytes: req.BandwidthQuotaBytes,
		SecretToken:         secretToken,
		Envs:                req.Envs,
		Disks:               mmdsDisks,
	}

	now := time.Now().UTC()
	// Gate firecracker.Start through the per-host boot semaphore. Caps
	// how many KVM ioctls hit the kernel at once, sidestepping the
	// nested-virt PCI MMIO race on cloud-VM hosts. No-op when no cap
	// is configured. The semaphore is released right after mgr.Create
	// returns (success or failure) so a stuck spawn doesn't permanently
	// hold a slot — Manager.Create's own timeout / retry policy applies.
	stopWait := t.Phase("boot.queue")
	release, qErr := s.acquireBootSlot(ctx)
	stopWait()
	if qErr != nil {
		return nil, fmt.Errorf("%w: boot queue: %s", api.ErrInvalidRequest, qErr.Error())
	}
	stopMgr := t.Phase("mgr.create")
	// Retry on transient SYN-blackhole "agent not ready" failures — a small
	// fraction of slots reach a persistent blackhole state and the manager
	// discards them on failure. Each retry gets a fresh slot from
	// replenish() (the bad one is gone). Up to 3 attempts covers a degraded
	// pool where multiple consecutive slots are bad (a kernel quirk can
	// leave a slot SYN-blackholed).
	var res *vm.CreateResult
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if req.SnapshotID != nil {
			res, err = s.createFromUserSnapshot(ctx, caller, req, vmReq)
			break // Never fall back to an empty boot after a restore failure.
		}
		res, err = s.Mgr.Create(ctx, vmReq)
		if err == nil || !strings.Contains(err.Error(), "agent not ready") {
			break
		}
	}
	stopMgr()
	release()
	if err != nil {
		// Translate Manager's validation errors into the api-layer sentinel
		// so handlers emit 400 (fail) instead of 500 (error). Strip the
		// duplicated "invalid request:" prefix vm's wrapper added.
		if errors.Is(err, vm.ErrInvalidRequest) {
			msg := strings.TrimPrefix(err.Error(), vm.ErrInvalidRequest.Error()+": ")
			return nil, fmt.Errorf("%w: %s", api.ErrInvalidRequest, msg)
		}
		if errors.Is(err, vm.ErrAtCapacity) {
			return nil, fmt.Errorf("%w: %s", api.ErrAtCapacity, err.Error())
		}
		// Don't INSERT a row here. Control already INSERTed the row
		// under the real sb-<ulid> id BEFORE forwarding to us (see
		// HandleCreateExternal), and its forward-error path flips THAT
		// row to `failed` when we return non-2xx. A synthetic
		// `failed-<unixnano>` row here would just be a second row for
		// the same failure event — wrong id format, no created_by,
		// no link back to the user's request.
		return nil, err
	}

	runningAt := time.Now().UTC()
	// All of these are runtime values of a successfully-spawned VM and
	// are therefore always non-empty; &local is the faithful pointer.
	hostID := s.Host
	mode := res.Mode
	ip := res.Sandbox.IP
	mac := res.Sandbox.Net.MAC
	rootfs := res.Sandbox.Rootfs
	apiSock := res.Sandbox.ApiSocket
	containerID := res.Sandbox.Net.ContainerID
	overlayPath := res.Sandbox.OverlayPath
	tok := secretToken
	// Name can in principle be empty (user omitted it and the row
	// pre-dates control's auto-naming); a NULL name is correct then.
	var namePtr *string
	if reqName != "" {
		namePtr = &reqName
	}
	rec := models.Sandbox{
		ID:                  res.Sandbox.ID,
		HostID:              &hostID,
		Status:              models.StatusRunning,
		Mode:                &mode,
		Name:                namePtr,
		IP:                  &ip,
		MAC:                 &mac,
		VCPU:                res.Sandbox.VCPU,
		MemMib:              res.Sandbox.MemMib,
		DiskMib:             res.Sandbox.DiskMib,
		CreatedAt:           now,
		RunningAt:           &runningAt,
		SpawnMs:             res.SpawnMs,
		Egress:              req.Egress,
		Labels:              req.Labels,
		Shape:               req.Shape,
		Rootfs:              &rootfs,
		CreatedBy:           caller,
		SSHPubkeys:          req.SSHPubkeys,
		BandwidthQuotaBytes: res.Sandbox.BandwidthQuota,
		APISock:             &apiSock,
		ContainerID:         &containerID,
		FCPid:               res.Sandbox.FCPid,
		OverlayPath:         &overlayPath,
		SecretToken:         &tok,
		Envs:                req.Envs,
	}
	// CPU lineage. Stamped here so the row carries the vendor of the
	// host the snapshot will be baked under (firecracker freezes source
	// CPUID into vmstate at pause). Empty when the host's hwinfo read
	// failed — defensive, lets create succeed and falls back to the
	// pre-cpu-vendor behaviour.
	if s.CPUVendor != "" {
		v := s.CPUVendor
		rec.CPUVendor = &v
	}
	if s.CPUFamily != "" {
		f := s.CPUFamily
		rec.CPUFamily = &f
	}
	if req.IngressEnabled != nil && *req.IngressEnabled {
		rec.IngressEnabled = true
	}
	// Note: in external-scheduler mode the durable INSERT was already
	// performed by control with envs stamped; the ON CONFLICT clause
	// in queries.sql excludes envs from the UPDATE list, so this
	// host-side upsert won't clobber control's value. Stamping envs
	// here covers the legacy single-process / direct-host path where
	// the host owns the row from creation.
	stopDB := t.Phase("db.insert")
	if err := s.Repo.Insert(ctx, rec); err != nil {
		log.WithContext(ctx).Warnf("[store] insert %s failed: %v", res.Sandbox.ID, err)
		if req.SnapshotID != nil {
			_ = s.Mgr.Destroy(res.Sandbox.ID)
			stopDB()
			return nil, fmt.Errorf("%w: snapshot restore could not be completed", api.ErrInfrastructure)
		}
	}
	stopDB()
	t.Attr("id", res.Sandbox.ID)

	// Publish this sandbox's overlay membership instantly. Without
	// this kick a freshly-created VM that joined a network can't
	// reach peers until the next reconciler tick (≤5s window) — long
	// enough that an immediate test or first connection from another
	// VM gets a TCP timeout. Non-blocking; cheap when no networks
	// are attached (reconcile sees the same member set + no-ops).
	s.Mgr.KickNetReconciler()

	s.StartSelfSignal(res.Sandbox)

	return &api.CreateResp{
		SnapshotID:          req.SnapshotID,
		ID:                  res.Sandbox.ID,
		Status:              string(models.StatusRunning),
		Name:                req.Name,
		Labels:              req.Labels,
		IP:                  res.Sandbox.IP,
		Shape:               req.Shape,
		Rootfs:              &rootfs,
		VCPU:                res.Sandbox.VCPU,
		MemMib:              res.Sandbox.MemMib,
		DiskMib:             res.Sandbox.DiskMib,
		SpawnMs:             res.SpawnMs,
		Egress:              req.Egress,
		BandwidthQuotaBytes: res.Sandbox.BandwidthQuota,
	}, nil
}

// RootfsCatalog returns the host's rootfs catalog (name → path) and the default name.
func (s *Service) RootfsCatalog(ctx context.Context) (map[string]string, string, error) {
	return s.Mgr.RootfsCatalog(), s.Mgr.DefaultRootfs, nil
}

// loadOwned fetches the sandbox record and applies the ownership check in
// one shot. Returns api.ErrNotFound if the row doesn't exist or doesn't
// belong to the caller.
func (s *Service) loadOwned(ctx context.Context, id, caller string) (*models.Sandbox, error) {
	rec, err := s.Repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := requireOwner(rec, caller); err != nil {
		return nil, err
	}
	// Warm the in-memory owner cache so subsequent authOwnedFast calls
	// on the same sandbox avoid this DB round-trip.
	if sb, ok := s.Mgr.Lookup(id); ok && sb.CachedOwner() == "" {
		sb.SetCachedOwner(rec.CreatedBy)
	}
	return rec, nil
}

// authOwnedFast is loadOwned without the returned record. Cheap ownership
// check for hot-path callers (exec, bandwidth, get) that don't need any
// DB row fields — they use Mgr.Lookup for the in-memory Sandbox anyway.
// When the manager already knows the sandbox and has a cached CreatedBy
// matching the caller, we skip the ~27ms Repo.Get entirely. Falls back
// to loadOwned on cache miss / mismatch — which also warms the cache.
// caller is the userID resolved by the middleware; passed explicitly so
// this function stays free of hidden context-lookups.
func (s *Service) authOwnedFast(ctx context.Context, id, caller string) error {
	if caller != "" {
		if sb, ok := s.Mgr.Lookup(id); ok {
			owner := sb.CachedOwner()
			if owner != "" && owner == caller {
				return nil
			}
			// Pool-claim race window: the DB row already has the new owner
			// (control's claim tx committed before returning the response
			// that caller carries), but the async kickPoolClaim POST that
			// updates this in-mem sentinel hasn't landed yet. The caller
			// arrives from an mTLS-authed control peer (role=control gate
			// upstream) that has already run its own owner check, so trust
			// its X-CreateOS-User-Id header and seed the cache directly.
			// Kills the ~35 ms first-exec-after-pool-claim spike.
			if owner == models.PoolUserID {
				sb.SetCachedOwner(caller)
				return nil
			}
			log.WithContext(ctx).Infof("[owner-cache-miss] sb=%s cached_empty=%v cached_pool=%v caller_matches=%v",
				id, owner == "", owner == models.PoolUserID, owner == caller)
		} else {
			log.WithContext(ctx).Infof("[owner-cache-miss] sb=%s sandbox_in_memory=false", id)
		}
	}
	_, err := s.loadOwned(ctx, id, caller)
	return err
}

// Recharge bumps a sandbox's bandwidth quota and lifts the cap if possible.
func (s *Service) Recharge(ctx context.Context, id, caller string, addBytes int64) (*api.BandwidthView, error) {
	if err := s.authOwnedFast(ctx, id, caller); err != nil {
		return nil, err
	}
	if _, ok := s.Mgr.Lookup(id); !ok {
		return nil, api.ErrNotFound
	}
	status, err := s.Mgr.Recharge(id, addBytes)
	if err != nil {
		if errors.Is(err, vm.ErrInvalidRequest) {
			msg := strings.TrimPrefix(err.Error(), vm.ErrInvalidRequest.Error()+": ")
			return nil, fmt.Errorf("%w: %s", api.ErrInvalidRequest, msg)
		}
		return nil, err
	}
	// Persist new quota and capped state.
	if err := s.Repo.SetBandwidthQuota(ctx, id, status.QuotaBytes); err != nil {
		log.WithContext(ctx).Warnf("[store] SetBandwidthQuota(%s): %v", id, err)
	}
	if err := s.Repo.SetBandwidthCapped(ctx, id, status.Capped); err != nil {
		log.WithContext(ctx).Warnf("[store] SetBandwidthCapped(%s): %v", id, err)
	}
	remaining := status.QuotaBytes - status.UsedBytes
	if remaining < 0 {
		remaining = 0
	}
	return &api.BandwidthView{
		ID:             status.ID,
		QuotaBytes:     status.QuotaBytes,
		UsedBytes:      status.UsedBytes,
		IngressBytes:   status.IngressBytes,
		RemainingBytes: remaining,
		Capped:         status.Capped,
	}, nil
}

func (s *Service) Exec(ctx context.Context, id, caller string, req proto.ExecRequest) (*api.ExecResp, error) {
	tA := time.Now()
	if err := s.authOwnedFast(ctx, id, caller); err != nil {
		return nil, err
	}
	authMs := float64(time.Since(tA).Microseconds()) / 1000.0

	tB := time.Now()
	sb, ok := s.Mgr.Lookup(id)
	lookupMs := float64(time.Since(tB).Microseconds()) / 1000.0
	if !ok {
		return nil, api.ErrNotFound
	}

	tC := time.Now()
	env, err := mergeExecEnv(sb.Envs, req.Env)
	envMs := float64(time.Since(tC).Microseconds()) / 1000.0
	if err != nil {
		return nil, err
	}
	req.Env = env

	start := time.Now()
	resp, sbPhases, err := sb.ExecTimed(ctx, req)
	execMs := float64(time.Since(start).Microseconds()) / 1000.0
	// Internal telemetry only — never returned to the caller. Grep server
	// logs by sandbox id to correlate a client-side wall time against the
	// per-phase breakdown here.
	log.WithContext(ctx).Infof("[exec-trace] rid=%s sb=%s auth=%.2f lookup=%.2f env=%.2f dial=%.2f write=%.2f read=%.2f total=%.2f",
		httpx.RequestID(ctx), id, authMs, lookupMs, envMs, sbPhases["dial"], sbPhases["write"], sbPhases["read"], execMs)
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	return &api.ExecResp{Result: resp, ExecMs: execMs}, nil
}

// ExecStream runs the command in streaming mode and copies the agent's
// NDJSON event stream into w. flush is invoked after each line so HTTP
// clients see output live (Fiber's response writer needs an explicit
// flush to break out of its buffered chunk encoder).
func (s *Service) ExecStream(ctx context.Context, id, caller string, req proto.ExecRequest, w io.Writer, flush func()) error {
	if err := s.authOwnedFast(ctx, id, caller); err != nil {
		return err
	}
	sb, ok := s.Mgr.Lookup(id)
	if !ok {
		return api.ErrNotFound
	}
	env, err := mergeExecEnv(sb.Envs, req.Env)
	if err != nil {
		return err
	}
	req.Env = env
	return sb.ExecStream(ctx, req, w, flush)
}

// mergeExecEnv builds the env map for one exec. The sandbox's persistent
// envs (set at sandbox-create) are both the base AND the allowlist: a
// per-exec `env` in the request body may override the *value* of a key
// that was declared at creation, but may not introduce a new key. That
// guard is the security boundary — without it a caller could inject
// arbitrary env (PATH, LD_PRELOAD, secrets) the sandbox owner never
// sanctioned. An undeclared key is rejected as a 400, not silently
// dropped, so the caller knows the override didn't take.
func mergeExecEnv(sbEnvs, reqEnv map[string]string) (map[string]string, error) {
	for k := range reqEnv {
		if _, ok := sbEnvs[k]; !ok {
			return nil, fmt.Errorf("%w: env key %q was not declared at sandbox creation", api.ErrInvalidRequest, k)
		}
	}
	if len(sbEnvs) == 0 {
		return nil, nil
	}
	eff := make(map[string]string, len(sbEnvs))
	maps.Copy(eff, sbEnvs)
	maps.Copy(eff, reqEnv)
	return eff, nil
}

// MergeProcessEnv applies the exec environment contract to managed process
// creation at the host trust boundary. Sandbox envs are inherited, and the
// request can override only keys declared when the sandbox was created.
func (s *Service) MergeProcessEnv(ctx context.Context, id, caller string, overrides map[string]string) (map[string]string, error) {
	if err := s.authOwnedFast(ctx, id, caller); err != nil {
		return nil, err
	}
	sb, ok := s.Mgr.Lookup(id)
	if !ok {
		return nil, api.ErrNotFound
	}
	return mergeExecEnv(sb.Envs, overrides)
}

func (s *Service) Destroy(ctx context.Context, id, caller string) error {
	rec, err := s.loadOwned(ctx, id, caller)
	if err != nil {
		return err
	}
	// Host-ownership check: Mgr.Lookup only knows about VMs this host
	// actually runs. If the sandbox belongs to a different host (drain
	// misroute, stale router cache, accidental cross-host call), this
	// returns NotFound — never destroys someone else's VM.
	if _, ok := s.Mgr.Lookup(id); !ok {
		return api.ErrNotFound
	}
	// Guest self-delete reaches the host without control first setting
	// destroying. Use the same guarded CAS so it cannot bypass capture
	// reservations. Ordinary control-driven deletes already made this change.
	if rec.Status != models.StatusDestroying {
		status, err := s.Repo.MarkDestroying(ctx, id)
		if err != nil {
			return err
		}
		if status == "" {
			return fmt.Errorf("%w: sandbox state changed or snapshot capture in progress", api.ErrInvalidRequest)
		}
	}
	s.StopSelfSignal(id)
	if err := s.Mgr.Destroy(id); err != nil {
		return err
	}
	// MarkDestroyed must not ride the request ctx: Mgr.Destroy can exceed
	// control's 30s client timeout (kernel locks on xt_lock/rtnl during
	// iptables+netns teardown), which would leave the DB row stuck as
	// `running` even though the VM is gone — the "phantom" bug. Decouple
	// with a background ctx + its own short deadline so this always lands.
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	note := "user delete"
	if err := s.Repo.MarkDestroyed(bg, id, time.Now().UTC(), &note); err != nil {
		// Slot stays in Mgr.pendingRelease; the reconcile tick picks it
		// up on next pass and retries MarkDestroyed + ReleaseSlot. Do
		// NOT release the slot here on error — the row is still
		// `destroying` in the DB and the slot must stay pinned until
		// the row is durably `destroyed`.
		log.WithContext(ctx).Warnf("[store] mark destroyed %s failed: %v — slot stays pinned, reconcile will retry", id, err)
		return nil
	}
	// ReleaseSlot synchronously removes every BPF policy entry belonging to
	// the old IP/interface before it makes the permanent slot reusable.
	// MarkDestroyed must land first so a later reconciler cannot legitimately
	// recreate those entries from the durable control-plane view.
	s.Mgr.ReleaseSlot(id)
	// Clean up the locality-cache bundle left by a previous pause.
	// Best-effort: not fatal if absent or still being written.
	if s.PauseCfg.PausedDir != "" {
		_ = os.RemoveAll(filepath.Join(s.PauseCfg.PausedDir, id))
	}
	return nil
}

func (s *Service) Get(ctx context.Context, id, caller string) (*api.SandboxView, error) {
	rec, err := s.loadOwned(ctx, id, caller)
	if err != nil {
		return nil, err
	}
	v := recordToView(*rec)
	return &v, nil
}

func (s *Service) SetEgress(ctx context.Context, id, caller string, rules []string) (*api.SandboxView, error) {
	// Ownership check + ensure the sandbox lives here. loadOwned scopes by
	// user_id (via auth context) and returns ErrNotFound if the row isn't
	// visible to the caller — same contract as Get/Exec/Destroy.
	rec, err := s.loadOwned(ctx, id, caller)
	if err != nil {
		return nil, err
	}
	if _, ok := s.Mgr.Lookup(id); !ok {
		// Not on this host (shouldn't happen via the control-plane forwarder
		// but defensive for direct host-side hits).
		return nil, api.ErrNotFound
	}
	// nil == empty == allow-all. Normalise to empty so DB never has NULL.
	if rules == nil {
		rules = []string{}
	}
	// Swap iptables first; if that fails, don't touch the DB (so a retry
	// can re-apply from the old stored rules without drift).
	if err := s.Mgr.UpdateEgress(id, rules); err != nil {
		return nil, err
	}
	if err := s.Repo.SetEgress(ctx, id, rules); err != nil {
		// iptables already changed; log and return — next heartbeat is
		// authoritative but this row is now out of sync. Rare path.
		log.WithContext(ctx).Warnf("[service] SetEgress DB persist failed for %s: %v (iptables updated)", id, err)
		return nil, err
	}
	rec.Egress = rules
	v := recordToView(*rec)
	return &v, nil
}

func recordToView(r models.Sandbox) api.SandboxView {
	return api.NewSandboxView(r)
}

// Ensure errors package is imported for potential future sentinel use.
var _ = errors.New

// Pause kicks off async pause for a running sandbox on this host.
// Returns the SandboxView with status='pausing' immediately; the
// actual snapshot+upload happens in a background goroutine.
func (s *Service) Pause(ctx context.Context, id, caller string) (*api.SandboxView, error) {
	if s.Storage == nil {
		return nil, fmt.Errorf("%w: pause not configured (R2_BUCKET unset)", api.ErrInvalidRequest)
	}
	rec, err := s.Repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, api.ErrNotFound
	}
	if err := requireOwner(rec, caller); err != nil {
		return nil, err
	}
	if rec.Status != models.StatusRunning {
		// Idempotent on 'pausing'; reject everything else.
		if rec.Status == models.StatusPausing {
			view := recordToView(*rec)
			return &view, nil
		}
		return nil, fmt.Errorf("%w: sandbox is %s, not running", api.ErrInvalidRequest, rec.Status)
	}
	now := time.Now().UTC()
	st, err := s.Repo.MarkPausing(ctx, id, now)
	if err != nil {
		return nil, err
	}
	if st == "" {
		return nil, fmt.Errorf("%w: row state changed concurrently", api.ErrInvalidRequest)
	}
	rec.Status = models.Status(st)
	rec.LastPauseAttemptAt = &now
	s.runPauseAsync(context.WithoutCancel(ctx), id)
	view := recordToView(*rec)
	return &view, nil
}

// AttachDisk live-attaches one disk to a running sandbox. Idempotent
// on disk_id. Returns api.ErrNotFound if the sandbox isn't on this host.
func (s *Service) AttachDisk(ctx context.Context, id, caller string, disk proto.MMDSDisk) error {
	if err := s.Mgr.AttachDiskLive(ctx, id, disk); err != nil {
		if errors.Is(err, vm.ErrSandboxNotFound) {
			return api.ErrNotFound
		}
		return err
	}
	return nil
}

// DetachDisk live-detaches a disk by id. S3 contents are untouched.
// 404 on unknown sandbox; success when the disk wasn't attached
// (idempotent).
func (s *Service) DetachDisk(ctx context.Context, id, caller, diskID, mountPath string) error {
	if err := s.Mgr.DetachDiskLive(ctx, id, diskID, mountPath); err != nil {
		if errors.Is(err, vm.ErrSandboxNotFound) {
			return api.ErrNotFound
		}
		return err
	}
	return nil
}

// KickNetReconciler implements the api.Service hook used by control to
// wake the overlay reconciler immediately after a sandbox_networks
// write.
func (s *Service) KickNetReconciler() {
	s.Mgr.KickNetReconciler()
}

// PoolClaimKick refreshes the guest clock so the tenant's first
// SigV4-signed request (S3 client, geesefs mount) doesn't see a
// stale timestamp inherited from the prewarm snapshot. Also seeds
// the in-memory ownership cache with the new owner so the tenant's
// first exec skips the DB round-trip.
//
// The endpoint is authenticated as a control-plane peer and is called only
// after the atomic pool-claim transaction commits, so its owner is
// authoritative. Writing it unconditionally also repairs empty/stale caches
// after host rehydration; the previous exact-"pool" guard silently skipped
// those and forced the first exec through PostgreSQL.
func (s *Service) PoolClaimKick(ctx context.Context, id, owner string) error {
	if sb, ok := s.Mgr.Lookup(id); ok {
		cached := sb.CachedOwner()
		log.WithContext(ctx).Infof("[owner-cache-kick] sb=%s cached_empty=%v cached_pool=%v incoming_empty=%v incoming_matches=%v",
			id, cached == "", cached == models.PoolUserID, owner == "", cached == owner)
		if owner != "" {
			sb.SetCachedOwner(owner)
		}
	} else {
		log.WithContext(ctx).Infof("[owner-cache-kick] sb=%s sandbox_in_memory=false incoming_empty=%v", id, owner == "")
	}
	return s.Mgr.RefreshNowNS(ctx, id)
}

// Resume runs on the host control's scheduler picked. Row is already
// 'resuming' (control flipped it before forwarding); we just kick the
// resume goroutine.
func (s *Service) Resume(ctx context.Context, id string, row models.Sandbox) (*api.SandboxView, error) {
	if s.Storage == nil {
		return nil, fmt.Errorf("%w: pause not configured (R2_BUCKET unset)", api.ErrInvalidRequest)
	}
	if row.Status != models.StatusResuming {
		return nil, fmt.Errorf("%w: row not in resuming state (got %s)", api.ErrInvalidRequest, row.Status)
	}
	s.runResumeAsync(context.WithoutCancel(ctx), row)
	view := recordToView(row)
	return &view, nil
}

// UnsealResolvedDiskCreds opens every entry's sealed cryptobox envelope
// in place, replacing rd.Credentials with the plaintext JSON the
// downstream proto.DecodeS3Creds expects. Returns an error on first
// failure — refuse to proceed if any disk's credentials are unreadable
// rather than silently mount with empty creds.
func (s *Service) UnsealResolvedDiskCreds(rds []proto.ResolvedDisk) error {
	if len(rds) == 0 {
		return nil
	}
	if len(s.HostPriv) == 0 {
		return errors.New("host private key not configured")
	}
	for i := range rds {
		if len(rds[i].Credentials) == 0 {
			continue
		}
		env, err := cryptobox.UnmarshalEnvelope(rds[i].Credentials)
		if err != nil {
			// Backwards-compat for one release: control pre-cryptobox
			// posts plaintext credentials JSON, which won't parse as an
			// envelope. Pass through so a host-first rollout keeps
			// working until control is rolled too. TODO(drop-next-release):
			// remove the fallback and return the parse error.
			log.Warnf("[disks] credentials not an envelope (legacy plaintext path), disk=%s", rds[i].DiskID)
			continue
		}
		plain, err := cryptobox.Open(s.HostPriv, cryptobox.PurposeDiskCredentials, env)
		if err != nil {
			return fmt.Errorf("disk %s: open: %w", rds[i].DiskID, err)
		}
		rds[i].Credentials = plain
	}
	return nil
}
