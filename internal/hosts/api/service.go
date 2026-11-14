package api

import (
	"context"
	"errors"
	"io"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Shared control↔host wire contracts live in proto. These aliases keep the
// host service's interface concise while preserving one canonical JSON shape.
type (
	CreateReq     = proto.CreateReq
	CreateResp    = proto.CreateResp
	BandwidthView = proto.BandwidthView
	RechargeReq   = proto.RechargeReq
	ExecResp      = proto.ExecResp
	SandboxView   = proto.SandboxView
	SetEgressReq  = proto.SetEgressReq
)

// Service is the contract the HTTP handlers depend on. The concrete
// implementation lives outside this package.
//
// Auth-gated methods take `caller` as an explicit user_id param — the
// value control forwards and the host's mTLS role gate accepts. Passing it
// through the signature (instead of stashing it in the context) keeps
// data flow visible at every hop.
type Service interface {
	Create(ctx context.Context, caller string, req CreateReq) (*CreateResp, error)
	RootfsCatalog(ctx context.Context) (map[string]string, string, error)
	Exec(ctx context.Context, id, caller string, req proto.ExecRequest) (*ExecResp, error)
	// ExecStream runs the command and streams its NDJSON event lines
	// (one ExecStreamEvent per line) into w, calling flush after each
	// line so HTTP clients see output live. Returns when the agent
	// closes the conn or on I/O error.
	ExecStream(ctx context.Context, id, caller string, req proto.ExecRequest, w io.Writer, flush func()) error
	Destroy(ctx context.Context, id, caller string) error
	Get(ctx context.Context, id, caller string) (*SandboxView, error)
	Recharge(ctx context.Context, id, caller string, addBytes int64) (*BandwidthView, error)
	// SetEgress atomically replaces the sandbox's egress allowlist:
	// swaps the iptables chain, persists to the DB. Returns the
	// post-update SandboxView so callers see the effective state.
	SetEgress(ctx context.Context, id, caller string, rules []string) (*SandboxView, error)
	// SecretToken returns the per-VM shared secret stored in the
	// host's in-memory Sandbox. Used by host-side handlers (tunnel,
	// file proxy) that dial the guest agent and must prepend
	// "AUTH <token>\n". Returns ErrNotFound for unknown sandboxes.
	SecretToken(ctx context.Context, id string) (string, error)
	// OpenFileTransfer authorizes the caller and captures the address, secret,
	// and cancellation context from one VM incarnation. Caller must Cancel.
	OpenFileTransfer(ctx context.Context, id, caller string) (*FileTransferTarget, error)

	// MergeProcessEnv applies the Exec environment contract to managed
	// process creation before the request crosses into the guest.
	MergeProcessEnv(ctx context.Context, id, caller string, overrides map[string]string) (map[string]string, error)

	// LookupIP returns the live VM IP for a sandbox on this host —
	// without enforcing the per-user ownership check. Used by the
	// internal tunnel/shell handlers: callers there are already
	// authenticated by the mTLS role gate (ingress/gateway/control)
	// and have authorised the user upstream, but they don't carry a
	// user id in the request context, so the owner-scoped Get would
	// always return ErrNotFound. Returns ErrNotFound if the sandbox
	// isn't running on this host.
	LookupIP(id string) (string, error)

	// Pause kicks off the async pause flow for a running sandbox.
	// Returns immediately after marking the row 'pausing'; the actual
	// snapshot+upload happens in a background goroutine. Callers
	// poll GET /v1/sandboxes/:id for terminal status.
	// Returns ErrNotFound if the sandbox doesn't exist on this host.
	Pause(ctx context.Context, id, caller string) (*SandboxView, error)

	// Resume kicks off the async resume flow for a paused sandbox.
	// On the host side this is invoked by control's forward after
	// scheduler placement; the row is already 'resuming' when we
	// receive it. Returns immediately; resume runs in a goroutine.
	Resume(ctx context.Context, id string, row models.Sandbox) (*SandboxView, error)

	// AttachDisk adds a disk to a running sandbox's desired set and
	// pushes the updated set via MMDS. Agent's reconciler mounts it on
	// its next tick. Idempotent — re-attaching with the same id
	// replaces the mount_path.
	AttachDisk(ctx context.Context, id, caller string, disk proto.MMDSDisk) error

	// UnsealResolvedDiskCreds opens the cryptobox envelope on each
	// entry's Credentials field in place, replacing it with the
	// plaintext JSON the agent expects. Refuses to proceed if any
	// envelope fails to open. Callers should run this once on receive
	// before decoding into MMDS form.
	UnsealResolvedDiskCreds(rds []proto.ResolvedDisk) error

	// DetachDisk removes one disk from a sandbox's desired set + pushes
	// the updated MMDS. The agent's reconciler unmounts the FUSE
	// backing on the next tick. S3 contents are untouched.
	DetachDisk(ctx context.Context, id, caller, diskID, mountPath string) error

	// KickNetReconciler wakes the overlay reconciler immediately. Used
	// by control after AttachNetwork so a freshly-added sandbox_networks
	// row gets programmed into BPF maps without waiting for the next tick.
	KickNetReconciler()

	// PoolClaimKick refreshes the guest clock on a sandbox that was just
	// claimed from the prewarm pool AND seeds the in-memory ownership
	// cache with the new owner so the tenant's first exec/bandwidth call
	// skips the DB round-trip. owner is only applied when the current
	// cached value is the pool sentinel — a defensive guard so the kick
	// can never overwrite a legitimate tenant.
	PoolClaimKick(ctx context.Context, id, owner string) error
}

// FileTransferTarget is internal host state, never a public API response.
type FileTransferTarget struct {
	IP      string
	Token   string
	Context context.Context
	Cancel  context.CancelFunc
}

// NewSandboxView projects a models.Sandbox into the user-facing SandboxView
// (lowercase JSON tags, secrets stripped, env values replaced with keys).
// Handlers MUST use this rather than returning a raw models.Sandbox — the
// Record's top-level fields lack json tags and would serialise as
// Title-case, breaking SDK clients.
func NewSandboxView(r models.Sandbox) SandboxView {
	var envKeys []string
	if len(r.Envs) > 0 {
		envKeys = make([]string, 0, len(r.Envs))
		for k := range r.Envs {
			envKeys = append(envKeys, k)
		}
	}
	return SandboxView{
		SnapshotID:            r.SnapshotID,
		ID:                    r.ID,
		Name:                  r.Name,
		Status:                string(r.Status),
		IP:                    r.IP,
		VCPU:                  r.VCPU,
		MemMib:                r.MemMib,
		DiskMib:               r.DiskMib,
		CreatedAt:             r.CreatedAt,
		RunningAt:             r.RunningAt,
		DestroyedAt:           r.DestroyedAt,
		SpawnMs:               r.SpawnMs,
		Egress:                r.Egress,
		SSHPubkeys:            r.SSHPubkeys,
		Shape:                 r.Shape,
		Rootfs:                r.Rootfs,
		CreatedBy:             r.CreatedBy,
		Labels:                r.Labels,
		Region:                r.Region,
		IngressEnabled:        r.IngressEnabled,
		BandwidthIngressBytes: r.BandwidthIngressBytes,
		Envs:                  envKeys,
		PausedAt:              r.PausedAt,
		LastResumedAt:         r.LastResumedAt,
		ForkedFrom:            r.ForkedFrom,
		AutoPauseAfterSeconds: r.AutoPauseAfterSeconds,
	}
}

// Sentinel errors — handlers translate these into the right JSend shape
// and HTTP status.
var (
	ErrNotFound       = errors.New("sandbox not found")
	ErrInvalidRequest = errors.New("invalid request")
	// ErrAtCapacity signals the host has hit its hard MaxVMs ceiling.
	// Handlers translate it to 503 Service Unavailable so the caller
	// (e.g. control's scheduler) knows to pick a different host.
	ErrAtCapacity = errors.New("host at capacity")
	// ErrInfrastructure marks failures in host dependencies such as template
	// storage. They are retryable service failures, not malformed user input.
	ErrInfrastructure = errors.New("host infrastructure unavailable")
)
