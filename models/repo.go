package models

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/NodeOps-app/sandbox/database"
)

// Repo is the Postgres-backed repository implementation. It delegates
// every method to the per-table free functions in this package. Used
// directly (as a concrete type) by the control plane, scheduler,
// ingress, and builder.
type Repo struct {
	DB *database.Db
}

// NewRepo wraps an already-open database handle.
func NewRepo(db *database.Db) *Repo { return &Repo{DB: db} }

// OpenRepo opens a Postgres connection (running pending migrations) and
// returns a ready repository. Convenience for callers that previously
// used store.New(store.Config{DSN: ...}).
func OpenRepo(ctx context.Context, dsn string) (*Repo, error) {
	return OpenRepoWithPoolConfig(ctx, dsn, database.PoolConfig{})
}

// OpenRepoWithPoolConfig opens a repository with caller-specific pgxpool bounds.
func OpenRepoWithPoolConfig(ctx context.Context, dsn string, poolConfig database.PoolConfig) (*Repo, error) {
	if dsn == "" {
		return nil, errors.New("models: empty Postgres DSN")
	}
	octx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	db, err := database.OpenDbWithPoolConfig(octx, dsn, poolConfig)
	if err != nil {
		return nil, err
	}
	return &Repo{DB: db}, nil
}

func (r *Repo) Close() { r.DB.Close() }

// Bootstrap is a no-op: migrations are applied by OpenDb at construction.
func (r *Repo) Bootstrap(ctx context.Context) error { return nil }

func (r *Repo) CountStaleNetworkMemberships(ctx context.Context, region string) (int, error) {
	return CountStaleNetworkMemberships(ctx, r.DB, region)
}

func (r *Repo) SweepStaleNetworkMemberships(ctx context.Context, region string) (int, error) {
	return SweepStaleNetworkMemberships(ctx, r.DB, region)
}

// ── sandboxes ──────────────────────────────────────────────────────────

func (r *Repo) Insert(ctx context.Context, rec Sandbox) error {
	return InsertSandbox(ctx, r.DB, rec)
}

func (r *Repo) CompleteSandboxCreate(ctx context.Context, rec Sandbox, hostID string) (bool, error) {
	return CompleteSandboxCreate(ctx, r.DB, rec, hostID)
}

func (r *Repo) MarkDestroyed(ctx context.Context, id string, at time.Time, note *string, emitter BillingEmitter) error {
	return MarkSandboxDestroyed(ctx, r.DB, id, at, note, emitter)
}

func (r *Repo) MarkDestroyingFromTerminalCAS(ctx context.Context, id string) (bool, error) {
	return MarkSandboxDestroyingFromTerminalCAS(ctx, r.DB, id)
}

func (r *Repo) MarkDestroyedFromDestroyingCAS(ctx context.Context, id string, at time.Time, note *string, emitter BillingEmitter) (bool, error) {
	return MarkSandboxDestroyedFromDestroyingCAS(ctx, r.DB, id, at, note, emitter)
}

func (r *Repo) MarkFailed(ctx context.Context, id string, errText *string, at time.Time, emitter BillingEmitter) error {
	return MarkSandboxFailed(ctx, r.DB, id, errText, at, emitter)
}

// MarkFailedFromCreatingCAS is the CAS-guarded variant used by host
// reconcile. Atomically flips status creating→failed iff the row is
// still creating AND host_id matches. Returns flipped=true on success,
// flipped=false on a lost race (no error).
func (r *Repo) MarkFailedFromCreatingCAS(ctx context.Context, id, hostID string, errText *string, at time.Time, emitter BillingEmitter) (bool, error) {
	return MarkSandboxFailedFromCreatingCAS(ctx, r.DB, id, hostID, errText, at, emitter)
}

// List keeps the original 4-arg shape for internal callers (sweep,
// reconcile, loops) that don't paginate. Hands off to ListSandboxes
// with offset=0. New code should prefer ListPaged.
func (r *Repo) List(ctx context.Context, host, userID, status string, limit int) ([]Sandbox, error) {
	return ListSandboxes(ctx, r.DB, host, userID, status, nil, limit, 0)
}

// ListPaged is the paginated variant used by the user-facing
// GET /v1/sandboxes handler.
func (r *Repo) ListPaged(ctx context.Context, host, userID, status string, labels map[string]string, limit, offset int) ([]Sandbox, error) {
	return ListSandboxes(ctx, r.DB, host, userID, status, labels, limit, offset)
}

// ListPinnedToHost is the drain-specific list — includes paused
// sandboxes whose host_id is NULL but cached_host_id matches.
func (r *Repo) ListPinnedToHost(ctx context.Context, host string, limit int) ([]Sandbox, error) {
	return ListPinnedToHost(ctx, r.DB, host, limit)
}

// CountSandboxesForList returns the total matching ListPaged's filters.
func (r *Repo) CountSandboxesForList(ctx context.Context, host, userID, status string, labels map[string]string) (int, error) {
	return CountSandboxesForList(ctx, r.DB, host, userID, status, labels)
}

func (r *Repo) Get(ctx context.Context, id string) (*Sandbox, error) {
	return GetSandbox(ctx, r.DB, id)
}

func (r *Repo) GetForExec(ctx context.Context, id string) (*Sandbox, error) {
	return GetSandboxExecRoute(ctx, r.DB, id)
}

func (r *Repo) GetByIP(ctx context.Context, ip string) (*Sandbox, error) {
	return GetSandboxByIP(ctx, r.DB, ip)
}

func (r *Repo) GetByIPForUser(ctx context.Context, userID, ip string) (*Sandbox, error) {
	return GetSandboxByIPForUser(ctx, r.DB, userID, ip)
}

func (r *Repo) ListLiveIDs(ctx context.Context, host string) ([]string, error) {
	return ListLiveIDs(ctx, r.DB, host)
}

func (r *Repo) ListRunningIDs(ctx context.Context, host string) ([]string, error) {
	return ListRunningIDs(ctx, r.DB, host)
}

func (r *Repo) SetSandboxHost(ctx context.Context, sandboxID string, hostID *string) error {
	return SetSandboxHost(ctx, r.DB, sandboxID, hostID)
}

func (r *Repo) SetSSHPubkeys(ctx context.Context, sandboxID string, keys []string) error {
	return SetSandboxSSHPubkeys(ctx, r.DB, sandboxID, keys)
}

func (r *Repo) SetEgress(ctx context.Context, sandboxID string, rules []string) error {
	return SetSandboxEgress(ctx, r.DB, sandboxID, rules)
}

func (r *Repo) SetEgressIfPaused(ctx context.Context, sandboxID string, rules []string) (bool, error) {
	return SetSandboxEgressIfPaused(ctx, r.DB, sandboxID, rules)
}

func (r *Repo) SetEnvs(ctx context.Context, sandboxID string, envs map[string]string) error {
	return SetSandboxEnvs(ctx, r.DB, sandboxID, envs)
}

func (r *Repo) SetDiskMib(ctx context.Context, sandboxID string, diskMib int64) error {
	return SetSandboxDiskMib(ctx, r.DB, sandboxID, diskMib)
}

func (r *Repo) SetRuntime(ctx context.Context, id string, apiSock, containerID, overlayPath *string, fcPid int) error {
	return SetSandboxRuntime(ctx, r.DB, id, apiSock, containerID, overlayPath, fcPid)
}

func (r *Repo) SetBandwidthQuota(ctx context.Context, sandboxID string, quotaBytes int64) error {
	return SetSandboxBandwidthQuota(ctx, r.DB, sandboxID, quotaBytes)
}

func (r *Repo) SetBandwidthUsed(ctx context.Context, sandboxID string, usedBytes int64) error {
	return SetSandboxBandwidthUsed(ctx, r.DB, sandboxID, usedBytes)
}

func (r *Repo) SetBandwidthCapped(ctx context.Context, sandboxID string, capped bool) error {
	return SetSandboxBandwidthCapped(ctx, r.DB, sandboxID, capped)
}

func (r *Repo) SetIngressEnabled(ctx context.Context, id string, enabled bool) error {
	return SetSandboxIngressEnabled(ctx, r.DB, id, enabled)
}

func (r *Repo) SetAutoPause(ctx context.Context, id string, seconds *int) error {
	return SetAutoPause(ctx, r.DB, id, seconds)
}

func (r *Repo) SetSandboxLabels(ctx context.Context, id string, labels map[string]string) error {
	return SetSandboxLabels(ctx, r.DB, id, labels)
}

func (r *Repo) TouchActivity(ctx context.Context, id string, meteredBytes int64) error {
	return TouchActivity(ctx, r.DB, id, meteredBytes)
}

func (r *Repo) TouchInteractiveActivity(ctx context.Context, id string) error {
	return TouchInteractiveActivity(ctx, r.DB, id)
}

func (r *Repo) GetIngressRoute(ctx context.Context, id string) (IngressRoute, error) {
	return GetIngressRoute(ctx, r.DB, id)
}

func (r *Repo) UpdateBandwidthIngress(ctx context.Context, id string, bytes int64) error {
	return UpdateSandboxBandwidthIngress(ctx, r.DB, id, bytes)
}

// ── rootfs catalog ─────────────────────────────────────────────────────

func (r *Repo) GetRootfsMetadata(ctx context.Context, name string) (*RootfsCatalog, error) {
	return GetRootfsMetadata(ctx, r.DB, name)
}

func (r *Repo) ListRootfsMetadata(ctx context.Context) ([]RootfsCatalog, error) {
	return ListRootfsMetadata(ctx, r.DB)
}

// ── pause / resume / fork ──────────────────────────────────────────────

func (r *Repo) MarkPausing(ctx context.Context, id string, at time.Time) (string, error) {
	return MarkPausing(ctx, r.DB, id, at)
}

func (r *Repo) MarkPaused(ctx context.Context, id string, manifest json.RawMessage,
	uri, cachedHostID *string, cachedUntil, pausedAt time.Time,
	emitter BillingEmitter) (string, error) {
	return MarkPaused(ctx, r.DB, id, manifest, uri, cachedHostID, cachedUntil, pausedAt, emitter)
}

func (r *Repo) MarkPauseRolledBack(ctx context.Context, id string, errMsg *string, at time.Time) (string, error) {
	return MarkPauseRolledBack(ctx, r.DB, id, errMsg, at)
}

func (r *Repo) MarkResuming(ctx context.Context, id string, clearFailedHosts bool, at time.Time) (string, error) {
	return MarkResuming(ctx, r.DB, id, clearFailedHosts, at)
}

func (r *Repo) MarkResumed(ctx context.Context, id string, ip, mac, apiSock, containerID, overlayPath *string,
	fcPid int, runningAt time.Time, host string, emitter BillingEmitter) (string, error) {
	return MarkResumed(ctx, r.DB, id, ip, mac, apiSock, containerID, overlayPath, fcPid, runningAt, host, emitter)
}

func (r *Repo) MarkResumeFailed(ctx context.Context, id, host string, errMsg *string, at time.Time) (string, error) {
	return MarkResumeFailed(ctx, r.DB, id, host, errMsg, at)
}

func (r *Repo) MarkResumeExhausted(ctx context.Context, id string, errMsg *string) (string, error) {
	return MarkResumeExhausted(ctx, r.DB, id, errMsg)
}

func (r *Repo) MarkStuckPauseFailed(ctx context.Context, id string, errMsg *string, emitter BillingEmitter) (string, error) {
	return MarkStuckPauseFailed(ctx, r.DB, id, errMsg, emitter)
}

func (r *Repo) MarkForking(ctx context.Context, srcID string, newRow Sandbox) (*Sandbox, error) {
	return MarkForking(ctx, r.DB, srcID, newRow)
}

func (r *Repo) MarkForkPaused(ctx context.Context, id string, manifest json.RawMessage,
	uri *string, pausedAt time.Time, emitter BillingEmitter) (string, error) {
	return MarkForkPaused(ctx, r.DB, id, manifest, uri, pausedAt, emitter)
}

func (r *Repo) ClearLocalCache(ctx context.Context, id, host string) error {
	return ClearLocalCache(ctx, r.DB, id, host)
}

func (r *Repo) MarkDestroying(ctx context.Context, id string) (string, error) {
	return MarkDestroying(ctx, r.DB, id)
}

func (r *Repo) ListPausing(ctx context.Context, host string) ([]string, error) {
	return ListPausing(ctx, r.DB, host)
}

func (r *Repo) ListPaused(ctx context.Context, cachedHost string) ([]string, error) {
	return ListPaused(ctx, r.DB, cachedHost)
}

func (r *Repo) ListStuckPausing(ctx context.Context, cutoff time.Time, region string) ([]Sandbox, error) {
	return ListStuckPausing(ctx, r.DB, cutoff, region)
}

func (r *Repo) ListStuckOrphanDestroying(ctx context.Context, cutoff time.Time, region string) ([]StuckOrphanDestroying, error) {
	return ListStuckOrphanDestroying(ctx, r.DB, cutoff, region)
}

func (r *Repo) IncDrainPauseAttempts(ctx context.Context, id string) (int, error) {
	return IncDrainPauseAttempts(ctx, r.DB, id)
}

func (r *Repo) ResetDrainPauseAttempts(ctx context.Context, id string) error {
	return ResetDrainPauseAttempts(ctx, r.DB, id)
}

func (r *Repo) ListStuckResuming(ctx context.Context, cutoff time.Time, region string) ([]Sandbox, error) {
	return ListStuckResuming(ctx, r.DB, cutoff, region)
}

func (r *Repo) ListStuckForking(ctx context.Context, cutoff time.Time, region string) ([]Sandbox, error) {
	return ListStuckForking(ctx, r.DB, cutoff, region)
}

func (r *Repo) MarkForkFailed(ctx context.Context, id string, errMsg *string, emitter BillingEmitter) (string, error) {
	return MarkForkFailed(ctx, r.DB, id, errMsg, emitter)
}

func (r *Repo) LocalCacheCandidates(ctx context.Context, host string) ([]LocalCacheCandidate, error) {
	return LocalCacheCandidates(ctx, r.DB, host)
}

// ── api keys ───────────────────────────────────────────────────────────

func (r *Repo) UpsertAPIKey(ctx context.Context, k APIKey) error {
	return UpsertAPIKey(ctx, r.DB, k)
}

func (r *Repo) RevokeAPIKeyByHash(ctx context.Context, authType string, keyHash []byte) error {
	return RevokeAPIKeyByHash(ctx, r.DB, authType, keyHash)
}

func (r *Repo) LookupAPIKeyByHash(ctx context.Context, authType string, keyHash []byte) (*APIKey, error) {
	return LookupAPIKeyByHash(ctx, r.DB, authType, keyHash)
}

func (r *Repo) DeleteAPIKeyByHash(ctx context.Context, authType string, keyHash []byte) error {
	return DeleteAPIKeyByHash(ctx, r.DB, authType, keyHash)
}

// ── sandbox access tokens ─────────────────────────────────────────────

func (r *Repo) CreateSandboxAccessToken(ctx context.Context, token SandboxAccessToken) error {
	return CreateSandboxAccessToken(ctx, r.DB, token)
}

func (r *Repo) GetSandboxAccessToken(ctx context.Context, sandboxID string) (*SandboxAccessToken, error) {
	return GetSandboxAccessToken(ctx, r.DB, sandboxID)
}

func (r *Repo) LookupSandboxAccessTokenByHash(ctx context.Context, tokenHash []byte) (*SandboxAccessToken, error) {
	return LookupSandboxAccessTokenByHash(ctx, r.DB, tokenHash)
}

func (r *Repo) RotateSandboxAccessToken(ctx context.Context, sandboxID string, tokenHash []byte, tokenHint string, rotatedAt time.Time) (*SandboxAccessToken, error) {
	return RotateSandboxAccessToken(ctx, r.DB, sandboxID, tokenHash, tokenHint, rotatedAt)
}

func (r *Repo) DeleteSandboxAccessToken(ctx context.Context, sandboxID string) (bool, error) {
	return DeleteSandboxAccessToken(ctx, r.DB, sandboxID)
}

func (r *Repo) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	return ListAPIKeys(ctx, r.DB)
}

func (r *Repo) DeleteExpiredExternalAPIKeys(ctx context.Context, before time.Time) ([]ExpiredAPIKey, error) {
	return DeleteExpiredExternalAPIKeys(ctx, r.DB, before)
}

// ── hosts ──────────────────────────────────────────────────────────────

func (r *Repo) UpsertHost(ctx context.Context, h Host) error {
	return UpsertHost(ctx, r.DB, h)
}

func (r *Repo) AssignHostSubnet(ctx context.Context, hostID, underlayIP, region string) (string, error) {
	return AssignHostSubnet(ctx, r.DB, hostID, underlayIP, region)
}

func (r *Repo) AssignHostWGIP(ctx context.Context, hostID, region string) (string, error) {
	return AssignHostWGIP(ctx, r.DB, hostID, region)
}

func (r *Repo) SetHostWGPublicKey(ctx context.Context, hostID string, pubkey []byte) error {
	return SetHostWGPublicKey(ctx, r.DB, hostID, pubkey)
}

func (r *Repo) RegisterRegion(ctx context.Context, name string) (int, error) {
	return RegisterRegion(ctx, r.DB, name)
}

func (r *Repo) HeartbeatHost(ctx context.Context, id string, inUseMib, vmCount int, status string, diskUsedMib int64, at time.Time) error {
	return HeartbeatHost(ctx, r.DB, id, inUseMib, vmCount, status, diskUsedMib, at)
}

func (r *Repo) ListHosts(ctx context.Context) ([]Host, error) {
	return ListHosts(ctx, r.DB)
}

func (r *Repo) ListActiveHosts(ctx context.Context) ([]Host, error) {
	return ListActiveHosts(ctx, r.DB)
}

func (r *Repo) SumUsageByHost(ctx context.Context) (map[string]HostUsage, error) {
	return SumUsageByHost(ctx, r.DB)
}

func (r *Repo) ListLiveSandboxes(ctx context.Context) ([]LiveSandbox, error) {
	return ListLiveSandboxes(ctx, r.DB)
}

func (r *Repo) StatusOfIDs(ctx context.Context, ids []string) (map[string]string, error) {
	return StatusOfIDs(ctx, r.DB, ids)
}

func (r *Repo) FailOrphanCreating(ctx context.Context, cutoff time.Time, region string, emitter BillingEmitter) ([]string, error) {
	return FailOrphanCreating(ctx, r.DB, cutoff, region, emitter)
}

func (r *Repo) MarkAgedRunningDestroyed(ctx context.Context, cutoff, destroyedAt time.Time, note, region string, emitter BillingEmitter) ([]AgedRunningRow, error) {
	return MarkAgedRunningDestroyed(ctx, r.DB, cutoff, destroyedAt, note, region, emitter)
}

func (r *Repo) GetHost(ctx context.Context, id string) (*Host, error) {
	return GetHost(ctx, r.DB, id)
}

func (r *Repo) SetHostStatus(ctx context.Context, id, status string) (string, error) {
	return SetHostStatus(ctx, r.DB, id, status)
}

func (r *Repo) SetHostSchedulingDisabled(ctx context.Context, id string, disabled bool) (string, error) {
	return SetHostSchedulingDisabled(ctx, r.DB, id, disabled)
}

func (r *Repo) SetHostDrain(ctx context.Context, id string) (string, error) {
	return SetHostDrain(ctx, r.DB, id)
}

func (r *Repo) ListRunningSandboxesOnHost(ctx context.Context, hostID string) ([]string, error) {
	return ListRunningSandboxesOnHost(ctx, r.DB, hostID)
}

func (r *Repo) MarkStaleHosts(ctx context.Context, cutoff time.Time, region string) (int, error) {
	return MarkStaleHosts(ctx, r.DB, cutoff, region)
}

// ── templates ──────────────────────────────────────────────────────────

func (r *Repo) InsertTemplate(ctx context.Context, t Template) error {
	return InsertTemplate(ctx, r.DB, t)
}

func (r *Repo) GetTemplate(ctx context.Context, id string) (*Template, error) {
	return GetTemplate(ctx, r.DB, id)
}

func (r *Repo) GetLatestReadyByName(ctx context.Context, userID, name string) (string, error) {
	return GetLatestReadyByName(ctx, r.DB, userID, name)
}

func (r *Repo) ListUserTemplates(ctx context.Context, userID string, limit int) ([]Template, error) {
	return ListUserTemplates(ctx, r.DB, userID, limit, 0)
}

func (r *Repo) ListUserTemplatesPaged(ctx context.Context, userID string, limit, offset int) ([]Template, error) {
	return ListUserTemplates(ctx, r.DB, userID, limit, offset)
}

func (r *Repo) CountUserTemplates(ctx context.Context, userID string) (int, error) {
	return CountUserTemplates(ctx, r.DB, userID)
}

func (r *Repo) CountInflightTemplatesForUser(ctx context.Context, userID string) (int, error) {
	return CountInflightTemplatesForUser(ctx, r.DB, userID)
}

func (r *Repo) TemplateNameTaken(ctx context.Context, userID, name string) (bool, error) {
	return TemplateNameTaken(ctx, r.DB, userID, name)
}

func (r *Repo) SoftDeleteTemplate(ctx context.Context, id, userID string) (string, error) {
	return SoftDeleteTemplate(ctx, r.DB, id, userID)
}

func (r *Repo) ClaimNextBuild(ctx context.Context, blockedUsers []string) (*Template, error) {
	return ClaimNextBuild(ctx, r.DB, blockedUsers)
}

func (r *Repo) CompleteTemplateBuild(ctx context.Context, id string, newStatus TemplateStatus,
	sha256 *string, sizeBytes, ext4SizeBytes int64) (string, error) {
	return CompleteTemplateBuild(ctx, r.DB, id, newStatus, sha256, sizeBytes, ext4SizeBytes)
}

func (r *Repo) ReapStuckBuilds(ctx context.Context, cutoff time.Time) ([]string, error) {
	return ReapStuckBuilds(ctx, r.DB, cutoff)
}

func (r *Repo) SetTemplateFailed(ctx context.Context, id string) (string, error) {
	return SetTemplateFailed(ctx, r.DB, id)
}

// ── host_cached_templates ──────────────────────────────────────────────

func (r *Repo) UpsertHostCachedTemplate(ctx context.Context, hostID, tplID string, cachedUntil time.Time) error {
	return UpsertHostCachedTemplate(ctx, r.DB, hostID, tplID, cachedUntil)
}

func (r *Repo) DeleteHostCachedTemplate(ctx context.Context, hostID, tplID string) error {
	return DeleteHostCachedTemplate(ctx, r.DB, hostID, tplID)
}

func (r *Repo) ListHostCachedTemplates(ctx context.Context, hostID string) ([]HostCachedTemplate, error) {
	return ListHostCachedTemplates(ctx, r.DB, hostID)
}

func (r *Repo) ListHostsForTemplate(ctx context.Context) ([]HostCachedTemplate, error) {
	return ListHostsForTemplate(ctx, r.DB)
}

func (r *Repo) HostCachedTemplateHasActiveSandbox(ctx context.Context, hostID, tplID string) (int, error) {
	return HostCachedTemplateHasActiveSandbox(ctx, r.DB, hostID, tplID)
}

// ── clusters ───────────────────────────────────────────────────────────

// ── overlay networks ───────────────────────────────────────────────────

func (r *Repo) CreateNetwork(ctx context.Context, n Network, region string) error {
	return CreateNetwork(ctx, r.DB, n, region)
}

func (r *Repo) GetNetwork(ctx context.Context, owner, idOrName string) (*Network, error) {
	return GetNetwork(ctx, r.DB, owner, idOrName)
}

func (r *Repo) ListNetworks(ctx context.Context, owner string) ([]Network, error) {
	return ListNetworks(ctx, r.DB, owner, 0, 0)
}

func (r *Repo) ListNetworksPaged(ctx context.Context, owner string, limit, offset int) ([]Network, error) {
	return ListNetworks(ctx, r.DB, owner, limit, offset)
}

func (r *Repo) CountUserNetworks(ctx context.Context, owner string) (int, error) {
	return CountUserNetworks(ctx, r.DB, owner)
}

func (r *Repo) DeleteNetwork(ctx context.Context, owner, idOrName string) error {
	return DeleteNetwork(ctx, r.DB, owner, idOrName)
}

func (r *Repo) AttachNetwork(ctx context.Context, sandboxID, networkID string) error {
	return AttachNetwork(ctx, r.DB, sandboxID, networkID)
}

func (r *Repo) DetachNetwork(ctx context.Context, sandboxID, networkID string) error {
	return DetachNetwork(ctx, r.DB, sandboxID, networkID)
}

func (r *Repo) NetworkHostState(ctx context.Context, hostID string) ([]NetworkMember, error) {
	return NetworkHostState(ctx, r.DB, hostID)
}

func (r *Repo) ListNetworkMembers(ctx context.Context, networkID string) ([]NetworkMemberView, error) {
	return ListNetworkMembers(ctx, r.DB, networkID)
}

// ── disks ──────────────────────────────────────────────────────────────

func (r *Repo) InsertDisk(ctx context.Context, rec *Disk) error {
	return InsertDisk(ctx, r.DB, rec)
}

func (r *Repo) GetDisk(ctx context.Context, userID, idOrName string) (*Disk, error) {
	return GetDisk(ctx, r.DB, userID, idOrName)
}

func (r *Repo) ListDisks(ctx context.Context, userID string, limit int) ([]Disk, error) {
	return ListDisks(ctx, r.DB, userID, limit, 0)
}

func (r *Repo) ListDisksPaged(ctx context.Context, userID string, limit, offset int) ([]Disk, error) {
	return ListDisks(ctx, r.DB, userID, limit, offset)
}

func (r *Repo) CountUserDisks(ctx context.Context, userID string) (int, error) {
	return CountUserDisks(ctx, r.DB, userID)
}

func (r *Repo) DeleteDisk(ctx context.Context, userID, idOrName string) error {
	return DeleteDisk(ctx, r.DB, userID, idOrName)
}

func (r *Repo) UpdateDiskCredentials(ctx context.Context, diskID, userID string, encrypted json.RawMessage) error {
	return UpdateDiskCredentials(ctx, r.DB, diskID, userID, encrypted)
}

func (r *Repo) ListRunningSandboxesForDisk(ctx context.Context, diskID string) ([]RunningSandboxAttachment, error) {
	return ListRunningSandboxesForDisk(ctx, r.DB, diskID)
}

func (r *Repo) AttachDisk(ctx context.Context, sandboxID, diskID, mountPath, subPath string) error {
	return AttachDisk(ctx, r.DB, sandboxID, diskID, mountPath, subPath)
}

func (r *Repo) AttachDiskIfRunning(ctx context.Context, sandboxID, diskID, mountPath, subPath string) (running, inserted, diskExists bool, err error) {
	return AttachDiskIfRunning(ctx, r.DB, sandboxID, diskID, mountPath, subPath)
}

func (r *Repo) DetachDisk(ctx context.Context, sandboxID, diskID, mountPath string) error {
	return DetachDisk(ctx, r.DB, sandboxID, diskID, mountPath)
}

func (r *Repo) ListSandboxDisks(ctx context.Context, sandboxID string) ([]SandboxDisk, error) {
	return ListSandboxDisks(ctx, r.DB, sandboxID)
}

func (r *Repo) ResolveSandboxDisks(ctx context.Context, sandboxID string) ([]Disk, []string, []string, error) {
	return ResolveSandboxDisks(ctx, r.DB, sandboxID)
}

func (r *Repo) SetSandboxDiskStatus(ctx context.Context, sandboxID, diskID, mountPath, status, mountError string) error {
	return SetSandboxDiskStatus(ctx, r.DB, sandboxID, diskID, mountPath, status, mountError)
}

func (r *Repo) ResetSandboxDiskStatus(ctx context.Context, sandboxID string) error {
	return ResetSandboxDiskStatus(ctx, r.DB, sandboxID)
}

// ── regions ────────────────────────────────────────────────────────────

func (r *Repo) GetRegion(ctx context.Context, name string) (*Region, error) {
	return GetRegion(ctx, r.DB, name)
}

func (r *Repo) ListRegions(ctx context.Context) ([]Region, error) {
	return ListRegions(ctx, r.DB)
}

func (r *Repo) InsertRegion(ctx context.Context, region Region) error {
	return InsertRegion(ctx, r.DB, region)
}

func (r *Repo) DisableRegion(ctx context.Context, name string) error {
	return DisableRegion(ctx, r.DB, name)
}

func (r *Repo) CountSandboxesActive(ctx context.Context, userID string) (int, error) {
	return CountSandboxesActive(ctx, r.DB, userID)
}
func (r *Repo) CountSandboxesActiveExcept(ctx context.Context, userID, excludeID string) (int, error) {
	return CountSandboxesActiveExcept(ctx, r.DB, userID, excludeID)
}
func (r *Repo) CountSandboxesSince(ctx context.Context, userID string, since time.Time) (int, error) {
	return CountSandboxesSince(ctx, r.DB, userID, since)
}
func (r *Repo) GetUserMetricsByStatus(ctx context.Context, userID string) ([]SandboxStatusCount, error) {
	return GetUserMetricsByStatus(ctx, r.DB, userID)
}
func (r *Repo) GetUserMetricsWindow(ctx context.Context, userID string, from, to time.Time) (UserMetricsRow, error) {
	return GetUserMetricsWindow(ctx, r.DB, userID, from, to)
}
func (r *Repo) GetUserMetricsByShape(ctx context.Context, userID string, from, to time.Time) ([]SandboxShapeRollup, error) {
	return GetUserMetricsByShape(ctx, r.DB, userID, from, to)
}
func (r *Repo) GetUserMetricsTimeseries(ctx context.Context, userID string, from, to time.Time, bucket string) ([]SandboxBucketRow, error) {
	return GetUserMetricsTimeseries(ctx, r.DB, userID, from, to, bucket)
}
func (r *Repo) CountNetworksActive(ctx context.Context, ownerID string) (int, error) {
	return CountNetworksActive(ctx, r.DB, ownerID)
}
func (r *Repo) CountNetworksSince(ctx context.Context, ownerID string, since time.Time) (int, error) {
	return CountNetworksSince(ctx, r.DB, ownerID, since)
}
func (r *Repo) CountDisksActive(ctx context.Context, userID string) (int, error) {
	return CountDisksActive(ctx, r.DB, userID)
}
func (r *Repo) CountDisksSince(ctx context.Context, userID string, since time.Time) (int, error) {
	return CountDisksSince(ctx, r.DB, userID, since)
}

func (r *Repo) CountTemplatesActive(ctx context.Context, userID string) (int, error) {
	return CountTemplatesActive(ctx, r.DB, userID)
}
func (r *Repo) CountTemplatesSince(ctx context.Context, userID string, since time.Time) (int, error) {
	return CountTemplatesSince(ctx, r.DB, userID, since)
}

func (r *Repo) IsInternalUser(ctx context.Context, userID string) (bool, error) {
	return IsInternalUser(ctx, r.DB, userID)
}

// ── shapes ─────────────────────────────────────────────────────────────

func (r *Repo) ListEnabledShapes(ctx context.Context) ([]Shape, error) {
	return ListEnabledShapes(ctx, r.DB)
}

// ── devices (user-device WireGuard VPN) ───────────────────────────────

func (r *Repo) AssignDeviceIP(ctx context.Context, region string) (string, error) {
	return AssignDeviceIP(ctx, r.DB, region)
}
func (r *Repo) CreateDevice(ctx context.Context, rec Device) (*Device, error) {
	return CreateDevice(ctx, r.DB, rec)
}
func (r *Repo) GetDevice(ctx context.Context, id string) (*Device, error) {
	return GetDevice(ctx, r.DB, id)
}
func (r *Repo) GetDeviceForUser(ctx context.Context, id, userID string) (*Device, error) {
	return GetDeviceForUser(ctx, r.DB, id, userID)
}
func (r *Repo) ListDevicesForUser(ctx context.Context, userID string, limit, offset int) ([]Device, error) {
	return ListDevicesForUser(ctx, r.DB, userID, limit, offset)
}
func (r *Repo) CountDevicesForUser(ctx context.Context, userID string) (int, error) {
	return CountDevicesForUser(ctx, r.DB, userID)
}
func (r *Repo) RevokeDevice(ctx context.Context, id, userID string) error {
	return RevokeDevice(ctx, r.DB, id, userID)
}
func (r *Repo) AttachDeviceToNetwork(ctx context.Context, deviceID, networkID string) error {
	return AttachDeviceToNetwork(ctx, r.DB, deviceID, networkID)
}
func (r *Repo) DetachDeviceFromNetwork(ctx context.Context, deviceID, networkID string) error {
	return DetachDeviceFromNetwork(ctx, r.DB, deviceID, networkID)
}
func (r *Repo) ListNetworksForDevice(ctx context.Context, deviceID string) ([]DeviceNetworkView, error) {
	return ListNetworksForDevice(ctx, r.DB, deviceID)
}
func (r *Repo) CreateDeviceSession(ctx context.Context, rec DeviceSession) (*DeviceSession, error) {
	return CreateDeviceSession(ctx, r.DB, rec)
}
func (r *Repo) GetDeviceSession(ctx context.Context, id string) (*DeviceSession, error) {
	return GetDeviceSession(ctx, r.DB, id)
}
func (r *Repo) DeleteDeviceSession(ctx context.Context, id, deviceID string) error {
	return DeleteDeviceSession(ctx, r.DB, id, deviceID)
}
func (r *Repo) GetActiveSessionForDevice(ctx context.Context, deviceID string) (*DeviceSession, error) {
	return GetActiveSessionForDevice(ctx, r.DB, deviceID)
}
func (r *Repo) RenewDeviceSession(ctx context.Context, id, deviceID string, ttlSecs int) (*DeviceSession, error) {
	return RenewDeviceSession(ctx, r.DB, id, deviceID, ttlSecs)
}
func (r *Repo) ListSessionsForDevice(ctx context.Context, deviceID string) ([]DeviceSession, error) {
	return ListSessionsForDevice(ctx, r.DB, deviceID)
}
func (r *Repo) ListSessionsForRelay(ctx context.Context, relayHostID string) ([]RelaySessionPeer, error) {
	return ListSessionsForRelay(ctx, r.DB, relayHostID)
}
func (r *Repo) PickLeastLoadedRelay(ctx context.Context, region string) (string, error) {
	return PickLeastLoadedRelay(ctx, r.DB, region)
}
func (r *Repo) PickLeastLoadedRelayAnyRegion(ctx context.Context, preferredRegion string) (string, error) {
	return PickLeastLoadedRelayAnyRegion(ctx, r.DB, preferredRegion)
}
func (r *Repo) ExpireDeviceSessions(ctx context.Context) ([]string, error) {
	return ExpireDeviceSessions(ctx, r.DB)
}
func (r *Repo) ListSubnetsForDeviceNetworks(ctx context.Context, deviceID string) ([]string, error) {
	return ListSubnetsForDeviceNetworks(ctx, r.DB, deviceID)
}
func (r *Repo) ListDevicePairsForRelay(ctx context.Context, relayHostID string) ([]DevicePair, error) {
	return ListDevicePairsForRelay(ctx, r.DB, relayHostID)
}
func (r *Repo) ListDeviceVMPairsForRelay(ctx context.Context, relayHostID string) ([]DevicePair, error) {
	return ListDeviceVMPairsForRelay(ctx, r.DB, relayHostID)
}
