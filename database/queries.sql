-- name: insertSandbox
INSERT INTO sandboxes (
    id, host_id, status, mode, ip, mac,
    vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
    created_at, running_at, destroyed_at,
    spawn_ms, error_text, note,
    egress, ssh_pubkeys,
    bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
    api_sock, container_id, fc_pid, overlay_path,
    ingress_enabled, bandwidth_ingress_bytes, region,
    secret_token,
    envs, labels,
    name,
    cpu_vendor, cpu_family,
    auto_pause_after_seconds
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11, $12,
    $13, $14, $15,
    $16, $17, $18,
    $19, $20,
    $21, $22, $23,
    $24, $25, $26, $27,
    $28, $29, $30,
    $31,
    $32::jsonb, $33::jsonb,
    $34,
    $35, $36,
    $37
)
ON CONFLICT (id) DO UPDATE SET
    host_id = EXCLUDED.host_id,
    status = EXCLUDED.status,
    mode = EXCLUDED.mode,
    ip = EXCLUDED.ip,
    mac = EXCLUDED.mac,
    vcpu = EXCLUDED.vcpu,
    mem_mib = EXCLUDED.mem_mib,
    disk_mib = EXCLUDED.disk_mib,
    shape = EXCLUDED.shape,
    rootfs = EXCLUDED.rootfs,
    created_by = EXCLUDED.created_by,
    created_at = EXCLUDED.created_at,
    running_at = EXCLUDED.running_at,
    destroyed_at = EXCLUDED.destroyed_at,
    spawn_ms = EXCLUDED.spawn_ms,
    error_text = EXCLUDED.error_text,
    note = EXCLUDED.note,
    egress = EXCLUDED.egress,
    ssh_pubkeys = EXCLUDED.ssh_pubkeys,
    bandwidth_quota_bytes = EXCLUDED.bandwidth_quota_bytes,
    bandwidth_used_bytes = EXCLUDED.bandwidth_used_bytes,
    bandwidth_capped = EXCLUDED.bandwidth_capped,
    api_sock = EXCLUDED.api_sock,
    container_id = EXCLUDED.container_id,
    fc_pid = EXCLUDED.fc_pid,
    overlay_path = EXCLUDED.overlay_path,
    -- secret_token is set once at INSERT time; preserve any non-empty
    -- existing value if a re-insert (creating→running upsert) carries
    -- empty (e.g. host paths that haven't been re-plumbed). Lets us
    -- ship the change incrementally without losing a freshly-minted
    -- token.
    secret_token = COALESCE(NULLIF(EXCLUDED.secret_token, ''), sandboxes.secret_token),
    -- name is stamped once at INSERT (by control); a host-side
    -- creating→running re-insert may carry empty, so preserve the
    -- existing value rather than clobbering it to NULL.
    name = COALESCE(NULLIF(EXCLUDED.name, ''), sandboxes.name),
    -- cpu_vendor / cpu_family are stamped by the host on the
    -- creating→running upsert. Control's earlier INSERT carries NULL;
    -- preserve any existing host-stamped value if a later re-insert
    -- happens to carry NULL (defensive).
    cpu_vendor = COALESCE(EXCLUDED.cpu_vendor, sandboxes.cpu_vendor),
    cpu_family = COALESCE(EXCLUDED.cpu_family, sandboxes.cpu_family);
    -- region / ingress_enabled / bandwidth_ingress_bytes / envs / labels /
    -- auto_pause_after_seconds are NOT
    -- in the ON CONFLICT update list: control stamps region+ingress_enabled
    -- +envs on INSERT and the meter loop owns bandwidth_ingress_bytes via
    -- updateBandwidthIngress. The host's upsert (when it transitions
    -- creating→running) would otherwise clobber control's values back
    -- to empty/false / {}. Envs are control-stamped server-side env vars
    -- the host injects into every /exec; preserving them across the
    -- creating→running transition is required for them to persist.

-- name: completeSandboxCreate
-- Host-reported completion is deliberately narrow. Control owns tenant and
-- policy fields (created_by, ssh_pubkeys, egress, quotas, envs, name); a host
-- may only publish runtime facts for the creating row assigned to itself.
UPDATE sandboxes
   SET status = 'running',
       mode = $3,
       ip = $4,
       mac = $5,
       running_at = $6,
       spawn_ms = $7,
       error_text = $8,
       note = $9,
       api_sock = $10,
       container_id = $11,
       fc_pid = $12,
       overlay_path = $13,
       secret_token = COALESCE(NULLIF($14, ''), secret_token),
       cpu_vendor = COALESCE($15, cpu_vendor),
       cpu_family = COALESCE($16, cpu_family)
 WHERE id = $1
   AND host_id = $2
   AND status = 'creating';

-- name: markSandboxDestroyed
-- Marks the sandbox destroyed AND drops its network memberships AND
-- flips every sandbox_disks row's mount_status to 'detached'. The
-- destroyed row is also excluded from idx_sandboxes_user_name's partial
-- predicate, so its name immediately frees up for reuse by a fresh
-- sandbox owned by the same user.
--
-- sandbox_disks rows are deliberately NOT deleted here: doing so caused
-- row-lock contention with the 30s disk-status poll's UPDATE, blowing
-- up destroy latency from ~50ms to ~30s. countDiskAttachments uses a
-- status filter to ignore destroyed sandboxes — the rows linger but
-- are user-invisible. We do however flip mount_status to 'detached' so
-- GET /v1/sandboxes/:id/disks doesn't keep advertising 'mounted' for a
-- VM that's gone.
WITH _victim AS (
    UPDATE sandboxes
       SET status = 'destroyed',
           destroyed_at = $2,
           note = COALESCE(NULLIF($3, ''), note)
     WHERE id = $1
    RETURNING id
),
_net AS (
    DELETE FROM sandbox_networks
     WHERE sandbox_id IN (SELECT id FROM _victim)
),
_disks AS (
    UPDATE sandbox_disks
       SET mount_status = 'detached',
           mount_error = NULL
     WHERE sandbox_id IN (SELECT id FROM _victim)
       AND mount_status <> 'detached'
),
_token AS (
    DELETE FROM sandbox_access_tokens
     WHERE sandbox_id IN (SELECT id FROM _victim)
)
SELECT id FROM _victim;

-- name: markSandboxDestroyingFromTerminalCAS
-- CAS-guarded first half of deleting a paused/error sandbox. Claiming the
-- row as destroying excludes a concurrent resume before any R2 object is
-- removed. The access token is revoked immediately; final relational cleanup
-- happens in markSandboxDestroyedFromDestroyingCAS after storage cleanup.
--
-- Without this guard a paused-destroy that races a resume can delete
-- the R2 bundle while a host is downloading it for restore (issue:
-- HandleDestroy paused fast-path raced HandleResume).
WITH _victim AS (
    UPDATE sandboxes
       SET status = 'destroying'
     WHERE id = $1
       AND status IN ('paused', 'error')
    RETURNING id, status
),
_token AS (
    DELETE FROM sandbox_access_tokens
     WHERE sandbox_id IN (SELECT id FROM _victim)
)
SELECT status FROM _victim;

-- name: markSandboxDestroyedFromDestroyingCAS
-- Final half of asynchronous paused deletion. The status CAS makes the
-- background worker and durable sweeper safe to race: only one can emit the
-- billing event and publish destroyed.
WITH _victim AS (
    UPDATE sandboxes
       SET status = 'destroyed',
           destroyed_at = $2,
           note = COALESCE(NULLIF($3, ''), note)
     WHERE id = $1
       AND status = 'destroying'
    RETURNING id, status
),
_net AS (
    DELETE FROM sandbox_networks
     WHERE sandbox_id IN (SELECT id FROM _victim)
),
_disks AS (
    UPDATE sandbox_disks
       SET mount_status = 'detached',
           mount_error = NULL
     WHERE sandbox_id IN (SELECT id FROM _victim)
       AND mount_status <> 'detached'
),
_token AS (
    DELETE FROM sandbox_access_tokens
     WHERE sandbox_id IN (SELECT id FROM _victim)
)
SELECT status FROM _victim;

-- name: markSandboxFailed
UPDATE sandboxes
   SET status = 'failed',
       error_text = $2,
       destroyed_at = $3
 WHERE id = $1;

-- name: markSandboxFailedFromCreatingCAS
-- Host-side reconcile uses this to instantly fail any 'creating' row
-- pinned to itself at serve startup. Without the CAS we'd risk:
--   - flipping a row that legitimately moved to 'running' between our
--     reconcile list and our Mark call (rare but possible on a serve
--     restart that races a slow Create handler)
--   - flipping a row that already belongs to a different host (cross-
--     host damage if a future bug clears host_id mid-flight)
-- Returns the resulting status when the CAS hits, no row when it
-- doesn't — caller MUST check and refuse side-effects on the empty
-- result, same pattern as markSandboxDestroyingFromTerminalCAS.
UPDATE sandboxes
   SET status       = 'failed',
       error_text   = $3,
       destroyed_at = $4
 WHERE id           = $1
   AND host_id      = $2
   AND status       = 'creating'
RETURNING status;

-- name: getSandbox
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE id = $1;

-- name: getSandboxForBilling
SELECT id, created_by, status, name, shape, vcpu, mem_mib, disk_mib,
       bandwidth_quota_bytes, bandwidth_used_bytes, COALESCE(region, ''),
       created_at, running_at, paused_at, destroyed_at, forked_from
  FROM sandboxes
 WHERE id = $1;

-- name: getSandboxExecRoute
-- Exec's authorization and routing gate deliberately avoids decoding the
-- complete sandbox row (envs, snapshot manifest, arrays, and runtime fields).
SELECT id, COALESCE(host_id, ''), status, created_by,
       auto_pause_after_seconds, bandwidth_used_bytes, bandwidth_ingress_bytes,
       ingress_enabled
  FROM sandboxes
 WHERE id = $1;

-- name: getSandboxByIp
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE ip = $1
 ORDER BY created_at DESC
 LIMIT 1;

-- name: getSandboxByIPForUser
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE ip = $1
   AND created_by = $2
 ORDER BY created_at DESC
 LIMIT 1;

-- name: listSandboxesPinnedToHost
-- Used by the sweep's drain pass to find every non-terminal sandbox still
-- "owned" by a draining host. Terminal rows are deliberately excluded before
-- LIMIT so a large history of destroyed rows cannot hide live work. Includes:
--   1. Live or transitional rows with host_id = $1.
--   2. Paused sandboxes whose host_id was wiped on pause but whose
--      cached_host_id still points to this host. These need
--      ResumeKickoff to migrate them off; without this branch the
--      sweep loses sight of them after MarkPaused wipes host_id and
--      drain finishes with VMs still pinned to the cordoned host.
-- Selects the same column list as listSandboxes for parity with the
-- scanSandbox helper.
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE (host_id = $1 AND status IN
          ('creating', 'running', 'pausing', 'resuming', 'destroying'))
    OR (status = 'paused' AND cached_host_id = $1)
 LIMIT $2;

-- name: listSandboxes
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE ($1 = '' OR host_id = $1)
   AND ($2 = '' OR created_by = $2)
   AND ($3 = '' OR status = $3)
   AND ($4::jsonb = '{}'::jsonb OR labels @> $4::jsonb)
 ORDER BY created_at DESC
 LIMIT $5 OFFSET $6;

-- name: countSandboxesForList
-- Total rows matching the same filters listSandboxes uses, ignoring
-- LIMIT/OFFSET. Drives the pagination.total field on GET /v1/sandboxes.
SELECT COUNT(*)::int FROM sandboxes
 WHERE ($1 = '' OR host_id = $1)
   AND ($2 = '' OR created_by = $2)
   AND ($3 = '' OR status = $3)
   AND ($4::jsonb = '{}'::jsonb OR labels @> $4::jsonb);

-- name: listRunningSandboxIds
SELECT id FROM sandboxes WHERE host_id = $1 AND status = 'running';

-- name: listLiveSandboxIdsByHost
-- Returns ids of every row on `host_id` whose status indicates the
-- sandbox is/was-just-now legitimately resident in mgr.Sandboxes.
-- Used by the periodic reconcile-tick's reverse direction to avoid
-- killing VMs whose row is in a transient pause/resume state — pause
-- briefly flips status to 'pausing' before the goroutine's MarkPaused
-- + tearDownAfterPause fully retires the sandbox; without this filter
-- a 30s reconcile tick that lands in that window kills the live VM
-- mid-snapshot.
SELECT id FROM sandboxes
 WHERE host_id = $1
   AND status IN ('creating', 'running', 'pausing', 'resuming');

-- name: listAgedRunning
-- Running sandboxes older than the given cutoff. Dry-run companion to
-- markAgedRunningDestroyed — returns the set the evictor *would*
-- destroy without mutating.
--
-- Pause-aware: TTL ticks against last-run time, not first-create time.
-- running_at is refreshed on every resume (see markResumed → running_at = now()),
-- so paused-then-resumed sandboxes get a fresh budget. COALESCE handles
-- the unlikely 'running' row with NULL running_at — falls back to created_at.
--
-- Paused sandboxes are never swept by this query (status='running' filter).
-- This matches the E2B/Daytona policy: pause = parked indefinitely, the
-- user pays for the snapshot storage while parked. No absolute ceiling
-- on lifetime — a sandbox kept productively in the running→pause→resume
-- loop can live forever.
--
-- Pool sandboxes (created_by='pool') are excluded — the predictive
-- pre-warm pool manages its own lifecycle via a shrink loop with its
-- own max_age (typically 6h), so the TTL evictor must not touch them.
SELECT id, host_id, created_at
  FROM sandboxes
 WHERE status = 'running'
   AND region = $2
   AND COALESCE(running_at, created_at) < $1
   AND created_by != 'pool'
 ORDER BY created_at ASC;

-- name: markAgedRunningDestroyed
-- Flip every row that's still 'running' and older than $1 to 'destroyed',
-- stamping destroyed_at = $2 and note = $3. Returns the flipped rows.
-- Used by the TTL-evictor CronJob. Also detaches any sandbox_disks rows
-- attached to those sandboxes (mount_status='detached') so the user-
-- visible GET /v1/sandboxes/:id/disks doesn't lie about a VM that's gone.
--
-- Pause-aware: see listAgedRunning above for the running_at semantics.
-- Same WHERE clause kept in sync.
WITH _victims AS (
    UPDATE sandboxes
       SET status = 'destroyed',
           destroyed_at = $2,
           note = $3
     WHERE status = 'running'
       AND region = $4
       AND COALESCE(running_at, created_at) < $1
       -- Pool sandboxes are managed by the pre-warm pool's own shrink
       -- loop (its own max_age); the TTL evictor must not touch them.
       AND created_by != 'pool'
    RETURNING id, host_id, created_at
),
_disks AS (
    UPDATE sandbox_disks
       SET mount_status = 'detached',
           mount_error = NULL
     WHERE sandbox_id IN (SELECT id FROM _victims)
       AND mount_status <> 'detached'
),
_tokens AS (
    DELETE FROM sandbox_access_tokens
     WHERE sandbox_id IN (SELECT id FROM _victims)
)
SELECT id, host_id, created_at FROM _victims;

-- name: claimPoolSandbox
-- Atomically hand off the oldest matching-spec pool sandbox to a real user.
-- Returns the row (with the new owner) on success, or no rows if the pool is
-- empty for this region/spec. FOR UPDATE SKIP LOCKED means two concurrent
-- claims never collide. The belt-and-suspenders `AND s.created_by = 'pool'`
-- on the UPDATE WHERE guards against a race where a claim CTE picks a row
-- that another tx just claimed in the microsecond between select and update.
--   $1 = new_owner_id (authenticated user)
--   $2 = region
--   $3 = shape
--   $4 = disk_mib
--   $5 = rootfs (COALESCE'd from '' to match rootfs IS NULL rows too)
WITH taken AS (
    SELECT id
      FROM sandboxes
     WHERE created_by = 'pool'
       AND status     = 'running'
       AND region     = $2
       AND shape      = $3
       AND disk_mib   = $4
       AND COALESCE(rootfs,'') = $5
     ORDER BY created_at ASC
     LIMIT 1
     FOR UPDATE SKIP LOCKED
)
UPDATE sandboxes s
   SET created_by = $1,
       created_at = now(),
       running_at = now()
  FROM taken
 WHERE s.id         = taken.id
   AND s.created_by = 'pool'
RETURNING s.id, COALESCE(s.host_id,''), s.status, s.mode, COALESCE(s.ip,''), COALESCE(s.mac,''),
          s.vcpu, s.mem_mib, s.disk_mib, s.shape, s.rootfs, s.created_by,
          s.created_at, s.running_at, s.destroyed_at,
          COALESCE(s.spawn_ms,0), COALESCE(s.error_text,''), COALESCE(s.note,''),
          s.egress, s.ssh_pubkeys,
          s.bandwidth_quota_bytes, s.bandwidth_used_bytes, s.bandwidth_capped,
          COALESCE(s.api_sock,''), COALESCE(s.container_id,''), COALESCE(s.fc_pid,0), COALESCE(s.overlay_path,''),
          s.ingress_enabled, s.bandwidth_ingress_bytes, COALESCE(s.region,''),
          COALESCE(s.secret_token,''),
          COALESCE(s.envs, '{}'::jsonb),
          COALESCE(s.labels, '{}'::jsonb),
          s.paused_at, COALESCE(s.snapshot_uri,''), s.snapshot_manifest,
          COALESCE(s.cached_host_id,''), s.cached_until, s.last_resumed_at,
          s.resume_failed_hosts,
          s.last_resume_error, s.last_resume_attempt_at,
          s.last_pause_error, s.last_pause_attempt_at,
          COALESCE(s.forked_from,''),
          s.bundle_uploaded_at,
          COALESCE(s.name,''),
          s.cpu_vendor, s.cpu_family,
          s.drain_pause_attempts,
          s.auto_pause_after_seconds, s.last_activity_at, s.last_metered_bytes;

-- name: claimPoolSandboxBatch
-- Batched claimPoolSandbox: claims up to K rows in one transaction,
-- assigning owners[i] to the i-th oldest row. Turns N per-claim WAL
-- fsyncs + FOR-UPDATE scans + connections into one each.
--   $1 = region, $2 = shape, $3 = disk_mib, $4 = rootfs (COALESCE'd),
--   $5 = owners (text[]) — one entry per pending claim, in request order.
-- Fewer rows than len($5) on a partial fill. Same RETURNING shape as
-- claimPoolSandbox so scanSandbox reads it unchanged.
WITH owners AS (
    SELECT owner, ordinality AS rn
      FROM unnest($5::text[]) WITH ORDINALITY AS o(owner, ordinality)
),
-- Lock the oldest K unclaimed rows. Kept separate from the row-number
-- step because Postgres forbids FOR UPDATE alongside a window function
-- in the same query level.
locked AS (
    SELECT id, created_at
      FROM sandboxes
     WHERE created_by = 'pool'
       AND status     = 'running'
       AND region     = $1
       AND shape      = $2
       AND disk_mib   = $3
       AND COALESCE(rootfs,'') = $4
     ORDER BY created_at ASC
     LIMIT (SELECT count(*) FROM owners)
     FOR UPDATE SKIP LOCKED
),
taken AS (
    SELECT id, row_number() OVER (ORDER BY created_at ASC) AS rn
      FROM locked
)
UPDATE sandboxes s
   SET created_by = owners.owner,
       created_at = now(),
       running_at = now()
  FROM taken JOIN owners USING (rn)
 WHERE s.id         = taken.id
   AND s.created_by = 'pool'
RETURNING s.id, COALESCE(s.host_id,''), s.status, s.mode, COALESCE(s.ip,''), COALESCE(s.mac,''),
          s.vcpu, s.mem_mib, s.disk_mib, s.shape, s.rootfs, s.created_by,
          s.created_at, s.running_at, s.destroyed_at,
          COALESCE(s.spawn_ms,0), COALESCE(s.error_text,''), COALESCE(s.note,''),
          s.egress, s.ssh_pubkeys,
          s.bandwidth_quota_bytes, s.bandwidth_used_bytes, s.bandwidth_capped,
          COALESCE(s.api_sock,''), COALESCE(s.container_id,''), COALESCE(s.fc_pid,0), COALESCE(s.overlay_path,''),
          s.ingress_enabled, s.bandwidth_ingress_bytes, COALESCE(s.region,''),
          COALESCE(s.secret_token,''),
          COALESCE(s.envs, '{}'::jsonb),
          COALESCE(s.labels, '{}'::jsonb),
          s.paused_at, COALESCE(s.snapshot_uri,''), s.snapshot_manifest,
          COALESCE(s.cached_host_id,''), s.cached_until, s.last_resumed_at,
          s.resume_failed_hosts,
          s.last_resume_error, s.last_resume_attempt_at,
          s.last_pause_error, s.last_pause_attempt_at,
          COALESCE(s.forked_from,''),
          s.bundle_uploaded_at,
          COALESCE(s.name,''),
          s.cpu_vendor, s.cpu_family,
          s.drain_pause_attempts,
          s.auto_pause_after_seconds, s.last_activity_at, s.last_metered_bytes;

-- name: countPoolDepth
-- Count of live pool rows for this region, matching-spec only. Drives the
-- grow-loop's per-tick depth check.
--   $1 = region, $2 = shape, $3 = disk_mib, $4 = rootfs
SELECT COUNT(*)::int
  FROM sandboxes
 WHERE created_by = 'pool'
   AND status     = 'running'
   AND region     = $1
   AND shape      = $2
   AND disk_mib   = $3
   AND COALESCE(rootfs,'') = $4;

-- name: selectAgedPoolSandboxes
-- Find pool VMs older than max_age. Shrink loop passes these to the destroy
-- pipeline. Uses SKIP LOCKED so a concurrent user-claim isn't torn down.
--   $1 = region, $2 = max_age_seconds, $3 = limit (bounded work per tick)
SELECT id
  FROM sandboxes
 WHERE created_by = 'pool'
   AND status     = 'running'
   AND region     = $1
   AND created_at < now() - make_interval(secs => $2)
 ORDER BY created_at ASC
 LIMIT $3
 FOR UPDATE SKIP LOCKED;

-- name: setSandboxHost
-- Stamp the placement target on the sandbox row.
UPDATE sandboxes SET host_id = $2 WHERE id = $1;

-- name: setSandboxSshPubkeys
UPDATE sandboxes SET ssh_pubkeys = $2 WHERE id = $1;

-- name: setSandboxEgress
UPDATE sandboxes SET egress = $2 WHERE id = $1;

-- name: setSandboxEgressIfPaused
-- A paused sandbox has no owning host on which to install iptables rules.
-- Persist the policy for resume, but only while it is still paused: this CAS
-- prevents a concurrent resume from loading the previous policy and then
-- running with rules different from the row.
UPDATE sandboxes
   SET egress = $2
 WHERE id = $1
   AND status = 'paused'
RETURNING id;

-- name: setSandboxDiskMib
UPDATE sandboxes SET disk_mib = $2 WHERE id = $1;

-- name: setSandboxRuntime
UPDATE sandboxes
   SET api_sock = $2,
       container_id = $3,
       overlay_path = $4,
       fc_pid = $5
 WHERE id = $1;

-- name: setSandboxEnvs
UPDATE sandboxes SET envs = $2::jsonb WHERE id = $1;

-- name: setSandboxBandwidthQuota
UPDATE sandboxes SET bandwidth_quota_bytes = $2 WHERE id = $1;

-- name: addSandboxBandwidthQuota
-- Increment-style recharge — used by the auto-top-up trigger so a
-- racing meter PATCH that grew used_bytes between read+write can't
-- silently undo the bump. $2 is bytes to ADD; negative values are
-- rejected at the model layer.
UPDATE sandboxes
   SET bandwidth_quota_bytes = bandwidth_quota_bytes + $2
 WHERE id = $1
RETURNING bandwidth_quota_bytes;

-- name: setSandboxBandwidthUsed
UPDATE sandboxes SET bandwidth_used_bytes = $2 WHERE id = $1;

-- name: setSandboxBandwidthCapped
UPDATE sandboxes SET bandwidth_capped = $2 WHERE id = $1;

-- name: upsertApiKey
-- $5 is_internal, $6 expires_at (NULL for internal rows; set for
-- external-validator cache rows so the GC sweep can drop them).
-- $7 auth_type, $8 key_hash — primary key. The same opaque token
-- sent under two different headers is two distinct rows.
INSERT INTO api_keys (user_id, name, created_at, revoked, is_internal, expires_at, auth_type, key_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (auth_type, key_hash) DO UPDATE SET
    user_id     = EXCLUDED.user_id,
    name        = EXCLUDED.name,
    created_at  = EXCLUDED.created_at,
    revoked     = EXCLUDED.revoked,
    is_internal = EXCLUDED.is_internal,
    expires_at  = EXCLUDED.expires_at;

-- name: revokeApiKey
UPDATE api_keys SET revoked = TRUE WHERE auth_type = $1 AND key_hash = $2;

-- name: lookupApiKeyByHash
-- Primary lookup. Keyed on (auth_type, key_hash) so the same opaque
-- token sent under two different headers caches separately (matches
-- upstream's per-header interpretation).
SELECT user_id, name, created_at, revoked, is_internal, expires_at, auth_type, key_hash
  FROM api_keys
 WHERE auth_type = $1 AND key_hash = $2;

-- name: deleteApiKeyByHash
-- Inline cleanup when upstream rejects a token (401/403/404 from
-- /v1/users/me). Removes the cached row so the next request will
-- re-validate against upstream from scratch.
DELETE FROM api_keys
 WHERE auth_type = $1 AND key_hash = $2;

-- name: listApiKeys
SELECT user_id, name, created_at, revoked, is_internal, expires_at, auth_type, key_hash
  FROM api_keys
 ORDER BY created_at DESC;

-- name: deleteExpiredExternalApiKeys
-- Periodic GC for stale external-cache entries. Internal rows are
-- skipped via the partial-index predicate.
DELETE FROM api_keys
 WHERE is_internal = FALSE
   AND expires_at IS NOT NULL
   AND expires_at < $1
RETURNING auth_type, key_hash;

-- name: createSandboxAccessToken
-- One live delegated credential per sandbox. A deleted credential leaves no
-- reusable row; the next create is a fresh INSERT with independent entropy.
-- FOR UPDATE serializes issuance against destroy: either issuance commits
-- first and destroy deletes it, or destroy wins and this inserts no row.
WITH _sandbox AS (
    SELECT id
      FROM sandboxes
     WHERE id = $1
       AND created_by = $4
       AND status NOT IN ('destroying', 'destroyed', 'failed')
     FOR UPDATE
)
INSERT INTO sandbox_access_tokens (
    sandbox_id, token_hash, token_hint, created_by, created_at
)
SELECT id, $2, $3, $4, $5 FROM _sandbox
ON CONFLICT (sandbox_id) DO NOTHING;

-- name: getSandboxAccessToken
SELECT sandbox_id, token_hash, token_hint, created_by, created_at, rotated_at
  FROM sandbox_access_tokens
 WHERE sandbox_id = $1;

-- name: lookupSandboxAccessTokenByHash
-- Terminal and destroying sandboxes fail closed even if an older binary missed
-- lifecycle cleanup. Normal destruction also hard-deletes this row atomically.
SELECT t.sandbox_id, t.token_hash, t.token_hint, t.created_by,
       t.created_at, t.rotated_at
  FROM sandbox_access_tokens t
  JOIN sandboxes s ON s.id = t.sandbox_id
 WHERE t.token_hash = $1
   AND s.status NOT IN ('destroying', 'destroyed', 'failed');

-- name: rotateSandboxAccessToken
UPDATE sandbox_access_tokens
   SET token_hash = $2,
       token_hint = $3,
       rotated_at = $4
 WHERE sandbox_id = $1
RETURNING sandbox_id, token_hash, token_hint, created_by, created_at, rotated_at;

-- name: deleteSandboxAccessToken
DELETE FROM sandbox_access_tokens WHERE sandbox_id = $1;

-- name: upsertHost
INSERT INTO hosts (
    id, addr, status, mem_capacity_mib, in_use_mib, vm_count,
    cpu_count, disk_total_mib, disk_used_mib, max_vms, rootfses,
    registered_at, last_seen, labels, public_key, region,
    cpu_vendor, cpu_family, wg_public_key,
    cpu_overcommit_x10, mem_overcommit_x10, disk_overcommit_x10, role,
    relay_devices_pubkey
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16,
    $17, $18, $19,
    $20, $21, $22,
    COALESCE(NULLIF($23, ''), 'compute'),
    $24
)
ON CONFLICT (id) DO UPDATE SET
    addr = EXCLUDED.addr,
    -- Preserve operator-set draining; otherwise accept register-time status.
    status = CASE WHEN hosts.status = 'draining' THEN 'draining' ELSE EXCLUDED.status END,
    mem_capacity_mib = EXCLUDED.mem_capacity_mib,
    in_use_mib = EXCLUDED.in_use_mib,
    vm_count = EXCLUDED.vm_count,
    cpu_count = EXCLUDED.cpu_count,
    disk_total_mib = EXCLUDED.disk_total_mib,
    disk_used_mib = EXCLUDED.disk_used_mib,
    max_vms = EXCLUDED.max_vms,
    rootfses = EXCLUDED.rootfses,
    registered_at = EXCLUDED.registered_at,
    last_seen = EXCLUDED.last_seen,
    labels = EXCLUDED.labels,
    -- public_key is set on every register; preserve any existing pubkey
    -- if the upsert carries NULL (defensive — register currently always
    -- includes a pubkey).
    public_key = COALESCE(EXCLUDED.public_key, hosts.public_key),
    -- region is stamped once; preserve existing on re-register that
    -- happens to carry NULL (defensive — register currently always
    -- includes a region).
    region = COALESCE(EXCLUDED.region, hosts.region),
    cpu_vendor = COALESCE(EXCLUDED.cpu_vendor, hosts.cpu_vendor),
    cpu_family = COALESCE(EXCLUDED.cpu_family, hosts.cpu_family),
    -- wg_public_key: empty bytea ('\x') is the migration default; treat
    -- it as "no key" and don't overwrite an existing real key.
    wg_public_key = CASE
        WHEN length(EXCLUDED.wg_public_key) = 32 THEN EXCLUDED.wg_public_key
        ELSE hosts.wg_public_key
    END,
    -- Overcommit factors: only overwrite when the register-time value
    -- is non-zero. 0 means "host didn't send one — keep the stored
    -- value if any". This lets an operator set factors via SQL update
    -- and have them survive subsequent re-registrations.
    cpu_overcommit_x10 = CASE
        WHEN EXCLUDED.cpu_overcommit_x10 > 0 THEN EXCLUDED.cpu_overcommit_x10
        ELSE hosts.cpu_overcommit_x10
    END,
    mem_overcommit_x10 = CASE
        WHEN EXCLUDED.mem_overcommit_x10 > 0 THEN EXCLUDED.mem_overcommit_x10
        ELSE hosts.mem_overcommit_x10
    END,
    disk_overcommit_x10 = CASE
        WHEN EXCLUDED.disk_overcommit_x10 > 0 THEN EXCLUDED.disk_overcommit_x10
        ELSE hosts.disk_overcommit_x10
    END,
    -- role is sticky once set; first-writer-wins. Empty register-time
    -- value preserves the existing role.
    role = COALESCE(NULLIF(EXCLUDED.role, ''), hosts.role),
    -- relay_devices_pubkey: overwrite when non-empty (relay always
    -- sends fresh pubkey at startup), preserve existing on empty.
    relay_devices_pubkey = CASE
        WHEN length(COALESCE(EXCLUDED.relay_devices_pubkey, '')) > 0 THEN EXCLUDED.relay_devices_pubkey
        ELSE hosts.relay_devices_pubkey
    END;

-- name: assignHostSubnet
-- Atomically allocate the next /22 from this region's slice of the
-- host_subnet_allocator and stamp it onto the host row. If subnet_cidr
-- is already set, return it as-is (idempotent). $3 = region.
--
-- Each region owns one /10 of the 10.0.0.0/8 space, indexed by
-- regions.slot_index (0..3):
--   slot 0 → 10.0.0.0/10    (10.0.0.0 .. 10.63.255.255)
--   slot 1 → 10.64.0.0/10
--   slot 2 → 10.128.0.0/10
--   slot 3 → 10.192.0.0/10
-- Within a region, idx 0..4095 enumerates the 4096 /22 slots in that
-- /10. The second-octet offset (slot_index * 64) makes all regions'
-- CIDRs globally unique — required for the pgEdge-replicated hosts
-- table and the cross-region WG mesh.
WITH alloc AS (
  UPDATE host_subnet_allocator
     SET next_index = next_index + 1
   WHERE region = $3
     AND EXISTS (SELECT 1 FROM hosts WHERE id = $1 AND subnet_cidr IS NULL)
  RETURNING next_index - 1 AS idx
), slot AS (
  SELECT slot_index AS region_slot
    FROM regions
   WHERE name = $3
), new_cidr AS (
  SELECT format('10.%s.%s.0/22',
                (slot.region_slot * 64) + (alloc.idx / 64),
                (alloc.idx % 64) * 4) AS cidr
    FROM alloc, slot
), updated AS (
  UPDATE hosts
     SET subnet_cidr = new_cidr.cidr,
         underlay_ip = $2
    FROM new_cidr
   WHERE hosts.id = $1
     AND hosts.subnet_cidr IS NULL
  RETURNING hosts.subnet_cidr
)
SELECT COALESCE(
  (SELECT subnet_cidr FROM updated),
  (SELECT subnet_cidr FROM hosts WHERE id = $1)
) AS subnet_cidr;

-- name: assignHostWGIP
-- Atomically allocate the next free /32 from 172.30.0.0/16 for this host's
-- region; stamp it on the host row. Idempotent — returns existing value if
-- already set. $1=host_id, $2=region.
--
-- Layout matches host_subnet_allocator (16,384 hosts per region):
--
--   region slot 0 → 172.30.0.0/18    (16,384 IPs)
--   region slot 1 → 172.30.64.0/18
--   region slot 2 → 172.30.128.0/18
--   region slot 3 → 172.30.192.0/18
--
-- Within a region, idx 0 is reserved; usable range is 1..16383. The global
-- offset for a host is (region.slot_index * 16384) + region_idx, mapped to
-- the third+fourth octets of 172.30.x.x. WG meshes can span regions, so
-- IPs MUST be globally unique — the per-region slot offset guarantees that.
WITH alloc AS (
  UPDATE host_wg_allocator
     SET next_index = next_index + 1
   WHERE region = $2
     AND EXISTS (SELECT 1 FROM hosts WHERE id = $1 AND wg_ip IS NULL)
  RETURNING next_index - 1 AS region_idx
), slot AS (
  SELECT slot_index AS region_slot
    FROM regions
   WHERE name = $2
), new_ip AS (
  SELECT format(
    '172.30.%s.%s',
    ((slot.region_slot * 16384) + alloc.region_idx) / 256,
    ((slot.region_slot * 16384) + alloc.region_idx) % 256
  )::inet AS ip
    FROM alloc, slot
   WHERE alloc.region_idx > 0 AND alloc.region_idx < 16384
), updated AS (
  UPDATE hosts
     SET wg_ip = new_ip.ip
    FROM new_ip
   WHERE hosts.id = $1
     AND hosts.wg_ip IS NULL
  RETURNING hosts.wg_ip
)
SELECT COALESCE(
  (SELECT host(wg_ip) FROM updated),
  (SELECT host(wg_ip) FROM hosts WHERE id = $1),
  ''
) AS wg_ip;

-- name: setHostWGPublicKey
UPDATE hosts SET wg_public_key = $2 WHERE id = $1;

-- name: heartbeatHost
-- Heartbeat updates liveness fields and resurrects from 'dead', but
-- NEVER overwrites operator-set 'draining' (cordon). The cordon
-- semantic is "this host is intentionally out of rotation"; heartbeats
-- shouldn't undo that just because the host is alive.
UPDATE hosts
   SET in_use_mib = $2,
       vm_count = $3,
       status = CASE WHEN status = 'draining' THEN 'draining' ELSE $4 END,
       disk_used_mib = $5,
       last_seen = $6
 WHERE id = $1;

-- name: listHosts
SELECT id, addr, status, mem_capacity_mib, in_use_mib, vm_count,
       cpu_count, disk_total_mib, disk_used_mib, max_vms, rootfses,
       registered_at, last_seen, labels, scheduling_disabled,
       public_key, subnet_cidr, underlay_ip, region,
       cpu_vendor, cpu_family, wg_public_key,
       COALESCE(host(wg_ip), '') AS wg_ip,
       cpu_overcommit_x10, mem_overcommit_x10, disk_overcommit_x10,
       COALESCE(role, 'compute') AS role,
       relay_devices_pubkey
  FROM hosts;

-- name: getHost
SELECT id, addr, status, mem_capacity_mib, in_use_mib, vm_count,
       cpu_count, disk_total_mib, disk_used_mib, max_vms, rootfses,
       registered_at, last_seen, labels, scheduling_disabled,
       public_key, subnet_cidr, underlay_ip, region,
       cpu_vendor, cpu_family, wg_public_key,
       COALESCE(host(wg_ip), '') AS wg_ip,
       cpu_overcommit_x10, mem_overcommit_x10, disk_overcommit_x10,
       COALESCE(role, 'compute') AS role,
       relay_devices_pubkey
  FROM hosts
 WHERE id = $1;

-- name: setHostStatus
-- System-driven lifecycle transitions: active <-> draining <-> dead.
-- Validity check is done in the handler.
UPDATE hosts SET status = $2 WHERE id = $1 RETURNING id;

-- name: setHostSchedulingDisabled
-- Operator-driven cordon bit. Independent of status — cordoning a healthy
-- host marks it ineligible for new schedules without changing its status,
-- and uncordoning later restores eligibility.
UPDATE hosts SET scheduling_disabled = $2 WHERE id = $1 RETURNING id;

-- name: setHostDrain
-- Atomic "begin drain" transition: set scheduling_disabled=true AND
-- status='draining' in one statement so the scheduler and the host
-- self-poll see a consistent view.
UPDATE hosts SET scheduling_disabled = TRUE, status = 'draining' WHERE id = $1 RETURNING id;

-- name: listRunningSandboxesOnHost
-- All creating/running sandboxes assigned to host_id. Used by drain to
-- find what needs destroying.
SELECT id FROM sandboxes
 WHERE host_id = $1
   AND status IN ('creating','running');

-- name: markStaleHosts
UPDATE hosts
   SET status = 'dead'
 WHERE last_seen < $1
   AND region = $2
   AND status <> 'dead'
RETURNING id;

-- name: sumUsageByHost
SELECT host_id, COALESCE(SUM(mem_mib), 0)::bigint AS used_mib, COUNT(*)::int AS vm_count
  FROM sandboxes
 WHERE status IN ('creating', 'running')
   AND host_id <> ''
 GROUP BY host_id;

-- name: listLiveSandboxes
-- One row per sandbox whose memory is currently allocated on its host,
-- with a committed host_id. Drives both the per-host capacity SUM (the
-- absolute view) and the per-id "seen" set used to drop in-flight
-- reservations from the scheduler's in-mem delta. The sandbox id IS the
-- reservation key — no opaque token.
--
-- Statuses included (everything that still pins memory on a host):
--   creating   — firecracker spawning, memory allocated
--   running    — VM live, memory allocated
--   pausing    — VM still alive while snapshot is taken (~5s window)
--   resuming   — host downloading + restoring; memory committed to dst
--   destroying — async delete flow: memory pinned until reconcile destroys
--
-- Excluded (memory released, no host pinning):
--   paused     — host tore the VM down after snapshot upload
--   destroyed/failed/error — terminal
SELECT id, host_id, shape, mem_mib, vcpu, disk_mib
  FROM sandboxes
 WHERE status IN ('creating','running','pausing','resuming','destroying')
   AND host_id <> '';

-- name: statusOfIDs
-- Bounded lookup the scheduler runs once per hydrate tick to learn the
-- current status of any sandbox ids it still holds in memory but didn't
-- see in `listLiveSandboxes`. Used to fast-drop deltas tied to
-- failed/destroyed rows without waiting for the 60s grace window.
SELECT id, status
  FROM sandboxes
 WHERE id = ANY($1::text[]);

-- name: failOrphanCreating
-- Promotes rows stuck in 'creating' for longer than the cutoff to 'failed'.
-- Catches the case where control crashed between Schedule and the host's
-- successful response, leaving a row no host will ever transition to running.
UPDATE sandboxes
   SET status      = 'failed',
       destroyed_at = now(),
       error_text  = 'creating timed out (control crash or stalled forward)'
 WHERE status      = 'creating'
   AND region      = $2
   AND created_at  < $1
RETURNING id;

-- name: listActiveHosts
SELECT id, addr, status, mem_capacity_mib, in_use_mib, vm_count,
       cpu_count, disk_total_mib, disk_used_mib, max_vms, rootfses,
       registered_at, last_seen, labels, scheduling_disabled,
       public_key, subnet_cidr, underlay_ip, region,
       cpu_vendor, cpu_family, wg_public_key,
       COALESCE(host(wg_ip), '') AS wg_ip,
       cpu_overcommit_x10, mem_overcommit_x10, disk_overcommit_x10,
       COALESCE(role, 'compute') AS role,
       relay_devices_pubkey
  FROM hosts
 WHERE status = 'active'
 ORDER BY id;

-- name: setSandboxIngressEnabled
UPDATE sandboxes SET ingress_enabled = $2 WHERE id = $1;

-- name: setAutoPause
UPDATE sandboxes SET auto_pause_after_seconds = $2 WHERE id = $1;

-- name: setSandboxLabels
UPDATE sandboxes SET labels = $2::jsonb WHERE id = $1;

-- name: touchActivity
-- Bump last_activity_at and snapshot current metered bytes for the idle-pause
-- sweeper. Called on exec, file PUT/GET, tunnel open, and resume.
UPDATE sandboxes
   SET last_activity_at   = now(),
       last_metered_bytes = $2
 WHERE id = $1
   AND status = 'running';

-- name: touchInteractiveActivity
-- Keep a live shell from being classified as idle. Read the counters from the
-- row itself: a long-lived shell must not repeatedly write the stale bandwidth
-- snapshot captured when the connection was opened.
UPDATE sandboxes
   SET last_activity_at   = now(),
       last_metered_bytes = bandwidth_used_bytes + bandwidth_ingress_bytes
 WHERE id = $1
   AND status = 'running';

-- name: listIdleSandboxes
-- Returns running sandboxes with auto-pause enabled whose activity window has
-- expired AND whose metered-bytes delta is below the idle threshold.
-- $1 = idle_threshold_bytes (e.g. 204800 for 200 KB)
-- $2 = region owned by this sweeper
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE status = 'running'
   AND region = $2
   AND auto_pause_after_seconds IS NOT NULL
   AND now() - last_activity_at > auto_pause_after_seconds * interval '1 second'
   AND (bandwidth_used_bytes + bandwidth_ingress_bytes - last_metered_bytes) < $1;

-- name: snapshotMeteredBytes
-- Snapshot current metered totals into last_metered_bytes for all running
-- auto-pause sandboxes in one region. The idle-pause sweeper calls this at the
-- end of each run so the next check measures delta over one sweep window, not
-- since the last user API call.
UPDATE sandboxes
   SET last_metered_bytes = bandwidth_used_bytes + bandwidth_ingress_bytes
 WHERE status = 'running'
   AND region = $1
   AND auto_pause_after_seconds IS NOT NULL;

-- name: markIdlePausing
-- CAS flip to 'pausing' for idle sandboxes. Returns the ids actually flipped
-- (status='running' guard prevents racing with user-initiated pause/destroy).
UPDATE sandboxes
   SET status    = 'pausing',
       last_pause_attempt_at = now()
 WHERE id = ANY($1)
   AND status = 'running'
RETURNING id;

-- name: getIngressRoute
-- One-shot lookup the ingress subcommand runs for every cache miss:
-- joins hosts so the proxy can dial the owning host directly. LEFT JOIN
-- so unscheduled rows still return (HostAddr=''); the handler maps that
-- to 502. Keep this projection narrow: ingress never receives sandbox
-- ownership, environment, SSH-key, or agent-secret fields.
SELECT s.id,
       COALESCE(h.addr, ''),
       s.status,
       s.ingress_enabled,
       COALESCE(s.region, ''),
       s.bandwidth_capped
  FROM sandboxes s
  LEFT JOIN hosts h ON s.host_id = h.id
 WHERE s.id = $1;

-- name: updateBandwidthIngress
UPDATE sandboxes SET bandwidth_ingress_bytes = $2 WHERE id = $1;

-- name: getRootfsCatalog
SELECT name, description, disabled, deprecated, successor, created_at, updated_at
  FROM rootfs_catalog
 WHERE name = $1;

-- name: listRootfsCatalog
SELECT name, description, disabled, deprecated, successor, created_at, updated_at
  FROM rootfs_catalog
 ORDER BY name;

-- ── Pause / Resume / Fork ────────────────────────────────────────────
--
-- Every transition is a CAS UPDATE that includes the expected status
-- in the WHERE clause and uses RETURNING status so the Go layer can
-- distinguish "applied" from "row had moved." Empty result = miss.

-- name: markPausing
UPDATE sandboxes
   SET status = 'pausing',
       last_pause_attempt_at = $2
 WHERE id = $1 AND status = 'running'
 RETURNING status;

-- name: markStuckPauseFailed
-- CAS-guarded flip: pausing → failed with an explanatory message.
-- This fires only when the host's pause goroutine truly went away
-- (5-min stale-state watchdog), at which point the VM's fate is
-- unknown from control's perspective. `failed` matches the host's
-- own permanent-failure path (markPauseFailed in service/pauseresume).
UPDATE sandboxes
   SET status           = 'failed',
       last_pause_error = $2,
       error_text       = $2
 WHERE id = $1 AND status = 'pausing'
 RETURNING status;

-- name: markPaused
-- Sets status='paused' AND stamps bundle_uploaded_at in a single
-- statement. Previously these were two separate UPDATEs which left
-- a small window where the row was visible as paused but the bundle
-- timestamp was still NULL — a client that polled status and
-- immediately forked could land in that window and 409 ("bundle still
-- uploading"). Atomically setting both fields eliminates the race.
--
UPDATE sandboxes
   SET status             = 'paused',
       host_id            = NULL,
       ip                 = NULL,
       mac                = NULL,
       api_sock           = NULL,
       container_id       = NULL,
       fc_pid             = NULL,
       overlay_path       = NULL,
       paused_at          = $2,
       snapshot_uri       = $3,
       snapshot_manifest  = $4::jsonb,
       cached_host_id     = $5,
       cached_until       = $6,
       last_pause_error   = NULL,
       -- The row becomes paused only after the bundle is durable.
       bundle_uploaded_at = $2
 WHERE id = $1 AND status = 'pausing'
 RETURNING status;

-- name: markPauseRolledBack
UPDATE sandboxes
   SET status                = 'running',
       last_pause_error      = $2,
       last_pause_attempt_at = $3
 WHERE id = $1 AND status = 'pausing'
 RETURNING status;

-- name: markResumingFromPaused
UPDATE sandboxes
   SET status                  = 'resuming',
       last_resume_attempt_at  = $2
 WHERE id = $1 AND status = 'paused'
 RETURNING status;

-- name: markResumingFromError
UPDATE sandboxes
   SET status                  = 'resuming',
       last_resume_attempt_at  = $2,
       resume_failed_hosts     = NULL,
       last_resume_error       = NULL
 WHERE id = $1 AND status = 'error'
 RETURNING status;

-- name: markResumed
-- $9 is the resuming host's id; written to host_id so multi-host code
-- paths see the new owner.
UPDATE sandboxes
   SET status                  = 'running',
       ip                      = $2,
       mac                     = $3,
       api_sock                = $4,
       container_id            = $5,
       overlay_path            = $6,
       fc_pid                  = $7,
       running_at              = $8,
       last_resumed_at         = $8,
       host_id                 = $9,
       cached_host_id          = NULL,
       cached_until            = NULL,
       snapshot_manifest       = NULL,
       snapshot_uri            = NULL,
       resume_failed_hosts     = NULL,
       last_resume_error       = NULL,
       last_resume_attempt_at  = NULL,
       last_activity_at        = now()
 WHERE id = $1 AND status = 'resuming'
 RETURNING status;

-- name: markResumeFailed
UPDATE sandboxes
   SET status                  = 'paused',
       resume_failed_hosts     = COALESCE(resume_failed_hosts, ARRAY[]::TEXT[]) || $2,
       last_resume_error       = $3,
       last_resume_attempt_at  = $4,
       host_id                 = NULL,
       ip                      = NULL,
       mac                     = NULL,
       api_sock                = NULL,
       container_id            = NULL,
       fc_pid                  = NULL,
       overlay_path            = NULL
 WHERE id = $1 AND status = 'resuming'
 RETURNING status;

-- name: markResumeExhausted
-- Rollback for a resume kick that never reached terminal running state:
-- bundle not yet in R2, scheduler had no host, host unreachable during the
-- POST /resume forward, sweep detected a >15min stuck 'resuming' row.
-- The snapshot bundle is intact (the pause goroutine committed it before
-- resume was ever called), so flip back to 'paused' so the user can retry
-- on their own — NOT 'error', which reads as terminal and scares users.
-- last_resume_error is kept as a breadcrumb for ops.
UPDATE sandboxes
   SET status            = 'paused',
       last_resume_error = $2,
       host_id           = NULL
 WHERE id = $1 AND status IN ('resuming','paused')
 RETURNING status;

-- name: markForkPaused
UPDATE sandboxes
   SET status             = 'paused',
       paused_at          = $2,
       snapshot_uri       = $3,
       snapshot_manifest  = $4::jsonb,
       -- The R2 CopyObject that preceded this UPDATE is what put the
       -- bundle in R2. Stamp bundle_uploaded_at so resume's "bundle
       -- not yet in R2" guard doesn't 503 the fresh fork.
       bundle_uploaded_at = $2
 WHERE id = $1 AND status = 'forking'
 RETURNING status;

-- name: markForkFailed
-- CAS-guarded flip: forking → failed with an explanatory message.
-- Fires from the fork orchestrator's error paths (R2 copy failed,
-- source bundle never landed, MarkForkPaused races) and from the
-- sweep CronJob's stuck-forking watchdog. Matches the host's own
-- permanent-failure pattern (markStuckPauseFailed).
UPDATE sandboxes
   SET status     = 'failed',
       error_text = $2
 WHERE id = $1 AND status = 'forking'
 RETURNING status;

-- name: markDestroying
WITH _victim AS (
    UPDATE sandboxes
       SET status = 'destroying'
     WHERE id = $1
       AND status NOT IN ('destroying','destroyed','failed')
    RETURNING id, status
),
_token AS (
    DELETE FROM sandbox_access_tokens
     WHERE sandbox_id IN (SELECT id FROM _victim)
)
SELECT status FROM _victim;

-- name: markPoolDestroying
WITH _victim AS (
    UPDATE sandboxes
       SET status = 'destroying'
     WHERE id = $1
       AND created_by = $2
       AND status = 'running'
    RETURNING id, status
),
_token AS (
    DELETE FROM sandbox_access_tokens
     WHERE sandbox_id IN (SELECT id FROM _victim)
)
SELECT status FROM _victim;

-- name: clearLocalCache
UPDATE sandboxes
   SET cached_host_id = NULL,
       cached_until   = NULL
 WHERE id = $1 AND cached_host_id = $2;

-- name: listPausingByHost
SELECT id
  FROM sandboxes
 WHERE status = 'pausing' AND host_id = $1;

-- name: listPausedByCachedHost
SELECT id
  FROM sandboxes
 WHERE status = 'paused' AND ($1 = '' OR cached_host_id = $1);

-- name: incDrainPauseAttempts
-- Bumps drain_pause_attempts and returns the new count. Sweep calls
-- this after a failed PauseOnHost during drain so a host that keeps
-- 500ing can't permanently pin a sandbox in 'running'.
UPDATE sandboxes
   SET drain_pause_attempts = drain_pause_attempts + 1
 WHERE id = $1
RETURNING drain_pause_attempts;

-- name: resetDrainPauseAttempts
-- Clears the counter once pause is successfully triggered (status
-- transitions to 'pausing') or when the sandbox leaves the host's
-- live set. Idempotent.
UPDATE sandboxes
   SET drain_pause_attempts = 0
 WHERE id = $1 AND drain_pause_attempts <> 0;

-- name: listStuckOrphanDestroying
-- Rows stuck in destroying with no owning host stamped — no
-- host's reconciler will ever claim them (host_id='' won't match any
-- WHERE host_id=$1 filter). Surfaces sandbox_id + snapshot_uri so the
-- watchdog can clean R2 before flipping to destroyed.
SELECT id, COALESCE(snapshot_uri, '')
  FROM sandboxes
 WHERE status = 'destroying'
   AND region = $2
   AND COALESCE(host_id,'') = ''
   AND COALESCE(running_at, created_at) < $1;

-- name: listStuckPausing
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE status = 'pausing'
   AND region = $2
   AND (last_pause_attempt_at IS NULL OR last_pause_attempt_at < $1);

-- name: listStuckResuming
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE status = 'resuming'
   AND region = $2
   AND (last_resume_attempt_at IS NULL OR last_resume_attempt_at < $1);

-- name: listStuckForking
-- Rows pinned in 'forking' past the orchestrator's expected duration.
-- A fork's background goroutine (handlers.runForkBackground) walks
-- R2 copy → MarkForkPaused → optional resume. Any silent failure
-- (process restart between MarkForking and the next CAS write, R2
-- outage longer than the in-process retry budget, panic in the
-- goroutine) leaves the row at 'forking' forever — there is no
-- reconciler that owns the row (host = '' for forks pre-MarkForkPaused).
-- The sweep watchdog flips them to 'failed' once they exceed the
-- transition cutoff so the user can see the failure + retry.
SELECT id, COALESCE(host_id,''), status, mode, COALESCE(ip,''), COALESCE(mac,''),
       vcpu, mem_mib, disk_mib, shape, rootfs, created_by,
       created_at, running_at, destroyed_at,
       COALESCE(spawn_ms,0), COALESCE(error_text,''), COALESCE(note,''),
       egress, ssh_pubkeys,
       bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
       COALESCE(api_sock,''), COALESCE(container_id,''), COALESCE(fc_pid,0), COALESCE(overlay_path,''),
       ingress_enabled, bandwidth_ingress_bytes, COALESCE(region, ''),
       COALESCE(secret_token, ''),
       COALESCE(envs, '{}'::jsonb),
       COALESCE(labels, '{}'::jsonb),
       paused_at, COALESCE(snapshot_uri, ''), snapshot_manifest,
       COALESCE(cached_host_id, ''), cached_until, last_resumed_at,
       resume_failed_hosts,
       last_resume_error, last_resume_attempt_at,
       last_pause_error, last_pause_attempt_at,
       COALESCE(forked_from, ''),
       bundle_uploaded_at,
       COALESCE(name, ''),
       cpu_vendor, cpu_family,
       drain_pause_attempts,
       auto_pause_after_seconds, last_activity_at, last_metered_bytes
  FROM sandboxes
 WHERE status = 'forking'
   AND region = $2
   AND created_at < $1;

-- name: localCacheCandidates
SELECT id, cached_until
  FROM sandboxes
 WHERE cached_host_id = $1
   AND cached_until IS NOT NULL
 ORDER BY COALESCE(last_resumed_at, paused_at) ASC;

-- name: insertForkRow
-- Insert a brand-new sandbox row in 'forking' state as a clone of the
-- source. Lineage fields (shape/vcpu/mem/disk/rootfs/created_by/region/
-- secret_token AND the CPU lineage cpu_vendor/cpu_family/cached_host_id)
-- are inherited directly from the source row via SELECT so they can never
-- silently drift out of sync — the bug that let forks resume cross-vendor.
-- Only the fields a fork legitimately changes are passed as parameters:
--   $1 = source id (also becomes forked_from)
--   $2 = new id
--   $3 = egress            (caller applies any request override)
--   $4 = ssh_pubkeys       (caller applies any request override)
--   $5 = created_at
--   $6 = bandwidth_quota_bytes (control-resolved cluster default)
--   $7 = ingress_enabled   (caller applies any request override)
--   $8 = envs              (caller applies any request override)
--   $9 = name              (fresh, to avoid the per-user unique-name index)
-- Runtime counters reset to zero/false; the SELECT's WHERE doubles as the
-- paused-source guard (0 rows inserted if the source isn't paused).
INSERT INTO sandboxes (
    id, status, mode, vcpu, mem_mib, disk_mib, shape, rootfs,
    egress, ssh_pubkeys, created_by, created_at, region,
    bandwidth_quota_bytes, bandwidth_used_bytes, bandwidth_capped,
    bandwidth_ingress_bytes, ingress_enabled,
    secret_token, envs, labels, forked_from, name,
    cached_host_id, cpu_vendor, cpu_family
)
SELECT
    $2, 'forking', 'snapshot', vcpu, mem_mib, disk_mib, shape, rootfs,
    $3, $4, created_by, $5, region,
    $6, 0, false,
    0, $7,
    secret_token, $8::jsonb, labels, $1, $9,
    cached_host_id, cpu_vendor, cpu_family
FROM sandboxes
WHERE id = $1 AND status = 'paused';

-- ─── Templates feature ────────────────────────────────────────────────
-- See DESIGN/templates.md.

-- name: insertTemplate
-- Submit a new build. Status starts at 'pending'; the builder claims
-- the row via FOR UPDATE SKIP LOCKED in claimNextBuild.
INSERT INTO templates (id, user_id, name, base, status, dockerfile, created_at)
VALUES ($1, $2, $3, $4, 'pending', $5, now());

-- name: getTemplate
SELECT id, user_id, name, base, status, dockerfile,
       size_bytes, ext4_size_bytes, sha256,
       created_at, built_at, deleted_at, attempts
  FROM templates
 WHERE id = $1;

-- name: getLatestReadyByName
-- Resolve "user_id + friendly name" → latest ready tpl_id. Uses the
-- partial index idx_templates_name_lookup.
SELECT id
  FROM templates
 WHERE user_id = $1
   AND name = $2
   AND status = 'ready'
   AND deleted_at IS NULL
 ORDER BY created_at DESC
 LIMIT 1;

-- name: listUserTemplates
SELECT id, user_id, name, base, status, dockerfile,
       size_bytes, ext4_size_bytes, sha256,
       created_at, built_at, deleted_at, attempts
  FROM templates
 WHERE user_id = $1
   AND deleted_at IS NULL
 ORDER BY created_at DESC
 LIMIT $2 OFFSET $3;

-- name: countUserTemplates
-- Drives pagination.total on GET /v1/templates.
SELECT COUNT(*)::int FROM templates
 WHERE user_id = $1 AND deleted_at IS NULL;

-- name: countInflightForUser
-- For per-user concurrency cap: how many of this user's templates are
-- currently 'pending' or 'building'?
SELECT COUNT(*)::int
  FROM templates
 WHERE user_id = $1
   AND status IN ('pending', 'building');

-- name: templateNameTaken
-- Pre-insert collision check: is there a non-deleted template owned by
-- this user with this name?
SELECT EXISTS (
  SELECT 1 FROM templates
   WHERE user_id = $1
     AND name = $2
     AND deleted_at IS NULL
);

-- name: softDeleteTemplate
UPDATE templates
   SET deleted_at = now()
 WHERE id = $1
   AND user_id = $2
   AND deleted_at IS NULL
RETURNING id;

-- name: claimNextBuild
-- Builder's atomic claim. Picks oldest pending row whose user_id is NOT
-- in the blocked-users array (per-user cap enforcement). Flips status
-- to 'building', stamps built_at, and increments attempts. The
-- attempts counter is read by the janitor — see reapStuckBuilds —
-- so persistently-stuck rows eventually go 'failed' instead of
-- looping forever as 'pending'. FOR UPDATE SKIP LOCKED makes multiple
-- builders safely race.
UPDATE templates
   SET status = 'building',
       built_at = now(),
       attempts = attempts + 1
 WHERE id = (
       SELECT id FROM templates
        WHERE status = 'pending'
          AND user_id != ALL($1::text[])
        ORDER BY created_at
        FOR UPDATE SKIP LOCKED
        LIMIT 1
   )
RETURNING id, user_id, name, base, dockerfile, created_at, attempts;

-- name: completeTemplateBuild
-- Builder's terminal write. Idempotent on (id, status='building').
-- Caller passes the new status ('ready' or 'failed') and the artifact
-- metadata.
UPDATE templates
   SET status = $2,
       sha256 = $3,
       size_bytes = $4,
       ext4_size_bytes = $5
 WHERE id = $1
   AND status = 'building'
RETURNING id;

-- name: reapStuckBuilds
-- Janitor sweep: any row stuck in `building` past the cutoff is
-- marked `failed`. No retry path — a stuck row means either the
-- dispatcher crashed mid-build or the build sandbox failed to PATCH
-- terminal state, and re-running on the same Dockerfile rarely
-- helps. Users retry by submitting again. Diagnostic build output
-- lives in ClickHouse, fetchable via `createos-cli templates logs`.
UPDATE templates
   SET status = 'failed',
       built_at = NULL
 WHERE status = 'building'
   AND built_at IS NOT NULL
   AND built_at < $1
RETURNING id;

-- name: setTemplateFailed
-- Used by control's POST /v1/templates path when validation fails
-- after insert, and by builder's "couldn't reach runner" branch.
-- Marks the row failed without going through the building→failed CAS.
UPDATE templates
   SET status = 'failed'
 WHERE id = $1
   AND status IN ('pending', 'building')
RETURNING id;

-- name: upsertHostCachedTemplate
-- Host-side write after ensureTemplate fetches + verifies the ext4.
-- Repeated for cache-hit refresh too; ON CONFLICT keeps fetched_at
-- on the original row but bumps the LRU timestamps.
INSERT INTO host_cached_templates (host_id, tpl_id, fetched_at, last_used_at, cached_until)
VALUES ($1, $2, now(), now(), $3)
ON CONFLICT (host_id, tpl_id)
DO UPDATE SET last_used_at = EXCLUDED.last_used_at,
              cached_until = EXCLUDED.cached_until;

-- name: deleteHostCachedTemplate
DELETE FROM host_cached_templates
 WHERE host_id = $1 AND tpl_id = $2;

-- name: listHostCachedTemplates
-- Host startup reconcile + reaper iteration.
SELECT host_id, tpl_id, fetched_at, last_used_at, cached_until
  FROM host_cached_templates
 WHERE host_id = $1
 ORDER BY last_used_at ASC;

-- name: listHostsForTemplate
-- Scheduler hydration: for each host, which templates does it have cached.
-- Returned as one row per (host, tpl) pair; caller pivots into a map.
SELECT host_id, tpl_id
  FROM host_cached_templates;

-- name: hostCachedTemplateHasActiveSandbox
-- Reaper safety check: never evict a template if any sandbox on this
-- host references it (running, paused-here, creating, etc.).
SELECT COUNT(*)::int
  FROM sandboxes
 WHERE host_id = $1
   AND rootfs = $2
   AND status NOT IN ('destroyed', 'failed');

-- ─── Build clusters ──────────────────────────────────────────────────
-- ── overlay networks ──────────────────────────────────────────────────────

-- name: createNetwork
-- Atomically allocates the next VNI from this region's slice and
-- inserts the network row. $4 = region. Each region owns a 2^22-VNI
-- window (slot_index << 22), so concurrent creates in different
-- regions can never produce the same VNI.
--
-- Slot upper-bound is enforced HERE: the UPDATE refuses to increment
-- past `(slot_index + 1) * 2^22`. When the slice is exhausted, the
-- UPDATE matches zero rows → alloc CTE empty → INSERT no-ops →
-- caller gets pgx.ErrNoRows and surfaces a 507. Without this guard,
-- region 'eu' could roll past 4194303 into 'reserved-1's slice and
-- produce a duplicate VNI across regions (the (region, vni) PK
-- doesn't catch cross-region collisions).
WITH alloc AS (
  UPDATE network_vni_allocator a
     SET next_vni = next_vni + 1
   WHERE region = $4
     AND next_vni < (
       SELECT (slot_index + 1) * 4194304
         FROM regions
        WHERE name = $4
     )
  RETURNING next_vni - 1 AS vni
)
INSERT INTO networks (id, name, owner, vni, created_at)
SELECT $1, $2, $3, alloc.vni, now()
  FROM alloc
RETURNING vni;

-- name: registerRegion
-- Idempotent bootstrap insert. Called by each control plane at startup
-- with its --region value. The slot_index is the lowest unused index
-- (0..3). If the region is already registered, this is a no-op and the
-- existing slot_index is preserved. The seed for the two allocators
-- only fires when the region is brand-new — on conflict the SELECT
-- returns no rows so the allocator inserts are no-ops too.
--
-- The NOT EXISTS guard skips the INSERT entirely when the region row
-- already exists. Important post-seed: with reserved-N rows pre-seeded
-- at slots 1..3, MAX(slot_index)+1 would be 4, which violates the
-- slot_index<4 CHECK constraint even though ON CONFLICT would discard
-- the row — CHECK fires before ON CONFLICT in Postgres.
WITH new_region AS (
  INSERT INTO regions (name, slot_index)
  SELECT $1, (SELECT COALESCE(MAX(slot_index), -1) + 1 FROM regions)
  WHERE NOT EXISTS (SELECT 1 FROM regions WHERE name = $1)
  RETURNING name, slot_index
), seed_vni AS (
  INSERT INTO network_vni_allocator (region, next_vni)
  SELECT name, slot_index * 4194304 FROM new_region
  ON CONFLICT (region) DO NOTHING
  RETURNING 1
), seed_subnet AS (
  INSERT INTO host_subnet_allocator (region, next_index)
  SELECT name, slot_index * 4096 FROM new_region
  ON CONFLICT (region) DO NOTHING
  RETURNING 1
)
SELECT slot_index FROM regions WHERE name = $1;

-- name: getNetworkByID
SELECT id, name, owner, vni, created_at, deleted_at
  FROM networks
 WHERE id = $1 AND owner = $2 AND deleted_at IS NULL;

-- name: getNetworkByName
SELECT id, name, owner, vni, created_at, deleted_at
  FROM networks
 WHERE name = $1 AND owner = $2 AND deleted_at IS NULL;

-- name: listNetworks
SELECT n.id, n.name, n.owner, n.vni, n.created_at, n.deleted_at,
       (SELECT COUNT(*)::int
          FROM sandbox_networks sn
          JOIN sandboxes s ON s.id = sn.sandbox_id
         WHERE sn.network_id = n.id
           AND s.status NOT IN ('destroyed', 'failed')) AS member_count
  FROM networks n
 WHERE n.owner = $1 AND n.deleted_at IS NULL
 ORDER BY n.created_at ASC
 LIMIT $2 OFFSET $3;

-- name: countUserNetworks
-- Drives pagination.total on GET /v1/networks.
SELECT COUNT(*)::int FROM networks
 WHERE owner = $1 AND deleted_at IS NULL;

-- name: countNetworkMembers
SELECT COUNT(*)::int
  FROM sandbox_networks sn
  JOIN sandboxes s ON s.id = sn.sandbox_id
 WHERE sn.network_id = $1
   AND s.status NOT IN ('destroyed', 'failed');

-- name: softDeleteNetwork
UPDATE networks SET deleted_at = now()
 WHERE id = $1 AND owner = $2 AND deleted_at IS NULL
RETURNING id;

-- name: attachNetwork
INSERT INTO sandbox_networks (sandbox_id, network_id, created_at)
VALUES ($1, $2, now())
ON CONFLICT (sandbox_id, network_id) DO NOTHING;

-- name: detachNetwork
DELETE FROM sandbox_networks
 WHERE sandbox_id = $1 AND network_id = $2;

-- name: countStaleNetworkMemberships
-- A membership has no runtime meaning once either side is terminal. Network
-- deletion is soft, while failed sandboxes do not pass through the normal
-- mark-destroyed CTE that removes memberships, so these rows can otherwise
-- linger indefinitely. Region scoping keeps each regional sweep confined to
-- its own sandbox rows.
SELECT COUNT(*)::int
  FROM sandbox_networks sn
  JOIN sandboxes s ON s.id = sn.sandbox_id
  JOIN networks n ON n.id = sn.network_id
 WHERE s.region = $1
   AND (n.deleted_at IS NOT NULL OR s.status IN ('destroyed', 'failed'));

-- name: sweepStaleNetworkMemberships
DELETE FROM sandbox_networks sn
 USING sandboxes s, networks n
 WHERE s.id = sn.sandbox_id
   AND n.id = sn.network_id
   AND s.region = $1
   AND (n.deleted_at IS NOT NULL OR s.status IN ('destroyed', 'failed'));

-- name: networkHostState
-- Returns one row per (endpoint, network) membership for any network
-- that has at least one running member on the given host. Endpoints
-- are either sandboxes OR devices (user-side WireGuard peers); both
-- types share the same VNI-based BPF policy, so the reconciler treats
-- them identically — only `kind` differs for telemetry.
--
-- For devices, host_id/wg_ip point at the RELAY that currently owns
-- the active session, so the per-host reconciler installs:
--   ip route <device_ip>/32 via <relay's wg-hosts IP> dev wg-hosts
WITH my_nets AS (
  SELECT DISTINCT sn.network_id
    FROM sandbox_networks sn
    JOIN sandboxes s ON s.id = sn.sandbox_id
   WHERE s.host_id = $1 AND s.status = 'running'
)
SELECT s.id  AS endpoint_id,
       s.ip,
       COALESCE(s.mac, '')         AS mac,
       s.host_id,
       COALESCE(h.underlay_ip, '') AS underlay_ip,
       COALESCE(host(h.wg_ip), '') AS wg_ip,
       sn.network_id,
       COALESCE(s.name, '')        AS name,
       n.vni,
       n.name                      AS network_name,
       (s.host_id = $1)            AS is_local,
       'vm'                        AS kind
  FROM sandbox_networks sn
  JOIN sandboxes s ON s.id  = sn.sandbox_id
  JOIN networks  n ON n.id  = sn.network_id
  JOIN hosts     h ON h.id  = s.host_id
 WHERE sn.network_id IN (SELECT network_id FROM my_nets)
   AND s.status = 'running'
   AND n.deleted_at IS NULL

UNION ALL

SELECT d.id                        AS endpoint_id,
       host(d.client_ip)           AS ip,
       ''                          AS mac,
       ds.relay_host_id            AS host_id,
       COALESCE(rh.underlay_ip, '') AS underlay_ip,
       COALESCE(host(rh.wg_ip), '') AS wg_ip,
       dn.network_id,
       COALESCE(d.name, '')        AS name,
       n.vni,
       n.name                      AS network_name,
       false                       AS is_local,
       'device'                    AS kind
  FROM device_networks dn
  JOIN devices         d  ON d.id = dn.device_id
  JOIN device_sessions ds ON ds.device_id = d.id
  JOIN networks        n  ON n.id = dn.network_id
  JOIN hosts           rh ON rh.id = ds.relay_host_id
 WHERE dn.network_id IN (SELECT network_id FROM my_nets)
   AND ds.expires_at > NOW()
   AND d.revoked_at IS NULL
   AND n.deleted_at IS NULL;

-- ─── disks ────────────────────────────────────────────────────────────
-- User-registered S3 disks attached to sandboxes via sandbox_disks.
-- credentials is an opaque AES-GCM envelope; only control reads it.

-- name: insertDisk
INSERT INTO disks (id, user_id, name, kind, config, credentials, created_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, now())
RETURNING created_at;

-- name: getDiskByID
SELECT id, user_id, name, kind, config, credentials, created_at, deleted_at
  FROM disks
 WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL;

-- name: getDiskByName
SELECT id, user_id, name, kind, config, credentials, created_at, deleted_at
  FROM disks
 WHERE name = $1 AND user_id = $2 AND deleted_at IS NULL;

-- name: countSandboxesActive
-- Concurrent-sandbox count for quota enforcement. Counts every sandbox
-- a user owns in any non-terminal state — running, paused, creating,
-- pausing, resuming, error, etc. — so the cap is "total live, including
-- paused" not "currently running". Terminal rows (destroyed, failed) are
-- excluded; they're storage liabilities, not capacity reservations.
SELECT count(*)::int
  FROM sandboxes
 WHERE created_by = $1
   AND status NOT IN ('destroyed', 'failed');

-- name: countSandboxesActiveExcept
-- Resume hot path. Same shape as countSandboxesActive but excludes
-- the sandbox being resumed — without this a free-tier user (cap=1)
-- with a single paused VM hits 429 trying to start it back up, because
-- the paused row is itself counted toward the cap.
SELECT count(*)::int
  FROM sandboxes
 WHERE created_by = $1
   AND status NOT IN ('destroyed', 'failed')
   AND id <> $2;

-- name: countSandboxesSince
-- Per-day creation count for quota enforcement. Counts EVERY row
-- (including destroyed) created since $2 — that's the "100 DB entries
-- per day" semantic: a user destroying and re-creating still burns
-- their daily allowance.
SELECT count(*)::int
  FROM sandboxes
 WHERE created_by = $1
   AND created_at >= $2;

-- name: countNetworksActive
-- Concurrent-network count: live networks (not soft-deleted) owned by
-- this user. Destroyed networks free up their slot immediately.
SELECT count(*)::int
  FROM networks
 WHERE owner = $1
   AND deleted_at IS NULL;

-- name: countNetworksSince
-- Per-day network-creation count: every network row (including soft-deleted)
-- created since $2. "N DB entries per day" — recreating a deleted network
-- still costs daily allowance. Mirrors countSandboxesSince / countDisksSince.
SELECT count(*)::int
  FROM networks
 WHERE owner = $1
   AND created_at >= $2;

-- name: countDisksActive
-- Concurrent-disk count: live disks owned by this user.
SELECT count(*)::int
  FROM disks
 WHERE user_id = $1
   AND deleted_at IS NULL;

-- name: countDisksSince
-- Per-day disk-creation count: every disk row (including soft-deleted)
-- created since $2. "100 DB entries per day" — recreating a soft-deleted
-- disk still costs daily allowance.
SELECT count(*)::int
  FROM disks
 WHERE user_id = $1
   AND created_at >= $2;

-- name: countTemplatesActive
-- Concurrent-template count: live templates (not soft-deleted) owned
-- by this user. Counts every non-deleted status — including pending
-- and building — so a stuck build can't be worked around by spamming
-- new submissions.
SELECT count(*)::int
  FROM templates
 WHERE user_id = $1
   AND deleted_at IS NULL;

-- name: countTemplatesSince
-- Per-day template-creation count: every template row (including
-- soft-deleted) created since $2.
SELECT count(*)::int
  FROM templates
 WHERE user_id = $1
   AND created_at >= $2;

-- name: listDisks
-- Paged list. $2 = LIMIT, $3 = OFFSET. Total drives the pagination
-- block via countUserDisks below.
SELECT id, user_id, name, kind, config, created_at, deleted_at
  FROM disks
 WHERE user_id = $1 AND deleted_at IS NULL
 ORDER BY created_at ASC
 LIMIT $2 OFFSET $3;

-- name: countUserDisks
-- Drives pagination.total on GET /v1/disks.
SELECT COUNT(*)::int FROM disks
 WHERE user_id = $1 AND deleted_at IS NULL;

-- name: countDiskAttachments
-- Refuse delete while attached to a non-terminal sandbox. Destroyed /
-- failed / destroying sandboxes don't pin the disk: their attachment
-- rows linger in sandbox_disks for forensic value but are filtered
-- out here so the user can delete the disk once the VM is gone.
SELECT COUNT(*)::int
  FROM sandbox_disks sd
  JOIN sandboxes s ON s.id = sd.sandbox_id
 WHERE sd.disk_id = $1
   AND s.status NOT IN ('destroyed', 'failed', 'destroying');

-- name: softDeleteDisk
UPDATE disks SET deleted_at = now()
 WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
RETURNING id;

-- name: deleteDiskIfUnattached
-- Atomic count-then-soft-delete, race-free against concurrent attach.
-- The FOR UPDATE on `disks` serializes against attachDiskIfRunning's
-- FOR KEY SHARE on the same row: a concurrent attach either commits
-- before our SELECT (then `attached.cnt > 0` and we skip the UPDATE)
-- or blocks until our transaction commits (then attach sees deleted_at
-- non-null and refuses to insert). Without this serialization a
-- count-then-delete pair would orphan the new attachment row.
-- Returns (exists, attached_count, deleted): caller distinguishes
--   exists=false                  -> 404
--   exists=true, deleted=false    -> 409 (still attached, cnt>0)
--   deleted=true                  -> 200
WITH locked AS (
  SELECT id FROM disks
   WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
   FOR UPDATE
),
attached AS (
  SELECT COUNT(*)::int AS cnt
    FROM sandbox_disks sd
    JOIN sandboxes s ON s.id = sd.sandbox_id
   WHERE sd.disk_id = $1
     AND s.status NOT IN ('destroyed', 'failed', 'destroying')
),
upd AS (
  UPDATE disks SET deleted_at = now()
   WHERE id = (SELECT id FROM locked)
     AND (SELECT cnt FROM attached) = 0
  RETURNING id
)
SELECT
  EXISTS(SELECT 1 FROM locked) AS exists_row,
  COALESCE((SELECT cnt FROM attached), 0) AS attached_cnt,
  EXISTS(SELECT 1 FROM upd) AS deleted;

-- name: updateDiskCredentials
-- Rotates the AES-GCM envelope on an existing disk. Owner-scoped; bumps
-- nothing else (config + name + kind unchanged).
UPDATE disks SET credentials = $1::jsonb
 WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL
RETURNING id;

-- name: listRunningSandboxesForDisk
-- Enumerates running sandboxes that hold any attachment of a given
-- disk, joining host addr + pubkey so control can fan out an MMDS
-- refresh per host AND seal the cred payload to that specific host.
-- mount_path + sub_path come through because a disk can mount at
-- multiple paths in the same VM.
SELECT sd.sandbox_id, sd.mount_path, COALESCE(sd.sub_path, ''),
       COALESCE(s.host_id, ''), COALESCE(h.addr, ''),
       COALESCE(h.public_key, ''::bytea)
  FROM sandbox_disks sd
  JOIN sandboxes s ON s.id = sd.sandbox_id
  LEFT JOIN hosts h ON h.id = s.host_id
 WHERE sd.disk_id = $1
   AND s.status = 'running';

-- name: attachDisk
-- The PK is (sandbox_id, disk_id, mount_path) so one disk can mount at
-- multiple paths in the same sandbox. idx_sandbox_disks_mount_path still
-- forbids two different disks at the same mount_path.
INSERT INTO sandbox_disks (sandbox_id, disk_id, mount_path, sub_path, created_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (sandbox_id, disk_id, mount_path) DO NOTHING;

-- name: attachDiskIfRunning
-- Atomic TOCTOU-safe version of attachDisk: lock the sandbox row, insert
-- ONLY if status='running' at lock time. The implicit row-lock from
-- SELECT FOR UPDATE serializes against markPausing (also an UPDATE on
-- this row), so a concurrent pause either:
--   - completes first: we observe status != 'running' and return running=false
--     (caller surfaces 409 instead of inserting a dangling row that
--     won't be in the snapshot bundle)
--   - blocks until we commit: pause's CAS still sees status='running' and
--     proceeds — but our row is already in the table when pause begins
--     snapshotting, so MMDS includes the new mount.
-- Returns (running, inserted): inserted=false with running=true means
-- the same (sandbox, disk, mount_path) is already attached (idempotent).
-- locked_disk takes FOR KEY SHARE on the disks row, serializing against
-- deleteDiskIfUnattached's FOR UPDATE — a concurrent delete blocks here
-- until our insert commits (after which delete sees attached_cnt>0 and
-- refuses), or runs first (after which deleted_at IS NULL filter misses
-- and locked_disk is empty -> disk_exists=false -> caller 404s instead
-- of inserting an orphan row).
WITH locked_sb AS (
  SELECT id, status FROM sandboxes WHERE id = $1 FOR UPDATE
), locked_disk AS (
  SELECT id FROM disks WHERE id = $2 AND deleted_at IS NULL FOR KEY SHARE
), ins AS (
  INSERT INTO sandbox_disks (sandbox_id, disk_id, mount_path, sub_path, created_at)
  SELECT $1, $2, $3, $4, now()
    FROM locked_sb, locked_disk
   WHERE locked_sb.status = 'running'
  ON CONFLICT (sandbox_id, disk_id, mount_path) DO NOTHING
  RETURNING 1
)
SELECT
  COALESCE((SELECT status FROM locked_sb), '') = 'running' AS running,
  EXISTS(SELECT 1 FROM ins) AS inserted,
  EXISTS(SELECT 1 FROM locked_disk) AS disk_exists;

-- name: detachDisk
-- Live detach: drop one attachment row keyed by mount_path so callers
-- with N mounts of the same disk can detach exactly one.
DELETE FROM sandbox_disks
 WHERE sandbox_id = $1 AND disk_id = $2 AND mount_path = $3
RETURNING disk_id;

-- name: listSandboxDisks
-- User-facing projection: joins disk metadata + per-attachment status.
SELECT sd.disk_id, d.name, d.kind, d.config,
       sd.mount_path, sd.sub_path, sd.mount_status, sd.mount_error, sd.created_at
  FROM sandbox_disks sd
  JOIN disks d ON d.id = sd.disk_id
 WHERE sd.sandbox_id = $1
 ORDER BY sd.created_at ASC;

-- name: resolveSandboxDisks
-- Host-scoped resolution: returns the encrypted-creds bundle for every
-- disk attached to a sandbox the calling host owns. Control decrypts
-- before forwarding to MMDS.
SELECT sd.disk_id, d.kind, d.config, d.credentials, sd.mount_path, sd.sub_path
  FROM sandbox_disks sd
  JOIN disks d ON d.id = sd.disk_id
 WHERE sd.sandbox_id = $1
   AND d.deleted_at IS NULL
 ORDER BY sd.created_at ASC;

-- name: setSandboxDiskStatus
-- Agent → host → control. mount_error may be NULL when mount_status='mounted'.
-- mount_path is part of the key so two attachments of the same disk
-- (different mount_paths) don't overwrite each other.
UPDATE sandbox_disks
   SET mount_status = $3, mount_error = $4
 WHERE sandbox_id = $1 AND disk_id = $2 AND mount_path = $5;

-- name: resetSandboxDiskStatus
-- Called by control at pause time so the UI doesn't keep reporting
-- 'mounted' for a VM whose disks are about to be unmounted.
UPDATE sandbox_disks
   SET mount_status = 'pending', mount_error = NULL
 WHERE sandbox_id = $1;

-- ─── regions ──────────────────────────────────────────────────────────

-- name: getRegion
SELECT name, description, country_code, created_at, disabled_at
  FROM regions
 WHERE name = $1;

-- name: listRegions
SELECT name, description, country_code, created_at, disabled_at
  FROM regions
 ORDER BY name;

-- name: insertRegion
INSERT INTO regions (name, description, country_code)
VALUES ($1, $2, $3);

-- name: disableRegion
UPDATE regions SET disabled_at = now()
 WHERE name = $1 AND disabled_at IS NULL;

-- ── billing event outbox ──────────────────────────────────────────────

-- name: insertBillingEvent
-- Atomic outbox insert. Caller is expected to run this in the same tx
-- as the sandbox status UPDATE; on tx commit, both land atomically.
-- Every transition is delivered as its own event — receivers dedup by
-- event_id and reconstruct intervals from the event stream.
INSERT INTO billing_events (id, sandbox_id, event_type, payload, occurred_at)
VALUES ($1, $2, $3, $4::jsonb, $5)
RETURNING id;

-- name: claimPendingBillingEvents
-- Worker's hot path. FOR UPDATE SKIP LOCKED lets N replicas race for
-- the same backlog without stepping on each other; each row goes to
-- exactly one worker per tick. Limit caps tick latency.
SELECT id, sandbox_id, event_type, payload, occurred_at, attempts
  FROM billing_events
 WHERE status         = 'pending'
   AND next_attempt_at <= now()
 ORDER BY next_attempt_at ASC
 LIMIT $1
   FOR UPDATE SKIP LOCKED;

-- name: markBillingEventDelivered
-- Called on a 2xx response from the webhook.
UPDATE billing_events
   SET status       = 'delivered',
       delivered_at = now(),
       last_error   = NULL
 WHERE id = $1;

-- name: markBillingEventPermanentFailure
-- Called on a 4xx response (excluding 408/429). Stops retrying; the
-- row stays visible for operator alerting via status='permanent_failure'.
-- $2 is the response body / error message.
UPDATE billing_events
   SET status       = 'permanent_failure',
       delivered_at = now(),
       last_error   = $2
 WHERE id = $1;

-- name: bumpBillingEventAttempt
-- Called on retryable failure (5xx, 408, 429, network error). Keeps
-- status='pending' so the worker picks it up again after next_attempt_at.
-- $2 is the error message; $3 is the next-attempt timestamp computed
-- by the worker's backoff schedule.
UPDATE billing_events
   SET attempts        = attempts + 1,
       last_error      = $2,
       next_attempt_at = $3
 WHERE id = $1;

-- name: isInternalUser
-- Returns true if the user has at least one active (non-revoked)
-- internal API key. Used by Handler.emitBillingEvent to record-but-
-- not-send: internal users' lifecycle events are persisted in the
-- outbox for audit, but never POSTed to the billing webhook.
SELECT EXISTS(
    SELECT 1 FROM api_keys
     WHERE user_id = $1
       AND is_internal = true
       AND revoked = false
);

-- name: markBillingEventInternalSkip
-- Marks a freshly-inserted event as status='internal_skip' so the
-- worker never picks it up. The row stays for audit; webhook never
-- fires. Caller runs this in the SAME tx as insertBillingEvent.
UPDATE billing_events
   SET status       = 'internal_skip',
       delivered_at = now()
 WHERE id = $1;

-- name: insertIssuedCert
-- Append a freshly-issued leaf cert to the ledger. cert_serial is a
-- 128-bit random hex string minted by the CA; PK conflict on collision
-- bubbles up to the caller (extremely unlikely).
INSERT INTO issued_certs (cert_serial, subject_kind, subject_id, expires_at)
VALUES ($1, $2, $3, $4);

-- name: revokePriorOnRotateImmediate
-- Tombstone every prior active cert for (subject_kind, subject_id) on
-- non-host rotation. Predecessor is gone from "active" the instant
-- this commits.
UPDATE issued_certs
   SET revoked_at = now(),
       revoked_by = 'rotation',
       replaced_by = $3
 WHERE subject_kind = $1
   AND subject_id   = $2
   AND cert_serial != $3
   AND revoked_at IS NULL;

-- name: scheduleRevokePriorOnRotate
-- Stamp scheduled_revoke_at on every prior active cert for the
-- subject. The $4::interval cast lets callers pass time.Duration.String()
-- (e.g. "24h0m0s") directly — postgres accepts that format.
UPDATE issued_certs
   SET scheduled_revoke_at = now() + $4::interval,
       replaced_by         = $3
 WHERE subject_kind = $1
   AND subject_id   = $2
   AND cert_serial != $3
   AND revoked_at IS NULL
   AND scheduled_revoke_at IS NULL;

-- name: revokeIssuedCert
-- Tombstone a single cert by serial. Idempotent — no-op when the row
-- is already revoked. `revoked_by` is freeform (RevokeByCompromise,
-- "admin:<uid>", etc.).
UPDATE issued_certs
   SET revoked_at = now(),
       revoked_by = $2
 WHERE cert_serial = $1
   AND revoked_at IS NULL;

-- name: applyScheduledRevocations
-- Called by the sweep CronJob. Flip revoked_at on every row whose
-- scheduled_revoke_at has elapsed. Preserves any pre-existing
-- revoked_by; defaults to 'rotation' when NULL.
UPDATE issued_certs
   SET revoked_at = scheduled_revoke_at,
       revoked_by = COALESCE(revoked_by, 'rotation')
 WHERE scheduled_revoke_at IS NOT NULL
   AND scheduled_revoke_at <= $1
   AND revoked_at IS NULL;

-- name: getActiveCertForSubject
-- Most-recent active (non-revoked, unexpired) cert for the subject.
SELECT cert_serial, subject_kind, subject_id,
       issued_at, expires_at,
       revoked_at, revoked_by, replaced_by, scheduled_revoke_at
  FROM issued_certs
 WHERE subject_kind = $1
   AND subject_id   = $2
   AND revoked_at IS NULL
   AND expires_at > now()
 ORDER BY issued_at DESC
 LIMIT 1;

-- name: listIssuedCertsForSubject
-- Full ledger for the subject, newest-first. Includes revoked + expired
-- rows for operator visibility.
SELECT cert_serial, subject_kind, subject_id,
       issued_at, expires_at,
       revoked_at, revoked_by, replaced_by, scheduled_revoke_at
  FROM issued_certs
 WHERE subject_kind = $1
   AND subject_id   = $2
 ORDER BY issued_at DESC;

-- name: listRevokedSerialsLedger
-- Feeds GET /v1/internal/crl.
SELECT cert_serial FROM issued_certs
 WHERE revoked_at IS NOT NULL;

-- name: listEnabledShapes
-- Returns every non-disabled shape in stable id-sorted order so
-- /v1/shapes responses + register payloads are deterministic.
SELECT id, vcpu, mem_mib, default_disk_mib, cpu_quota_pct
  FROM shapes
 WHERE disabled = false
 ORDER BY id;


-- ============================================================================
-- audit_events / webhooks / webhook_deliveries (see migration
-- 20260622000000_audit_events_webhooks.sql for schema + index rationale).
-- ============================================================================

-- name: insertAuditEvent
-- Single-row insert. Caller wraps in their own tx so the audit row
-- lands atomically with whatever business mutation it records.
INSERT INTO audit_events
    (id, user_id, action, operation_type,
     actor, hashed_token, request_id, user_agent, ip_address,
     expires_at, metadata, subject_type, subject_id,
     occurred_at, is_internal)
VALUES ($1, $2, $3, $4,
        $5, $6, $7, $8, $9,
        $10, $11::jsonb, $12, $13,
        $14, $15);

-- name: listAuditEventsForUser
-- User-facing pagination. ORDER + LIMIT/OFFSET hit idx_audit_events_user_time.
SELECT id, user_id, action, operation_type,
       actor, hashed_token, request_id, user_agent, ip_address,
       expires_at, metadata, subject_type, subject_id,
       occurred_at, is_internal
  FROM audit_events
 WHERE user_id = $1
 ORDER BY occurred_at DESC
 LIMIT $2 OFFSET $3;

-- name: countAuditEventsForUser
-- Sibling count for the paginated list (UI total).
SELECT count(*) FROM audit_events WHERE user_id = $1;

-- name: sweepExpiredAuditEvents
-- Retention cron. Partial index idx_audit_events_expiry keeps the
-- scan bounded even when most rows have NULL expires_at.
DELETE FROM audit_events WHERE expires_at IS NOT NULL AND expires_at <= now();



-- name: claimPendingAuditEvents
-- Backend shipper hot path. Mirrors claimPendingBillingEvents — FOR
-- UPDATE SKIP LOCKED lets N workers race for the same backlog.
--
-- is_internal=true rows stay in audit_events for forensics but are
-- NEVER shipped to the backend. Covers internal API keys + admin
-- actions like host cordon/uncordon — both classified is_internal
-- at emit time. The retention sweep eventually removes them.
SELECT id, user_id, action, operation_type,
       actor, hashed_token, request_id, user_agent, ip_address,
       expires_at, metadata, subject_type, subject_id,
       occurred_at, is_internal, attempts
  FROM audit_events
 WHERE status         = 'pending'
   AND is_internal    = false
   AND next_attempt_at <= now()
 ORDER BY next_attempt_at ASC
 LIMIT $1
   FOR UPDATE SKIP LOCKED;

-- name: markAuditEventShipped
UPDATE audit_events
   SET status     = 'shipped',
       shipped_at = now()
 WHERE id = $1;

-- name: markAuditEventPermanentFailure
UPDATE audit_events
   SET status     = 'permanent_failure',
       shipped_at = now(),
       last_error = $2
 WHERE id = $1;

-- name: bumpAuditEventShipAttempt
UPDATE audit_events
   SET attempts        = attempts + 1,
       last_error      = $2,
       next_attempt_at = $3
 WHERE id = $1;

-- name: userMetricsByStatus
-- Live counts of a user's sandboxes by status. Excludes terminal states
-- (destroyed, failed, error) — they don't represent capacity in-use.
-- Returns one row per status bucket the user currently has.
SELECT status, count(*)::int
  FROM sandboxes
 WHERE created_by = $1
   AND status NOT IN ('destroyed', 'failed', 'error')
 GROUP BY status;

-- name: userMetricsWindow
-- Per-user aggregate stats over [from, to). Counts spawn/destroy events
-- and rolls up compute (vcpu * seconds, mem_mib * seconds, disk_mib *
-- seconds) and bandwidth for every sandbox that overlapped the window.
-- Lifetime is destroyed_at - created_at; only includes rows that
-- destroyed inside the window (so an in-flight long-lived VM doesn't
-- skew p50 downward). Compute uses LEAST/GREATEST to clip each sandbox's
-- alive window to the query window.
WITH overlap AS (
  SELECT vcpu, mem_mib, disk_mib,
         created_at, destroyed_at,
         bandwidth_used_bytes, bandwidth_ingress_bytes,
         EXTRACT(EPOCH FROM (
           LEAST(COALESCE(destroyed_at, $3::timestamptz), $3::timestamptz)
           - GREATEST(created_at, $2::timestamptz)
         ))::float8 AS alive_s
    FROM sandboxes
   WHERE created_by = $1
     AND created_at < $3
     AND COALESCE(destroyed_at, $3::timestamptz) > $2
)
SELECT
  (SELECT count(*)::int FROM sandboxes
     WHERE created_by = $1 AND created_at >= $2 AND created_at < $3) AS spawned,
  (SELECT count(*)::int FROM sandboxes
     WHERE created_by = $1 AND destroyed_at >= $2 AND destroyed_at < $3) AS destroyed,
  COALESCE(MIN(EXTRACT(EPOCH FROM (destroyed_at - created_at))) FILTER (
    WHERE destroyed_at >= $2 AND destroyed_at < $3
  ), 0)::float8 AS lifetime_min,
  COALESCE(percentile_cont(0.50) WITHIN GROUP (ORDER BY
    EXTRACT(EPOCH FROM (destroyed_at - created_at))) FILTER (
    WHERE destroyed_at >= $2 AND destroyed_at < $3
  ), 0)::float8 AS lifetime_p50,
  COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY
    EXTRACT(EPOCH FROM (destroyed_at - created_at))) FILTER (
    WHERE destroyed_at >= $2 AND destroyed_at < $3
  ), 0)::float8 AS lifetime_p95,
  COALESCE(AVG(EXTRACT(EPOCH FROM (destroyed_at - created_at))) FILTER (
    WHERE destroyed_at >= $2 AND destroyed_at < $3
  ), 0)::float8 AS lifetime_avg,
  COALESCE(SUM(GREATEST(alive_s, 0) * vcpu),     0)::float8 AS vcpu_seconds,
  COALESCE(SUM(GREATEST(alive_s, 0) * mem_mib),  0)::float8 AS mem_mib_seconds,
  COALESCE(SUM(GREATEST(alive_s, 0) * disk_mib), 0)::float8 AS disk_mib_seconds,
  COALESCE(SUM(bandwidth_used_bytes)    FILTER (WHERE destroyed_at >= $2 AND destroyed_at < $3), 0)::bigint AS egress_bytes,
  COALESCE(SUM(bandwidth_ingress_bytes) FILTER (WHERE destroyed_at >= $2 AND destroyed_at < $3), 0)::bigint AS ingress_bytes
FROM overlap;

-- name: userMetricsByShape
-- Per-shape sandbox count + vcpu*seconds rollup over [from, to).
-- Clipped to the window the same way as userMetricsWindow's compute.
SELECT shape,
       count(*)::int AS count,
       COALESCE(SUM(GREATEST(EXTRACT(EPOCH FROM (
         LEAST(COALESCE(destroyed_at, $3::timestamptz), $3::timestamptz)
         - GREATEST(created_at, $2::timestamptz)
       )), 0) * vcpu), 0)::float8 AS vcpu_seconds
  FROM sandboxes
 WHERE created_by = $1
   AND created_at < $3
   AND COALESCE(destroyed_at, $3::timestamptz) > $2
 GROUP BY shape
 ORDER BY count DESC;

-- name: userMetricsTimeseries
-- Per-bucket counts of spawned, destroyed, and a running-snapshot
-- (sandboxes whose alive interval overlapped the bucket end). Bucket
-- size is passed as a Postgres interval literal via $4 (e.g. '1 hour'
-- or '1 day'). Uses generate_series to fill empty buckets with zeros.
WITH buckets AS (
  SELECT generate_series(
    date_trunc('hour', $2::timestamptz),
    date_trunc('hour', $3::timestamptz),
    ($4::text)::interval
  ) AS ts
)
SELECT b.ts,
  (SELECT count(*)::int FROM sandboxes
     WHERE created_by = $1
       AND created_at >= b.ts
       AND created_at <  b.ts + ($4::text)::interval) AS spawned,
  (SELECT count(*)::int FROM sandboxes
     WHERE created_by = $1
       AND destroyed_at >= b.ts
       AND destroyed_at <  b.ts + ($4::text)::interval) AS destroyed,
  (SELECT count(*)::int FROM sandboxes
     WHERE created_by = $1
       AND created_at <= b.ts + ($4::text)::interval
       AND COALESCE(destroyed_at, NOW()) > b.ts) AS running
  FROM buckets b
 ORDER BY b.ts;

-- ── devices (user-device WireGuard VPN) ──────────────────────────────

-- name: assignDeviceIP
-- Atomically allocate the next free /32 from the full CGNAT /10 pool
-- (100.64.0.0/10, RFC 6598). Per-region slice is /12 (1,048,576 IPs):
--
--   region slot 0 → 100.64.0.0/12
--   region slot 1 → 100.80.0.0/12
--   region slot 2 → 100.96.0.0/12
--   region slot 3 → 100.112.0.0/12
--
-- $1 = region. Returns the new IP as text. Returns empty if the per-region
-- /12 is exhausted; caller surfaces 503.
WITH alloc AS (
  UPDATE device_ip_allocator
     SET next_index = next_index + 1
   WHERE region = $1
  RETURNING next_index - 1 AS region_idx
), slot AS (
  SELECT slot_index AS region_slot
    FROM regions
   WHERE name = $1
), total AS (
  SELECT (slot.region_slot * 1048576) + alloc.region_idx AS n
    FROM alloc, slot
   WHERE alloc.region_idx > 0 AND alloc.region_idx < 1048576
), new_ip AS (
  SELECT format(
    '100.%s.%s.%s',
    64 + (total.n / 65536),
    (total.n / 256) % 256,
    total.n % 256
  )::inet AS ip
    FROM total
)
SELECT COALESCE((SELECT host(ip) FROM new_ip), '') AS client_ip;

-- name: createDevice
-- Insert a fresh device row. client_ip should be the value returned by
-- assignDeviceIP. Hostname/os may be empty if the client didn't supply.
INSERT INTO devices (id, user_id, name, pubkey, client_ip, hostname, os, created_at)
VALUES ($1, $2, $3, $4, $5::inet, $6, $7, NOW())
RETURNING id, user_id, name, pubkey, host(client_ip) AS client_ip,
          hostname, os, created_at, last_seen_at, revoked_at;

-- name: getDevice
SELECT id, user_id, name, pubkey, host(client_ip) AS client_ip,
       hostname, os, created_at, last_seen_at, revoked_at
  FROM devices
 WHERE id = $1 AND revoked_at IS NULL;

-- name: getDeviceForUser
-- Authz-scoped: ensures cross-tenant device lookups 404 even with a guessable id.
SELECT id, user_id, name, pubkey, host(client_ip) AS client_ip,
       hostname, os, created_at, last_seen_at, revoked_at
  FROM devices
 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: listDevicesForUser
SELECT id, user_id, name, pubkey, host(client_ip) AS client_ip,
       hostname, os, created_at, last_seen_at, revoked_at
  FROM devices
 WHERE user_id = $1 AND revoked_at IS NULL
 ORDER BY created_at DESC
 LIMIT $2 OFFSET $3;

-- name: countDevicesForUser
SELECT count(*)::int FROM devices
 WHERE user_id = $1 AND revoked_at IS NULL;

-- name: revokeDevice
-- Soft-delete: marks revoked but keeps row + IP for audit. Cascades drop
-- device_networks and device_sessions via FK ON DELETE CASCADE — we want
-- soft-delete here so we keep history; explicit cleanup below.
UPDATE devices SET revoked_at = NOW() WHERE id = $1 AND user_id = $2;

-- name: deleteDeviceNetworksForDevice
DELETE FROM device_networks WHERE device_id = $1;

-- name: deleteDeviceSessionsForDevice
DELETE FROM device_sessions WHERE device_id = $1;

-- name: attachDeviceToNetwork
INSERT INTO device_networks (device_id, network_id, attached_at)
VALUES ($1, $2, NOW())
ON CONFLICT (device_id, network_id) DO NOTHING;

-- name: detachDeviceFromNetwork
DELETE FROM device_networks
 WHERE device_id = $1 AND network_id = $2;

-- name: listNetworksForDevice
SELECT n.id, n.name, n.owner, n.vni, n.created_at, n.deleted_at,
       dn.attached_at
  FROM device_networks dn
  JOIN networks n ON n.id = dn.network_id
 WHERE dn.device_id = $1 AND n.deleted_at IS NULL
 ORDER BY dn.attached_at ASC;

-- name: createDeviceSession
INSERT INTO device_sessions (id, device_id, relay_host_id, endpoint_addr, created_at, expires_at)
VALUES ($1, $2, $3, $4, NOW(), $5)
RETURNING id, device_id, relay_host_id, endpoint_addr, created_at, expires_at;

-- name: getDeviceSession
SELECT id, device_id, relay_host_id, endpoint_addr, created_at, expires_at
  FROM device_sessions
 WHERE id = $1;

-- name: deleteDeviceSession
DELETE FROM device_sessions WHERE id = $1 AND device_id = $2;

-- name: listSessionsForDevice
SELECT id, device_id, relay_host_id, endpoint_addr, created_at, expires_at
  FROM device_sessions
 WHERE device_id = $1 AND expires_at > NOW()
 ORDER BY created_at DESC;

-- name: listSessionsForRelay
-- Hot path on the relay's reconcile tick: rebuild wg-devices peer list
-- from the union of (device.pubkey, device.client_ip) for all sessions
-- bound to this relay that haven't expired.
SELECT s.id, d.pubkey, host(d.client_ip) AS client_ip, s.expires_at
  FROM device_sessions s
  JOIN devices d ON d.id = s.device_id
 WHERE s.relay_host_id = $1
   AND s.expires_at > NOW()
   AND d.revoked_at IS NULL;

-- name: pickLeastLoadedRelay
-- API picks the active relay with the fewest sessions for a new bind.
-- $1 = region; the picker stays in-region so a device gets a relay in
-- the same POP its control landed at (GeoDNS + Spock replication mean
-- either region's control sees every relay, but you never want a US
-- device dialing an EU endpoint).
SELECT h.id
  FROM hosts h
  LEFT JOIN device_sessions s
         ON s.relay_host_id = h.id AND s.expires_at > NOW()
 WHERE h.role = 'relay' AND h.status = 'active' AND h.region = $1
 GROUP BY h.id
 ORDER BY count(s.id) ASC, h.id ASC
 LIMIT 1;

-- name: pickLeastLoadedRelayAnyRegion
-- Fallback picker used ONLY when RelayCrossRegionFallback is enabled and
-- pickLeastLoadedRelay returned zero rows for the caller's region.
-- Prefers same-region if any row is present (belt-and-suspenders, since
-- the fallback should have been avoided in that case anyway), otherwise
-- picks the fleet-wide least-loaded relay. Never called on the fast path.
SELECT h.id
  FROM hosts h
  LEFT JOIN device_sessions s
         ON s.relay_host_id = h.id AND s.expires_at > NOW()
 WHERE h.role = 'relay' AND h.status = 'active'
 GROUP BY h.id
 ORDER BY (h.region = $1) DESC, count(s.id) ASC, h.id ASC
 LIMIT 1;

-- name: expireDeviceSessions
-- Sweeper: drops rows past TTL, returns affected device_ids so the
-- caller can kick reconcilers on hosts in those devices' networks.
DELETE FROM device_sessions
 WHERE expires_at <= NOW()
RETURNING device_id;

-- name: getActiveSessionForDevice
-- Most recent unexpired session for a device, or no rows. Used by the
-- session-create handler to detect "device is reconnecting" → reuse the
-- same relay + renew TTL in place instead of inserting a parallel row.
SELECT id, device_id, relay_host_id, endpoint_addr, created_at, expires_at
  FROM device_sessions
 WHERE device_id = $1
   AND expires_at > NOW()
 ORDER BY expires_at DESC
 LIMIT 1;

-- name: renewDeviceSession
-- Sliding-window renewal — bumps expires_at = NOW() + $2 seconds, scoped
-- to (id, device_id) so a session can't be renewed on the wrong device.
-- No rows returned = session not found / expired / wrong device → caller
-- treats as 404 so the client tears down its tunnel instead of running
-- with stale local state.
UPDATE device_sessions
   SET expires_at = NOW() + ($3 * INTERVAL '1 second')
 WHERE id = $1 AND device_id = $2
RETURNING id, device_id, relay_host_id, endpoint_addr, created_at, expires_at;

-- name: listSubnetsForDeviceNetworks
-- AllowedIPs material for a device session. Returns the union of host
-- VM subnets (host.subnet_cidr) for every host that has at least one
-- running VM in any network the device is attached to. The client's
-- kernel uses these CIDRs to decide "which destination IPs route
-- through the VPN tunnel."
--
-- Empty result is legitimate: device attached to network(s) with no
-- running VMs yet — handler can degrade to just the device's /32.
SELECT DISTINCT h.subnet_cidr
  FROM device_networks dn
  JOIN sandbox_networks sn ON sn.network_id = dn.network_id
  JOIN sandboxes s         ON s.id = sn.sandbox_id
  JOIN hosts     h         ON h.id = s.host_id
 WHERE dn.device_id = $1
   AND s.status = 'running'
   AND h.subnet_cidr IS NOT NULL
   AND h.subnet_cidr <> ''
 ORDER BY h.subnet_cidr;

-- name: listDevicePairsForRelay
-- All ordered (a, b) device IP pairs where:
--   - both devices have an active session on this relay
--   - they share at least one network
-- Returns symmetric pairs so the BPF map has both directions.
-- The relay's fc_wg_ingress BPF program looks up (src_ip, dst_ip)
-- in fc_vmip_pair; if present → allow, else drop.
SELECT DISTINCT
  host(da.client_ip) AS src_ip,
  host(db.client_ip) AS dst_ip
  FROM device_sessions sa
  JOIN device_sessions sb ON sa.id <> sb.id
  JOIN devices da ON da.id = sa.device_id
  JOIN devices db ON db.id = sb.device_id
  JOIN device_networks dna ON dna.device_id = sa.device_id
  JOIN device_networks dnb ON dnb.device_id = sb.device_id
                          AND dnb.network_id = dna.network_id
 WHERE sa.relay_host_id = $1
   AND sb.relay_host_id = $1
   AND sa.expires_at > NOW()
   AND sb.expires_at > NOW()
   AND da.revoked_at IS NULL
   AND db.revoked_at IS NULL;

-- name: listDeviceVMPairsForRelay
-- Symmetric (device_ip, vm_ip) pairs for fc_vmip_pair on the relay's
-- wg-devices ingress. Without these, fc_wg_ingress drops the decrypted
-- device→VM packet (and the return path can't establish flow state).
-- Each (device, VM) sharing at least one network emits BOTH directions
-- so device→VM and VM→device both look up an allowed pair.
SELECT DISTINCT
  host(d.client_ip) AS src_ip,
  s.ip              AS dst_ip
  FROM device_sessions ds
  JOIN devices d ON d.id = ds.device_id
  JOIN device_networks dn ON dn.device_id = d.id
  JOIN sandbox_networks sn ON sn.network_id = dn.network_id
  JOIN sandboxes s ON s.id = sn.sandbox_id
 WHERE ds.relay_host_id = $1
   AND ds.expires_at > NOW()
   AND d.revoked_at IS NULL
   AND s.status = 'running'
   AND s.ip IS NOT NULL
   AND s.ip <> ''
UNION
SELECT DISTINCT
  s.ip              AS src_ip,
  host(d.client_ip) AS dst_ip
  FROM device_sessions ds
  JOIN devices d ON d.id = ds.device_id
  JOIN device_networks dn ON dn.device_id = d.id
  JOIN sandbox_networks sn ON sn.network_id = dn.network_id
  JOIN sandboxes s ON s.id = sn.sandbox_id
 WHERE ds.relay_host_id = $1
   AND ds.expires_at > NOW()
   AND d.revoked_at IS NULL
   AND s.status = 'running'
   AND s.ip IS NOT NULL
   AND s.ip <> '';
