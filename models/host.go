package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NodeOps-app/sandbox/database"

	"github.com/jackc/pgx/v5"
)

// HostStatus is the lifecycle state of a host row in the `hosts` table.
type HostStatus = string

const (
	HostStatusActive   HostStatus = "active"   // heartbeating, schedulable
	HostStatusDraining HostStatus = "draining" // operator drain in progress; existing VMs being destroyed
	HostStatusDead     HostStatus = "dead"     // last_seen exceeded the reap window
)

// HostRole names the kind of work a host row does. Stored in
// hosts.role; defaults to RoleCompute. Every comparison/assignment
// against the role column MUST go through these constants — string
// literals are forbidden so a typo can't silently misroute traffic
// (e.g. "Relay" vs "relay" → "I'm a compute host" silently).
type HostRole = string

const (
	HostRoleCompute HostRole = "compute"
	HostRoleRelay   HostRole = "relay"
)

// Host describes a registered createos host in multi-host mode
// (mirror of store.HostRecord).
type Host struct {
	ID             string `json:"id" sql:"id"`
	Addr           string `json:"addr" sql:"addr"` // "host:port" of host's internal API
	MemCapacityMib int    `json:"mem_capacity_mib" sql:"mem_capacity_mib"`
	InUseMib       int    `json:"in_use_mib" sql:"in_use_mib"`
	VMCount        int    `json:"vm_count" sql:"vm_count"`
	Status         string `json:"status" sql:"status"` // "active" | "draining" | "dead"
	Role           string `json:"role" sql:"role"`     // "compute" | "relay"
	// RelayDevicesPubkey is the wg-devices pubkey for role='relay' hosts;
	// nil/empty for compute hosts. Distinct from WGPublicKey (wg-hosts).
	RelayDevicesPubkey []byte    `json:"relay_devices_pubkey,omitempty" sql:"relay_devices_pubkey"`
	RegisteredAt       time.Time `json:"registered_at" sql:"registered_at"`
	LastSeen           time.Time `json:"last_seen" sql:"last_seen"`

	// Hardware capacity (auto-detected by the host).
	CPUCount     int   `json:"cpu_count" sql:"cpu_count"`
	DiskTotalMib int64 `json:"disk_total_mib" sql:"disk_total_mib"`
	DiskUsedMib  int64 `json:"disk_used_mib" sql:"disk_used_mib"`

	// Multi-dimensional oversubscription factors. Stored as integer
	// 10ths so 20 = 2.0×, 50 = 5.0×, 10 = 1.0×. Per-host configurable
	// so different hardware tiers (NVMe vs SATA, big-mem vs balanced)
	// can run with different commit ratios. Defaults applied on register
	// when host doesn't send a value:
	//   cpu  = 20 (2.0×)  — bursty sandbox workloads
	//   mem  = 10 (1.0×)  — OOM is unforgiving, don't oversell
	//   disk = 50 (5.0×)  — per-VM overlays are sparse
	CPUOvercommitX10  int `json:"cpu_overcommit_x10" sql:"cpu_overcommit_x10"`
	MemOvercommitX10  int `json:"mem_overcommit_x10" sql:"mem_overcommit_x10"`
	DiskOvercommitX10 int `json:"disk_overcommit_x10" sql:"disk_overcommit_x10"`

	// In-use sums computed by the scheduler's hydrate from
	// SUM(vcpu)/SUM(disk_mib) over live sandboxes per host. NOT
	// persisted — derived view, written into the host cache only.
	// MemInUseMib is the legacy InUseMib field above (kept for
	// backward compat); these mirror it for the other two dimensions.
	VCPUInUse    int   `json:"vcpu_in_use,omitempty" sql:"-"`
	DiskInUseMib int64 `json:"disk_in_use_mib,omitempty" sql:"-"`
	// DiskHeadroomMib is scheduler-only capacity withheld after applying the
	// host's sparse-disk overcommit factor. It is never persisted.
	DiskHeadroomMib int64 `json:"disk_headroom_mib,omitempty" sql:"-"`

	// CPU identity from /proc/cpuinfo. Captured for cross-host snapshot
	// portability. Today: telemetry only — no scheduler filter. When the
	// cpu_compat plugin is enabled, the scheduler will pin a resume to
	// hosts matching the source's CPUVendor.
	CPUVendor string `json:"cpu_vendor,omitempty" sql:"cpu_vendor"` // GenuineIntel | AuthenticAMD | ...
	CPUFamily string `json:"cpu_family,omitempty" sql:"cpu_family"` // family:model:stepping

	// MaxVMs is the host-advertised concurrent-VM ceiling. 0 = unlimited.
	MaxVMs int `json:"max_vms" sql:"max_vms"`

	// Rootfses are the catalog names this host can create VMs from.
	Rootfses []string `json:"rootfses" sql:"rootfses"`

	// Labels are operator-assigned key/value tags used by the scheduler's
	// LabelSelectorFilter.
	Labels map[string]string `json:"labels" sql:"labels"`

	// SchedulingDisabled is the operator-set cordon bit.
	SchedulingDisabled bool `json:"scheduling_disabled" sql:"scheduling_disabled"`

	// PublicKey is the host's Ed25519 verify key, registered on /hosts/register.
	PublicKey []byte `json:"public_key" sql:"public_key"`

	// SubnetCIDR is the /22 assigned to this host at first registration.
	SubnetCIDR *string `json:"subnet_cidr,omitempty" sql:"subnet_cidr"`
	// UnderlayIP is the host's public address used by peers as the
	// WireGuard endpoint when sending encrypted overlay traffic here.
	UnderlayIP *string `json:"underlay_ip,omitempty" sql:"underlay_ip"`

	// Region pins this host to one regions.name. The scheduler refuses
	// to place a sandbox on a host whose region != sandbox.region.
	// NOT NULL in DB (defaults to 'eu' for legacy rows).
	Region string `json:"region" sql:"region"`

	// WGPublicKey is the host's WireGuard mesh public key (32-byte
	// Curve25519). Empty for hosts that haven't yet started a serve
	// process post-migration.
	WGPublicKey []byte `json:"wg_public_key,omitempty" sql:"wg_public_key"`

	// WGIP is the host's WG mesh address (172.30.0.<idx>), assigned
	// by control's host_wg_allocator at first register. Empty until
	// allocated.
	WGIP string `json:"wg_ip,omitempty" sql:"wg_ip"`

	// CachedTemplates is the set of tpl_<ulid>s this host has on local
	// disk and ready to boot from. Hydrated by the scheduler; never
	// persisted on the host row itself.
	CachedTemplates []string `json:"cached_templates" sql:"-"`
}

// HasCachedTemplate reports whether h has the template ext4 cached
// locally. Empty CachedTemplates → false.
func (h Host) HasCachedTemplate(tplID string) bool {
	for _, t := range h.CachedTemplates {
		if t == tplID {
			return true
		}
	}
	return false
}

// HasRootfs reports whether h advertises the given rootfs catalog name.
// Legacy hosts that reported no rootfs list (nil/empty) are treated as
// capable — we don't want old registrations to suddenly fail scheduling.
func (h Host) HasRootfs(name string) bool {
	if len(h.Rootfses) == 0 {
		return true
	}
	for _, r := range h.Rootfses {
		if r == name {
			return true
		}
	}
	return false
}

func scanHost(s scannable) (*Host, error) {
	var (
		h          Host
		rootfses   []string
		labelsRaw  []byte // JSONB
		pubkey     []byte // BYTEA, may be NULL on legacy rows
		subnetCIDR *string
		underlayIP *string
		cpuVendor  *string // nullable for legacy rows pre-2026-05-22 migration
		cpuFamily  *string
		wgPubkey   []byte // BYTEA, may be empty before first WG-aware register
		wgIP       string // text-formatted, empty when unallocated
	)
	err := s.Scan(
		&h.ID, &h.Addr, &h.Status, &h.MemCapacityMib, &h.InUseMib, &h.VMCount,
		&h.CPUCount, &h.DiskTotalMib, &h.DiskUsedMib, &h.MaxVMs, &rootfses,
		&h.RegisteredAt, &h.LastSeen, &labelsRaw, &h.SchedulingDisabled,
		&pubkey, &subnetCIDR, &underlayIP, &h.Region,
		&cpuVendor, &cpuFamily,
		&wgPubkey, &wgIP,
		&h.CPUOvercommitX10, &h.MemOvercommitX10, &h.DiskOvercommitX10,
		&h.Role,
		&h.RelayDevicesPubkey,
	)
	if err != nil {
		return nil, err
	}
	h.Rootfses = rootfses
	if len(labelsRaw) > 0 {
		labels := make(map[string]string)
		if err := json.Unmarshal(labelsRaw, &labels); err != nil {
			return nil, fmt.Errorf("decode host labels: %w", err)
		}
		h.Labels = labels
	}
	h.PublicKey = pubkey
	h.SubnetCIDR = subnetCIDR
	h.UnderlayIP = underlayIP
	if cpuVendor != nil {
		h.CPUVendor = *cpuVendor
	}
	if cpuFamily != nil {
		h.CPUFamily = *cpuFamily
	}
	h.WGPublicKey = wgPubkey
	h.WGIP = wgIP
	return &h, nil
}

func UpsertHost(ctx context.Context, d *database.Db, h Host) error {
	q, err := query(d, "upsertHost")
	if err != nil {
		return err
	}
	labels := h.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("marshal host labels: %w", err)
	}
	// pgx encodes nil []byte as NULL, which is what we want for legacy
	// hosts that haven't yet sent a pubkey.
	var pubkey any = h.PublicKey
	if len(h.PublicKey) == 0 {
		pubkey = nil
	}
	// Empty strings become NULL so the upsert's COALESCE preserves
	// previously-recorded values (e.g. a brief register from a host
	// that didn't read /proc/cpuinfo shouldn't blank out the column).
	var cpuVendor, cpuFamily any
	if h.CPUVendor != "" {
		cpuVendor = h.CPUVendor
	}
	if h.CPUFamily != "" {
		cpuFamily = h.CPUFamily
	}
	// wg_public_key: pass through as-is. Upsert's CASE clause treats a
	// non-32-byte value (e.g. empty bytea) as "no key" and preserves any
	// existing real key on re-register.
	wgPubkey := h.WGPublicKey
	if wgPubkey == nil {
		wgPubkey = []byte{}
	}
	var relayDevicesPubkey any
	if len(h.RelayDevicesPubkey) > 0 {
		relayDevicesPubkey = h.RelayDevicesPubkey
	}
	_, err = d.Con.Exec(ctx, q,
		h.ID, h.Addr, h.Status, h.MemCapacityMib, h.InUseMib, h.VMCount,
		h.CPUCount, h.DiskTotalMib, h.DiskUsedMib, h.MaxVMs, nullableStrings(h.Rootfses),
		h.RegisteredAt, h.LastSeen, labelsJSON, pubkey, h.Region,
		cpuVendor, cpuFamily, wgPubkey,
		h.CPUOvercommitX10, h.MemOvercommitX10, h.DiskOvercommitX10,
		h.Role,
		relayDevicesPubkey,
	)
	return err
}

func AssignHostSubnet(ctx context.Context, d *database.Db, hostID, underlayIP, region string) (string, error) {
	q, err := query(d, "assignHostSubnet")
	if err != nil {
		return "", err
	}
	var cidr string
	if err := d.Con.QueryRow(ctx, q, hostID, underlayIP, region).Scan(&cidr); err != nil {
		return "", fmt.Errorf("assignHostSubnet %s: %w", hostID, err)
	}
	return cidr, nil
}

// AssignHostWGIP allocates the next /32 from 172.30.0.0/24 for this host's
// region. Idempotent — returns the existing value on re-register. Returns
// empty string when the allocator is exhausted (>254 hosts in region).
func AssignHostWGIP(ctx context.Context, d *database.Db, hostID, region string) (string, error) {
	q, err := query(d, "assignHostWGIP")
	if err != nil {
		return "", err
	}
	var ip string
	if err := d.Con.QueryRow(ctx, q, hostID, region).Scan(&ip); err != nil {
		return "", fmt.Errorf("assignHostWGIP %s: %w", hostID, err)
	}
	return ip, nil
}

// SetHostWGPublicKey stamps the host's WG mesh public key. Idempotent.
func SetHostWGPublicKey(ctx context.Context, d *database.Db, hostID string, pubkey []byte) error {
	q, err := query(d, "setHostWGPublicKey")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, hostID, pubkey)
	return err
}

// RegisterRegion is the idempotent bootstrap that each control plane
// runs at startup. If the region is new, it claims the next slot_index
// (0..3) and seeds the per-region allocator rows. If it already exists,
// returns the existing slot_index unchanged. Returns the slot_index.
func RegisterRegion(ctx context.Context, d *database.Db, name string) (int, error) {
	q, err := query(d, "registerRegion")
	if err != nil {
		return 0, err
	}
	var slot int
	if err := d.Con.QueryRow(ctx, q, name).Scan(&slot); err != nil {
		return 0, fmt.Errorf("registerRegion %s: %w", name, err)
	}
	return slot, nil
}

func HeartbeatHost(ctx context.Context, d *database.Db, id string, inUseMib, vmCount int, status string, diskUsedMib int64, at time.Time) error {
	q, err := query(d, "heartbeatHost")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, inUseMib, vmCount, status, diskUsedMib, at)
	return err
}

func ListHosts(ctx context.Context, d *database.Db) ([]Host, error) {
	q, err := query(d, "listHosts")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

func ListActiveHosts(ctx context.Context, d *database.Db) ([]Host, error) {
	q, err := query(d, "listActiveHosts")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

func GetHost(ctx context.Context, d *database.Db, id string) (*Host, error) {
	q, err := query(d, "getHost")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, id)
	h, err := scanHost(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return h, nil
}

func SetHostStatus(ctx context.Context, d *database.Db, id, status string) (string, error) {
	q, err := query(d, "setHostStatus")
	if err != nil {
		return "", err
	}
	var got string
	err = d.Con.QueryRow(ctx, q, id, status).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return got, err
}

func SetHostSchedulingDisabled(ctx context.Context, d *database.Db, id string, disabled bool) (string, error) {
	q, err := query(d, "setHostSchedulingDisabled")
	if err != nil {
		return "", err
	}
	var got string
	err = d.Con.QueryRow(ctx, q, id, disabled).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return got, err
}

func SetHostDrain(ctx context.Context, d *database.Db, id string) (string, error) {
	q, err := query(d, "setHostDrain")
	if err != nil {
		return "", err
	}
	var got string
	err = d.Con.QueryRow(ctx, q, id).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return got, err
}

func MarkStaleHosts(ctx context.Context, d *database.Db, cutoff time.Time, region string) (int, error) {
	q, err := query(d, "markStaleHosts")
	if err != nil {
		return 0, err
	}
	rows, err := d.Con.Query(ctx, q, cutoff, region)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}
