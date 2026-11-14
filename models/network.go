package models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"

	"github.com/jackc/pgx/v5"
)

// ErrHasMembers is returned by DeleteNetwork when sandboxes are still joined.
var ErrHasMembers = fmt.Errorf("network has active members")

// Network is one row of the networks table (mirror of store.NetworkRecord).
type Network struct {
	ID    string `json:"id" sql:"id"` // net-<ulid>
	Name  string `json:"name" sql:"name"`
	Owner string `json:"owner" sql:"owner"` // api_keys.user_id
	// VNI is the overlay network identifier — infra detail, never exposed to end
	// users. json:"-" keeps it out of any response that accidentally
	// marshals *models.Network directly (the safe path is types.NetworkView,
	// which has no VNI field at all). Hosts still need VNI but they get
	// it via NetworkMember on the host-state internal endpoint.
	VNI         int        `json:"-" sql:"vni"`
	CreatedAt   time.Time  `json:"created_at" sql:"created_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty" sql:"deleted_at"`
	MemberCount int        `json:"member_count" sql:"member_count"` // populated by ListNetworks only
}

// NetworkMember is one row from the NetworkHostState query — one
// (endpoint, network) membership needed for eBPF map population.
// Endpoint kind = "vm" or "device"; reconciler treats both identically
// (same VNI policy), Kind is only for telemetry.
type NetworkMember struct {
	SandboxID   string `json:"sandbox_id" sql:"endpoint_id"` // sandbox or device id (legacy field name)
	IP          string `json:"ip" sql:"ip"`
	MAC         string `json:"mac,omitempty" sql:"mac"`
	HostID      string `json:"host_id" sql:"host_id"` // for devices: relay host id (route next-hop)
	UnderlayIP  string `json:"underlay_ip,omitempty" sql:"underlay_ip"`
	WGIP        string `json:"wg_ip,omitempty" sql:"wg_ip"` // peer's WG mesh IP; reconciler prefers this over UnderlayIP
	NetworkID   string `json:"network_id" sql:"network_id"`
	NetworkName string `json:"network_name,omitempty" sql:"network_name"`
	Name        string `json:"name,omitempty" sql:"name"` // user-facing name
	VNI         int    `json:"vni" sql:"vni"`
	IsLocal     bool   `json:"is_local" sql:"is_local"`   // true when host_id == querying host (always false for devices)
	Kind        string `json:"kind,omitempty" sql:"kind"` // "vm" | "device"
}

// NetworkMemberView is the user-facing projection of a sandbox→network
// membership returned by ListNetworkMembers.
type NetworkMemberView struct {
	SandboxID string `json:"sandbox_id" sql:"id"`
	Status    string `json:"status" sql:"status"`
	IP        string `json:"ip,omitempty" sql:"ip"`
	Name      string `json:"name,omitempty" sql:"name"` // the sandbox's user-facing name
}

// ErrVNIExhausted is returned by CreateNetwork when this region's
// 2^22-VNI slice is fully allocated. Handler surfaces it as 507.
var ErrVNIExhausted = errors.New("region VNI slice exhausted")

func CreateNetwork(ctx context.Context, d *database.Db, n Network, region string) error {
	q, err := query(d, "createNetwork")
	if err != nil {
		return err
	}
	err = d.Con.QueryRow(ctx, q, n.ID, n.Name, n.Owner, region).Scan(&n.VNI)
	if errors.Is(err, pgx.ErrNoRows) {
		// The CTE's UPDATE refused to advance next_vni past the slot
		// boundary → no rows flowed through to the INSERT. Distinct
		// from any other failure mode; surface as a typed error.
		return ErrVNIExhausted
	}
	return err
}

func GetNetwork(ctx context.Context, d *database.Db, owner, idOrName string) (*Network, error) {
	var q string
	var qerr error
	if strings.HasPrefix(idOrName, "net-") || strings.HasPrefix(idOrName, "net_") {
		q, qerr = query(d, "getNetworkByID")
	} else {
		q, qerr = query(d, "getNetworkByName")
	}
	if qerr != nil {
		return nil, qerr
	}
	n := &Network{}
	err := d.Con.QueryRow(ctx, q, idOrName, owner).Scan(
		&n.ID, &n.Name, &n.Owner, &n.VNI, &n.CreatedAt, &n.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return n, err
}

func ListNetworks(ctx context.Context, d *database.Db, owner string, limit, offset int) ([]Network, error) {
	q, err := query(d, "listNetworks")
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := d.Con.Query(ctx, q, owner, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Network
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.ID, &n.Name, &n.Owner, &n.VNI, &n.CreatedAt, &n.DeletedAt, &n.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CountUserNetworks returns the total number of non-deleted networks
// the user owns. Drives pagination.total on GET /v1/networks.
func CountUserNetworks(ctx context.Context, d *database.Db, owner string) (int, error) {
	q, err := query(d, "countUserNetworks")
	if err != nil {
		return 0, err
	}
	var n int
	if err := d.Con.QueryRow(ctx, q, owner).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func DeleteNetwork(ctx context.Context, d *database.Db, owner, idOrName string) error {
	net, err := GetNetwork(ctx, d, owner, idOrName)
	if err != nil {
		return err
	}
	if net == nil {
		return fmt.Errorf("network not found")
	}
	// Check member count first.
	cntQ, err := query(d, "countNetworkMembers")
	if err != nil {
		return err
	}
	var cnt int
	if err := d.Con.QueryRow(ctx, cntQ, net.ID).Scan(&cnt); err != nil {
		return err
	}
	if cnt > 0 {
		return ErrHasMembers
	}
	delQ, err := query(d, "softDeleteNetwork")
	if err != nil {
		return err
	}
	var gotID string
	err = d.Con.QueryRow(ctx, delQ, net.ID, owner).Scan(&gotID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("network not found")
	}
	return err
}

func AttachNetwork(ctx context.Context, d *database.Db, sandboxID, networkID string) error {
	q, err := query(d, "attachNetwork")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, networkID)
	return err
}

func DetachNetwork(ctx context.Context, d *database.Db, sandboxID, networkID string) error {
	q, err := query(d, "detachNetwork")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, networkID)
	return err
}

// CountStaleNetworkMemberships returns join rows that no longer represent a
// live attachment because the network was deleted or the sandbox is terminal.
func CountStaleNetworkMemberships(ctx context.Context, d *database.Db, region string) (int, error) {
	q, err := query(d, "countStaleNetworkMemberships")
	if err != nil {
		return 0, err
	}
	var count int
	if err := d.Con.QueryRow(ctx, q, region).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// SweepStaleNetworkMemberships removes only sandbox↔network join rows. It
// never deletes a sandbox or network record.
func SweepStaleNetworkMemberships(ctx context.Context, d *database.Db, region string) (int, error) {
	q, err := query(d, "sweepStaleNetworkMemberships")
	if err != nil {
		return 0, err
	}
	result, err := d.Con.Exec(ctx, q, region)
	if err != nil {
		return 0, err
	}
	return int(result.RowsAffected()), nil
}

func NetworkHostState(ctx context.Context, d *database.Db, hostID string) ([]NetworkMember, error) {
	q, err := query(d, "networkHostState")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetworkMember
	for rows.Next() {
		var m NetworkMember
		if err := rows.Scan(&m.SandboxID, &m.IP, &m.MAC, &m.HostID, &m.UnderlayIP, &m.WGIP,
			&m.NetworkID, &m.Name, &m.VNI, &m.NetworkName, &m.IsLocal, &m.Kind); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func ListNetworkMembers(ctx context.Context, d *database.Db, networkID string) ([]NetworkMemberView, error) {
	const q = `
SELECT s.id, COALESCE(s.status, ''), COALESCE(s.ip, ''), COALESCE(s.name, '')
  FROM sandbox_networks sn
  JOIN sandboxes s ON s.id = sn.sandbox_id
 WHERE sn.network_id = $1
 ORDER BY sn.created_at`
	rows, err := d.Con.Query(ctx, q, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetworkMemberView
	for rows.Next() {
		var v NetworkMemberView
		if err := rows.Scan(&v.SandboxID, &v.Status, &v.IP, &v.Name); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func CountNetworksActive(ctx context.Context, d *database.Db, ownerID string) (int, error) {
	q, err := query(d, "countNetworksActive")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, ownerID).Scan(&n)
}

// CountNetworksSince returns the number of network rows (including
// soft-deleted) created by `ownerID` since `since`. Used by the
// per-day creation cap; mirrors CountSandboxesSince/CountDisksSince.
func CountNetworksSince(ctx context.Context, d *database.Db, ownerID string, since time.Time) (int, error) {
	q, err := query(d, "countNetworksSince")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, ownerID, since).Scan(&n)
}
