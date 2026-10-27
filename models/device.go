package models

import (
	"context"
	"time"

	"github.com/NodeOps-app/sandbox/database"
)

// Device is one row of the devices table — a registered user machine
// identified by its WireGuard pubkey, holding a permanent CGNAT IP.
type Device struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Pubkey     []byte     `json:"pubkey"` // raw 32-byte Curve25519 pubkey
	ClientIP   string     `json:"client_ip"`
	Hostname   *string    `json:"hostname,omitempty"`
	OS         *string    `json:"os,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// DeviceNetwork is a persistent attachment row (device ↔ network).
type DeviceNetwork struct {
	DeviceID   string    `json:"device_id"`
	NetworkID  string    `json:"network_id"`
	AttachedAt time.Time `json:"attached_at"`
}

// DeviceSession is a live WG tunnel binding a device to a specific relay.
type DeviceSession struct {
	ID           string    `json:"id"`
	DeviceID     string    `json:"device_id"`
	RelayHostID  string    `json:"relay_host_id"`
	EndpointAddr *string   `json:"endpoint_addr,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// RelaySessionPeer is the per-tick projection the relay reconciler uses
// to rebuild its wg-devices peer list.
type RelaySessionPeer struct {
	SessionID string
	Pubkey    []byte
	ClientIP  string
	ExpiresAt time.Time
}

// AssignDeviceIP allocates the next CGNAT /32 in the user's region.
// Returns "" if the per-region /18 is exhausted.
func AssignDeviceIP(ctx context.Context, d *database.Db, region string) (string, error) {
	q, err := query(d, "assignDeviceIP")
	if err != nil {
		return "", err
	}
	var ip string
	return ip, d.Con.QueryRow(ctx, q, region).Scan(&ip)
}

func CreateDevice(ctx context.Context, d *database.Db, rec Device) (*Device, error) {
	q, err := query(d, "createDevice")
	if err != nil {
		return nil, err
	}
	var out Device
	err = d.Con.QueryRow(ctx, q,
		rec.ID, rec.UserID, rec.Name, rec.Pubkey, rec.ClientIP, rec.Hostname, rec.OS,
	).Scan(
		&out.ID, &out.UserID, &out.Name, &out.Pubkey, &out.ClientIP,
		&out.Hostname, &out.OS, &out.CreatedAt, &out.LastSeenAt, &out.RevokedAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func GetDevice(ctx context.Context, d *database.Db, id string) (*Device, error) {
	q, err := query(d, "getDevice")
	if err != nil {
		return nil, err
	}
	var out Device
	err = d.Con.QueryRow(ctx, q, id).Scan(
		&out.ID, &out.UserID, &out.Name, &out.Pubkey, &out.ClientIP,
		&out.Hostname, &out.OS, &out.CreatedAt, &out.LastSeenAt, &out.RevokedAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func GetDeviceForUser(ctx context.Context, d *database.Db, id, userID string) (*Device, error) {
	q, err := query(d, "getDeviceForUser")
	if err != nil {
		return nil, err
	}
	var out Device
	err = d.Con.QueryRow(ctx, q, id, userID).Scan(
		&out.ID, &out.UserID, &out.Name, &out.Pubkey, &out.ClientIP,
		&out.Hostname, &out.OS, &out.CreatedAt, &out.LastSeenAt, &out.RevokedAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func ListDevicesForUser(ctx context.Context, d *database.Db, userID string, limit, offset int) ([]Device, error) {
	q, err := query(d, "listDevicesForUser")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var r Device
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.Name, &r.Pubkey, &r.ClientIP,
			&r.Hostname, &r.OS, &r.CreatedAt, &r.LastSeenAt, &r.RevokedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func CountDevicesForUser(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countDevicesForUser")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID).Scan(&n)
}

// RevokeDevice soft-deletes the device row and hard-deletes attachments
// and sessions in one shot. IP is NOT freed (audit retention); a separate
// GC sweep frees abandoned IPs after a longer grace period.
func RevokeDevice(ctx context.Context, d *database.Db, id, userID string) error {
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	revokeQ, err := query(d, "revokeDevice")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, revokeQ, id, userID); err != nil {
		return err
	}
	delNetQ, err := query(d, "deleteDeviceNetworksForDevice")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, delNetQ, id); err != nil {
		return err
	}
	delSessQ, err := query(d, "deleteDeviceSessionsForDevice")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, delSessQ, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func AttachDeviceToNetwork(ctx context.Context, d *database.Db, deviceID, networkID string) error {
	q, err := query(d, "attachDeviceToNetwork")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, deviceID, networkID)
	return err
}

func DetachDeviceFromNetwork(ctx context.Context, d *database.Db, deviceID, networkID string) error {
	q, err := query(d, "detachDeviceFromNetwork")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, deviceID, networkID)
	return err
}

// DeviceNetworkView pairs a Network with the attached_at timestamp.
type DeviceNetworkView struct {
	Network    Network   `json:"network"`
	AttachedAt time.Time `json:"attached_at"`
}

func ListNetworksForDevice(ctx context.Context, d *database.Db, deviceID string) ([]DeviceNetworkView, error) {
	q, err := query(d, "listNetworksForDevice")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceNetworkView
	for rows.Next() {
		var v DeviceNetworkView
		if err := rows.Scan(
			&v.Network.ID, &v.Network.Name, &v.Network.Owner, &v.Network.VNI,
			&v.Network.CreatedAt, &v.Network.DeletedAt, &v.AttachedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func CreateDeviceSession(ctx context.Context, d *database.Db, rec DeviceSession) (*DeviceSession, error) {
	q, err := query(d, "createDeviceSession")
	if err != nil {
		return nil, err
	}
	var out DeviceSession
	err = d.Con.QueryRow(ctx, q,
		rec.ID, rec.DeviceID, rec.RelayHostID, rec.EndpointAddr, rec.ExpiresAt,
	).Scan(
		&out.ID, &out.DeviceID, &out.RelayHostID, &out.EndpointAddr,
		&out.CreatedAt, &out.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func GetDeviceSession(ctx context.Context, d *database.Db, id string) (*DeviceSession, error) {
	q, err := query(d, "getDeviceSession")
	if err != nil {
		return nil, err
	}
	var out DeviceSession
	err = d.Con.QueryRow(ctx, q, id).Scan(
		&out.ID, &out.DeviceID, &out.RelayHostID, &out.EndpointAddr,
		&out.CreatedAt, &out.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func DeleteDeviceSession(ctx context.Context, d *database.Db, id, deviceID string) error {
	q, err := query(d, "deleteDeviceSession")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, deviceID)
	return err
}

// GetActiveSessionForDevice returns the device's most recent unexpired
// session, or (nil, pgx.ErrNoRows) if none. Used by the session-create
// handler for sticky-relay-per-device on reconnect.
func GetActiveSessionForDevice(ctx context.Context, d *database.Db, deviceID string) (*DeviceSession, error) {
	q, err := query(d, "getActiveSessionForDevice")
	if err != nil {
		return nil, err
	}
	var out DeviceSession
	err = d.Con.QueryRow(ctx, q, deviceID).Scan(
		&out.ID, &out.DeviceID, &out.RelayHostID, &out.EndpointAddr,
		&out.CreatedAt, &out.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RenewDeviceSession slides expires_at forward to NOW + ttlSecs. Scoped
// on (id, deviceID). Returns (nil, pgx.ErrNoRows) when the session no
// longer exists — caller surfaces as 404 so the CLI tears down its
// now-orphan tunnel instead of pretending it still works.
func RenewDeviceSession(ctx context.Context, d *database.Db, id, deviceID string, ttlSecs int) (*DeviceSession, error) {
	q, err := query(d, "renewDeviceSession")
	if err != nil {
		return nil, err
	}
	var out DeviceSession
	err = d.Con.QueryRow(ctx, q, id, deviceID, ttlSecs).Scan(
		&out.ID, &out.DeviceID, &out.RelayHostID, &out.EndpointAddr,
		&out.CreatedAt, &out.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func ListSessionsForDevice(ctx context.Context, d *database.Db, deviceID string) ([]DeviceSession, error) {
	q, err := query(d, "listSessionsForDevice")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceSession
	for rows.Next() {
		var s DeviceSession
		if err := rows.Scan(
			&s.ID, &s.DeviceID, &s.RelayHostID, &s.EndpointAddr,
			&s.CreatedAt, &s.ExpiresAt,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListSessionsForRelay is the relay reconciler's hot path. Returns
// active (pubkey, client_ip) tuples to populate wg-devices peers.
func ListSessionsForRelay(ctx context.Context, d *database.Db, relayHostID string) ([]RelaySessionPeer, error) {
	q, err := query(d, "listSessionsForRelay")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, relayHostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RelaySessionPeer
	for rows.Next() {
		var p RelaySessionPeer
		if err := rows.Scan(&p.SessionID, &p.Pubkey, &p.ClientIP, &p.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PickLeastLoadedRelay returns the relay host id in `region` with the
// fewest active sessions, or "" if no relay is registered in that region.
func PickLeastLoadedRelay(ctx context.Context, d *database.Db, region string) (string, error) {
	q, err := query(d, "pickLeastLoadedRelay")
	if err != nil {
		return "", err
	}
	var id string
	err = d.Con.QueryRow(ctx, q, region).Scan(&id)
	return id, err
}

// PickLeastLoadedRelayAnyRegion returns the fleet-wide least-loaded
// active relay, preferring same-region rows if any exist. Used only as
// a fallback during initial multi-region bring-up; the caller decides
// when to invoke it based on config.
func PickLeastLoadedRelayAnyRegion(ctx context.Context, d *database.Db, preferredRegion string) (string, error) {
	q, err := query(d, "pickLeastLoadedRelayAnyRegion")
	if err != nil {
		return "", err
	}
	var id string
	err = d.Con.QueryRow(ctx, q, preferredRegion).Scan(&id)
	return id, err
}

// DevicePair is one (src_ip, dst_ip) allowed pair returned by
// ListDevicePairsForRelay — used by the relay to populate fc_vmip_pair.
type DevicePair struct {
	SrcIP string
	DstIP string
}

// ListDevicePairsForRelay returns ordered (a, b) pairs of device IPs
// where both devices have an active session on this relay AND share at
// least one network. Symmetric (both directions returned).
func ListDevicePairsForRelay(ctx context.Context, d *database.Db, relayHostID string) ([]DevicePair, error) {
	q, err := query(d, "listDevicePairsForRelay")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, relayHostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DevicePair
	for rows.Next() {
		var p DevicePair
		if err := rows.Scan(&p.SrcIP, &p.DstIP); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListDeviceVMPairsForRelay returns symmetric (device_ip, vm_ip) pairs
// for every (device, VM) where the device has an active session on this
// relay AND they share at least one network. Used by the relay to allow
// device↔VM traffic through fc_wg_ingress on wg-devices.
func ListDeviceVMPairsForRelay(ctx context.Context, d *database.Db, relayHostID string) ([]DevicePair, error) {
	q, err := query(d, "listDeviceVMPairsForRelay")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, relayHostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DevicePair
	for rows.Next() {
		var p DevicePair
		if err := rows.Scan(&p.SrcIP, &p.DstIP); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListSubnetsForDeviceNetworks returns the union of host VM subnets
// reachable from this device — used to fill AllowedIPs on the wg-quick
// config we hand to the client.
func ListSubnetsForDeviceNetworks(ctx context.Context, d *database.Db, deviceID string) ([]string, error) {
	q, err := query(d, "listSubnetsForDeviceNetworks")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		out = append(out, cidr)
	}
	return out, rows.Err()
}

// ExpireDeviceSessions deletes sessions past TTL and returns the device
// IDs of those sessions so the caller can kick reconcilers.
func ExpireDeviceSessions(ctx context.Context, d *database.Db) ([]string, error) {
	q, err := query(d, "expireDeviceSessions")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
