package models

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

var auditDSNFile = flag.String("audit-dev-dsn-file", "", "explicit dev DSN file for isolated audit fixtures")

func auditDB(t *testing.T) (context.Context, *database.Db) {
	t.Helper()
	if *auditDSNFile == "" {
		t.Skip("dev PostgreSQL fixture only")
	}
	raw, err := os.ReadFile(*auditDSNFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	base, err := pgx.Connect(ctx, strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("connect dev fixture failed")
	}
	schema := fmt.Sprintf("audit_three_%d", time.Now().UnixNano())
	if _, err = base.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_, err := base.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
		if err != nil {
			t.Error(err)
		}
		base.Close(cleanupCtx)
	})
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("application_name", schema)
	u.RawQuery = q.Encode()
	d, err := database.OpenDbWithPoolConfig(ctx, u.String(), database.PoolConfig{MinConns: 1, MaxConns: 4})
	if err != nil {
		t.Fatal("open isolated DB failed")
	}
	t.Cleanup(d.Close)
	_, err = d.Con.Exec(ctx, `CREATE TABLE regions(name text PRIMARY KEY,slot_index integer); CREATE TABLE device_ip_allocator(region text PRIMARY KEY,next_index bigint);
 CREATE TABLE devices (LIKE public.devices INCLUDING ALL);
 CREATE TABLE disks (LIKE public.disks INCLUDING ALL);
 CREATE TABLE sandboxes(id text PRIMARY KEY,status text,forked_from text);
 CREATE TABLE sandbox_disks(sandbox_id text,disk_id text,mount_path text,sub_path text,created_at timestamptz,PRIMARY KEY(sandbox_id,disk_id,mount_path));
 INSERT INTO regions VALUES ('audit',0); INSERT INTO device_ip_allocator VALUES ('audit',1);`)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, d
}
func auditRegister(ctx context.Context, d *database.Db, rec Device) (*Device, error) {
	return CreateDevice(ctx, d, rec, "audit")
}

func TestAuditRejectedDeviceAllocation(t *testing.T) {
	ctx, d := auditDB(t)
	rec := Device{ID: "dev_audit_a", UserID: "audit-user", Name: "same-name", Pubkey: make([]byte, 32)}
	if _, err := auditRegister(ctx, d, rec); err != nil {
		t.Fatal(err)
	}
	var before, after int64
	if err := d.Con.QueryRow(ctx, "SELECT next_index FROM device_ip_allocator WHERE region='audit'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r := rec
		r.ID = fmt.Sprintf("dev_audit_%d", i)
		r.Pubkey = make([]byte, 32)
		r.Pubkey[0] = byte(i + 1)
		if _, err := auditRegister(ctx, d, r); err == nil {
			t.Fatal("duplicate accepted")
		}
	}
	if err := d.Con.QueryRow(ctx, "SELECT next_index FROM device_ip_allocator WHERE region='audit'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	t.Logf("allocator before=%d after=%d rejected=3", before, after)
	if before != after {
		t.Fatalf("rejected requests consumed %d IPs", after-before)
	}
	// A different name with the same key must roll back too.
	duplicateKey := rec
	duplicateKey.ID = "dev_audit_key"
	duplicateKey.Name = "other-name"
	if _, err := auditRegister(ctx, d, duplicateKey); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if err := d.Con.QueryRow(ctx, "SELECT next_index FROM device_ip_allocator WHERE region='audit'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("duplicate key consumed an IP")
	}
	valid := rec
	valid.ID = "dev_audit_valid"
	valid.Name = "valid-name"
	valid.Pubkey = make([]byte, 32)
	valid.Pubkey[0] = 99
	out, err := auditRegister(ctx, d, valid)
	if err != nil {
		t.Fatal(err)
	}
	if out.ClientIP != "100.64.0.2" {
		t.Fatalf("next successful allocation=%s", out.ClientIP)
	}
	if _, err = d.Con.Exec(ctx, "UPDATE device_ip_allocator SET next_index=1048576 WHERE region='audit'"); err != nil {
		t.Fatal(err)
	}
	valid.ID = "dev_audit_full"
	valid.Name = "full-name"
	if _, err = auditRegister(ctx, d, valid); !errors.Is(err, ErrDeviceIPExhausted) {
		t.Fatalf("exhaustion: %v", err)
	}
	if err := d.Con.QueryRow(ctx, "SELECT next_index FROM device_ip_allocator WHERE region='audit'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 1048576 {
		t.Fatal("exhausted allocation advanced counter")
	}
	t.Log("duplicate name/key, valid allocation, and exhaustion rollback passed")
}
func TestAuditDiskAttachDeleteRace(t *testing.T) {
	ctx, d := auditDB(t)
	rec := &Disk{ID: "disk_audit", UserID: "audit-user", Name: "audit", Kind: "s3", Config: []byte(`{}`), Credentials: []byte(`{}`)}
	if err := InsertDisk(ctx, d, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Con.Exec(ctx, "INSERT INTO sandboxes(id,status) VALUES ('sb-audit','running')"); err != nil {
		t.Fatal(err)
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	query, _ := d.GetQuery("attachDiskIfRunning")
	var running, inserted, exists bool
	if err = tx.QueryRow(ctx, query, "sb-audit", rec.ID, "/mnt/audit", "").Scan(&running, &inserted, &exists); err != nil {
		t.Fatal(err)
	}
	if !running || !inserted || !exists {
		t.Fatal("attach fixture did not insert")
	}
	result := make(chan error, 1)
	go func() { result <- DeleteDisk(ctx, d, "audit-user", rec.ID) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		err = d.Con.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("delete did not wait for attach lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-result
	var deleted bool
	if e := d.Con.QueryRow(ctx, "SELECT deleted_at IS NOT NULL FROM disks WHERE id=$1", rec.ID).Scan(&deleted); e != nil {
		t.Fatal(e)
	}
	t.Logf("delete error=%v attached_disk_deleted=%v", err, deleted)
	if !errors.Is(err, ErrDiskAttached) || deleted {
		t.Fatal("concurrent attachment was missed")
	}
	if err := DeleteDisk(ctx, d, "another-user", rec.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ownership: %v", err)
	}
	if _, err = d.Con.Exec(ctx, "DELETE FROM sandbox_disks WHERE disk_id=$1", rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDisk(ctx, d, "audit-user", rec.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.Con.QueryRow(ctx, query, "sb-audit", rec.ID, "/mnt/audit", "").Scan(&running, &inserted, &exists); err != nil {
		t.Fatal(err)
	}
	if inserted || exists {
		t.Fatal("attachment accepted deleted disk")
	}
	t.Log("wrong owner rejected, unattached deletion succeeded, deleted disk attach rejected")
}

// Exercise tombstones with retained memberships: deleting one network must
// remove its permissions without revoking access through another live network.
func TestAuditDeletedNetworkRelayPermissions(t *testing.T) {
	ctx, d := auditDB(t)
	exec := func(sql string) {
		t.Helper()
		if _, err := d.Con.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TABLE networks(id text PRIMARY KEY,name text,owner text,vni bigint,created_at timestamptz DEFAULT now(),deleted_at timestamptz);
 CREATE TABLE device_networks(device_id text,network_id text);
 CREATE TABLE device_sessions(id text,device_id text,relay_host_id text,expires_at timestamptz);
 CREATE TABLE sandbox_networks(sandbox_id text,network_id text);
 CREATE TABLE hosts(id text,subnet_cidr text);
 ALTER TABLE sandboxes ADD COLUMN ip text, ADD COLUMN host_id text;
 INSERT INTO networks(id,name,owner,vni) VALUES ('net-audit','deleted','audit-user',1),('net-live','live','audit-user',2);`)
	for i, id := range []string{"dev-a", "dev-b"} {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		if _, err := auditRegister(ctx, d, Device{ID: id, UserID: "audit-user", Name: id, Pubkey: key}); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO device_networks VALUES ('dev-a','net-audit'),('dev-b','net-audit');
 INSERT INTO device_sessions VALUES ('sa','dev-a','relay-audit',now()+interval '1 hour'),('sb','dev-b','relay-audit',now()+interval '1 hour');`)
	check := func(label string, wantDevices, wantVMs, wantRoutes int) {
		t.Helper()
		pairs, err := ListDevicePairsForRelay(ctx, d, "relay-audit")
		if err != nil {
			t.Fatal(err)
		}
		vms, err := ListDeviceVMPairsForRelay(ctx, d, "relay-audit")
		if err != nil {
			t.Fatal(err)
		}
		routes, err := ListSubnetsForDeviceNetworks(ctx, d, "dev-a")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: device pairs=%d VM pairs=%d routes=%d", label, len(pairs), len(vms), len(routes))
		if len(pairs) != wantDevices || len(vms) != wantVMs || len(routes) != wantRoutes {
			t.Errorf("%s: want %d/%d/%d", label, wantDevices, wantVMs, wantRoutes)
		}
	}
	check("before deletion", 2, 0, 0)
	if err := DeleteNetwork(ctx, d, "audit-user", "net-audit"); err != nil {
		t.Fatal(err)
	}
	check("after deletion", 0, 0, 0)
	// Old membership rows can arrive after the tombstone through replication.
	exec(`INSERT INTO hosts VALUES ('host-audit','10.0.0.0/24');
 INSERT INTO sandboxes(id,status,ip,host_id) VALUES ('sb-audit','running','10.0.0.2','host-audit');
 INSERT INTO sandbox_networks VALUES ('sb-audit','net-audit');`)
	check("stale VM membership", 0, 0, 0)
	exec(`INSERT INTO device_networks VALUES ('dev-a','net-live'),('dev-b','net-live');
 INSERT INTO sandbox_networks VALUES ('sb-audit','net-live');`)
	check("another live network", 2, 4, 1)
}

func TestAuditDeadHostEviction(t *testing.T) {
	ctx, d := auditDB(t)
	exec := func(sql string) {
		t.Helper()
		if _, err := d.Con.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`ALTER TABLE sandboxes ADD COLUMN host_id text, ADD COLUMN region text, ADD COLUMN destroyed_at timestamptz, ADD COLUMN note text;
 ALTER TABLE sandbox_disks ADD COLUMN mount_status text, ADD COLUMN mount_error text;
 CREATE TABLE sandbox_networks(sandbox_id text);
 CREATE TABLE sandbox_access_tokens(sandbox_id text);
 CREATE TABLE hosts(id text PRIMARY KEY,region text,status text,last_seen timestamptz);
 CREATE TABLE snapshots(sandbox_id text,status text,captured_at timestamptz,deleted_at timestamptz);`)
	cutoff := time.Now().Add(-time.Hour)
	for _, tc := range []struct {
		name, change string
		want         bool
	}{
		{"still dead", "", true},
		{"recovered host", "UPDATE hosts SET status='active',last_seen=now()", false},
		{"heartbeat while waiting for host lock", "UPDATE hosts SET status='active',last_seen=now()", false},
		{"fresh heartbeat", "UPDATE hosts SET last_seen=now()", false},
		{"moved sandbox", "UPDATE sandboxes SET host_id='other-host'", false},
		{"paused sandbox", "UPDATE sandboxes SET status='paused'", false},
		{"foreign host", "UPDATE hosts SET region='us'", false},
		{"foreign sandbox", "UPDATE sandboxes SET region='us'", false},
		{"pending capture", "INSERT INTO snapshots VALUES ('sb-audit','creating',NULL,NULL)", false},
		{"completed capture", "INSERT INTO snapshots VALUES ('sb-audit','creating',now(),NULL)", true},
		{"creating sandbox", "UPDATE sandboxes SET status='creating'", true},
		{"destroying sandbox", "UPDATE sandboxes SET status='destroying'", true},
		{"resuming sandbox", "UPDATE sandboxes SET status='resuming'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(`TRUNCATE sandboxes,hosts,snapshots,sandbox_networks,sandbox_access_tokens;
 INSERT INTO hosts VALUES ('host-audit','eu','dead',now()-interval '2 hours');
 INSERT INTO sandboxes(id,status,host_id,region) VALUES ('sb-audit','running','host-audit','eu');
 INSERT INTO sandbox_networks VALUES ('sb-audit'); INSERT INTO sandbox_access_tokens VALUES ('sb-audit');`)
			tx, err := d.Con.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			lock := "SELECT id FROM sandboxes WHERE id='sb-audit' FOR UPDATE"
			if tc.name == "heartbeat while waiting for host lock" {
				lock = "SELECT id FROM hosts WHERE id='host-audit' FOR UPDATE"
			}
			if _, err = tx.Exec(ctx, lock); err != nil {
				t.Fatal(err)
			}
			if tc.change != "" {
				if _, err = tx.Exec(ctx, tc.change); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() {
				changed, err := MarkSandboxDestroyedOnDeadHost(ctx, d, "sb-audit", "host-audit", "eu", cutoff, time.Now(), nil, nil)
				if err == nil && changed != tc.want {
					err = fmt.Errorf("changed=%v want=%v", changed, tc.want)
				}
				result <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var waiting bool
				if err = d.Con.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("eviction did not wait on sandbox lock")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err != nil {
				t.Error(err)
			}
			var destroyed bool
			var memberships, tokens int
			if err = d.Con.QueryRow(ctx, `SELECT status='destroyed',(SELECT count(*) FROM sandbox_networks),(SELECT count(*) FROM sandbox_access_tokens) FROM sandboxes WHERE id='sb-audit'`).Scan(&destroyed, &memberships, &tokens); err != nil {
				t.Fatal(err)
			}
			t.Logf("destroyed=%v memberships=%d tokens=%d", destroyed, memberships, tokens)
			if destroyed != tc.want {
				t.Errorf("destroyed=%v want=%v", destroyed, tc.want)
			}
			if !tc.want && (memberships != 1 || tokens != 1) {
				t.Error("rejected eviction removed resources")
			}
			if tc.want {
				changed, err := MarkSandboxDestroyedOnDeadHost(ctx, d, "sb-audit", "host-audit", "eu", cutoff, time.Now(), nil, nil)
				if err != nil || changed {
					t.Errorf("repeat eviction changed=%v err=%v", changed, err)
				}
			}

		})
	}
}

// A failing billing write must roll back lifecycle and resource cleanup together.
func TestAuditDeadHostEvictionBillingRollback(t *testing.T) {
	ctx, d := auditDB(t)
	_, err := d.Con.Exec(ctx, `ALTER TABLE sandboxes ADD COLUMN host_id text, ADD COLUMN region text, ADD COLUMN destroyed_at timestamptz, ADD COLUMN note text;
 ALTER TABLE sandbox_disks ADD COLUMN mount_status text, ADD COLUMN mount_error text;
 CREATE TABLE sandbox_networks(sandbox_id text); CREATE TABLE sandbox_access_tokens(sandbox_id text);
 CREATE TABLE hosts(id text PRIMARY KEY,region text,status text,last_seen timestamptz);
 CREATE TABLE snapshots(sandbox_id text,status text,captured_at timestamptz,deleted_at timestamptz);
 INSERT INTO hosts VALUES ('h','eu','dead',now()-interval '2 hours');
 INSERT INTO sandboxes(id,status,host_id,region) VALUES ('s','running','h','eu');
 INSERT INTO sandbox_networks VALUES ('s'); INSERT INTO sandbox_access_tokens VALUES ('s');`)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	failed := errors.New("injected billing failure")
	emitter := auditEvictionEmitter(func(ctx context.Context, tx pgx.Tx, id, event, prev string) error { calls++; return failed })
	changed, err := MarkSandboxDestroyedOnDeadHost(ctx, d, "s", "h", "eu", time.Now().Add(-time.Hour), time.Now(), nil, emitter)
	if changed || !errors.Is(err, failed) || calls != 1 {
		t.Fatalf("changed=%v error=%v billing_calls=%d", changed, err, calls)
	}
	var intact bool
	if err = d.Con.QueryRow(ctx, `SELECT status='running' AND destroyed_at IS NULL AND EXISTS(SELECT 1 FROM sandbox_networks) AND EXISTS(SELECT 1 FROM sandbox_access_tokens) FROM sandboxes WHERE id='s'`).Scan(&intact); err != nil || !intact {
		t.Fatalf("rollback intact=%v error=%v", intact, err)
	}
	t.Log("billing failure rolled back status, timestamp, memberships and tokens")
}

type auditEvictionEmitter func(context.Context, pgx.Tx, string, string, string) error

func (f auditEvictionEmitter) EmitInTx(ctx context.Context, tx pgx.Tx, id, event, prev string) error {
	return f(ctx, tx, id, event, prev)
}
