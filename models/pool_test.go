package models

import (
	"context"
	"flag"
	"testing"

	"github.com/NodeOps-app/createos-sandbox/database"
)

var poolTestDSN = flag.String("pool-test-dsn", "", "disposable PostgreSQL database for pool ownership regression")

func TestPoolShrinkClaimRace(t *testing.T) {
	if *poolTestDSN == "" {
		t.Skip("requires -pool-test-dsn for isolated PostgreSQL")
	}
	ctx := context.Background()
	db, err := database.OpenDbWithPoolConfig(ctx, *poolTestDSN, database.PoolConfig{MinConns: 1, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Temporary tables are private to this connection and disappear on close.
	_, err = db.Con.Exec(ctx, `CREATE TEMP TABLE sandboxes(id text PRIMARY KEY,created_by text,status text); CREATE TEMP TABLE sandbox_access_tokens(sandbox_id text); INSERT INTO sandboxes VALUES ('claimed','pool','running'),('unclaimed','pool','running'); INSERT INTO sandbox_access_tokens VALUES ('claimed'),('unclaimed')`)
	if err != nil {
		t.Fatal(err)
	}
	var staleOwner string
	if err := db.Con.QueryRow(ctx, "SELECT created_by FROM sandboxes WHERE id='claimed'").Scan(&staleOwner); err != nil {
		t.Fatal(err)
	}
	// Force the exact ordering: shrink reads pool ownership, then the user claims.
	if _, err := db.Con.Exec(ctx, "UPDATE sandboxes SET created_by='tenant' WHERE id='claimed'"); err != nil {
		t.Fatal(err)
	}
	repo := &Repo{DB: db}
	status, err := repo.MarkPoolDestroying(ctx, "claimed", staleOwner)
	if err != nil || status != "" {
		t.Fatalf("claimed sandbox transitioned: status=%q err=%v", status, err)
	}
	var owner, current string
	var tokens int
	if err := db.Con.QueryRow(ctx, "SELECT created_by,status FROM sandboxes WHERE id='claimed'").Scan(&owner, &current); err != nil {
		t.Fatal(err)
	}
	if err := db.Con.QueryRow(ctx, "SELECT count(*) FROM sandbox_access_tokens WHERE sandbox_id='claimed'").Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if owner != "tenant" || current != "running" || tokens != 1 {
		t.Fatalf("claim damaged: %s %s tokens=%d", owner, current, tokens)
	}
	status, err = repo.MarkPoolDestroying(ctx, "unclaimed", PoolUserID)
	if err != nil || status != "destroying" {
		t.Fatalf("pool shrink failed: %q %v", status, err)
	}
	if err := db.Con.QueryRow(ctx, "SELECT count(*) FROM sandbox_access_tokens WHERE sandbox_id='unclaimed'").Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatalf("pool token not revoked: %d", tokens)
	}
	// A shrink that wins first removes the row from the running pool-claim set.
	tag, err := db.Con.Exec(ctx, "UPDATE sandboxes SET created_by='tenant' WHERE id='unclaimed' AND created_by='pool' AND status='running'")
	if err != nil || tag.RowsAffected() != 0 {
		t.Fatalf("claimed destroying row: %v", err)
	}
	status, err = repo.MarkPoolDestroying(ctx, "unclaimed", PoolUserID)
	if err != nil || status != "" {
		t.Fatalf("duplicate shrink: %q %v", status, err)
	}
}
