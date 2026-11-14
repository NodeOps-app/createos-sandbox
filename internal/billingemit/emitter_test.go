package billingemit

import (
	"context"
	"testing"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// fakeShapesProvider is a tiny stand-in for the DB-backed shape cache
// so shapeMillicores can be unit-tested without bringing up Postgres.
type fakeShapesProvider struct{ list []proto.Shape }

func (f fakeShapesProvider) Shapes(context.Context) []proto.Shape { return f.list }

func TestShapeMillicores(t *testing.T) {
	// Catalog matches the seed in migrations_fs/20260612000000_shapes_table.sql
	// for the IDs this test exercises.
	provider := fakeShapesProvider{list: []proto.Shape{
		{ID: "s-1vcpu-256mb", VCPU: 1, MemMib: 256, DefaultDisk: 10240},
		{ID: "s-0.25vcpu-512mb", VCPU: 1, MemMib: 512, DefaultDisk: 10240, CPUQuotaPct: 25},
		{ID: "s-0.5vcpu-1gb", VCPU: 1, MemMib: 1024, DefaultDisk: 10240, CPUQuotaPct: 50},
		{ID: "s-1vcpu-1gb", VCPU: 1, MemMib: 1024, DefaultDisk: 10240},
		{ID: "s-2vcpu-2gb", VCPU: 2, MemMib: 2048, DefaultDisk: 10240},
		{ID: "s-4vcpu-4gb", VCPU: 4, MemMib: 4096, DefaultDisk: 10240},
		{ID: "s-8vcpu-16gb", VCPU: 8, MemMib: 16384, DefaultDisk: 10240},
	}}
	e := &Emitter{Shapes: provider}

	tests := []struct {
		name  string
		shape string
		vcpu  int
		want  int
	}{
		{"burstable 0.25", "s-0.25vcpu-512mb", 1, 250},
		{"burstable 0.5", "s-0.5vcpu-1gb", 1, 500},
		{"dedicated 1vcpu", "s-1vcpu-1gb", 1, 1000},
		{"dedicated 2vcpu", "s-2vcpu-2gb", 2, 2000},
		{"dedicated 4vcpu", "s-4vcpu-4gb", 4, 4000},
		{"dedicated 8vcpu", "s-8vcpu-16gb", 8, 8000},
		{"legacy 256mb", "s-1vcpu-256mb", 1, 1000},
		// Unknown shape falls back to vcpu * 1000 so we never emit zero
		// for a sandbox that somehow carries a shape string not in the
		// catalog (e.g. retired shape on a long-paused VM).
		{"unknown shape uses vcpu fallback", "s-99vcpu-99gb", 3, 3000},
		{"unknown shape vcpu 0 emits 0", "ghost", 0, 0},
		// Empty shape string: same fallback path, must not panic.
		{"empty shape uses vcpu fallback", "", 1, 1000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := e.shapeMillicores(context.Background(), tc.shape, tc.vcpu)
			if got != tc.want {
				t.Errorf("shapeMillicores(%q, %d) = %d, want %d", tc.shape, tc.vcpu, got, tc.want)
			}
		})
	}
}
