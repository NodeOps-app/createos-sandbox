package cache

import (
	"errors"
	"testing"
	"time"
)

func TestRootfsEmptyCatalogRecovers(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "expired"}[expired], func(t *testing.T) {
			c := NewRootfs(time.Hour)
			c.Put(&Snapshot{}) // All hosts were dead when the catalog was loaded.
			if expired {
				c.exp = time.Now().Add(-time.Second)
			}
			calls := 0
			load := func() (*Snapshot, error) {
				calls++
				return &Snapshot{Names: []string{"devbox:1"}}, nil
			}
			for i := 0; i < 2; i++ {
				s, err := c.GetOrLoad(load)
				if err != nil || len(s.Names) != 1 || s.Names[0] != "devbox:1" {
					t.Fatalf("recovered catalog = %v, error = %v", s, err)
				}
			}
			if calls != 1 {
				t.Fatalf("load calls = %d; want 1 (healthy catalog remains cached)", calls)
			}
		})
	}
}

func TestRootfsEmptyCatalogRefreshFailure(t *testing.T) {
	c := NewRootfs(time.Hour)
	c.Put(&Snapshot{})
	want := errors.New("database unavailable")
	_, err := c.GetOrLoad(func() (*Snapshot, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatalf("refresh error = %v; want %v", err, want)
	}
}
