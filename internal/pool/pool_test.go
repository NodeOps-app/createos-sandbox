package pool

import (
	"fmt"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/config"
)

func TestBucketNameForHour(t *testing.T) {
	for h := 0; h < 24; h++ {
		want := fmt.Sprintf("%02d", h)
		if got := bucketNameForHour(h); got != want {
			t.Errorf("bucketNameForHour(%d) = %q, want %q", h, got, want)
		}
	}
}

func TestCurrentBucket(t *testing.T) {
	buckets := allBuckets(1)
	buckets["09"] = config.PoolBucket{Target: 9, RefillInterval: time.Second}
	buckets["17"] = config.PoolBucket{Target: 17, RefillInterval: time.Second}

	cases := []struct {
		at         time.Time
		wantName   string
		wantTarget int
	}{
		{time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), "00", 1},
		{time.Date(2026, 1, 2, 0, 59, 0, 0, time.UTC), "00", 1},
		{time.Date(2026, 1, 2, 1, 0, 0, 0, time.UTC), "01", 1},
		{time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC), "09", 9},
		{time.Date(2026, 1, 2, 9, 59, 0, 0, time.UTC), "09", 9},
		{time.Date(2026, 1, 2, 17, 0, 0, 0, time.UTC), "17", 17},
		{time.Date(2026, 1, 2, 23, 59, 0, 0, time.UTC), "23", 1},
	}
	for _, tc := range cases {
		p := &Pool{
			cfg: config.PoolConfig{Buckets: buckets},
			now: func() time.Time { return tc.at },
		}
		name, b := p.currentBucket()
		if name != tc.wantName {
			t.Errorf("at %s: name=%q, want %q", tc.at.Format(time.RFC3339), name, tc.wantName)
		}
		if b.Target != tc.wantTarget {
			t.Errorf("at %s: target=%d, want %d", tc.at.Format(time.RFC3339), b.Target, tc.wantTarget)
		}
	}
}

func TestCurrentBucketNonUTC(t *testing.T) {
	// 08:00 in a +10 zone → UTC hour 22.
	loc := time.FixedZone("plus10", 10*3600)
	at := time.Date(2026, 1, 2, 8, 0, 0, 0, loc)
	p := &Pool{cfg: config.PoolConfig{Buckets: allBuckets(1)}, now: func() time.Time { return at }}
	name, _ := p.currentBucket()
	if name != "22" {
		t.Errorf("non-UTC now: got bucket %q, want 22", name)
	}
}

func TestCurrentBucketWeeklyWindow(t *testing.T) {
	ist := time.FixedZone("IST", 5*60*60+30*60)
	cfg := config.PoolConfig{
		Buckets: allBuckets(10),
		WeeklyWindows: []config.PoolWeeklyWindow{{
			Weekday: time.Friday, Timezone: ist,
			Start: 15 * time.Hour, End: 23 * time.Hour, Target: 150,
		}},
	}
	cases := []struct {
		at         time.Time
		wantTarget int
	}{
		{time.Date(2026, 10, 16, 9, 29, 59, 0, time.UTC), 10},
		{time.Date(2026, 10, 16, 9, 30, 0, 0, time.UTC), 150},
		{time.Date(2026, 10, 16, 17, 29, 59, 0, time.UTC), 150},
		{time.Date(2026, 10, 16, 17, 30, 0, 0, time.UTC), 10},
		{time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC), 10},
	}
	for _, tc := range cases {
		p := &Pool{cfg: cfg, now: func() time.Time { return tc.at }}
		_, got := p.currentBucket()
		if got.Target != tc.wantTarget {
			t.Errorf("at %s: target=%d, want %d", tc.at, got.Target, tc.wantTarget)
		}
	}
}

func TestValidateBuckets(t *testing.T) {
	if err := validateBuckets(allBuckets(1)); err != nil {
		t.Fatalf("full map: unexpected err %v", err)
	}
	for _, missing := range bucketNames {
		m := allBuckets(1)
		delete(m, missing)
		if err := validateBuckets(m); err == nil {
			t.Errorf("missing %q: expected error, got nil", missing)
		}
	}
}

func TestGrowShrinkMath(t *testing.T) {
	cases := []struct {
		name         string
		depth        int
		target       int
		perTickCap   int
		wantGrow     int
		wantShrinkEx int
	}{
		{"empty pool, small target", 0, 3, 5, 3, 0},
		{"empty pool, large target hits cap", 0, 20, 5, 5, 0},
		{"at target", 3, 3, 5, 0, 0},
		{"over target within cap", 8, 5, 5, 0, 3},
		{"over target above cap", 20, 5, 5, 0, 5},
		{"under target within cap", 2, 4, 5, 2, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var grow int
			if gap := tc.target - tc.depth; gap > 0 {
				grow = gap
				if grow > tc.perTickCap {
					grow = tc.perTickCap
				}
			}
			var shrinkEx int
			if tc.depth > tc.target {
				shrinkEx = tc.depth - tc.target
				if shrinkEx > tc.perTickCap {
					shrinkEx = tc.perTickCap
				}
			}
			if grow != tc.wantGrow {
				t.Errorf("grow=%d, want %d", grow, tc.wantGrow)
			}
			if shrinkEx != tc.wantShrinkEx {
				t.Errorf("shrinkEx=%d, want %d", shrinkEx, tc.wantShrinkEx)
			}
		})
	}
}

func allBuckets(target int) map[string]config.PoolBucket {
	m := make(map[string]config.PoolBucket, 24)
	for h := 0; h < 24; h++ {
		m[fmt.Sprintf("%02d", h)] = config.PoolBucket{Target: target, RefillInterval: time.Second}
	}
	return m
}
