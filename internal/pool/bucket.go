package pool

import (
	"fmt"
	"time"

	"github.com/NodeOps-app/createos-sandbox/config"
)

// bucketNames are the 24 hourly UTC bucket keys ("00" .. "23").
var bucketNames = func() [24]string {
	var names [24]string
	for i := 0; i < 24; i++ {
		names[i] = fmt.Sprintf("%02d", i)
	}
	return names
}()

func (p *Pool) currentBucket() (string, config.PoolBucket) {
	now := p.now()
	name := bucketNameForHour(now.UTC().Hour())
	bucket := p.cfg.Buckets[name]
	for i, window := range p.cfg.WeeklyWindows {
		local := now.In(window.Timezone)
		sinceMidnight := time.Duration(local.Hour())*time.Hour +
			time.Duration(local.Minute())*time.Minute +
			time.Duration(local.Second())*time.Second
		if local.Weekday() == window.Weekday &&
			sinceMidnight >= window.Start && sinceMidnight < window.End {
			bucket.Target = window.Target
			return fmt.Sprintf("weekly-%d", i), bucket
		}
	}
	return name, bucket
}

// bucketNameForHour is split out so tests can drive it without a Pool.
func bucketNameForHour(h int) string {
	return fmt.Sprintf("%02d", h)
}

func validateBuckets(m map[string]config.PoolBucket) error {
	for _, n := range bucketNames {
		if _, ok := m[n]; !ok {
			return fmt.Errorf("pool: missing bucket %q (24 hourly UTC keys 00..23 required)", n)
		}
	}
	return nil
}
