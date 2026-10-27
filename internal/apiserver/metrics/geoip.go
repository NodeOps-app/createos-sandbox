package metrics

import (
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

// geoipDBHolder wraps the loaded MaxMind reader. nil = GeoIP disabled;
// every lookup then short-circuits to "unknown". Kept behind a mutex so
// a future reload path (SIGHUP, watcher, cron) can swap it atomically.
type geoipDBHolder struct {
	mu sync.RWMutex
	db *maxminddb.Reader
}

var geoDB geoipDBHolder

// LoadGeoIPDB opens the MaxMind mmdb file at path and installs it as
// the process-wide GeoIP source. Empty path or a missing/corrupt file
// is a soft failure: control keeps starting; every Country() call
// returns "unknown". This keeps the metric label stable even on
// operator misconfig — no startup crash from a data-plane concern.
func LoadGeoIPDB(path string) {
	if path == "" {
		return
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		log.Warnf("[metrics] geoip: could not open %s: %v (labels will read \"unknown\")", path, err)
		return
	}
	geoDB.mu.Lock()
	old := geoDB.db
	geoDB.db = r
	geoDB.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	log.Infof("[metrics] geoip: loaded %s", path)
}

// Country returns the ISO 3166-1 alpha-2 country code for ipStr, or
// "unknown" for any parse error, private range, unmapped IP, or when
// no DB is loaded. Callers should use this value directly as a
// Prometheus label — cardinality is bounded to ~250 ISO codes + the
// "unknown" sentinel.
func Country(ipStr string) string {
	if ipStr == "" {
		return "unknown"
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "unknown"
	}
	geoDB.mu.RLock()
	db := geoDB.db
	geoDB.mu.RUnlock()
	if db == nil {
		return "unknown"
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := db.Lookup(ip, &rec); err != nil || rec.Country.ISOCode == "" {
		return "unknown"
	}
	return rec.Country.ISOCode
}
