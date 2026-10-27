package agent

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type meminfoResp struct {
	TotalBytes     uint64 `json:"total_bytes"`
	FreeBytes      uint64 `json:"free_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	BuffersBytes   uint64 `json:"buffers_bytes"`
	CachedBytes    uint64 `json:"cached_bytes"`
	// UsedBytes matches `free`'s formula: total - free - buffers - cached.
	UsedBytes uint64 `json:"used_bytes"`
}

func handleMeminfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		http.Error(w, "read /proc/meminfo", http.StatusInternalServerError)
		return
	}
	var out meminfoResp
	for _, line := range strings.Split(string(b), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := line[:colon]
		fields := strings.Fields(line[colon+1:])
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		n *= 1024 // /proc/meminfo is in kB
		switch key {
		case "MemTotal":
			out.TotalBytes = n
		case "MemFree":
			out.FreeBytes = n
		case "MemAvailable":
			out.AvailableBytes = n
		case "Buffers":
			out.BuffersBytes = n
		case "Cached":
			out.CachedBytes = n
		}
	}
	if out.TotalBytes > out.FreeBytes+out.BuffersBytes+out.CachedBytes {
		out.UsedBytes = out.TotalBytes - out.FreeBytes - out.BuffersBytes - out.CachedBytes
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
