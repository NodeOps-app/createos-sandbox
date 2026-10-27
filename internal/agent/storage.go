package agent

import (
	"encoding/json"
	"net/http"
	"syscall"
)

type storageResp struct {
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
}

func handleStorage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		http.Error(w, "statfs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Bavail (not Bfree) — root-reserved blocks don't count as free to userspace.
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	free := st.Bavail * bsize
	var used uint64
	if total > free {
		used = total - free
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(storageResp{
		TotalBytes: total,
		FreeBytes:  free,
		UsedBytes:  used,
	})
}
