package ingress

import (
	"fmt"
	"os"
	"time"
)

// logTunnelClose emits one structured stdout line per tunnel-close.
// No headers, no body, no token, no host_addr — only fields that are
// safe to surface in logs.
func logTunnelClose(sandboxID string, port int, status int, dur time.Duration, bytesResp int64) {
	fmt.Fprintf(os.Stdout,
		"time=%s sandbox_id=%s port=%d status=%d dur_ms=%d bytes_resp=%d\n",
		time.Now().UTC().Format(time.RFC3339), sandboxID, port, status,
		dur.Milliseconds(), bytesResp)
}
