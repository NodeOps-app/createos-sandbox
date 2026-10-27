package builder

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestSandboxRunnerBoundsAndSharesLogState(t *testing.T) {
	t.Parallel()
	for _, required := range [][]byte{
		[]byte("MAX_LOG_BYTES=$((1024 * 1024))"),
		[]byte("MAX_LOG_CHUNK_BYTES=$((32 * 1024))"),
		[]byte("MAX_LOG_LINES=10000"),
		[]byte(`read -r last_byte sent_bytes sent_lines truncation_sent < "$LOG_STATE"`),
		[]byte(`flock 9`),
		[]byte("flush_logs()"),
		[]byte("build log truncated after"),
	} {
		if !bytes.Contains(sandboxRunner, required) {
			t.Fatalf("sandbox runner missing log-budget contract %q", required)
		}
	}

	cmd := exec.Command("/bin/sh", "-n")
	cmd.Stdin = bytes.NewReader(sandboxRunner)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandbox runner syntax: %v: %s", err, out)
	}
}
