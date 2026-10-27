// Host-side dial helpers into the guest agent for values the host can't
// read from cgroups. Every dial injects the per-VM AUTH secret; results
// cached per sandbox so the 10s scraper tick doesn't hammer 500 VMs.

package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

const (
	guestAgentFilePort = 1025
	guestMemTTL        = 60 * time.Second
)

type guestMemSample struct {
	usedBytes uint64
	ts        time.Time
}

type guestStorageSample struct {
	usedBytes, totalBytes uint64
	ts                    time.Time
}

var (
	guestMemMu        sync.Mutex
	guestMemCache     = make(map[string]guestMemSample, 64)
	guestStorageMu    sync.Mutex
	guestStorageCache = make(map[string]guestStorageSample, 64)
)

type guestMemResp struct {
	UsedBytes uint64 `json:"used_bytes"`
}

type guestStorageResp struct {
	TotalBytes uint64 `json:"total_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
}

func (m *Manager) SandboxGuestMemUsedBytes(id string) (uint64, bool) {
	guestMemMu.Lock()
	sample, ok := guestMemCache[id]
	guestMemMu.Unlock()
	if ok && time.Since(sample.ts) < guestMemTTL {
		return sample.usedBytes, true
	}

	m.Mu.RLock()
	sb, alive := m.Sandboxes[id]
	m.Mu.RUnlock()
	if !alive || sb.IP == "" || sb.SecretToken == "" {
		return 0, false
	}

	used, err := dialGuestMeminfo(sb.IP, sb.SecretToken)
	if err != nil {
		if ok {
			return sample.usedBytes, true
		}
		return 0, false
	}
	guestMemMu.Lock()
	guestMemCache[id] = guestMemSample{usedBytes: used, ts: time.Now()}
	guestMemMu.Unlock()
	return used, true
}

func (m *Manager) DropGuestMemCache(id string) {
	guestMemMu.Lock()
	delete(guestMemCache, id)
	guestMemMu.Unlock()
	guestStorageMu.Lock()
	delete(guestStorageCache, id)
	guestStorageMu.Unlock()
}

// SandboxGuestStorage reads statfs("/") from inside the guest. The host
// can't reliably read the overlay ext4 superblock — firecracker's drive
// cache holds guest writes in host page cache without flushing the
// backing file's superblock until VM shutdown.
func (m *Manager) SandboxGuestStorage(id string) (used, total uint64, ok bool) {
	guestStorageMu.Lock()
	sample, hit := guestStorageCache[id]
	guestStorageMu.Unlock()
	if hit && time.Since(sample.ts) < guestMemTTL {
		return sample.usedBytes, sample.totalBytes, true
	}

	m.Mu.RLock()
	sb, alive := m.Sandboxes[id]
	m.Mu.RUnlock()
	if !alive || sb.IP == "" || sb.SecretToken == "" {
		return 0, 0, false
	}

	u, t, err := dialGuestStorage(sb.IP, sb.SecretToken)
	if err != nil {
		if hit {
			return sample.usedBytes, sample.totalBytes, true
		}
		return 0, 0, false
	}
	guestStorageMu.Lock()
	guestStorageCache[id] = guestStorageSample{usedBytes: u, totalBytes: t, ts: time.Now()}
	guestStorageMu.Unlock()
	return u, t, true
}

func dialGuestMeminfo(ip, token string) (uint64, error) {
	// DisableKeepAlives: true so this per-call Transport doesn't leave
	// idle persistConn goroutines running after we return. The scraper
	// only probes each sandbox every 60s (guestMemTTL), so keepalive
	// wouldn't be reused across ticks anyway. See sibling fetchDiskStatus
	// (disks.go) for the same pattern.
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 500 * time.Millisecond}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if _, werr := c.Write([]byte(proto.AuthPrefix + token + "\n")); werr != nil {
				c.Close()
				return nil, fmt.Errorf("auth write: %w", werr)
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 1500 * time.Millisecond}
	url := "http://" + net.JoinHostPort(ip, strconv.Itoa(guestAgentFilePort)) + "/meminfo"
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("agent meminfo status %d", resp.StatusCode)
	}
	var body guestMemResp
	if err := decodeGuestProbe(resp.Body, &body); err != nil {
		return 0, err
	}
	return body.UsedBytes, nil
}

func dialGuestStorage(ip, token string) (used, total uint64, err error) {
	// DisableKeepAlives: same reasoning as dialGuestMeminfo — avoid a
	// per-call Transport orphaning its persistConn goroutines.
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 500 * time.Millisecond}
			c, derr := d.DialContext(ctx, network, addr)
			if derr != nil {
				return nil, derr
			}
			if _, werr := c.Write([]byte(proto.AuthPrefix + token + "\n")); werr != nil {
				c.Close()
				return nil, fmt.Errorf("auth write: %w", werr)
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 1500 * time.Millisecond}
	url := "http://" + net.JoinHostPort(ip, strconv.Itoa(guestAgentFilePort)) + "/storage"
	resp, err := client.Get(url)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("agent storage status %d", resp.StatusCode)
	}
	var body guestStorageResp
	if err := decodeGuestProbe(resp.Body, &body); err != nil {
		return 0, 0, err
	}
	return body.UsedBytes, body.TotalBytes, nil
}

// Probe responses contain small status objects, not file contents. Read a
// bounded body before decoding so whitespace and unknown JSON fields cannot
// make the decoder buffer an arbitrarily large guest response.
const maxGuestProbeResponseBytes = 1 << 20

func decodeGuestProbe(r io.Reader, value any) error {
	body, err := io.ReadAll(io.LimitReader(r, maxGuestProbeResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxGuestProbeResponseBytes {
		return fmt.Errorf("guest probe response exceeds %d bytes", maxGuestProbeResponseBytes)
	}
	return json.Unmarshal(body, value)
}
