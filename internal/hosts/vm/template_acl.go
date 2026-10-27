package vm

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/NodeOps-app/sandbox/models"
)

// setfacl performs a read-modify-write of the file ACL. Serialize all ACL
// changes so concurrent starts using the same template cannot lose grants.
var (
	templateACLmu      sync.Mutex
	securedTemplateACL = make(map[string]struct{})
)

func isTemplateRootfs(name string) bool {
	return strings.HasPrefix(name, models.TemplateIDPrefix)
}

// grantTemplateAccess removes stale grants for this reusable slot UID from
// every cached template, then grants read-only access to the selected image.
func (m *Manager) grantTemplateAccess(name, path string, uid uint32) error {
	if uid == 0 {
		return nil
	}
	templateACLmu.Lock()
	defer templateACLmu.Unlock()

	m.RootfsesMu.RLock()
	entries := make([]string, 0, len(m.Rootfses))
	for rootfsName, rootfsPath := range m.Rootfses {
		if isTemplateRootfs(rootfsName) {
			entries = append(entries, rootfsPath)
		}
	}
	m.RootfsesMu.RUnlock()
	uidText := strconv.FormatUint(uint64(uid), 10)
	for _, candidate := range entries {
		if _, secured := securedTemplateACL[candidate]; !secured {
			// Preserve any named-user grants while removing access for the
			// owning group and everyone else. The ACL mask remains read-only,
			// which is the maximum permission any slot grant may receive.
			out, secureErr := exec.Command("setfacl", "-m", "u::rw-,g::---,o::---,m::r--", "--", candidate).CombinedOutput()
			if secureErr != nil {
				return fmt.Errorf("secure template rootfs ACL path=%s: %w: %s", candidate, secureErr, strings.TrimSpace(string(out)))
			}
			securedTemplateACL[candidate] = struct{}{}
		}
		if candidate == path {
			continue
		}
		// A missing named-user entry is harmless; setfacl reports it as an
		// error, so stale-grant cleanup is deliberately best-effort here.
		_ = exec.Command("setfacl", "-x", "u:"+uidText, "--", candidate).Run()
	}
	if !isTemplateRootfs(name) {
		return nil
	}
	if out, err := exec.Command("setfacl", "-m", "u:"+uidText+":r--", "--", path).CombinedOutput(); err != nil {
		return fmt.Errorf("grant template rootfs ACL uid=%d path=%s: %w: %s", uid, path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func revokeTemplateAccess(name, path string, uid uint32) error {
	if uid == 0 || !isTemplateRootfs(name) || path == "" {
		return nil
	}
	templateACLmu.Lock()
	defer templateACLmu.Unlock()
	out, err := exec.Command("setfacl", "-x", "u:"+strconv.FormatUint(uint64(uid), 10), "--", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("revoke template rootfs ACL uid=%d path=%s: %w: %s", uid, path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RevokeTemplateAccess removes the rootfs grant for a stopped sandbox. The
// Firecracker process must be dead before this is called.
func (m *Manager) RevokeTemplateAccess(sb *Sandbox) error {
	if sb == nil || sb.Net == nil || !isTemplateRootfs(sb.Rootfs) {
		return nil
	}
	path, ok := m.LookupRootfs(sb.Rootfs)
	if !ok {
		return nil
	}
	return revokeTemplateAccess(sb.Rootfs, path, m.SlotUID(sb.Net.VsockCID))
}
