package wg

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LoadOrCreateKey reads a 32-byte Curve25519 private key from path, or
// generates a fresh one and persists it. Mode 0600. Idempotent — safe to
// call on every host start.
//
// Defends against drift: if an operator (or a copy/restore) widened the
// perms on an existing key file, log loudly and re-tighten to 0600.
func LoadOrCreateKey(path string) (wgtypes.Key, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) == wgtypes.KeyLen {
		var k wgtypes.Key
		copy(k[:], b)
		if info, serr := os.Stat(path); serr == nil {
			if mode := info.Mode().Perm(); mode != 0o600 {
				log.Warnf("[wg] private key %q had insecure permissions %o; tightening to 0600", path, mode)
				if cerr := os.Chmod(path, 0o600); cerr != nil {
					log.Warnf("[wg] chmod 0600 %q: %v", path, cerr)
				}
			}
		}
		return k, nil
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate WG private key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return wgtypes.Key{}, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, k[:], 0o600); err != nil {
		return wgtypes.Key{}, fmt.Errorf("write WG key %s: %w", path, err)
	}
	return k, nil
}
