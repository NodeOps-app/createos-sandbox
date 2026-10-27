package userapikey

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Hasher wraps the HMAC-SHA256 pepper used to derive api_keys.key_hash
// from a user-supplied token. Constructed once at startup and shared
// across goroutines (HMAC instances are not safe for concurrent reuse,
// so each Hash() call builds a fresh one — cheap, ~200 ns).
//
// A zero / nil-pepper Hasher returns nil from Hash(), signalling
// "hashing not configured" to callers. Useful for phase-A rollouts
// where the pepper may not be wired up yet.
type Hasher struct {
	pepper []byte
}

// NewHasher returns a Hasher with the given 32-byte pepper. Empty
// pepper is permitted (Hash returns nil); a non-empty but != 32-byte
// pepper is still accepted (HMAC tolerates any key length) but
// operators are expected to use 32 bytes for parity with the disk
// credential key.
func NewHasher(pepper []byte) *Hasher {
	cp := make([]byte, len(pepper))
	copy(cp, pepper)
	return &Hasher{pepper: cp}
}

// Hash returns HMAC-SHA256(pepper, token). Returns nil when the pepper
// is unconfigured — callers should treat that as "fall back to
// plaintext lookup" during the rollout window.
func (h *Hasher) Hash(token string) []byte {
	if h == nil || len(h.pepper) == 0 {
		return nil
	}
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write([]byte(token))
	return mac.Sum(nil)
}

// Enabled reports whether this Hasher will actually produce a hash.
// Equivalent to checking len(pepper) > 0; provided for callers that
// want to branch on "hashing on" without constructing a real input.
func (h *Hasher) Enabled() bool { return h != nil && len(h.pepper) > 0 }
