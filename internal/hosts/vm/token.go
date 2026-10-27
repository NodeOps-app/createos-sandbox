package vm

import (
	"crypto/rand"
	"encoding/hex"
)

// NewSecretToken returns a fresh per-sandbox shared secret as 64 hex chars
// (256 bits of entropy). The host stamps this into MMDS at create time;
// the guest agent stores it after the first MMDS read; every host→agent
// dial then prepends "AUTH <token>\n".
func NewSecretToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failures are unrecoverable on Linux — getrandom(2)
		// can only fail if the kernel is wedged or seccomp blocks it,
		// neither of which we can paper over.
		panic("vm: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
