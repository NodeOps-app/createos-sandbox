package handlers

import (
	"math/rand/v2"
	"strings"

	"github.com/NodeOps-app/createos-sandbox/internal/namesgenerator"
)

// maxSandboxNameLen mirrors the cap enforced by validateSandboxName.
const maxSandboxNameLen = 22

// suffixLen is the length of the random tail appended to every
// auto-generated sandbox name. 4 chars from [a-z0-9] = 36^4 ≈ 1.68M
// combinations per (adjective, surname) pair, taking the effective
// namespace from ~25k to ~42B — collision-free at any realistic burst.
// The suffix is what keeps the [control] "generated name collided,
// retrying" retry loop from firing under N=100+ spawns.
const suffixLen = 4

// suffixAlphabet is the DNS-safe character set for the random tail.
// Lowercase letters + digits only — same character class as the
// adjective/surname words, so the whole name remains a valid DNS label.
const suffixAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// generateSandboxName returns a fresh Docker-style
// "<adjective>-<surname>-<4chars>" name drawn from the namesgenerator
// word lists with a random suffix. The upstream package joins with an
// underscore, so we swap '_' for '-' and re-roll if the total (base +
// suffix) exceeds maxSandboxNameLen. Not guaranteed unique — the caller
// persists it under a per-user partial-unique index — but the 36^4
// suffix space makes collisions vanishingly rare in practice.
func generateSandboxName() string {
	for {
		base := strings.ReplaceAll(namesgenerator.GetRandomName(0), "_", "-")
		if len(base)+1+suffixLen > maxSandboxNameLen {
			continue // re-roll: base too long for suffix to fit
		}
		return base + "-" + randomSuffix()
	}
}

// randomSuffix returns a suffixLen-char string over suffixAlphabet.
// math/rand/v2 is thread-safe; the pool of workers under a create
// burst can call this concurrently without a shared lock.
func randomSuffix() string {
	var b [suffixLen]byte
	for i := range b {
		b[i] = suffixAlphabet[rand.IntN(len(suffixAlphabet))]
	}
	return string(b[:])
}
