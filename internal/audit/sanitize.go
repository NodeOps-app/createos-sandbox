package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/ssh"
)

// HashToken: unkeyed sha256 so audit consumers can correlate
// "this key did X" without needing the api_keys.key_hash pepper.
func HashToken(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func FingerprintSSH(authorizedKey string) string {
	authorizedKey = strings.TrimSpace(authorizedKey)
	if authorizedKey == "" {
		return ""
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(pk.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func SSHKeyType(authorizedKey string) string {
	authorizedKey = strings.TrimSpace(authorizedKey)
	if authorizedKey == "" {
		return ""
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return ""
	}
	return pk.Type()
}

func SSHKeyComment(authorizedKey string) string {
	authorizedKey = strings.TrimSpace(authorizedKey)
	if authorizedKey == "" {
		return ""
	}
	_, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return ""
	}
	return comment
}

// First line only, capped — multi-line errors and stack traces have
// historically leaked secrets (paths in panics, env-var dumps in stderr).
func TruncateError(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const maxLen = 240
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}
