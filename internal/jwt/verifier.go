package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PublicKeyResolver returns the public key to verify a JWT against. kid is
// the value from the JWT header (and must match Claims.Iss; the verifier
// enforces that). Returning (nil, nil) means "no such signer" and the
// caller emits 401. Returning (nil, err) means the lookup itself failed
// (e.g. DB error) — caller should emit 503.
type PublicKeyResolver func(kid string) (ed25519.PublicKey, error)

// Verifier validates JWTs minted by some Signer in the cluster. Resolver
// is the strategy that maps `kid` → pubkey; for createos it's typically a
// closure over the host-pubkey cache plus a static map of operator-role
// pubkeys (control, ingress, gateway) loaded from config.
type Verifier struct {
	Resolve PublicKeyResolver
}

// Verify decodes and validates a JWT. Returns the claims on success.
//
// Validation steps (in order):
//
//  1. Parse header.payload.signature — must be exactly 3 base64url segments.
//  2. Decode header — alg must be "EdDSA", typ must be "JWT", kid present.
//  3. Decode payload into Claims.
//  4. Enforce header.kid == Claims.Iss (rfc7515 §4.1.4 says kid is a hint;
//     we make it authoritative-and-must-match the iss claim to prevent any
//     split-brain where the lookup uses one identity and the audit log shows
//     another).
//  5. Resolve the pubkey via Resolve(kid).
//  6. ed25519.Verify the signature.
//  7. Check exp > now-leeway and nbf <= now+leeway.
//
// Caller is responsible for additional claim checks (aud, op, sandbox_id) —
// VerifyExpect helper below does the common case.
func (v *Verifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT: expected 3 segments")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported alg %q (want EdDSA)", hdr.Alg)
	}
	if hdr.Typ != "" && hdr.Typ != "JWT" {
		return nil, fmt.Errorf("unsupported typ %q", hdr.Typ)
	}
	if hdr.Kid == "" {
		return nil, errors.New("header missing kid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	if c.Iss != hdr.Kid {
		return nil, fmt.Errorf("kid/iss mismatch: header=%q payload=%q", hdr.Kid, c.Iss)
	}

	pub, err := v.Resolve(hdr.Kid)
	if err != nil {
		return nil, fmt.Errorf("resolve signer %q: %w", hdr.Kid, err)
	}
	if pub == nil {
		return nil, fmt.Errorf("unknown signer %q", hdr.Kid)
	}
	if len(pub) != ed25519.PublicKeySize {
		// DB drift / corrupted config. Fail closed and let the caller alert.
		return nil, fmt.Errorf("malformed pubkey for %q: got %d bytes, want %d",
			hdr.Kid, len(pub), ed25519.PublicKeySize)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	signedInput := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pub, signedInput, sig) {
		return nil, errors.New("bad signature")
	}

	now := time.Now().UTC().Unix()
	leeway := int64(SkewLeeway / time.Second)
	if c.Exp <= 0 {
		return nil, errors.New("token missing or invalid exp")
	}
	if now > c.Exp+leeway {
		return nil, fmt.Errorf("token expired: exp=%d now=%d", c.Exp, now)
	}
	if c.Nbf != 0 && now+leeway < c.Nbf {
		return nil, fmt.Errorf("token not yet valid: nbf=%d now=%d", c.Nbf, now)
	}

	return &c, nil
}

// VerifyExpect runs Verify and additionally enforces that the claims match
// the expected audience. Pass "" to skip the check. Per-route operation
// authorization happens at the handler level (e.g. RequireSandboxOwner
// for sandbox writes), not in the JWT itself.
func (v *Verifier) VerifyExpect(token, expectedAud string) (*Claims, error) {
	c, err := v.Verify(token)
	if err != nil {
		return nil, err
	}
	if expectedAud != "" && c.Aud != expectedAud {
		return nil, fmt.Errorf("wrong audience: aud=%q want=%q", c.Aud, expectedAud)
	}
	return c, nil
}

// StaticResolver is a convenience PublicKeyResolver that looks up kids in
// an in-memory map. Suitable for control/ingress/gateway pubkeys loaded
// from config at startup. For host pubkeys (which live in Postgres), use
// a closure over the host pubkey cache.
func StaticResolver(keys map[string]ed25519.PublicKey) PublicKeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		return keys[kid], nil
	}
}
