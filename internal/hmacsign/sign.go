// Package hmacsign produces the shared HMAC-SHA256 signature used for
// HTTP request authentication between createos and external partners
// (billing webhooks outbound, createos credit-API outbound). Both ends
// of the wire compute the same value over "<unix-ts>.<raw-body>" and
// the receiver compares constant-time.
package hmacsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Sign returns "sha256=<hex>" — the canonical X-CreateOS-Signature
// header value. The timestamp is authenticated but this function enforces no
// replay policy: receivers must check freshness and deduplicate as needed.
func Sign(secret, body []byte, ts time.Time) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%d.", ts.Unix())
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
