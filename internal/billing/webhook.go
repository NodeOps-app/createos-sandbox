// Package billing delivers sandbox lifecycle events to the configured
// external billing webhook. See docs (plan) and queries.sql section
// "billing event outbox" for the surrounding design.
package billing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/NodeOps-app/sandbox/internal/hmacsign"
)

// Webhook is the delivery client. One per process; safe for concurrent
// use (http.Client is goroutine-safe).
type Webhook struct {
	URL    string
	Secret []byte
	Client *http.Client
}

// New constructs a Webhook with sensible defaults. Empty url returns a
// zero-value Webhook whose Deliver always errors — caller should
// short-circuit on len(URL)==0 instead.
func New(url, secret string) *Webhook {
	return &Webhook{
		URL:    url,
		Secret: []byte(secret),
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    16,
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

// Sign returns the X-CreateOS-Signature header value for `body` at `ts`.
// Thin shim over hmacsign.Sign so the webhook and createos client both
// produce identical signatures.
func (w *Webhook) Sign(body []byte, ts time.Time) string {
	return hmacsign.Sign(w.Secret, body, ts)
}

// Deliver POSTs one event to the webhook. Returns:
//   - nil on 2xx (caller marks delivered)
//   - PermanentError on 4xx except 408/429 (caller stops retrying)
//   - RetryableError on 408/429/5xx/transport (caller bumps attempts)
func (w *Webhook) Deliver(ctx context.Context, eventID, eventType string, body []byte) error {
	if w == nil || w.Client == nil || w.URL == "" {
		return &RetryableError{Inner: fmt.Errorf("billing webhook is not configured")}
	}
	now := time.Now().UTC()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return &RetryableError{Inner: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CreateOS-Event-Id", eventID)
	req.Header.Set("X-CreateOS-Event-Type", eventType)
	req.Header.Set("X-CreateOS-Timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("X-CreateOS-Signature", w.Sign(body, now))

	resp, err := w.Client.Do(req)
	if err != nil {
		return &RetryableError{Inner: err}
	}
	defer resp.Body.Close()

	// Read up to 4 KiB of body for the error message — we want the
	// receiver's error in the outbox for debugging, but bounded so a
	// misbehaving billing system can't OOM us.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout, // 408
		resp.StatusCode == http.StatusTooManyRequests, // 429
		resp.StatusCode >= 500:
		return &RetryableError{
			Inner: fmt.Errorf("%d %s: %s", resp.StatusCode, resp.Status, truncate(respBody, 256)),
		}
	default:
		return &PermanentError{
			Inner: fmt.Errorf("%d %s: %s", resp.StatusCode, resp.Status, truncate(respBody, 256)),
		}
	}
}

// RetryableError signals the worker should bump attempts and try again
// later (5xx, network errors, 408, 429).
type RetryableError struct{ Inner error }

func (e *RetryableError) Error() string { return e.Inner.Error() }
func (e *RetryableError) Unwrap() error { return e.Inner }

// PermanentError signals the worker should stop retrying (4xx other
// than 408/429 — billing-system bug or schema mismatch).
type PermanentError struct{ Inner error }

func (e *PermanentError) Error() string { return e.Inner.Error() }
func (e *PermanentError) Unwrap() error { return e.Inner }

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
