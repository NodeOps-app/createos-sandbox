package auditshipper

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/NodeOps-app/createos-sandbox/models"
)

type auditTestTransport func(*http.Request) (*http.Response, error)

func (f auditTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestShipRequiresSignature(t *testing.T) {
	for _, secret := range []string{"", "test-secret"} {
		t.Run("configured="+strconv.FormatBool(secret != ""), func(t *testing.T) {
			sent := false
			w := &Worker{BackendURL: "https://audit.example/events", Secret: []byte(secret)}
			w.HTTP = &http.Client{Transport: auditTestTransport(func(r *http.Request) (*http.Response, error) {
				sent = true
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				ts := r.Header.Get("X-CreateOS-Timestamp")
				if ts == "" {
					t.Fatal("missing timestamp")
				}
				mac := hmac.New(sha256.New, []byte(secret))
				mac.Write([]byte(ts + "."))
				mac.Write(body)
				want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
				if got := r.Header.Get("X-CreateOS-Signature"); got != want {
					t.Fatalf("signature=%q want=%q", got, want)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			})}
			err := w.ship(context.Background(), models.AuditEvent{ID: "test-event"})
			if secret == "" {
				if err == nil || sent {
					t.Fatalf("unsigned delivery: sent=%v err=%v", sent, err)
				}
			} else if err != nil || !sent {
				t.Fatalf("signed delivery: sent=%v err=%v", sent, err)
			}
		})
	}
}
