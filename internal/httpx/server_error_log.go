package httpx

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/utils"
)

// LogServerErrors emits request metadata and a value-free description of the
// request body for failed server requests. Request values are deliberately
// never logged: bodies may contain credentials, environment secrets, API keys,
// or uploaded file contents.
func LogServerErrors(component string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		started := time.Now()
		err := c.Next()
		status := c.Response().StatusCode()
		if ferr, ok := err.(*fiber.Error); ok {
			status = ferr.Code
		} else if err != nil && status < fiber.StatusInternalServerError {
			status = fiber.StatusInternalServerError
		}
		if status < fiber.StatusInternalServerError {
			return err
		}

		errType := "none"
		if err != nil {
			errType = fmt.Sprintf("%T", err)
		}
		bodyBytes := c.Request().Header.ContentLength()
		bodyShape := "binary"
		if c.Method() != fiber.MethodPut || !strings.HasSuffix(c.Path(), "/files") {
			body := c.Body()
			bodyBytes = len(body)
			bodyShape = safeBodyShape(body)
		}
		remoteAddr, peerIdentity := RequestPeer(c)
		log.WithFields(log.Fields{
			"component":   component,
			"request_id":  c.Locals("requestid"),
			"method":      c.Method(),
			"path":        c.Route().Path,
			"remote_addr": remoteAddr,
			"mtls_peer":   peerIdentity,
			"status":      status,
			"duration_ms": float64(time.Since(started).Microseconds()) / 1000,
			"body_bytes":  bodyBytes,
			"body_shape":  bodyShape,
			"user_id":     utils.UserID(c),
			"error_type":  errType,
		}).Error("[http-5xx] request failed")
		return err
	}
}

// RequestPeer returns the actual TCP peer and, when present, the identity from
// its verified mTLS leaf. RemoteAddr is read from the socket rather than from a
// forwarding header, so an untrusted request cannot spoof the diagnostic.
func RequestPeer(c *fiber.Ctx) (remoteAddr, mtlsPeer string) {
	if addr := c.Context().RemoteAddr(); addr != nil {
		remoteAddr = addr.String()
	}
	state := c.Context().TLSConnectionState()
	if state == nil || len(state.PeerCertificates) == 0 {
		return remoteAddr, ""
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.URIs) > 0 {
		return remoteAddr, leaf.URIs[0].String()
	}
	return remoteAddr, "certificate-without-uri-san"
}

// safeBodyShape keeps enough structure to diagnose malformed/unexpected
// requests while ensuring values cannot leak into production logs. Arrays and
// objects retain their field names and sizes; scalar values retain only type.
func safeBodyShape(body []byte) string {
	if len(body) == 0 {
		return "empty"
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return fmt.Sprintf("non_json(bytes=%d)", len(body))
	}
	return describeJSON(value, 0)
}

func describeJSON(value any, depth int) string {
	if depth >= 4 {
		return "<max-depth>"
	}
	switch v := value.(type) {
	case map[string]any:
		parts := make([]string, 0, len(v))
		for key, child := range v {
			parts = append(parts, key+":"+describeJSON(child, depth+1))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		return fmt.Sprintf("array(len=%d)", len(v))
	case string:
		return fmt.Sprintf("string(bytes=%d)", len(v))
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", value)
	}
}
