package proto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const CheckpointIDParam = "checkpoint"

// ValidateCheckpointID prevents route separators from entering internal URLs.
// IDs use 128 random bits, matching the managed-process opaque ID convention.
func ValidateCheckpointID(id string) error {
	if !strings.HasPrefix(id, "cp_") {
		return errors.New("invalid checkpoint id")
	}
	raw := strings.TrimPrefix(id, "cp_")
	if len(raw) != base64.RawURLEncoding.EncodedLen(16) {
		return errors.New("invalid checkpoint id")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != 16 {
		return errors.New("invalid checkpoint id")
	}
	return nil
}

// CheckpointCreateReq selects a directory inside the authenticated sandbox.
// Names are optional, non-unique labels. Parentage is resolved from the live
// directory by the agent, never accepted from the caller.
type CheckpointCreateReq struct {
	Path string  `json:"path"`
	Name *string `json:"name,omitempty"`
}

// DirectoryCheckpoint describes file history, not a VM memory snapshot.
// Storage layer paths are private to the agent and must not enter this DTO.
type DirectoryCheckpoint struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Name      *string   `json:"name,omitempty"`
	ParentID  *string   `json:"parent_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CheckpointRestoreResp identifies the restored view. Restore uses the original
// directory recorded by the agent; clients cannot redirect it to another path.
type CheckpointRestoreResp struct {
	CheckpointID string `json:"checkpoint_id"`
	Path         string `json:"path"`
}

// ValidateCheckpointName is shared by control and the guest trust boundary.
func ValidateCheckpointName(name *string) error {
	if name == nil {
		return nil
	}
	s := *name
	if len(s) > 63 {
		return errors.New("name must be at most 63 characters")
	}
	alphaNum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	if s == "" {
		return nil
	}
	if !alphaNum(s[0]) || !alphaNum(s[len(s)-1]) {
		return errors.New("name must start and end with a letter or number")
	}
	for i := range s {
		if !alphaNum(s[i]) && s[i] != '-' && s[i] != '_' {
			return errors.New("name may contain only letters, numbers, hyphens and underscores")
		}
	}
	return nil
}

// Checkpoint RPCs share the existing authenticated exec connection. A distinct
// line prefix keeps them separate from public exec JSON and shell commands.
const (
	CheckpointRequestPrefix = "CHECKPOINT "
	CheckpointActionCreate  = "create"
	CheckpointActionList    = "list"
	CheckpointActionDelete  = "delete"
	CheckpointActionRestore = "restore"
)

type CheckpointAgentRequest struct {
	Action string               `json:"action"`
	ID     string               `json:"id,omitempty"`
	Create *CheckpointCreateReq `json:"create,omitempty"`
}

type CheckpointAgentResponse struct {
	Status int             `json:"status"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}
