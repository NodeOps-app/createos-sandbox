package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/sandboxaccess"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/NodeOps-app/createos-sandbox/models"
)

const sandboxAccessTokenExistsMessage = "sandbox access token already exists"

type sandboxAccessTokenCreateResp struct {
	Token     string     `json:"token"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

type sandboxAccessTokenMetadataResp struct {
	Enabled   bool       `json:"enabled"`
	TokenHint string     `json:"token_hint,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

func sandboxTokenLifecycleBlocked(status models.Status) bool {
	return status == models.StatusDestroying ||
		status == models.StatusDestroyed ||
		status == models.StatusFailed
}

// ownedSandboxForTokenManagement deliberately requires a normal user
// principal. A sandbox principal can never inspect, rotate, disable, or mint
// its own credential.
func (h *Handler) ownedSandboxForTokenManagement(c *fiber.Ctx) (*models.Sandbox, error) {
	if utils.UserIDFromContext(c.UserContext()) == "" {
		return nil, httpx.Fail(c, fiber.StatusForbidden,
			"sandbox access token cannot manage access tokens")
	}
	id := c.Params(middlewares.ParamSandboxID)
	record, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] get sandbox %s: %v", id, err)
		return nil, httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if record == nil || !ownerOK(c, record) {
		return nil, httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return record, nil
}

// forwardSandboxTokenManagementIfRemote keeps access-token lifecycle writes
// on the sandbox's home region. Both regional databases replicate this table,
// but replication is asynchronous: allowing each region to mint or rotate a
// token independently during a partition could return two plaintext tokens
// while conflict resolution eventually retains only one hash. The home region
// is therefore the single writer for create, inspect, rotate, and disable.
//
// The peer receives the caller's API key and repeats normal authentication and
// ownership checks. If it is unavailable, fail closed rather than mutating the
// local replica.
func (h *Handler) forwardSandboxTokenManagementIfRemote(c *fiber.Ctx, record *models.Sandbox) (bool, error) {
	if record.Region == "" || record.Region == h.region {
		return false, nil
	}
	return true, h.forwardToPeerControl(c, record.Region, c.Method(), c.Path())
}

func (h *Handler) HandleSandboxAccessTokenCreate(c *fiber.Ctx) error {
	record, responseErr := h.ownedSandboxForTokenManagement(c)
	if record == nil {
		return responseErr
	}
	if forwarded, err := h.forwardSandboxTokenManagementIfRemote(c, record); forwarded {
		return err
	}
	if sandboxTokenLifecycleBlocked(record.Status) {
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(record.Status))
	}

	plaintext, err := sandboxaccess.Generate()
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] generate sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	digest, err := sandboxaccess.Hash(h.apiKeyHasher, plaintext)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] hash sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	hint, err := sandboxaccess.Hint(plaintext)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] hint sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	createdAt := time.Now().UTC()
	err = h.repo.CreateSandboxAccessToken(c.UserContext(), models.SandboxAccessToken{
		SandboxID: record.ID,
		TokenHash: digest,
		TokenHint: hint,
		CreatedBy: record.CreatedBy,
		CreatedAt: createdAt,
	})
	if errors.Is(err, models.ErrSandboxAccessTokenExists) {
		return httpx.Fail(c, fiber.StatusConflict, sandboxAccessTokenExistsMessage)
	}
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] create sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, sandboxAccessTokenCreateResp{
		Token:     plaintext,
		Enabled:   true,
		CreatedAt: createdAt,
	})
}

func (h *Handler) HandleSandboxAccessTokenGet(c *fiber.Ctx) error {
	record, responseErr := h.ownedSandboxForTokenManagement(c)
	if record == nil {
		return responseErr
	}
	if forwarded, err := h.forwardSandboxTokenManagementIfRemote(c, record); forwarded {
		return err
	}
	token, err := h.repo.GetSandboxAccessToken(c.UserContext(), record.ID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] inspect sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if token == nil {
		return httpx.Success(c, sandboxAccessTokenMetadataResp{Enabled: false})
	}
	return httpx.Success(c, sandboxAccessTokenMetadataResp{
		Enabled:   true,
		TokenHint: token.TokenHint,
		CreatedAt: &token.CreatedAt,
		RotatedAt: token.RotatedAt,
	})
}

func (h *Handler) HandleSandboxAccessTokenRotate(c *fiber.Ctx) error {
	record, responseErr := h.ownedSandboxForTokenManagement(c)
	if record == nil {
		return responseErr
	}
	if forwarded, err := h.forwardSandboxTokenManagementIfRemote(c, record); forwarded {
		return err
	}
	if sandboxTokenLifecycleBlocked(record.Status) {
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(record.Status))
	}

	plaintext, err := sandboxaccess.Generate()
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] rotate generate sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	digest, err := sandboxaccess.Hash(h.apiKeyHasher, plaintext)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] rotate hash sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	hint, err := sandboxaccess.Hint(plaintext)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] rotate hint sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	rotatedAt := time.Now().UTC()
	token, err := h.repo.RotateSandboxAccessToken(c.UserContext(), record.ID, digest, hint, rotatedAt)
	if errors.Is(err, models.ErrSandboxAccessTokenNotFound) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox access token not found")
	}
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] rotate sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, sandboxAccessTokenCreateResp{
		Token:     plaintext,
		Enabled:   true,
		CreatedAt: token.CreatedAt,
		RotatedAt: token.RotatedAt,
	})
}

func (h *Handler) HandleSandboxAccessTokenDelete(c *fiber.Ctx) error {
	record, responseErr := h.ownedSandboxForTokenManagement(c)
	if record == nil {
		return responseErr
	}
	if forwarded, err := h.forwardSandboxTokenManagementIfRemote(c, record); forwarded {
		return err
	}
	if _, err := h.repo.DeleteSandboxAccessToken(c.UserContext(), record.ID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[sandbox-access-token] delete sandbox=%s: %v", record.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, sandboxAccessTokenMetadataResp{Enabled: false})
}
