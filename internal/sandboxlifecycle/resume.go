// Package sandboxlifecycle coordinates sandbox state transitions and host RPCs
// shared by the API server and background workers.
package sandboxlifecycle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/hostrpc"
	"github.com/NodeOps-app/sandbox/internal/placementpolicy"
	schedclient "github.com/NodeOps-app/sandbox/internal/scheduler/client"
	"github.com/NodeOps-app/sandbox/models"
)

type ResumeDeps struct {
	Repo     *models.Repo
	Client   *schedclient.Client
	HostHTTP *http.Client
	Region   string
}

// KickoffResume owns background resume orchestration: claim the paused row,
// ask the scheduler for a host ID, then pass that ID to hostrpc.Resume.
func KickoffResume(ctx context.Context, d ResumeDeps, id string) error {
	if d.Client == nil {
		return errors.New("scheduler not configured")
	}
	rec, err := d.Repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if rec == nil {
		return errors.New("row vanished")
	}
	if rec.Region != "" && d.Region != "" && rec.Region != d.Region {
		return fmt.Errorf("resume region mismatch: sandbox %s is region %q, this control is %q", id, rec.Region, d.Region)
	}
	status, err := d.Repo.MarkResuming(ctx, id, false, time.Now().UTC())
	if err != nil {
		return err
	}
	if status == "" {
		log.WithContext(ctx).Infof("[resume] %s aborted: row no longer paused (concurrent destroy/resume)", id)
		return nil
	}
	region := rec.Region
	if region == "" {
		region = d.Region
	}
	request, buildErr := placementpolicy.BuildResumeScheduleRequest(
		ctx, d.Repo, rec, placementpolicy.ResumeScheduleOpts{Region: region},
	)
	if buildErr != nil {
		message := buildErr.Error()
		_, _ = d.Repo.MarkResumeExhausted(ctx, id, &message)
		return buildErr
	}
	placement, err := d.Client.Schedule(ctx, request)
	if err != nil || placement == nil {
		message := fmt.Sprintf("scheduler: %v", err)
		_, _ = d.Repo.MarkResumeExhausted(ctx, id, &message)
		if err != nil {
			return err
		}
		return errors.New("scheduler returned no placement")
	}
	hostID := placement.HostID
	if err := d.Repo.SetSandboxHost(ctx, id, &hostID); err != nil {
		message := "set resume host: " + err.Error()
		_, _ = d.Repo.MarkResumeExhausted(ctx, id, &message)
		return err
	}
	rec.HostID = &hostID
	rec.Status = models.StatusResuming
	response, err := hostrpc.Resume(ctx, d.Repo, d.HostHTTP, hostID, rec)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("host returned %d", response.StatusCode)
	}
	return nil
}
