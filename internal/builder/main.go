// Package builder implements the control builder service: a long-lived
// loop that claims pending template builds from Postgres, dispatches a
// disposable CreateOS sandbox per claim, and finalises the row when it exits.
package builder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/buildqueue"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
)

// Config bundles the runtime knobs Service.Run needs.
type Config struct {
	BuilderID          string
	ControlURL         string
	BuildTimeout       time.Duration
	GlobalConcurrency  int
	PerUserConcurrency int
	PollInterval       time.Duration
	JanitorInterval    time.Duration
	SizeCapMiB         int64
	AllowedBases       []string
}

// Service wires the queue, per-build grants, and sandbox executor into the main loop.
type Service struct {
	cfg    Config
	queue  buildqueue.Queue
	grants *GrantIssuer
	exec   Executor
	clk    func() time.Time

	// in-process accounting
	mu       sync.Mutex
	inflight map[string]int      // userID -> running build count
	active   map[string]struct{} // template IDs owned by live worker goroutines
	total    int
}

// NewService constructs a Service. The caller wires up dependencies
// (queue, grants, executor) so tests can swap them.
func NewService(cfg Config, q buildqueue.Queue, g *GrantIssuer, executor Executor) *Service {
	if cfg.GlobalConcurrency <= 0 {
		cfg.GlobalConcurrency = 6
	}
	if cfg.PerUserConcurrency <= 0 {
		cfg.PerUserConcurrency = 2
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.JanitorInterval <= 0 {
		cfg.JanitorInterval = 60 * time.Second
	}
	if cfg.BuildTimeout <= 0 {
		cfg.BuildTimeout = 10 * time.Minute
	}
	if cfg.SizeCapMiB <= 0 {
		cfg.SizeCapMiB = 5120
	}
	return &Service{
		cfg:      cfg,
		queue:    q,
		grants:   g,
		exec:     executor,
		clk:      func() time.Time { return time.Now().UTC() },
		inflight: map[string]int{},
		active:   map[string]struct{}{},
	}
}

// Run blocks until ctx is cancelled. Spawns the janitor goroutine and
// runs the main poll loop.
func (s *Service) Run(ctx context.Context) error {
	go s.janitor(ctx)

	tick := time.NewTicker(s.cfg.PollInterval)
	defer tick.Stop()
	log.WithContext(ctx).Infof("[builder] starting; global=%d per_user=%d poll=%s",
		s.cfg.GlobalConcurrency, s.cfg.PerUserConcurrency, s.cfg.PollInterval)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			s.tryDispatch(ctx)
		}
	}
}

func (s *Service) tryDispatch(ctx context.Context) {
	s.mu.Lock()
	if s.total >= s.cfg.GlobalConcurrency {
		s.mu.Unlock()
		return
	}
	blocked := s.usersAtCapLocked()
	s.mu.Unlock()

	job, err := s.queue.Claim(ctx, blocked)
	if errors.Is(err, buildqueue.ErrEmpty) {
		return
	}
	if err != nil {
		log.WithContext(ctx).Warnf("[builder] queue.Claim: %v", err)
		return
	}

	// Validate Dockerfile in-process. Failed validation flips the row
	// to 'failed' immediately without a sandbox ever being created.
	if _, vErr := ValidateDockerfile([]byte(job.Dockerfile), s.cfg.AllowedBases); vErr != nil {
		// Surface the validation error as a single log line in
		// ClickHouse so users see the same diagnostic via
		// `createos-cli templates logs`. The templates row itself only
		// carries terminal status — error text isn't mirrored.
		s.logValidationFailure(ctx, job.TplID, vErr)
		_ = s.queue.Complete(ctx, job.TplID, buildqueue.Outcome{Status: buildqueue.StatusFailed})
		log.WithContext(ctx).Infof("[builder] %s: validation failed: %v", job.TplID, vErr)
		return
	}

	s.mu.Lock()
	s.total++
	s.inflight[job.UserID]++
	s.active[job.TplID] = struct{}{}
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.total--
			delete(s.active, job.TplID)
			s.inflight[job.UserID]--
			if s.inflight[job.UserID] == 0 {
				delete(s.inflight, job.UserID)
			}
			s.mu.Unlock()
		}()
		s.runOneBuild(ctx, *job)
	}()
}

func (s *Service) buildIsActive(tplID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.active[tplID]
	return ok
}

func (s *Service) usersAtCapLocked() []string {
	if s.cfg.PerUserConcurrency <= 0 {
		return nil
	}
	var out []string
	for u, n := range s.inflight {
		if n >= s.cfg.PerUserConcurrency {
			out = append(out, u)
		}
	}
	return out
}

// runOneBuild owns the lifecycle of a single dispatched job.
func (s *Service) runOneBuild(parent context.Context, job buildqueue.Job) {
	// BuildTimeout is the single execution deadline. The janitor's extra five
	// minutes are only crash-detection grace and must not extend guest runtime.
	ctx, cancel := context.WithTimeout(parent, s.cfg.BuildTimeout)
	defer cancel()
	tplID := job.TplID
	log.WithContext(parent).Infof("[builder] %s: dispatching build", tplID)

	// Mint credentials scoped to this template build. The sandbox API key
	// remains in the builder process and is never copied into the guest.
	grants, err := s.grants.Issue(ctx, tplID)
	if err != nil {
		s.failBuild(ctx, tplID, "issue grants: "+err.Error())
		return
	}

	if err := s.exec.Run(ctx, BuildSpec{
		TplID:      tplID,
		Dockerfile: job.Dockerfile,
		Grants:     grants,
		ControlURL: s.cfg.ControlURL,
		SizeCapMiB: s.cfg.SizeCapMiB,
	}); err != nil {
		s.failBuild(ctx, tplID, "sandbox build: "+err.Error())
		return
	}

	// The runner has already PATCHed ready using its scoped JWT. This is
	// an idempotent confirmation in case that response was lost.
	_ = s.queue.Complete(ctx, tplID, buildqueue.Outcome{Status: buildqueue.StatusReady})
	log.WithContext(parent).Infof("[builder] %s: build succeeded", tplID)
}

// failBuild flips the row to 'failed'. Idempotent: if the runner
// already PATCHed the row first, our CAS misses harmlessly.
func (s *Service) failBuild(ctx context.Context, tplID, msg string) {
	_ = s.queue.Complete(ctx, tplID, buildqueue.Outcome{Status: buildqueue.StatusFailed})
	log.WithContext(ctx).Warnf("[builder] %s: %s", tplID, msg)
}

// janitor runs immediately and then every JanitorInterval. It fails builds
// older than BuildTimeout plus five minutes and, when the executor supports
// SandboxJanitor, cleans up orphaned build sandboxes. Active local workers
// retain ownership of their cleanup. Failed builds are not re-enqueued.
func (s *Service) janitor(ctx context.Context) {
	tick := time.NewTicker(s.cfg.JanitorInterval)
	defer tick.Stop()
	s.runJanitorPass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.runJanitorPass(ctx)
		}
	}
}

func (s *Service) runJanitorPass(ctx context.Context) {
	cutoff := s.cfg.BuildTimeout + 5*time.Minute
	failed, err := s.queue.Reap(ctx, cutoff)
	if err != nil {
		log.WithContext(ctx).Warnf("[builder] janitor reap: %v", err)
		return
	}
	if len(failed) > 0 {
		log.WithContext(ctx).Warnf("[builder] janitor: marked %d stuck builds failed: %v", len(failed), failed)
	}

	cleaner, ok := s.exec.(SandboxJanitor)
	if !ok {
		return
	}
	sandboxes, err := cleaner.ListBuildSandboxes(ctx)
	if err != nil {
		log.WithContext(ctx).Warnf("[builder] janitor list sandboxes: %v", err)
		return
	}
	for _, sandbox := range sandboxes {
		// The live worker owns cleanup until Executor.Run returns. The runner
		// can mark its template ready shortly before its process exits; deleting
		// here would race the worker's wait request and manufacture a 502.
		if s.buildIsActive(sandbox.TemplateID) {
			continue
		}
		terminal, err := s.queue.Terminal(ctx, sandbox.TemplateID)
		if err != nil {
			log.WithContext(ctx).Warnf("[builder] janitor template %s: %v", sandbox.TemplateID, err)
			continue
		}
		if !terminal && sandbox.ProcessID != "" {
			finished, inspectErr := cleaner.BuildProcessFinished(ctx, sandbox)
			if inspectErr != nil {
				log.WithContext(ctx).Warnf("[builder] janitor inspect process %s: %v", sandbox.ProcessID, inspectErr)
				continue
			}
			if finished {
				if err := s.queue.Complete(ctx, sandbox.TemplateID, buildqueue.Outcome{Status: buildqueue.StatusFailed}); err != nil {
					log.WithContext(ctx).Warnf("[builder] janitor fail finished build %s: %v", sandbox.TemplateID, err)
					continue
				}
				terminal = true
			}
		}
		if !terminal {
			// A missing process label is the create→label crash gap. Do not
			// guess a process; the database timeout will make it terminal.
			continue
		}
		if err := cleaner.DestroyBuildSandbox(ctx, sandbox.ID); err != nil {
			log.WithContext(ctx).Warnf("[builder] janitor destroy sandbox %s: %v", sandbox.ID, err)
			continue
		}
		log.WithContext(ctx).Infof("[builder] janitor: deleted terminal build sandbox %s for %s", sandbox.ID, sandbox.TemplateID)
	}
}

// logValidationFailure ships a single line to control's log-ingest
// endpoint so users see WHY validation rejected via `createos-cli templates
// logs`. The builder uses the JWT it would have minted for the runner
// — same scoping (sub == tpl_id), one credential.
func (s *Service) logValidationFailure(ctx context.Context, tplID string, vErr error) {
	if s.grants == nil {
		return
	}
	g, err := s.grants.Issue(ctx, tplID)
	if err != nil {
		return
	}
	body := fmt.Sprintf(`{"line":%q,"level":"err"}`, "dockerfile validation failed: "+vErr.Error())
	url := strings.TrimRight(s.cfg.ControlURL, "/") + "/v1/internal/templates/" + tplID + "/log"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+g.JWT)
	req.Header.Set("Content-Type", "application/x-ndjson")
	httpx.SetRequestIDHeader(ctx, req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
