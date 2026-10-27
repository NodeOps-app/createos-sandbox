package handlers

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

const shellActivityMaxInterval = time.Minute

// keepInteractiveActivity prevents the idle-pause worker from pausing a
// sandbox while an authenticated shell is attached. The immediate touch
// closes the race with a nearly-expired idle window; later touches are bounded
// to avoid turning terminal input into per-keystroke database traffic.
func (h *Handler) keepInteractiveActivity(sandboxID string, autoPauseSeconds int) func() {
	ctx, cancel := context.WithCancel(context.Background())
	touch := func() {
		touchCtx, touchCancel := context.WithTimeout(ctx, 5*time.Second)
		defer touchCancel()
		if err := h.repo.TouchInteractiveActivity(touchCtx, sandboxID); err != nil && ctx.Err() == nil {
			log.WithError(err).WithField("sandbox_id", sandboxID).
				Warn("[shell] refresh activity")
		}
	}

	touch()
	// Refresh at most once per minute for ordinary configurations. When the
	// sandbox has a shorter auto-pause window, refresh every one-third of that
	// window instead. The one-third interval gives us multiple chances to
	// record activity before the idle-pause worker can consider the sandbox
	// idle, even if one database update is delayed or fails.
	interval := shellActivityMaxInterval
	if autoPauseSeconds > 0 {
		third := time.Duration(autoPauseSeconds) * time.Second / 3
		// Do not create a sub-second database-update loop for very small or
		// accidentally configured auto-pause values.
		if third < time.Second {
			third = time.Second
		}
		if third < interval {
			interval = third
		}
	}

	// Keep touching the activity timestamp for as long as the interactive
	// shell is attached. The returned cancel function closes ctx when the
	// shell disconnects, which stops this goroutine and its ticker.
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				touch()
			case <-ctx.Done():
				return
			}
		}
	}()
	return cancel
}
