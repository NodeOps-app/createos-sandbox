package process

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const maxHTTPWaitTimeout = 30 * time.Second

type waitScope string

const (
	waitLeader waitScope = "leader"
	waitTree   waitScope = "tree"
)

func (h *HTTPHandler) inspect(response http.ResponseWriter, route httpRoute) {
	details, err := h.manager.InspectProcess(route.ID)
	if err != nil {
		writeHTTPObservationError(response, err)
		return
	}
	_ = writeHTTPJSON(response, http.StatusOK, details)
}

func (h *HTTPHandler) wait(response http.ResponseWriter, request *http.Request, route httpRoute) {
	release, err := h.manager.acquireObserver()
	if err != nil {
		writeHTTPObservationError(response, err)
		return
	}
	defer release()

	scope, waitContext, cancel, err := parseHTTPWait(request)
	if err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_wait_options")
		return
	}
	defer cancel()

	var details ProcessDetails
	switch scope {
	case waitLeader:
		details, err = h.manager.WaitProcess(waitContext, route.ID)
	case waitTree:
		details, err = h.manager.WaitProcessTree(waitContext, route.ID)
	default:
		err = errors.New("invalid wait scope")
	}
	if err != nil {
		writeHTTPObservationError(response, err)
		return
	}
	_ = writeHTTPJSON(response, http.StatusOK, details)
}

func parseHTTPWait(request *http.Request) (waitScope, context.Context, context.CancelFunc, error) {
	query := request.URL.Query()
	scope := waitScope(query.Get("scope"))
	if scope == "" {
		scope = waitLeader
	}
	if scope != waitLeader && scope != waitTree {
		return "", nil, nil, errors.New("invalid wait scope")
	}
	timeoutText := query.Get("timeout_ms")
	if timeoutText == "" || timeoutText == "0" {
		// Fiber does not cancel its user context when the downstream client
		// disconnects. Every wait therefore needs a server-owned deadline so an
		// abandoned request cannot retain an observer slot indefinitely.
		ctx, cancel := context.WithTimeout(request.Context(), maxHTTPWaitTimeout)
		return scope, ctx, cancel, nil
	}
	timeoutMillis, err := strconv.ParseUint(timeoutText, 10, 64)
	if err != nil || timeoutMillis > uint64(maxHTTPWaitTimeout/time.Millisecond) {
		return "", nil, nil, errors.New("invalid wait timeout")
	}
	ctx, cancel := context.WithTimeout(request.Context(), time.Duration(timeoutMillis)*time.Millisecond)
	return scope, ctx, cancel, nil
}

func writeHTTPObservationError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrProcessNotFound):
		writeHTTPError(response, http.StatusNotFound, "process_not_found")
	case errors.Is(err, errObserverLimit):
		writeHTTPError(response, http.StatusTooManyRequests, "process_observer_limit_reached")
	case errors.Is(err, context.DeadlineExceeded):
		writeHTTPError(response, http.StatusRequestTimeout, "wait_timeout")
	case errors.Is(err, context.Canceled):
		writeHTTPError(response, http.StatusRequestTimeout, "wait_cancelled")
	default:
		writeHTTPError(response, http.StatusInternalServerError, "process_observation_failed")
	}
}
