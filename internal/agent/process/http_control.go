package process

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

const (
	maxHTTPInputBytes      = 256 << 10
	defaultHTTPGracePeriod = time.Second
	maxHTTPGracePeriod     = time.Minute
)

type inputHTTPRequest struct {
	DataBase64 string `json:"data_base64"`
}

type inputHTTPResponse struct {
	InputSeq uint64 `json:"input_seq"`
}

type resizeHTTPRequest struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

type signalHTTPRequest struct {
	Signal string `json:"signal"`
}

func (h *HTTPHandler) control(response http.ResponseWriter, request *http.Request, route httpRoute) {
	switch route.Action {
	case "input":
		h.writeInput(response, request, route)
	case "stdin/close":
		if err := h.manager.CloseStdin(request.Context(), route.ID); err != nil {
			writeHTTPControlError(response, err)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	case "resize":
		h.resizePTY(response, request, route)
	case "signal":
		h.signal(response, request, route)
	default:
		http.NotFound(response, request)
	}
}

func (h *HTTPHandler) writeInput(response http.ResponseWriter, request *http.Request, route httpRoute) {
	var body inputHTTPRequest
	if err := decodeHTTPJSON(response, request, &body); err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	data, err := base64.StdEncoding.DecodeString(body.DataBase64)
	if err != nil || len(data) > maxHTTPInputBytes {
		writeHTTPError(response, http.StatusBadRequest, "invalid_input")
		return
	}
	receipt, err := h.manager.WriteInput(request.Context(), route.ID, data)
	if err != nil {
		writeHTTPControlError(response, err)
		return
	}
	_ = writeHTTPJSON(response, http.StatusOK, inputHTTPResponse{InputSeq: receipt.Seq})
}

func (h *HTTPHandler) resizePTY(response http.ResponseWriter, request *http.Request, route httpRoute) {
	var body resizeHTTPRequest
	if err := decodeHTTPJSON(response, request, &body); err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.manager.ResizePTY(route.ID, body.Rows, body.Cols); err != nil {
		writeHTTPControlError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *HTTPHandler) signal(response http.ResponseWriter, request *http.Request, route httpRoute) {
	var body signalHTTPRequest
	if err := decodeHTTPJSON(response, request, &body); err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	signal, ok := httpSignals[body.Signal]
	if !ok {
		writeHTTPError(response, http.StatusBadRequest, "invalid_signal")
		return
	}
	if err := h.manager.Signal(route.ID, signal); err != nil {
		writeHTTPControlError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *HTTPHandler) terminate(response http.ResponseWriter, request *http.Request, route httpRoute) {
	grace, err := parseHTTPGracePeriod(request)
	if err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_grace_period")
		return
	}
	details, err := h.manager.TerminateProcess(request.Context(), route.ID, grace)
	if err != nil {
		log.Printf("agent.process event=terminate_failed process_id=%s error=%q", route.ID, err)
		writeHTTPControlError(response, err)
		return
	}
	_ = writeHTTPJSON(response, http.StatusOK, details)
}

func parseHTTPGracePeriod(request *http.Request) (time.Duration, error) {
	text := request.URL.Query().Get("grace_ms")
	if text == "" {
		return defaultHTTPGracePeriod, nil
	}
	millis, err := strconv.ParseUint(text, 10, 64)
	if err != nil || millis > uint64(maxHTTPGracePeriod/time.Millisecond) {
		return 0, errors.New("invalid grace period")
	}
	return time.Duration(millis) * time.Millisecond, nil
}

func writeHTTPControlError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrProcessNotFound):
		writeHTTPError(response, http.StatusNotFound, "process_not_found")
	case errors.Is(err, ErrWrongMode):
		writeHTTPError(response, http.StatusConflict, "wrong_process_kind")
	case errors.Is(err, ErrProcessExited):
		writeHTTPError(response, http.StatusConflict, "process_exited")
	case errors.Is(err, ErrStdinClosed):
		writeHTTPError(response, http.StatusConflict, "stdin_closed")
	case errors.Is(err, context.DeadlineExceeded):
		writeHTTPError(response, http.StatusRequestTimeout, "operation_timeout")
	case errors.Is(err, context.Canceled):
		writeHTTPError(response, http.StatusRequestTimeout, "operation_cancelled")
	default:
		writeHTTPError(response, http.StatusInternalServerError, "process_control_failed")
	}
}

var httpSignals = map[string]syscall.Signal{
	"SIGHUP":   syscall.SIGHUP,
	"SIGINT":   syscall.SIGINT,
	"SIGQUIT":  syscall.SIGQUIT,
	"SIGKILL":  syscall.SIGKILL,
	"SIGTERM":  syscall.SIGTERM,
	"SIGUSR1":  syscall.SIGUSR1,
	"SIGUSR2":  syscall.SIGUSR2,
	"SIGWINCH": syscall.SIGWINCH,
}
