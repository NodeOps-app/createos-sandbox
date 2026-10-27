package process

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const httpStreamHeartbeat = 5 * time.Second

type outputHTTPEvent struct {
	Type       string       `json:"type"`
	Seq        uint64       `json:"seq,omitempty"`
	Stream     OutputStream `json:"stream,omitempty"`
	DataBase64 string       `json:"data_base64,omitempty"`
	ExitCode   *int         `json:"exit_code,omitempty"`
	Signal     string       `json:"signal,omitempty"`
	Error      string       `json:"error,omitempty"`
	OldestSeq  uint64       `json:"oldest_available_seq,omitempty"`
}

func (h *HTTPHandler) connectProcessOutput(
	response http.ResponseWriter,
	request *http.Request,
	route httpRoute,
) {
	release, err := h.manager.acquireObserver()
	if err != nil {
		writeHTTPConnectError(response, err)
		return
	}
	defer release()

	after, err := parseHTTPOutputSequence(request)
	if err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_output_sequence")
		return
	}
	reader, err := h.manager.ConnectOutput(route.ID, after)
	if err != nil {
		writeHTTPConnectError(response, err)
		return
	}
	prepareNDJSON(response)
	response.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(response).Flush()
	h.streamOutput(request.Context(), response, reader)
}

func (h *HTTPHandler) streamOutput(
	ctx context.Context,
	response http.ResponseWriter,
	reader *OutputReader,
) {
	controller := http.NewResponseController(response)
	for {
		batch, heartbeat, err := nextOutputBatch(ctx, reader)
		if err != nil {
			if ctx.Err() == nil {
				_ = writeNDJSON(response, streamErrorEvent(err))
				_ = controller.Flush()
			}
			return
		}
		if heartbeat {
			if writeNDJSON(response, outputHTTPEvent{Type: "heartbeat"}) != nil || controller.Flush() != nil {
				return
			}
			continue
		}
		for _, event := range batch.Events {
			if err := writeNDJSON(response, outputHTTPEvent{
				Type:       "data",
				Seq:        event.Seq,
				Stream:     event.Stream,
				DataBase64: base64.StdEncoding.EncodeToString(event.Data),
			}); err != nil {
				return
			}
		}
		if batch.Ended {
			exit := outputHTTPEvent{Type: "exit"}
			if batch.Final != nil {
				exit.ExitCode = batch.Final.ExitCode
				exit.Signal = batch.Final.Signal
			}
			_ = writeNDJSON(response, exit)
			_ = controller.Flush()
			return
		}
		if controller.Flush() != nil {
			return
		}
	}
}

func nextOutputBatch(ctx context.Context, reader *OutputReader) (OutputBatch, bool, error) {
	heartbeatContext, cancel := context.WithTimeout(ctx, httpStreamHeartbeat)
	defer cancel()
	batch, err := reader.Next(heartbeatContext)
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return OutputBatch{}, true, nil
	}
	return batch, false, err
}

func parseHTTPOutputSequence(request *http.Request) (uint64, error) {
	text := request.URL.Query().Get("after")
	if text == "" {
		return 0, nil
	}
	return strconv.ParseUint(text, 10, 64)
}

func prepareNDJSON(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "application/x-ndjson")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeNDJSON(writer io.Writer, value any) error {
	return json.NewEncoder(writer).Encode(value)
}

func writeHTTPConnectError(response http.ResponseWriter, err error) {
	var expired *OutputOffsetExpiredError
	if errors.As(err, &expired) {
		_ = writeHTTPJSON(response, http.StatusGone, outputHTTPEvent{
			Type:      "error",
			Error:     "output_offset_expired",
			OldestSeq: expired.OldestAvailable,
		})
		return
	}
	writeHTTPObservationError(response, err)
}

func streamErrorEvent(err error) outputHTTPEvent {
	var expired *OutputOffsetExpiredError
	if errors.As(err, &expired) {
		return outputHTTPEvent{
			Type:      "error",
			Error:     "output_offset_expired",
			OldestSeq: expired.OldestAvailable,
		}
	}
	return outputHTTPEvent{Type: "error", Error: "output_stream_failed"}
}
