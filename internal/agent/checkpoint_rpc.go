package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// handleCheckpointConn runs after the normal per-VM AUTH handshake. It never
// interprets input as a shell command and never opens an additional listener.
func handleCheckpointConn(conn net.Conn, reader *bufio.Reader) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReaderSize(reader, (16<<10)+len(proto.CheckpointRequestPrefix)+1).ReadSlice('\n')
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err != nil || !bytes.HasPrefix(line, []byte(proto.CheckpointRequestPrefix)) {
		writeJSON(conn, proto.CheckpointAgentResponse{Status: http.StatusBadRequest, Error: "invalid checkpoint request"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	reply := guestCheckpoints.request(bytes.TrimPrefix(line, []byte(proto.CheckpointRequestPrefix)))
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	writeJSON(conn, reply)
}

func (m *checkpointManager) request(body []byte) proto.CheckpointAgentResponse {
	fail := func(status int, message string) proto.CheckpointAgentResponse {
		return proto.CheckpointAgentResponse{Status: status, Error: message}
	}
	var req proto.CheckpointAgentRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if len(body) > 16<<10 || dec.Decode(&req) != nil {
		return fail(http.StatusBadRequest, "invalid checkpoint request")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fail(http.StatusBadRequest, "invalid checkpoint request")
	}
	switch req.Action {
	case proto.CheckpointActionCreate:
		if req.Create == nil || req.ID != "" {
			return fail(http.StatusBadRequest, "invalid checkpoint request")
		}
		if req.Create.Name != nil {
			name := strings.TrimSpace(*req.Create.Name)
			req.Create.Name = &name
			if name == "" {
				req.Create.Name = nil
			}
		}
		if err := proto.ValidateCheckpointName(req.Create.Name); err != nil {
			return fail(http.StatusBadRequest, err.Error())
		}
		if len(req.Create.Path) > 4096 {
			return fail(http.StatusBadRequest, "invalid directory path")
		}
	case proto.CheckpointActionList:
		if req.Create != nil || req.ID != "" {
			return fail(http.StatusBadRequest, "invalid checkpoint request")
		}
	case proto.CheckpointActionDelete, proto.CheckpointActionRestore:
		if req.Create != nil || proto.ValidateCheckpointID(req.ID) != nil {
			return fail(http.StatusBadRequest, "invalid checkpoint request")
		}
	default:
		return fail(http.StatusBadRequest, "invalid checkpoint operation")
	}
	if !m.mu.TryLock() {
		return fail(http.StatusConflict, errCheckpointBusy.Error())
	}
	defer m.mu.Unlock()
	start := time.Now()
	var result any
	err := m.initialize()
	if err == nil {
		switch req.Action {
		case proto.CheckpointActionCreate:
			result, err = m.create(*req.Create)
		case proto.CheckpointActionList:
			result = m.list()
		case proto.CheckpointActionRestore:
			result, err = m.restore(req.ID)
		case proto.CheckpointActionDelete:
			err = m.delete(req.ID)
			result = struct{}{}
		}
	}
	id := req.ID
	if created, ok := result.(proto.DirectoryCheckpoint); ok && err == nil {
		id = created.ID
	}
	log.Printf("agent.checkpoint operation=%s checkpoint_id=%s duration_ms=%d error=%v", req.Action, id, time.Since(start).Milliseconds(), err)
	if err != nil {
		switch {
		case errors.Is(err, errCheckpointBusy), errors.Is(err, errCheckpointOverlap), errors.Is(err, errCheckpointMount), errors.Is(err, errCheckpointLimit):
			return fail(http.StatusConflict, err.Error())
		case errors.Is(err, errCheckpointPath):
			return fail(http.StatusBadRequest, err.Error())
		case errors.Is(err, errCheckpointMissing):
			return fail(http.StatusNotFound, err.Error())
		case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
			return fail(http.StatusInsufficientStorage, "not enough sandbox disk space")
		default:
			return fail(http.StatusInternalServerError, "checkpoint operation could not complete")
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return fail(http.StatusInternalServerError, "checkpoint response could not be encoded")
	}
	return proto.CheckpointAgentResponse{Status: http.StatusOK, Data: data}
}
