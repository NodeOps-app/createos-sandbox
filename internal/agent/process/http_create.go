package process

import (
	"errors"
	"net/http"
)

type createProcessHTTPRequest struct {
	Cmd  string            `json:"cmd"`
	Args []string          `json:"args,omitempty"`
	Cwd  string            `json:"cwd,omitempty"`
	Env  map[string]string `json:"env,omitempty"`
	PTY  *createPTYOptions `json:"pty,omitempty"`
}

type createPTYOptions struct {
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

type processListHTTPResponse struct {
	Processes []ProcessDetails `json:"processes"`
}

func (h *HTTPHandler) list(response http.ResponseWriter) {
	_ = writeHTTPJSON(response, http.StatusOK, processListHTTPResponse{
		Processes: h.manager.ListProcesses(),
	})
}

func (h *HTTPHandler) create(response http.ResponseWriter, request *http.Request) {
	var body createProcessHTTPRequest
	if err := decodeHTTPJSON(response, request, &body); err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if body.Cmd == "" && len(body.Args) != 0 {
		writeHTTPError(response, http.StatusBadRequest, "invalid_process_spec")
		return
	}
	var created CreatedProcess
	var err error
	argv := commandArgv(body.Cmd, body.Args)
	if body.PTY == nil {
		spec := ProcessSpec{Argv: argv, Cwd: body.Cwd, Env: body.Env}
		if _, _, _, err := prepareCommand(spec.Argv, spec.Cwd, spec.Env, false); err != nil {
			writeHTTPError(response, http.StatusBadRequest, "invalid_process_spec")
			return
		}
		created, err = h.manager.CreateProcess(request.Context(), spec)
	} else {
		if len(argv) == 0 {
			argv = defaultPTYArgv()
		}
		if _, _, _, err := prepareCommand(argv, body.Cwd, body.Env, true); err != nil {
			writeHTTPError(response, http.StatusBadRequest, "invalid_process_spec")
			return
		}
		created, err = h.manager.CreatePTY(request.Context(), PTYSpec{
			Argv: argv,
			Cwd:  body.Cwd,
			Env:  body.Env,
			Cols: body.PTY.Cols,
			Rows: body.PTY.Rows,
		})
	}
	if err != nil {
		writeHTTPCreateError(response, err)
		return
	}
	details, err := h.manager.InspectProcess(created.ID)
	if err != nil {
		writeHTTPError(response, http.StatusInternalServerError, "process_inspection_failed")
		return
	}
	_ = writeHTTPJSON(response, http.StatusCreated, details)
}

func commandArgv(command string, args []string) []string {
	if command == "" {
		return nil
	}
	argv := make([]string, 1, len(args)+1)
	argv[0] = command
	return append(argv, args...)
}

func writeHTTPCreateError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errProcessLimit):
		writeHTTPError(response, http.StatusTooManyRequests, "process_limit_reached")
	default:
		writeHTTPError(response, http.StatusInternalServerError, "process_creation_failed")
	}
}
