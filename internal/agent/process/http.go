package process

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	processAPIBasePath     = "/v1/processes"
	processAPIMaxBodyBytes = 1 << 20
)

type httpRoute struct {
	ID         string
	Action     string
	Collection bool
}

func parseHTTPRoute(path string) (httpRoute, bool) {
	remainder, ok := cutHTTPBasePath(path)
	if !ok {
		return httpRoute{}, false
	}
	if remainder == "" {
		return httpRoute{Collection: true}, true
	}
	parts := strings.Split(remainder, "/")
	if len(parts) > 3 || parts[0] == "" {
		return httpRoute{}, false
	}
	if _, err := parseProcessID(parts[0]); err != nil {
		return httpRoute{}, false
	}
	route := httpRoute{ID: parts[0]}
	if len(parts) > 1 {
		for _, part := range parts[1:] {
			if part == "" {
				return httpRoute{}, false
			}
		}
		route.Action = strings.Join(parts[1:], "/")
		if route.Action == "" {
			return httpRoute{}, false
		}
	}
	return route, true
}

func cutHTTPBasePath(path string) (string, bool) {
	if path == processAPIBasePath {
		return "", true
	}
	if strings.HasPrefix(path, processAPIBasePath+"/") {
		return strings.TrimPrefix(path, processAPIBasePath+"/"), true
	}
	return "", false
}

func decodeHTTPJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, processAPIMaxBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return err
	}
	return nil
}

func writeHTTPJSON(response http.ResponseWriter, status int, value any) error {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	return json.NewEncoder(response).Encode(value)
}

type httpError struct {
	Error string `json:"error"`
}

func writeHTTPError(response http.ResponseWriter, status int, code string) {
	_ = writeHTTPJSON(response, status, httpError{Error: code})
}

type HTTPHandler struct {
	manager *Manager
}

func NewHTTPHandler(manager *Manager) (*HTTPHandler, error) {
	if manager == nil {
		return nil, errors.New("process HTTP handler requires a manager")
	}
	return &HTTPHandler{manager: manager}, nil
}

func (h *HTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	route, ok := parseHTTPRoute(request.URL.Path)
	if !ok {
		http.NotFound(response, request)
		return
	}
	if !route.Collection {
		h.serveResource(response, request, route)
		return
	}

	switch request.Method {
	case http.MethodGet:
		h.list(response)
	case http.MethodPost:
		h.create(response, request)
	default:
		response.Header().Set("Allow", "GET, POST")
		writeHTTPError(response, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (h *HTTPHandler) serveResource(response http.ResponseWriter, request *http.Request, route httpRoute) {
	switch {
	case request.Method == http.MethodGet && route.Action == "connect":
		h.connectProcessOutput(response, request, route)
	case request.Method == http.MethodGet && route.Action == "":
		h.inspect(response, route)
	case request.Method == http.MethodGet && route.Action == "wait":
		h.wait(response, request, route)
	case request.Method == http.MethodPost:
		h.control(response, request, route)
	case request.Method == http.MethodDelete && route.Action == "":
		h.terminate(response, request, route)
	default:
		response.Header().Set("Allow", allowedHTTPMethods(route))
		writeHTTPError(response, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func allowedHTTPMethods(route httpRoute) string {
	if route.Action == "" {
		return "GET, DELETE"
	}
	if route.Action == "wait" {
		return "GET"
	}
	if route.Action == "connect" {
		return "GET"
	}
	return "POST"
}
