package computer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func (h *Handler) windowOperation(w http.ResponseWriter, r *http.Request, remainder string) {
	parts := strings.Split(remainder, "/")
	if len(parts) < 1 || len(parts) > 2 || !validWindowID(parts[0]) {
		badRequest(w, "invalid_window_id")
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			h.window(w, r, id)
		case http.MethodDelete:
			runOK(w, r, "xdotool", "windowclose", id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	action := parts[1]
	switch {
	case r.Method == http.MethodGet && action == "geometry":
		h.windowGeometryResponse(w, r, id)
	case r.Method == http.MethodPost && action == "focus":
		h.focusWindow(w, r, id)
	case r.Method == http.MethodPost && action == "move":
		h.moveWindow(w, r, id)
	case r.Method == http.MethodPost && action == "resize":
		h.resizeWindow(w, r, id)
	case r.Method == http.MethodPost && action == "maximize":
		runOK(w, r, "wmctrl", "-i", "-r", id, "-b", "add,maximized_vert,maximized_horz")
	case r.Method == http.MethodPost && action == "restore":
		runOK(w, r, "wmctrl", "-i", "-r", id, "-b", "remove,maximized_vert,maximized_horz")
	case r.Method == http.MethodPost && action == "minimize":
		runOK(w, r, "xdotool", "windowminimize", "--sync", id)
	default:
		http.NotFound(w, r)
	}
}

func readWindowGeometry(ctx context.Context, id string) (windowGeometryResponse, error) {
	out, err := command(ctx, "xdotool", "getwindowgeometry", "--shell", id)
	if err != nil {
		return windowGeometryResponse{}, err
	}
	values := make(map[string]int, 6)
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parsed, parseErr := strconv.Atoi(value)
		if parseErr == nil {
			values[key] = parsed
		}
	}
	for _, key := range []string{"X", "Y", "WIDTH", "HEIGHT", "SCREEN"} {
		if _, ok := values[key]; !ok {
			return windowGeometryResponse{}, errors.New("invalid window geometry")
		}
	}
	if values["WIDTH"] <= 0 || values["HEIGHT"] <= 0 {
		return windowGeometryResponse{}, errors.New("invalid window geometry")
	}
	return windowGeometryResponse{
		ID: id, X: values["X"], Y: values["Y"], Width: values["WIDTH"],
		Height: values["HEIGHT"], Screen: values["SCREEN"],
	}, nil
}

func (h *Handler) windowGeometryResponse(w http.ResponseWriter, r *http.Request, id string) {
	ctx, cancel := requestContext(r)
	defer cancel()
	geometry, err := readWindowGeometry(ctx, id)
	if err != nil {
		operationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, geometry)
}

func (h *Handler) moveWindow(w http.ResponseWriter, r *http.Request, id string) {
	var req windowMoveRequest
	if decode(w, r, &req) != nil || req.X < 0 || req.Y < 0 || req.X > 65535 || req.Y > 65535 {
		badRequest(w, "invalid_coordinates")
		return
	}
	runOK(w, r, "xdotool", "windowmove", "--sync", id, strconv.Itoa(req.X), strconv.Itoa(req.Y))
}

func (h *Handler) resizeWindow(w http.ResponseWriter, r *http.Request, id string) {
	var req windowResizeRequest
	if decode(w, r, &req) != nil || req.Width < 1 || req.Height < 1 || req.Width > 3840 || req.Height > 2160 {
		badRequest(w, "invalid_dimensions")
		return
	}
	runOK(w, r, "xdotool", "windowsize", "--sync", id, strconv.Itoa(req.Width), strconv.Itoa(req.Height))
}

func screenshotArea(ctx context.Context, r *http.Request) (string, error) {
	query := r.URL.Query()
	windowID := query.Get("window_id")
	regionKeys := []string{"x", "y", "width", "height"}
	hasRegion := false
	for _, key := range regionKeys {
		hasRegion = hasRegion || query.Has(key)
	}
	if windowID != "" && hasRegion {
		return "", errors.New("window and region are mutually exclusive")
	}
	if windowID != "" {
		if !validWindowID(windowID) {
			return "", errors.New("invalid window id")
		}
		geometry, err := readWindowGeometry(ctx, windowID)
		if err != nil || geometry.X < 0 || geometry.Y < 0 {
			return "", errors.New("window is not capturable")
		}
		return fmt.Sprintf("%d,%d,%d,%d", geometry.X, geometry.Y, geometry.Width, geometry.Height), nil
	}
	if !hasRegion {
		return "", nil
	}
	values := make([]int, len(regionKeys))
	for i, key := range regionKeys {
		if !query.Has(key) {
			return "", errors.New("incomplete screenshot region")
		}
		parsed, err := strconv.Atoi(query.Get(key))
		if err != nil {
			return "", errors.New("invalid screenshot region")
		}
		values[i] = parsed
	}
	x, y, width, height := values[0], values[1], values[2], values[3]
	if x < 0 || y < 0 || width < 1 || height < 1 || width > 3840 || height > 2160 {
		return "", errors.New("invalid screenshot region")
	}
	return fmt.Sprintf("%d,%d,%d,%d", x, y, width, height), nil
}
