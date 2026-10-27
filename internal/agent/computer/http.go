// Package computer exposes safe, native controls for an X11 desktop running
// inside the sandbox. Commands are always executed with argv (never through a
// shell), so user-provided text cannot become executable command syntax.
package computer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	apiBasePath = "/v1/computer"
	maxBody     = 1 << 20
	maxImage    = 32 << 20
)

type Handler struct {
	screensMu    sync.Mutex
	screenTimers [maxScreens]*time.Timer
}

type point struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type clickRequest struct {
	Button string `json:"button,omitempty"`
	X      *int   `json:"x,omitempty"`
	Y      *int   `json:"y,omitempty"`
	Count  int    `json:"count,omitempty"`
}

type scrollRequest struct {
	Direction string `json:"direction,omitempty"`
	Amount    int    `json:"amount,omitempty"`
}

type dragRequest struct {
	From point `json:"from"`
	To   point `json:"to"`
}

type buttonRequest struct {
	Button string `json:"button,omitempty"`
}

type typeRequest struct {
	Text      string `json:"text"`
	DelayInMS int    `json:"delay_in_ms,omitempty"`
}

type pressRequest struct {
	Keys []string `json:"keys"`
}

type clipboardRequest struct {
	Text string `json:"text"`
}

type windowMoveRequest struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type windowResizeRequest struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type openRequest struct {
	Target string `json:"target"`
}

type launchRequest struct {
	Application string `json:"application"`
	URI         string `json:"uri,omitempty"`
}

type windowResponse struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
}

type clipboardResponse struct {
	Text string `json:"text"`
}

type windowGeometryResponse struct {
	ID     string `json:"id"`
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Screen int    `json:"screen"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type screenResponse struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

func NewHTTPHandler() http.Handler {
	h := &Handler{}
	h.restoreScreenTokenExpirations()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, apiBasePath)
	if path == "/screens" || strings.HasPrefix(path, "/screens/") {
		h.screens(w, r, path)
		return
	}
	display, err := screenDisplay(r.URL.Query().Get("screen_id"))
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, errorResponse{Error: "invalid_screen_id"})
		return
	}
	if !screenConfigured(display) {
		jsonResponse(w, http.StatusNotFound, errorResponse{Error: "screen_not_found"})
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), displayContextKey{}, display))
	switch {
	case r.Method == http.MethodGet && path == "/screenshot":
		h.screenshot(w, r)
	case r.Method == http.MethodGet && path == "/screen":
		h.screen(w, r)
	case r.Method == http.MethodGet && path == "/cursor":
		h.cursor(w, r)
	case r.Method == http.MethodPost && path == "/mouse/move":
		h.move(w, r)
	case r.Method == http.MethodPost && path == "/mouse/click":
		h.click(w, r)
	case r.Method == http.MethodPost && path == "/mouse/scroll":
		h.scroll(w, r)
	case r.Method == http.MethodPost && path == "/mouse/drag":
		h.drag(w, r)
	case r.Method == http.MethodPost && path == "/mouse/down":
		h.button(w, r, "mousedown")
	case r.Method == http.MethodPost && path == "/mouse/up":
		h.button(w, r, "mouseup")
	case r.Method == http.MethodPost && path == "/keyboard/type":
		h.typeText(w, r)
	case r.Method == http.MethodPost && path == "/keyboard/press":
		h.press(w, r)
	case r.Method == http.MethodPost && path == "/keyboard/down":
		h.keyState(w, r, "keydown")
	case r.Method == http.MethodPost && path == "/keyboard/up":
		h.keyState(w, r, "keyup")
	case r.Method == http.MethodGet && path == "/clipboard":
		h.getClipboard(w, r)
	case r.Method == http.MethodPut && path == "/clipboard":
		h.setClipboard(w, r)
	case r.Method == http.MethodPost && path == "/open":
		h.open(w, r)
	case r.Method == http.MethodPost && path == "/launch":
		h.launch(w, r)
	case r.Method == http.MethodGet && path == "/windows/current":
		h.currentWindow(w, r)
	case r.Method == http.MethodGet && path == "/windows":
		h.windows(w, r)
	case strings.HasPrefix(path, "/windows/"):
		h.windowOperation(w, r, strings.TrimPrefix(path, "/windows/"))
	default:
		http.NotFound(w, r)
	}
}

// commandInputDiscard is used for programs such as xclip that fork a
// long-lived selection owner. Capturing their output would leave the capture
// pipe open in that child and make Cmd.Wait block until the request deadline.
func commandInputDiscard(ctx context.Context, input string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DISPLAY="+contextDisplay(ctx))
	cmd.Stdin = strings.NewReader(input)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DISPLAY="+contextDisplay(ctx))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func requestContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 15*time.Second)
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return err
	}
	return nil
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func badRequest(w http.ResponseWriter, code string) {
	jsonResponse(w, http.StatusBadRequest, errorResponse{Error: code})
}

func operationError(w http.ResponseWriter, err error) {
	if errors.Is(err, exec.ErrNotFound) {
		jsonResponse(w, http.StatusNotImplemented, errorResponse{Error: "desktop_tools_unavailable"})
		return
	}
	jsonResponse(w, http.StatusConflict, errorResponse{Error: "desktop_unavailable"})
}

func validPoint(p point) bool { return p.X >= 0 && p.Y >= 0 && p.X <= 65535 && p.Y <= 65535 }

func mouseButton(button string) (string, bool) {
	switch button {
	case "", "left":
		return "1", true
	case "middle":
		return "2", true
	case "right":
		return "3", true
	default:
		return "", false
	}
}

func runOK(w http.ResponseWriter, r *http.Request, name string, args ...string) {
	ctx, cancel := requestContext(r)
	defer cancel()
	if _, err := command(ctx, name, args...); err != nil {
		operationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, struct{}{})
}

// startOK is used for desktop applications whose lifetime must outlive the
// request that launched them. The agent is PID 1 and already reaps orphaned
// children, so releasing the direct gtk-launch child does not accumulate
// zombies when it exits after handing the application to the desktop session.
func startOK(w http.ResponseWriter, r *http.Request, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "DISPLAY="+contextDisplay(r.Context()))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		operationError(w, err)
		return
	}
	if err := cmd.Process.Release(); err != nil {
		operationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, struct{}{})
}

func (h *Handler) screenshot(w http.ResponseWriter, r *http.Request) {
	f, err := os.CreateTemp("/tmp", "fc-computer-*.png")
	if err != nil {
		operationError(w, err)
		return
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)
	// scrot refuses to overwrite an existing path. CreateTemp gives us an
	// unpredictable, private name; unlink the placeholder before capture.
	if err := os.Remove(path); err != nil {
		operationError(w, err)
		return
	}
	ctx, cancel := requestContext(r)
	defer cancel()
	args := []string{"--pointer"}
	area, err := screenshotArea(ctx, r)
	if err != nil {
		badRequest(w, "invalid_screenshot_target")
		return
	}
	if area != "" {
		args = append(args, "-a", area)
	}
	args = append(args, path)
	if _, err := command(ctx, "scrot", args...); err != nil {
		operationError(w, err)
		return
	}
	image, err := os.ReadFile(path)
	if err != nil || len(image) == 0 || len(image) > maxImage {
		operationError(w, errors.New("invalid screenshot"))
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(image)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(image)
}

func (h *Handler) screen(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := requestContext(r)
	defer cancel()
	out, err := command(ctx, "xdotool", "getdisplaygeometry")
	if err != nil {
		operationError(w, err)
		return
	}
	parts := strings.Fields(string(out))
	if len(parts) != 2 {
		operationError(w, errors.New("invalid display geometry"))
		return
	}
	width, errW := strconv.Atoi(parts[0])
	height, errH := strconv.Atoi(parts[1])
	if errW != nil || errH != nil || width <= 0 || height <= 0 {
		operationError(w, errors.New("invalid display geometry"))
		return
	}
	jsonResponse(w, http.StatusOK, screenResponse{Width: width, Height: height})
}

func (h *Handler) cursor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := requestContext(r)
	defer cancel()
	out, err := command(ctx, "xdotool", "getmouselocation", "--shell")
	if err != nil {
		operationError(w, err)
		return
	}
	values := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "X" && key != "Y") {
			continue
		}
		if parsed, err := strconv.Atoi(value); err == nil {
			values[strings.ToLower(key)] = parsed
		}
	}
	x, okX := values["x"]
	y, okY := values["y"]
	if !okX || !okY {
		operationError(w, errors.New("invalid cursor position"))
		return
	}
	jsonResponse(w, http.StatusOK, point{X: x, Y: y})
}

func (h *Handler) move(w http.ResponseWriter, r *http.Request) {
	var req point
	if decode(w, r, &req) != nil || !validPoint(req) {
		badRequest(w, "invalid_coordinates")
		return
	}
	runOK(w, r, "xdotool", "mousemove", "--sync", strconv.Itoa(req.X), strconv.Itoa(req.Y))
}

func (h *Handler) click(w http.ResponseWriter, r *http.Request) {
	var req clickRequest
	if decode(w, r, &req) != nil || (req.X == nil) != (req.Y == nil) {
		badRequest(w, "invalid_request")
		return
	}
	button, ok := mouseButton(req.Button)
	if !ok {
		badRequest(w, "invalid_button")
		return
	}
	count := req.Count
	if count == 0 {
		count = 1
	}
	if count < 1 || count > 10 {
		badRequest(w, "invalid_count")
		return
	}
	ctx, cancel := requestContext(r)
	defer cancel()
	if req.X != nil {
		p := point{X: *req.X, Y: *req.Y}
		if !validPoint(p) {
			badRequest(w, "invalid_coordinates")
			return
		}
		if _, err := command(ctx, "xdotool", "mousemove", "--sync", strconv.Itoa(p.X), strconv.Itoa(p.Y)); err != nil {
			operationError(w, err)
			return
		}
	}
	if _, err := command(ctx, "xdotool", "click", "--repeat", strconv.Itoa(count), button); err != nil {
		operationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, struct{}{})
}

func (h *Handler) scroll(w http.ResponseWriter, r *http.Request) {
	var req scrollRequest
	if decode(w, r, &req) != nil {
		badRequest(w, "invalid_request")
		return
	}
	if req.Direction == "" {
		req.Direction = "down"
	}
	if req.Amount == 0 {
		req.Amount = 1
	}
	if req.Amount < 1 || req.Amount > 100 || (req.Direction != "up" && req.Direction != "down") {
		badRequest(w, "invalid_scroll")
		return
	}
	button := "5"
	if req.Direction == "up" {
		button = "4"
	}
	runOK(w, r, "xdotool", "click", "--repeat", strconv.Itoa(req.Amount), button)
}

func (h *Handler) drag(w http.ResponseWriter, r *http.Request) {
	var req dragRequest
	if decode(w, r, &req) != nil || !validPoint(req.From) || !validPoint(req.To) {
		badRequest(w, "invalid_coordinates")
		return
	}
	ctx, cancel := requestContext(r)
	defer cancel()
	steps := [][]string{
		{"mousemove", "--sync", strconv.Itoa(req.From.X), strconv.Itoa(req.From.Y)},
		{"mousedown", "1"},
		{"mousemove", "--sync", strconv.Itoa(req.To.X), strconv.Itoa(req.To.Y)},
		{"mouseup", "1"},
	}
	pressed := false
	for _, args := range steps {
		if _, err := command(ctx, "xdotool", args...); err != nil {
			if pressed {
				releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, _ = command(releaseCtx, "xdotool", "mouseup", "1")
				releaseCancel()
			}
			operationError(w, err)
			return
		}
		pressed = args[0] == "mousedown" || (pressed && args[0] != "mouseup")
	}
	jsonResponse(w, http.StatusOK, struct{}{})
}

func (h *Handler) button(w http.ResponseWriter, r *http.Request, action string) {
	var req buttonRequest
	if decode(w, r, &req) != nil {
		badRequest(w, "invalid_request")
		return
	}
	button, ok := mouseButton(req.Button)
	if !ok {
		badRequest(w, "invalid_button")
		return
	}
	runOK(w, r, "xdotool", action, button)
}

func (h *Handler) typeText(w http.ResponseWriter, r *http.Request) {
	var req typeRequest
	if decode(w, r, &req) != nil || len(req.Text) > 64<<10 {
		badRequest(w, "invalid_text")
		return
	}
	if req.DelayInMS == 0 {
		req.DelayInMS = 25
	}
	if req.DelayInMS < 0 || req.DelayInMS > 1000 {
		badRequest(w, "invalid_delay")
		return
	}
	runOK(w, r, "xdotool", "type", "--clearmodifiers", "--delay", strconv.Itoa(req.DelayInMS), "--", req.Text)
}

func (h *Handler) press(w http.ResponseWriter, r *http.Request) {
	var req pressRequest
	if decode(w, r, &req) != nil || len(req.Keys) == 0 || len(req.Keys) > 16 {
		badRequest(w, "invalid_keys")
		return
	}
	for _, key := range req.Keys {
		if !validKey(key) {
			badRequest(w, "invalid_keys")
			return
		}
	}
	runOK(w, r, "xdotool", "key", "--clearmodifiers", strings.Join(req.Keys, "+"))
}

func (h *Handler) keyState(w http.ResponseWriter, r *http.Request, action string) {
	var req pressRequest
	if decode(w, r, &req) != nil || len(req.Keys) == 0 || len(req.Keys) > 16 {
		badRequest(w, "invalid_keys")
		return
	}
	for _, key := range req.Keys {
		if !validKey(key) {
			badRequest(w, "invalid_keys")
			return
		}
	}
	ctx, cancel := requestContext(r)
	defer cancel()
	completed := make([]string, 0, len(req.Keys))
	for _, key := range req.Keys {
		if _, err := command(ctx, "xdotool", action, key); err != nil {
			if action == "keydown" {
				releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
				for i := len(completed) - 1; i >= 0; i-- {
					_, _ = command(releaseCtx, "xdotool", "keyup", completed[i])
				}
				releaseCancel()
			}
			operationError(w, err)
			return
		}
		completed = append(completed, key)
	}
	jsonResponse(w, http.StatusOK, struct{}{})
}

func (h *Handler) getClipboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := requestContext(r)
	defer cancel()
	out, err := command(ctx, "xclip", "-selection", "clipboard", "-out")
	if err != nil {
		if strings.Contains(err.Error(), "target STRING not available") ||
			strings.Contains(err.Error(), "selection doesn't exist") {
			jsonResponse(w, http.StatusOK, clipboardResponse{Text: ""})
			return
		}
		operationError(w, err)
		return
	}
	if len(out) > maxBody {
		operationError(w, errors.New("clipboard too large"))
		return
	}
	jsonResponse(w, http.StatusOK, clipboardResponse{Text: string(out)})
}

func (h *Handler) setClipboard(w http.ResponseWriter, r *http.Request) {
	var req clipboardRequest
	if decode(w, r, &req) != nil || len(req.Text) > maxBody || strings.ContainsRune(req.Text, 0) {
		badRequest(w, "invalid_clipboard")
		return
	}
	ctx, cancel := requestContext(r)
	defer cancel()
	if err := commandInputDiscard(ctx, req.Text, "xclip", "-selection", "clipboard", "-in"); err != nil {
		operationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, struct{}{})
}

func (h *Handler) open(w http.ResponseWriter, r *http.Request) {
	var req openRequest
	if decode(w, r, &req) != nil || !validArgument(req.Target, 4096) {
		badRequest(w, "invalid_target")
		return
	}
	runOK(w, r, "xdg-open", req.Target)
}

func (h *Handler) launch(w http.ResponseWriter, r *http.Request) {
	var req launchRequest
	if decode(w, r, &req) != nil || !validArgument(req.Application, 256) ||
		(req.URI != "" && !validArgument(req.URI, 4096)) {
		badRequest(w, "invalid_application")
		return
	}
	args := []string{req.Application}
	if req.URI != "" {
		args = append(args, req.URI)
	}
	startOK(w, r, "gtk-launch", args...)
}

func (h *Handler) currentWindow(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := requestContext(r)
	defer cancel()
	out, err := command(ctx, "xdotool", "getwindowfocus")
	if err != nil {
		operationError(w, err)
		return
	}
	id := strings.TrimSpace(string(out))
	if !validWindowID(id) {
		operationError(w, errors.New("invalid current window"))
		return
	}
	jsonResponse(w, http.StatusOK, windowResponse{ID: id})
}

func (h *Handler) windows(w http.ResponseWriter, r *http.Request) {
	application := r.URL.Query().Get("application")
	if application != "" && !validArgument(application, 256) {
		badRequest(w, "invalid_application")
		return
	}
	ctx, cancel := requestContext(r)
	defer cancel()
	out, err := command(ctx, "xdotool", "search", "--onlyvisible", "--class", application)
	if err != nil {
		// xdotool exits 1 when no matching windows exist. That is a valid,
		// empty search result rather than an unavailable desktop.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			jsonResponse(w, http.StatusOK, []windowResponse{})
			return
		}
		operationError(w, err)
		return
	}
	windows := make([]windowResponse, 0)
	for _, id := range strings.Fields(string(out)) {
		if validWindowID(id) {
			windows = append(windows, windowResponse{ID: id})
		}
	}
	jsonResponse(w, http.StatusOK, windows)
}

func (h *Handler) window(w http.ResponseWriter, r *http.Request, id string) {
	if !validWindowID(id) {
		badRequest(w, "invalid_window_id")
		return
	}
	ctx, cancel := requestContext(r)
	defer cancel()
	out, err := command(ctx, "xdotool", "getwindowname", id)
	if err != nil {
		operationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, windowResponse{ID: id, Title: strings.TrimSpace(string(out))})
}

func (h *Handler) focusWindow(w http.ResponseWriter, r *http.Request, id string) {
	if !validWindowID(id) {
		badRequest(w, "invalid_window_id")
		return
	}
	runOK(w, r, "xdotool", "windowactivate", "--sync", id)
}

func validArgument(value string, max int) bool {
	return value != "" && len(value) <= max && !strings.ContainsRune(value, 0)
}

func validWindowID(id string) bool {
	if id == "" || len(id) > 20 {
		return false
	}
	_, err := strconv.ParseUint(id, 10, 64)
	return err == nil
}

func validKey(key string) bool {
	if key == "" || len(key) > 64 {
		return false
	}
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
