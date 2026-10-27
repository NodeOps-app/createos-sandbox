package computer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

const (
	screenStateDir = "/var/lib/createos/computer-screens"
	screenRunDir   = "/run/createos/computer-screens"
	maxScreens     = 8
	baseVNCServer  = 5900
	baseNoVNCPort  = 6080
	screenTokenTTL = time.Hour
)

type displayContextKey struct{}

type screenRecord struct {
	ID        string `json:"screen_id"`
	Display   string `json:"display"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	VNCServer int    `json:"vnc_port"`
	NoVNCPort int    `json:"novnc_port"`
	Token     string `json:"-"`
	ExpiresAt int64  `json:"-"`
}

type createScreenRequest struct {
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`
}

type resizeScreenRequest struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type connectScreenResponse struct {
	ScreenID  string    `json:"screen_id"`
	Port      int       `json:"port"`
	Path      string    `json:"path"`
	Token     string    `json:"token"`
	URL       string    `json:"url,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

func contextDisplay(ctx context.Context) string {
	if display, ok := ctx.Value(displayContextKey{}).(string); ok {
		return display
	}
	return ":0"
}

func screenDisplay(id string) (string, error) {
	index, err := screenIndex(id)
	if err != nil {
		return "", err
	}
	return ":" + strconv.Itoa(index), nil
}

func screenIndex(id string) (int, error) {
	if id == "" {
		return 0, nil
	}
	if !strings.HasPrefix(id, "screen-") {
		return 0, errors.New("invalid screen id")
	}
	index, err := strconv.Atoi(strings.TrimPrefix(id, "screen-"))
	if err != nil || index < 0 || index >= maxScreens {
		return 0, errors.New("invalid screen id")
	}
	return index, nil
}

func screenConfigPath(index int) string {
	return filepath.Join(screenStateDir, fmt.Sprintf("screen-%d.conf", index))
}

func screenConfigured(display string) bool {
	index, err := strconv.Atoi(strings.TrimPrefix(display, ":"))
	if err != nil {
		return false
	}
	_, err = os.Stat(screenConfigPath(index))
	return err == nil
}

func readScreen(index int) (screenRecord, error) {
	data, err := os.ReadFile(screenConfigPath(index))
	if err != nil {
		return screenRecord{}, err
	}
	fields := strings.Fields(string(data))
	if len(fields) != 3 && len(fields) != 4 {
		return screenRecord{}, errors.New("invalid screen configuration")
	}
	width, errW := strconv.Atoi(fields[0])
	height, errH := strconv.Atoi(fields[1])
	if errW != nil || errH != nil || len(fields[2]) != 64 {
		return screenRecord{}, errors.New("invalid screen configuration")
	}
	if _, err := hex.DecodeString(fields[2]); err != nil {
		return screenRecord{}, errors.New("invalid screen token")
	}
	expiresAt := int64(0)
	if len(fields) == 4 {
		var err error
		expiresAt, err = strconv.ParseInt(fields[3], 10, 64)
		if err != nil || expiresAt < 0 {
			return screenRecord{}, errors.New("invalid screen token expiry")
		}
	}
	return screenRecord{
		ID: "screen-" + strconv.Itoa(index), Display: ":" + strconv.Itoa(index),
		Width: width, Height: height, VNCServer: baseVNCServer + index,
		NoVNCPort: baseNoVNCPort + index, Token: fields[2], ExpiresAt: expiresAt,
	}, nil
}

func listScreens() ([]screenRecord, error) {
	records := make([]screenRecord, 0, maxScreens)
	for index := 0; index < maxScreens; index++ {
		record, err := readScreen(index)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func newScreenToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func writeScreenToken(record *screenRecord, token string, expiresAt int64) error {
	index, err := screenIndex(record.ID)
	if err != nil {
		return err
	}
	type replacement struct{ path, contents string }
	files := []replacement{
		{filepath.Join(screenRunDir, fmt.Sprintf("screen-%d.tokens", index)), fmt.Sprintf("%s: 127.0.0.1:%d\n", token, record.VNCServer)},
		{screenConfigPath(index), fmt.Sprintf("%d %d %s %d\n", record.Width, record.Height, token, expiresAt)},
	}
	for _, file := range files {
		temporary := file.path + ".new"
		if err := os.WriteFile(temporary, []byte(file.contents), 0o600); err != nil {
			return err
		}
		if err := os.Rename(temporary, file.path); err != nil {
			_ = os.Remove(temporary)
			return err
		}
	}
	record.Token = token
	record.ExpiresAt = expiresAt
	return nil
}

func (h *Handler) issueScreenToken(record *screenRecord) (time.Time, error) {
	token, err := newScreenToken()
	if err != nil {
		return time.Time{}, err
	}
	expires := time.Now().Add(screenTokenTTL).UTC()
	if err := writeScreenToken(record, token, expires.Unix()); err != nil {
		return time.Time{}, err
	}
	index, _ := screenIndex(record.ID)
	h.scheduleScreenTokenExpiry(index, token, expires)
	return expires, nil
}

// scheduleScreenTokenExpiry invalidates only the token it was created for.
// A later /connect rotates the bearer and replaces the timer, so an older
// callback can never revoke the newly issued token. Existing websocket
// sessions remain connected; only future handshakes are denied.
func (h *Handler) scheduleScreenTokenExpiry(index int, token string, expires time.Time) {
	if timer := h.screenTimers[index]; timer != nil {
		timer.Stop()
	}
	delay := time.Until(expires)
	if delay < 0 {
		delay = 0
	}
	h.screenTimers[index] = time.AfterFunc(delay, func() {
		h.screensMu.Lock()
		defer h.screensMu.Unlock()
		record, err := readScreen(index)
		if err != nil || record.Token != token || record.ExpiresAt == 0 {
			return
		}
		if remaining := time.Until(time.Unix(record.ExpiresAt, 0)); remaining > 0 {
			h.scheduleScreenTokenExpiry(index, token, time.Unix(record.ExpiresAt, 0))
			return
		}
		replacement, err := newScreenToken()
		if err == nil {
			_ = writeScreenToken(&record, replacement, 0)
		}
	})
}

func (h *Handler) restoreScreenTokenExpirations() {
	h.screensMu.Lock()
	defer h.screensMu.Unlock()
	for index := 0; index < maxScreens; index++ {
		record, err := readScreen(index)
		if err != nil || record.ExpiresAt == 0 {
			continue
		}
		expires := time.Unix(record.ExpiresAt, 0)
		if !expires.After(time.Now()) {
			replacement, randomErr := newScreenToken()
			if randomErr == nil {
				_ = writeScreenToken(&record, replacement, 0)
			}
			continue
		}
		h.scheduleScreenTokenExpiry(index, record.Token, expires)
	}
}

func runScreenScript(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "/usr/local/bin/fc-screen", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("fc-screen: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (h *Handler) screens(w http.ResponseWriter, r *http.Request, path string) {
	h.screensMu.Lock()
	defer h.screensMu.Unlock()

	if path == "/screens" {
		switch r.Method {
		case http.MethodGet:
			records, err := listScreens()
			if err != nil {
				operationError(w, err)
				return
			}
			for i := range records {
				records[i].Token = ""
			}
			jsonResponse(w, http.StatusOK, records)
		case http.MethodPost:
			h.createScreen(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	remainder := strings.TrimPrefix(path, "/screens/")
	id, action, _ := strings.Cut(remainder, "/")
	index, err := screenIndex(id)
	if err != nil || id == "" {
		badRequest(w, "invalid_screen_id")
		return
	}
	record, err := readScreen(index)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			jsonResponse(w, http.StatusNotFound, errorResponse{Error: "screen_not_found"})
			return
		}
		operationError(w, err)
		return
	}
	if action == "" && r.Method == http.MethodGet {
		record.Token = ""
		jsonResponse(w, http.StatusOK, record)
		return
	}
	if action == "connect" && r.Method == http.MethodGet {
		// A fresh connection request invalidates the previously issued bearer.
		// Existing websocket sessions remain connected, but stale URLs copied
		// from browser history or access logs cannot establish a new session.
		expiresAt, err := h.issueScreenToken(&record)
		if err != nil {
			operationError(w, err)
			return
		}
		path := "vnc.html?autoconnect=1&resize=remote&path=websockify%3Ftoken%3D" + record.Token
		url := strings.Replace(r.Header.Get(proto.HeaderSandboxIngressURLTemplate), "<port>", strconv.Itoa(record.NoVNCPort), 1)
		if url != "" {
			url = strings.TrimRight(url, "/") + "/" + path
		}
		jsonResponse(w, http.StatusOK, connectScreenResponse{
			ScreenID: record.ID, Port: record.NoVNCPort, Token: record.Token,
			Path: path, URL: url, ExpiresAt: expiresAt,
		})
		return
	}
	if action == "resize" && r.Method == http.MethodPost {
		h.resizeScreen(w, r, record)
		return
	}
	if action == "" && r.Method == http.MethodDelete {
		if index == 0 {
			jsonResponse(w, http.StatusConflict, errorResponse{Error: "primary_screen_cannot_be_deleted"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := runScreenScript(ctx, "stop", strconv.Itoa(index)); err != nil {
			operationError(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, struct{}{})
		return
	}
	http.NotFound(w, r)
}

func (h *Handler) resizeScreen(w http.ResponseWriter, r *http.Request, previous screenRecord) {
	var req resizeScreenRequest
	if err := decode(w, r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	if !validScreenDimensions(req.Width, req.Height) {
		badRequest(w, "invalid_dimensions")
		return
	}
	token, err := newScreenToken()
	if err != nil {
		operationError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	index, _ := screenIndex(previous.ID)
	if err := runScreenScript(ctx, "start", strconv.Itoa(index), strconv.Itoa(req.Width), strconv.Itoa(req.Height), token); err != nil {
		// Starting a screen stops the old display first. Restore its persisted
		// geometry and bearer if the replacement fails so a bad resize does not
		// permanently remove a working desktop.
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 15*time.Second)
		rollbackErr := runScreenScript(rollbackCtx, "start", strconv.Itoa(index),
			strconv.Itoa(previous.Width), strconv.Itoa(previous.Height), previous.Token, strconv.FormatInt(previous.ExpiresAt, 10))
		rollbackCancel()
		if rollbackErr != nil {
			err = fmt.Errorf("resize failed: %w; restore previous screen: %v", err, rollbackErr)
		}
		operationError(w, err)
		return
	}
	record, err := readScreen(index)
	if err != nil {
		operationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, record)
}

func (h *Handler) createScreen(w http.ResponseWriter, r *http.Request) {
	var req createScreenRequest
	if err := decode(w, r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	if req.Width == 0 {
		req.Width = 1280
	}
	if req.Height == 0 {
		req.Height = 800
	}
	if !validScreenDimensions(req.Width, req.Height) {
		badRequest(w, "invalid_dimensions")
		return
	}
	index := -1
	for candidate := 1; candidate < maxScreens; candidate++ {
		if _, err := os.Stat(screenConfigPath(candidate)); errors.Is(err, os.ErrNotExist) {
			index = candidate
			break
		}
	}
	if index < 0 {
		jsonResponse(w, http.StatusConflict, errorResponse{Error: "screen_limit_reached"})
		return
	}
	token, err := newScreenToken()
	if err != nil {
		operationError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := runScreenScript(ctx, "start", strconv.Itoa(index), strconv.Itoa(req.Width), strconv.Itoa(req.Height), token); err != nil {
		operationError(w, err)
		return
	}
	record, err := readScreen(index)
	if err != nil {
		operationError(w, err)
		return
	}
	record.Token = ""
	jsonResponse(w, http.StatusCreated, record)
}

func validScreenDimensions(width, height int) bool {
	return width >= 320 && width <= 3840 && height >= 240 && height <= 2160
}
