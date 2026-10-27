// Browser-side PTY: WebSocket wrapper over the existing /shell byte
// pipe to the agent. Lives here (not in the WS-only file the route
// registers) so it can use the Handler's OpenShell helper.

package handlers

import (
	"io"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

// Bound complete inbound messages, including fragmented WebSocket messages.
const maxShellMessageBytes = 64 * 1024

// wsShellUpgrade upgrades the inbound request to a WS connection and
// bridges it to the upstream pipe (host → agent:1027 PTY). The browser
// already sends the agent's binary frame format (0x00+data, 0x01+resize),
// so we just shovel bytes both directions.
func wsShellUpgrade(c *fiber.Ctx, h *Handler, autoPauseSeconds *int) error {
	id, _ := c.Locals("shell_sb_id").(string)
	userID, _ := c.Locals("shell_owner_id").(string)
	if id == "" {
		return fiber.NewError(fiber.StatusBadRequest, "missing sandbox id")
	}
	if !websocket.IsWebSocketUpgrade(c) {
		return fiber.NewError(fiber.StatusUpgradeRequired, "expected WebSocket upgrade")
	}
	stopActivity := func() {}
	if autoPauseSeconds != nil {
		stopActivity = h.keepInteractiveActivity(id, *autoPauseSeconds)
	}
	// Open upstream once; if it fails we 502 BEFORE the upgrade so the
	// browser sees a real HTTP error instead of a mysterious close.
	upstream, err := h.OpenShellAs(c.UserContext(), id, userID)
	if err != nil {
		stopActivity()
		log.WithContext(c.UserContext()).Errorf("[shell-ws] open upstream sb=%s: %v", id, err)
		return fiber.NewError(fiber.StatusBadGateway, "upstream open failed")
	}
	c.Locals("shell_upstream", upstream)
	logCtx := c.UserContext()
	return websocket.New(func(ws *websocket.Conn) {
		ws.SetReadLimit(maxShellMessageBytes)
		up, _ := ws.Locals("shell_upstream").(io.ReadWriteCloser)
		if up == nil {
			_ = ws.Close()
			return
		}
		defer up.Close()
		defer stopActivity()
		log.WithContext(logCtx).Infof("[control] shell-ws sandbox=%s active", id)

		// upstream → browser: raw stdout bytes, sent as one binary frame
		// per chunk. xterm.js can render any size.
		done := make(chan struct{}, 2)
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := up.Read(buf)
				if n > 0 {
					if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}()

		// browser → upstream: client emits already-framed bytes; we forward verbatim.
		go func() {
			for {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					break
				}
				if _, werr := up.Write(msg); werr != nil {
					break
				}
			}
			done <- struct{}{}
		}()

		<-done
		log.WithContext(logCtx).Infof("[control] shell-ws sandbox=%s closed", id)
	})(c)
}
