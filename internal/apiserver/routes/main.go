// Package routes wires the control-plane HTTP routes onto a Fiber app.
// It depends only on the handlers and middlewares packages, never on
// internal/apiserver itself, so route definitions stay independent of
// server lifecycle.
package routes

import (
	"fmt"
	"runtime"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/pprof"

	"github.com/NodeOps-app/sandbox/internal/apiserver/handlers"
	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/proto"
)

// Register mounts every control-plane route onto app. The global
// middleware (recover, requestid, logger, user-auth gate) is mounted by
// the caller in internal/apiserver before Register runs.
//
// promSDToken gates GET /v1/internal/sd/hosts (Prometheus
// http_sd target list); empty disables the endpoint.
func Register(app fiber.Router, h *handlers.Handler, mw *middlewares.Middleware, promSDToken string) {
	id := middlewares.ParamSandboxID
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return httpx.Success(c, proto.HealthzResp{Up: true})
	})
	app.Get("/readyz", h.HandleControlReadyz)
	app.Get("/swagger.json", h.HandleSwagger)

	v1 := app.Group("/v1")
	v1.Get("/shapes", h.HandleListShapes)
	v1.Get("/rootfs", h.HandleListRootfs)
	v1.Get("/egress/presets", h.HandleListEgressPresets)
	v1.Get("/whoami", h.HandleWhoAmI)
	v1.Get("/metrics", h.HandleUserMetrics)
	v1.Get("/metrics/timeseries", h.HandleUserMetricsTimeseries)

	// Devices + relay-state — handlers/relay.go
	v1.Post("/devices", h.HandleDeviceCreate)
	v1.Get("/devices", h.HandleDeviceList)
	v1.Get(fmt.Sprintf("/devices/:%s", id), h.HandleDeviceGet)
	v1.Delete(fmt.Sprintf("/devices/:%s", id), h.HandleDeviceDelete)
	v1.Post(fmt.Sprintf("/devices/:%s/networks", id), h.HandleDeviceAttachNetwork)
	v1.Get(fmt.Sprintf("/devices/:%s/networks", id), h.HandleDeviceListNetworks)
	v1.Delete(fmt.Sprintf("/devices/:%s/networks/:%s", id, middlewares.ParamNetworkID), h.HandleDeviceDetachNetwork)
	v1.Post(fmt.Sprintf("/devices/:%s/sessions", id), h.HandleDeviceSessionCreate)
	v1.Get(fmt.Sprintf("/devices/:%s/sessions", id), h.HandleDeviceSessionList)
	v1.Put(fmt.Sprintf("/devices/:%s/sessions/:%s", id, middlewares.ParamSessionID), h.HandleDeviceSessionRenew)
	v1.Delete(fmt.Sprintf("/devices/:%s/sessions/:%s", id, middlewares.ParamSessionID), h.HandleDeviceSessionDelete)
	v1.Post("/sandboxes", h.HandleCreate)
	v1.Get("/sandboxes", h.HandleList)
	v1.Get(fmt.Sprintf("/sandboxes/by-ip/:%s", middlewares.ParamIP), h.HandleGetByIP)
	v1.Get(fmt.Sprintf("/sandboxes/:%s", id), h.HandleGet)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/access-token", id), h.HandleSandboxAccessTokenCreate)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/access-token", id), h.HandleSandboxAccessTokenGet)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/access-token/rotate", id), h.HandleSandboxAccessTokenRotate)
	v1.Delete(fmt.Sprintf("/sandboxes/:%s/access-token", id), h.HandleSandboxAccessTokenDelete)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/egress", id), h.HandleGetEgress)
	v1.Put(fmt.Sprintf("/sandboxes/:%s/egress", id), h.HandleSetEgress)
	v1.Patch(fmt.Sprintf("/sandboxes/:%s", id), h.HandlePatchSandbox)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/ssh-pubkeys", id), h.HandleAddSSHPubkey)
	v1.Delete(fmt.Sprintf("/sandboxes/:%s", id), h.HandleDestroy)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/exec", id), h.HandleExec)
	processID := middlewares.ParamProcessID
	v1.Post(fmt.Sprintf("/sandboxes/:%s/processes", id), h.HandleProcesses)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/processes", id), h.HandleProcesses)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/processes/:%s", id, processID), h.HandleProcesses)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/processes/:%s/connect", id, processID), h.HandleProcessConnect)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/processes/:%s/input", id, processID), h.HandleProcesses)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/processes/:%s/stdin/close", id, processID), h.HandleProcesses)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/processes/:%s/resize", id, processID), h.HandleProcesses)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/processes/:%s/signal", id, processID), h.HandleProcesses)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/processes/:%s/wait", id, processID), h.HandleProcesses)
	v1.Delete(fmt.Sprintf("/sandboxes/:%s/processes/:%s", id, processID), h.HandleProcesses)
	for _, path := range []string{"screenshot", "screen", "cursor", "windows", "windows/current"} {
		v1.Get(fmt.Sprintf("/sandboxes/:%s/computer/%s", id, path), h.HandleComputer)
	}
	v1.Get(fmt.Sprintf("/sandboxes/:%s/computer/windows/:window", id), h.HandleComputer)
	v1.Delete(fmt.Sprintf("/sandboxes/:%s/computer/windows/:window", id), h.HandleComputer)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/computer/windows/:window/focus", id), h.HandleComputer)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/computer/windows/:window/geometry", id), h.HandleComputer)
	for _, action := range []string{"move", "resize", "maximize", "minimize", "restore"} {
		v1.Post(fmt.Sprintf("/sandboxes/:%s/computer/windows/:window/%s", id, action), h.HandleComputer)
	}
	v1.Get(fmt.Sprintf("/sandboxes/:%s/computer/screens", id), h.HandleComputer)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/computer/screens", id), h.HandleComputer)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/computer/screens/:screen", id), h.HandleComputer)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/computer/screens/:screen/connect", id), h.HandleComputer)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/computer/screens/:screen/resize", id), h.HandleComputer)
	v1.Delete(fmt.Sprintf("/sandboxes/:%s/computer/screens/:screen", id), h.HandleComputer)
	for _, path := range []string{
		"mouse/move", "mouse/click", "mouse/scroll", "mouse/drag", "mouse/down", "mouse/up",
		"keyboard/type", "keyboard/press", "keyboard/down", "keyboard/up", "open", "launch",
	} {
		v1.Post(fmt.Sprintf("/sandboxes/:%s/computer/%s", id, path), h.HandleComputer)
	}
	v1.Get(fmt.Sprintf("/sandboxes/:%s/computer/clipboard", id), h.HandleComputer)
	v1.Put(fmt.Sprintf("/sandboxes/:%s/computer/clipboard", id), h.HandleComputer)
	v1.Put(fmt.Sprintf("/sandboxes/:%s/files", id), h.HandleFileUpload)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/files", id), h.HandleFileDownload)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/bandwidth", id), h.HandleBandwidth)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/metrics", id), h.HandleSandboxMetrics)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/metrics/timeseries", id), h.HandleSandboxMetricsTimeseries)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/bandwidth/recharge", id), h.HandleRecharge)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/pause", id), h.HandlePause)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/resume", id), h.HandleResume)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/fork", id), h.HandleFork)
	// Keyless port-forward: API-key-authenticated, authorised by sandbox
	// ownership. `createos-cli tunnel` uses this instead of the SSH gateway.
	v1.Post(fmt.Sprintf("/sandboxes/:%s/tunnel/:%s", id, middlewares.ParamPort), h.HandleUserTunnel)
	// Interactive PTY shell, authed by API key + sandbox ownership — the
	// keyless `createos-cli shell` path (no SSH gateway, no SSH key).
	v1.Post(fmt.Sprintf("/sandboxes/:%s/shell", id), h.HandleShell)
	// Browser-friendly WS flavor of the same PTY. xterm.js in the
	// web console talks to this. Same auth (API key, ?token= for
	// browsers that can't set headers on a WS handshake).
	v1.Get(fmt.Sprintf("/sandboxes/:%s/shell-ws", id), h.HandleShellWS)

	// Templates — user-facing endpoints; MustBeAuthenticated already in chain.
	v1.Post("/templates", h.HandleTemplateSubmit)
	v1.Get("/templates", h.HandleTemplateList)
	v1.Get(fmt.Sprintf("/templates/:%s", id), h.HandleTemplateGet)
	v1.Get(fmt.Sprintf("/templates/:%s/logs", id), h.HandleTemplateLogs)
	v1.Delete(fmt.Sprintf("/templates/:%s", id), h.HandleTemplateDelete)

	// Disks — user-registered S3 mounts.
	v1.Post("/disks", h.HandleDiskCreate)
	v1.Get("/disks", h.HandleDiskList)
	v1.Get(fmt.Sprintf("/disks/:%s", id), h.HandleDiskGet)
	v1.Patch(fmt.Sprintf("/disks/:%s", id), h.HandleDiskCredentialRotate)
	v1.Delete(fmt.Sprintf("/disks/:%s", id), h.HandleDiskDelete)
	v1.Get(fmt.Sprintf("/sandboxes/:%s/disks", id), h.HandleSandboxDisksList)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/disks", id), h.HandleSandboxDiskAttach)
	v1.Delete(fmt.Sprintf("/sandboxes/:%s/disks/:%s", id, middlewares.ParamDiskID), h.HandleSandboxDiskDetach)

	// Networks (overlay VPCs) — user-facing endpoints.
	v1.Post("/networks", h.HandleNetworkCreate)
	v1.Get("/networks", h.HandleNetworkList)
	v1.Get(fmt.Sprintf("/networks/:%s", id), h.HandleNetworkGet)
	v1.Delete(fmt.Sprintf("/networks/:%s", id), h.HandleNetworkDelete)
	v1.Post(fmt.Sprintf("/sandboxes/:%s/networks", id), h.HandleNetworkAttach)
	v1.Delete(fmt.Sprintf("/sandboxes/:%s/networks/:%s", id, middlewares.ParamNetwork), h.HandleNetworkDetach)

	// Deliberately narrow bearer-token operator surface. API-key management,
	// listings, and certificate lifecycle are not exposed here.
	admin := v1.Group("/admin", mw.MustBeAdmin())
	admin.Post(fmt.Sprintf("/hosts/:%s/cordon", id), h.HandleOperatorCordonHost)
	admin.Post(fmt.Sprintf("/hosts/:%s/uncordon", id), h.HandleOperatorUncordonHost)
	admin.Post(fmt.Sprintf("/hosts/:%s/drain", id), h.HandleOperatorDrainHost)
	// Live profiling shares the narrow operator gate. Keep mutex and block
	// sampling enabled so their profiles contain useful data during incidents.
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
	admin.Use(pprof.New(pprof.Config{Prefix: "/v1/admin"}))

	internal := v1.Group("/internal", middlewares.InstrumentInternalRPC("control"))
	// Service-to-service RPCs: mTLS-only (no JWT fallback for internal).
	// Bootstrap, CRL, Prometheus, builder, and billing reconcile retain
	// their dedicated gates below.
	internal.Get("/scheduler/health", mw.MustBePeerRoleMTLS("host"), h.HandleSchedulerHealth)
	// Register: bootstrap-token only. Host has no cert yet at this moment.
	internal.Post("/hosts/register", mw.MustBeBootstrappingHost(), h.HandleHostRegister)
	// Host CSR is bootstrap-token-gated; actor certificates are issued
	// offline with the admin CA CLI and are never minted over HTTP.
	internal.Post("/hosts/csr", mw.MustBeBootstrappingHost(), h.HandleHostCSR)
	// CRL: unauthenticated by design — contents are opaque random
	// serials, no secret material.
	internal.Get("/crl", h.HandleCRL)
	// Public ingress gets only the narrow routing projection it needs.
	// Keeping this behind ingress-role mTLS removes database credentials
	// from the internet-facing ingress process.
	internal.Get(fmt.Sprintf("/ingress/routes/:%s", id),
		mw.MustBePeerRoleMTLS("ingress"), h.HandleInternalIngressRoute)
	internal.Post("/hosts/heartbeat",
		mw.MustBePeerRoleMTLS("host"),
		mw.MustBeSelfHostFromBody("id"),
		h.HandleHostHeartbeat)
	internal.Get("/hosts", mw.MustBePeerRoleMTLS("host"), h.HandleListHosts)
	// Prometheus http_sd target list. Static bearer token, NOT mTLS —
	// Prometheus has no key infrastructure.
	internal.Get("/sd/hosts", handlers.PromSDAuth(promSDToken), h.HandlePromSDHosts)
	// Control's own scrape endpoint (isolated registry). Same token gate.
	internal.Get("/metrics/prometheus", handlers.PromSDAuth(promSDToken), h.HandlePromScrape)
	// Build sandboxes use a narrowly scoped JWT because they have no service cert.
	internal.Patch(fmt.Sprintf("/templates/:%s", id), mw.MustBeIssuedBy("builder"), h.HandleInternalTemplatePatch)
	internal.Post(fmt.Sprintf("/templates/:%s/log", id), mw.MustBeIssuedBy("builder"), h.HandleInternalTemplateLogIngest)
	internal.Get("/networks/host-state",
		mw.MustBePeerRoleMTLS("host"),
		mw.MustBeSelfHostFromQuery(middlewares.QueryHostID),
		h.HandleInternalNetworkHostState)
	// Relay reconciler hot-path: sessions + BPF policy pairs for THIS relay.
	// Same shape as host-state but scoped to relay-side concerns. The gate
	// is role=host because the SPIFFE URI is `spiffe://createos/host/<id>`
	// for every leaf (compute + relay alike) — there's no separate "relay"
	// role on the cert. The handler narrows access by (1) matching the
	// caller's SPIFFE host_id against the ?host_id query param and (2)
	// asserting the requested host row is role='relay' in the DB.
	internal.Get("/relay-state", mw.MustBePeerRoleMTLS("host"), h.HandleInternalRelayState)
	// Billing reconcile: external billing service queries a single
	// sandbox's current state by id. Auth via the billing service's
	// own Ed25519 key — verified through control's static-actor map
	// (--verify-billing-pubkey).
	internal.Get(fmt.Sprintf("/billing/sandboxes/:%s", id),
		mw.MustBeIssuedBy("billing"), h.HandleBillingGetSandbox)
	// DB reads + writes: JWT-required. Writes additionally check
	// sandbox ownership (MustBeOwningHost inside registerDBProxy).
	// Wake-on-request: the ingress (mTLS role=ingress) hits this when a
	// browser lands on the public URL of a paused sandbox. Fires a resume
	// and returns 202 immediately; the ingress serves the waking page and
	// reloads until the sandbox is running.
	// role=ingress: the direct call from an ingress. role=control: a peer
	// control forwarding a cross-region wake (it dials with its own cert).
	internal.Post(fmt.Sprintf("/sandboxes/:%s/wake", id), mw.MustBePeerRoleMTLS("ingress", "control"), h.HandleInternalWake)

	dbGroup := internal.Group("/db")
	registerDBProxy(dbGroup, h, mw)
}

// registerDBProxy mounts the /v1/internal/db/* routes. Every route is
// mTLS-gated by an identity-role check:
//   - reads: host or gateway (the union of DB-less readers — the host's
//     controlclient.Client + host-proxy presenting the host's cert, and
//     the gateway's sandbox/host lookup at SSH auth time).
//   - writes: host only.
//   - /sandboxes/:id/* mutations additionally pass MustBeOwningHost so a
//     host can only mutate rows for sandboxes it owns.
func registerDBProxy(g fiber.Router, h *handlers.Handler, mw *middlewares.Middleware) {
	id := middlewares.ParamSandboxID
	// mTLS-only role gates. Names describe caller identity, not HTTP method.
	// owningHost = sandbox host-ownership check (reads SPIFFE identity from Locals).
	// scopedRead adds per-host scoping for `host` callers on routes that
	// take a sandbox id (host can only read its own sandboxes).
	// scopedHostQuery adds per-host scoping on routes that take a
	// `?host=` query param.
	// Note: host-proxy is intentionally absent. The machine proxy
	// binary runs on each bare-metal host alongside machine host and
	// presents the HOST's mTLS leaf (spiffe://createos/host/<id>) — not
	// a separate proxy cert. So host-proxy traffic is already gated by
	// role=host here, and MustOwnSandboxIfHostRole scopes its reads to
	// the proxy's own host.
	hostOrGateway := mw.MustBePeerRoleMTLS("host", "gateway")
	hostOnly := mw.MustBePeerRoleMTLS("host")
	owningHost := mw.MustBeOwningHost()
	scopedRead := mw.MustOwnSandboxIfHostRole()
	scopedHostQuery := mw.MustOwnHostQueryIfHostRole("host")

	// Sandboxes table
	// Static paths registered before the :id wildcard so Fiber doesn't
	// route "running-ids" into dbGetSandbox as id="running-ids".
	g.Get("/sandboxes/running-ids", hostOrGateway, scopedHostQuery, h.DbListRunningIDs)
	g.Get("/sandboxes/live-ids", hostOrGateway, scopedHostQuery, h.DbListLiveIDs)
	g.Get(fmt.Sprintf("/sandboxes/by-ip/:%s", middlewares.ParamIP), hostOrGateway, h.DbGetSandboxByIP)
	g.Get(fmt.Sprintf("/sandboxes/:%s", id), hostOrGateway, scopedRead, h.DbGetSandbox)
	g.Get("/sandboxes", hostOnly, scopedHostQuery, h.DbListSandboxes)
	g.Post("/sandboxes", hostOnly,
		mw.MustBeOwningHostFromBody("id"),
		mw.MustBeSelfHostFromBody("host_id"),
		h.DbInsertSandbox)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/destroyed", id), hostOnly, owningHost, h.DbMarkDestroyed)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/failed", id), hostOnly, owningHost, h.DbMarkFailed)
	// Host-reconcile self-heal: CAS-guarded creating→failed transition,
	// scoped to the calling host by both the `owningHost` middleware
	// (verifies sandbox.host_id == SPIFFE id) and a defense-in-depth
	// SQL CAS that also pins host_id from the body.
	g.Patch(fmt.Sprintf("/sandboxes/:%s/failed-from-creating", id), hostOnly, owningHost, h.DbMarkFailedFromCreatingCAS)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/host", id), hostOnly, owningHost, h.DbSetSandboxHost)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/ssh-pubkeys", id), hostOnly, owningHost, h.DbSetSSHPubkeys)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/egress", id), hostOnly, owningHost, h.DbSetEgress)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/disk", id), hostOnly, owningHost, h.DbSetDiskMib)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/runtime", id), hostOnly, owningHost, h.DbSetRuntime)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/bandwidth/quota", id), hostOnly, owningHost, h.DbSetBandwidthQuota)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/bandwidth/used", id), hostOnly, owningHost, h.DbSetBandwidthUsed)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/bandwidth/capped", id), hostOnly, owningHost, h.DbSetBandwidthCapped)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/bandwidth/ingress", id), hostOnly, owningHost, h.DbUpdateBandwidthIngress)
	g.Patch(fmt.Sprintf("/sandboxes/:%s/ingress", id), hostOnly, owningHost, h.DbSetIngressEnabled)
	g.Get(fmt.Sprintf("/sandboxes/:%s/ingress-route", id), hostOrGateway, scopedRead, h.DbGetIngressRoute)
	// Disks: PATCH per-attachment mount status (host's poller → control),
	// GET resolved bundle for rehydrate (host fetches after serve restart).
	// Both are owner-gated so only the sandbox's owning host can read/write.
	g.Patch(fmt.Sprintf("/sandboxes/:%s/disks/:%s/status",
		id, middlewares.ParamDiskID), hostOnly, owningHost, h.DbSetSandboxDiskStatus)
	g.Get(fmt.Sprintf("/sandboxes/:%s/disks/resolved", id),
		hostOrGateway, owningHost, h.DbResolveSandboxDisks)
	g.Post(fmt.Sprintf("/sandboxes/:%s/disks/reset", id),
		hostOnly, owningHost, h.DbResetSandboxDiskStatus)

	// Hosts table
	g.Get("/hosts", hostOrGateway, h.DbListHosts)
	g.Get(fmt.Sprintf("/hosts/:%s", id), hostOrGateway, h.DbGetHost)
	// DbUpsertHost takes a full models.Host row; the body "id" field pins
	// which row UpsertHost's ON CONFLICT (id) DO UPDATE will overwrite.
	// Without the body-self-check, host-A can post {id:"host-B", addr:"..."}
	// to MITM control/gateway/ingress dials to host-B.
	g.Post("/hosts", hostOnly, mw.MustBeSelfHostFromBody("id"), h.DbUpsertHost)
	// Host heartbeat is a PATCH but :id is a host id, not a sandbox id —
	// it must NOT go through MustBeOwningHost. Instead, gate with
	// MustBeSelfHostFromParam so host-A cannot heartbeat host-B's row
	// (which would suppress the stale-host eviction scheduler relies on).
	g.Patch(fmt.Sprintf("/hosts/:%s/heartbeat", id), hostOnly,
		mw.MustBeSelfHostFromParam(id), h.DbHeartbeatHost)
	// Pause / resume / fork — all JWT-gated writes, hosts call these
	// from their pause/resume goroutines. The sandbox id rides in the
	// JSON body (not the URL), so apply the body-scoped variants of
	// MustBeOwningHost / MustBeSelfHost to prevent host-A from
	// corrupting host-B's sandbox lifecycle.
	//
	// Gate selection:
	//   - "owningHostFromBody": caller must own the current row (running → pausing,
	//      pausing → paused, etc.). Used for the pause + destroy paths.
	//   - "selfHost": body carries a `host` field the caller is
	//      claiming to act as. Used where the row's owner is NULL or
	//      transitioning (resume completion/failure, cache eviction).
	owningHostFromBody := mw.MustBeOwningHostFromBody("id")
	selfInBody := mw.MustBeSelfHostFromBody("host")
	g.Post("/pause/mark-pausing", hostOnly, owningHostFromBody, h.DbMarkPausing)
	g.Post("/pause/mark-paused", hostOnly, owningHostFromBody, h.DbMarkPaused)
	g.Post("/pause/mark-rolled-back", hostOnly, owningHostFromBody, h.DbMarkPauseRolledBack)
	g.Post("/pause/mark-resumed", hostOnly, selfInBody, h.DbMarkResumed)
	g.Post("/pause/mark-resume-failed", hostOnly, selfInBody, h.DbMarkResumeFailed)
	g.Post("/pause/mark-destroying", hostOnly, owningHostFromBody, h.DbMarkDestroying)
	g.Post("/pause/clear-local-cache", hostOnly, selfInBody, h.DbClearLocalCache)
	g.Get("/pause/list-pausing", hostOnly,
		mw.MustOwnHostQueryIfHostRole("host"), h.DbListPausing)
	g.Get("/pause/list-paused", hostOnly,
		mw.MustOwnHostQueryIfHostRole("cached_host"), h.DbListPaused)
	g.Get("/pause/list-stuck-resuming", hostOnly, h.DbListStuckResuming)
	g.Get("/pause/local-cache-candidates", hostOrGateway, scopedHostQuery, h.DbLocalCacheCandidates)
	g.Get(fmt.Sprintf("/pause/local-cache-state/:%s", id), hostOnly, h.DbLocalCacheState)

	// Templates — host-side reads + per-host cache writes.
	g.Get(fmt.Sprintf("/templates/:%s", id), hostOnly, h.DbGetTemplate)
	g.Get("/host-cached-templates", hostOrGateway, scopedHostQuery, h.DbListHostCachedTemplates)
	g.Post("/host-cached-templates/upsert", hostOnly,
		mw.MustBeSelfHostFromBody("host_id"), h.DbUpsertHostCachedTemplate)
	g.Delete(fmt.Sprintf("/host-cached-templates/:%s/:%s", middlewares.ParamHost, middlewares.ParamTemplate),
		hostOnly, mw.MustBeSelfHostFromParam(middlewares.ParamHost), h.DbDeleteHostCachedTemplate)
	g.Get(fmt.Sprintf("/host-cached-templates/:%s/:%s/active-count", middlewares.ParamHost, middlewares.ParamTemplate),
		hostOrGateway, mw.MustBeSelfHostFromParam(middlewares.ParamHost), h.DbHostCachedTemplateActiveCount)

	// Generic
	g.Post("/bootstrap", hostOnly, h.DbBootstrap)
}
