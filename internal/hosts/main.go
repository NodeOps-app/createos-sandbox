// Package hosts is the entry point for the `machine host` subcommand
// — the per-host agent that owns Firecracker VMs, NetPool, OverlayPools,
// egress chains, and the bandwidth meter.
//
// cmd/machine/main.go is pure CLI wiring; the Serve function below is
// the actual host process body. Startup and background-loop helpers also
// live in the other files in this package.
package hosts

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"crypto/tls"
	"crypto/x509"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/internal/ca"
	"github.com/NodeOps-app/createos-sandbox/internal/ca/crl"
	"github.com/NodeOps-app/createos-sandbox/internal/ca/renew"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/api"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/metrics"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/service"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/wg"
	authjwt "github.com/NodeOps-app/createos-sandbox/internal/jwt"
	"github.com/NodeOps-app/createos-sandbox/internal/mtlsclient"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// bootstrapHTTPClient returns an http.Client used by the cert renewer
// to POST CSRs against control's /v1/internal/hosts/csr endpoint.
//
// Properties:
//   - RootCAs = cluster CA bundle (control's :443 serves a CA-signed
//     cert; public root CAs don't trust it).
//   - Presents the host's CURRENT leaf cert as mTLS client cert
//     (loaded fresh on each handshake via GetClientCertificate, so
//     a rotated cert is picked up immediately). Control's :443
//     listener requires mTLS at the TLS layer — even though the CSR
//     route itself checks the bootstrap token, the handshake won't
//     complete without a client cert.
//   - Injects X-Bootstrap-Token on every request (the actual auth gate).
//
// First-time bootstrap (no cert yet) is handled by install.sh via the
// control's :8080 public listener, which doesn't require mTLS. The
// renewer only runs in steady-state when a cert already exists.
func bootstrapHTTPClient(token, certPath, keyPath, caPath string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certs parsed from %s", caPath)
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &bootstrapTokenRT{token: token, base: tr},
	}, nil
}

type bootstrapTokenRT struct {
	token string
	base  http.RoundTripper
}

func (b *bootstrapTokenRT) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(proto.HeaderBootstrapToken, b.token)
	return b.base.RoundTrip(req)
}

// newNetReconcilerClient builds the http.Client the net reconciler uses to
// hit control's internal mTLS endpoint. When TLS paths are empty it returns
// a plain client (dev fallback). HTTP/2 is intentionally disabled to match
// the controlclient pattern (see internal/hosts/controlclient/main.go).
func newNetReconcilerClient(tlsCert, tlsKey, tlsCA string, verify func([][]byte, [][]*x509.Certificate) error) *http.Client {
	base := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	if tlsCert == "" || tlsKey == "" || tlsCA == "" {
		return &http.Client{Timeout: 5 * time.Second, Transport: base}
	}
	tr, err := mtlsclient.NewTransportWithVerify(tlsCert, tlsKey, tlsCA, base, verify)
	if err != nil {
		log.Errorf("[net-reconciler] mTLS transport init failed, falling back to plain HTTP: %v", err)
		return &http.Client{Timeout: 5 * time.Second, Transport: base}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: tr}
}

// buildWGPeers turns the controlclient's view of `hosts` into the peer
// list wg.ReconcilePeers consumes. Filters out self, dead hosts, and peers
// that haven't yet completed a WG-aware registration (empty pubkey or wg_ip).
// Draining hosts remain peers until their existing VMs have been removed.
func buildWGPeers(ctx context.Context, repo *controlclient.Client, selfID string, port int) ([]wg.Peer, error) {
	hosts, err := repo.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]wg.Peer, 0, len(hosts))
	for _, h := range hosts {
		if h.ID == selfID {
			continue
		}
		if h.Status == models.HostStatusDead {
			continue
		}
		if len(h.WGPublicKey) != wgtypes.KeyLen || h.WGIP == "" {
			continue
		}
		if h.UnderlayIP == nil || *h.UnderlayIP == "" {
			continue
		}
		var pk wgtypes.Key
		copy(pk[:], h.WGPublicKey)
		endpointIP := net.ParseIP(*h.UnderlayIP)
		if endpointIP == nil {
			continue
		}
		wgIP := net.ParseIP(h.WGIP)
		if wgIP == nil {
			continue
		}
		var subnet *net.IPNet
		if h.SubnetCIDR != nil && *h.SubnetCIDR != "" {
			if _, sn, err := net.ParseCIDR(*h.SubnetCIDR); err == nil {
				subnet = sn
			}
		}
		var extra []net.IPNet
		if h.Role == models.HostRoleRelay {
			// Relays carry device traffic with src in CGNAT 100.64.0.0/10
			_, devicePool, _ := net.ParseCIDR("100.64.0.0/10")
			if devicePool != nil {
				extra = append(extra, *devicePool)
			}
		}
		out = append(out, wg.Peer{
			PublicKey:       pk,
			Endpoint:        &net.UDPAddr{IP: endpointIP, Port: port},
			WGIP:            wgIP,
			VMSubnet:        subnet,
			ExtraAllowedIPs: extra,
		})
	}
	return out, nil
}

// Serve runs the `machine host` subcommand: bring up Manager, register
// with control, run the host's Fiber API. It's the host process's main.
func Serve(c *cli.Context) error {
	cfg, err := config.ServeFromContext(c)
	if err != nil {
		return err
	}
	vm.SetRuntimeDir(cfg.RuntimeDir)
	metrics.SetRuntimeDir(cfg.RuntimeDir)
	ctx := context.Background()

	// Boost the host binary's nice value so it always wins CFS
	// contention against the per-VM firecracker processes (each VM
	// burns ~17% CPU polling MMDS even when "idle", so 100 VMs would
	// otherwise share createos 1:100). Best-effort.
	if err := vm.SetSelfPriority(); err != nil {
		log.Warnf("[host] setpriority(self, %d) failed: %v (continuing at default nice)", vm.PriorityHostBinary, err)
	} else {
		got, _ := vm.GetSelfPriority()
		log.Infof("[host] nice level = %d (target %d)", got, vm.PriorityHostBinary)
	}
	// CPU lane isolation: reserve a small set of cores for createos +
	// new firecracker boots. Existing/running firecrackers are confined
	// to the tenant lane so they cannot starve a /snapshot/load. See
	// internal/hosts/vm/cpulane.go for the design.
	if err := vm.ConfigureCPULanes(); err != nil {
		log.Warnf("[host] %v (continuing without lane isolation)", err)
	} else {
		log.Infof("[host] %s", vm.LaneSummary())
		if n, err := vm.PinExistingFirecrackersToTenantLane(); err != nil {
			log.Warnf("[host] retro-pin firecrackers to tenant lane: %v", err)
		} else if n > 0 {
			log.Infof("[host] retro-pinned %d existing firecracker(s) to tenant lane", n)
		}
	}

	// Start the prometheus /metrics endpoint on its own listener (separate
	// port from the API server so it can be firewall-isolated). No-op when
	// cfg.MetricsAddr is empty. Errors during ListenAndServe are logged
	// but don't take down serve — observability shouldn't be a hard dep.
	go func() {
		if err := metrics.Serve(ctx, metrics.ServeConfig{
			Addr:      cfg.MetricsAddr,
			TokenFile: cfg.MetricsTokenFile,
		}); err != nil {
			log.Errorf("[metrics] server exited: %v", err)
		}
	}()

	// Hosts access persistence through control's /v1/internal/db/*
	// endpoints using their mTLS identity, without a direct database connection.
	if cfg.ControlURL == "" {
		return fmt.Errorf("--control-url is required")
	}
	// Storage bucket is no longer host-side config — control delivers
	// it in the register response. Validation moved to post-register
	// (controlStorage nil-check).
	if cfg.Region == "" {
		return fmt.Errorf("region is required (set --region or REGION env)")
	}
	// bpffs is a hard requirement now (BPF meter + BPF policy programs both
	// pin maps under /sys/fs/bpf). Fail fast with a clear message instead
	// of mysterious bpf-syscall errors later.
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return fmt.Errorf("bpffs not mounted at /sys/fs/bpf — run: mount -t bpf bpffs /sys/fs/bpf")
	}
	// Load (or generate-on-first-boot) the host's Ed25519 keypair. The
	// PUBLIC half travels with /register and is the first-writer-wins
	// identity anchor on hosts.public_key. The private half no longer
	// signs anything — control verifies host-originated requests via
	// the mTLS SPIFFE URI on the client cert, not via JWT.
	hostPriv, err := authjwt.LoadOrGenerateSeed(cfg.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("load/generate host signing key: %w", err)
	}
	hostPub := hostPriv.Public().(ed25519.PublicKey)
	fmt.Fprintf(os.Stderr, "[hostagent] register pubkey=%x\n", hostPub)

	// CRL fetcher: pulls /v1/internal/crl every 60s and exposes
	// VerifyPeerCertificate for every mTLS site on this host (inbound
	// :9090 listener + outbound controlclient + net-reconciler). A
	// revoked cert is rejected at handshake within ~60s of the
	// `admin ca revoke` call.
	// Uses a dedicated http.Client (cluster-CA roots + this host's
	// own client cert) to dodge a chicken-and-egg: the fetcher itself
	// must reach control even before it has fetched any CRL.
	var crlVerify func([][]byte, [][]*x509.Certificate) error
	if cfg.TLSCertPath != "" && cfg.TLSCAPath != "" {
		crlClient, err := bootstrapHTTPClient("", cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath)
		if err != nil {
			return fmt.Errorf("crl http client: %w", err)
		}
		crlFetcher := crl.New(cfg.ControlURL, crlClient)
		crlFetcher.Logger = log.WithField("component", "crl")
		go crlFetcher.Run(ctx)
		crlVerify = crlFetcher.VerifyPeerCertificate
	}

	repo, err := controlclient.NewClientWithTLSAndVerify(cfg.ControlURL,
		cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath, crlVerify)
	if err != nil {
		return fmt.Errorf("controlclient TLS init: %w", err)
	}
	// Load (or generate-on-first-boot) the host's WireGuard mesh keypair.
	// Sent at register time so control allocates a 172.30.0.<idx> for us
	// and so peers can authenticate our outbound packets. Must come BEFORE
	// register so the pubkey is in the request.
	wgPriv, err := wg.LoadOrCreateKey(cfg.WGSigningKey)
	if err != nil {
		return fmt.Errorf("load/generate host WG key: %w", err)
	}
	wgPub := wgPriv.PublicKey()
	fmt.Fprintf(os.Stderr, "[hostagent] wg pubkey=%s\n", wgPub.String())

	// Register synchronously to obtain the per-host token BEFORE
	// we touch the (remote) repo. We pass cfg.MaxVMs verbatim
	// because the resolved value (auto-derived from IPAM if 0)
	// isn't known yet — heartbeat will update it once the
	// manager is up.
	//
	// The underlay IP is the same IP the kernel would use to reach
	// the control URL — UDP connect()-only probe, no packet leaves
	// the box (see detectOutboundIP doc).
	underlayIP := detectOutboundIP(cfg.ControlURL)
	assignedSubnet,
		assignedWGIP,
		controlShapes,
		controlStorage,
		err := registerHost(ctx,
		repo,
		cfg,
		cfg.Hostname,
		resolveRegisterAddr(cfg),
		underlayIP,
		cfg.MaxVMs,
		hostPub,
		wgPub[:])
	if err != nil {
		return fmt.Errorf("hostagent register: %w", err)
	}
	if controlStorage == nil || controlStorage.Bucket == "" {
		return fmt.Errorf("control plane returned no storage config; refuse to start without pause/resume bucket")
	}
	fmt.Fprintf(os.Stderr, "[hostagent] assigned overlay subnet %s underlay %s wg %s\n", assignedSubnet, underlayIP, assignedWGIP)

	// Resolve the initial shape catalog. Control owns the cluster-wide
	// catalog (the `shapes` DB table) and pushes it on register +
	// heartbeat. An empty list here means the DB was unreachable or the
	// table was empty at register time — the host will prewarm nothing
	// until a subsequent heartbeat returns a non-empty catalog.
	initialShapes := controlShapes
	if len(initialShapes) == 0 {
		log.Warnf("[host] control returned no shapes; host will prewarm nothing until a heartbeat returns shapes")
	}

	// Bring up wg-hosts before any other overlay work. EnsureInterface
	// is idempotent so restarts find the device in its existing state.
	wgIPParsed := net.ParseIP(assignedWGIP)
	if wgIPParsed == nil {
		return fmt.Errorf("control returned malformed wg_ip %q", assignedWGIP)
	}
	// /16 covers the entire 172.30.0.0/16 WG mesh address space (up to
	// 65,534 hosts across 4 region slots). Even though each region uses
	// a distinct /18 within that /16, the mesh is global — every host
	// peers with every other host regardless of region — so the local
	// interface route must cover the whole /16.
	wgAddr := &net.IPNet{IP: wgIPParsed, Mask: net.CIDRMask(16, 32)}
	if err := wg.EnsureInterface("wg-hosts", cfg.WGPort, wgPriv, wgAddr); err != nil {
		return fmt.Errorf("bring up wg-hosts: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[hostagent] wg-hosts up on %s/16 port %d\n", assignedWGIP, cfg.WGPort)

	// Cert auto-renewer. Watches /etc/createos/tls/tls.crt; when remaining
	// life drops below 30d, re-CSRs against control (bootstrap-token
	// authenticated, same path install.sh used at onboarding), writes
	// the new cert + key atomically, and the host's TLS listener picks
	// up the new cert within 60s via its GetCertificate reloader. Host
	// cert TTL is 90d, so this runs once per ~60d in steady state.
	if cfg.TLSCertPath != "" && cfg.BootstrapToken != "" {
		renewHTTP, err := bootstrapHTTPClient(cfg.BootstrapToken, cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath)
		if err != nil {
			return fmt.Errorf("renewer http client: %w", err)
		}
		// Inherit the issued SANs; mutable network config must not expand them.
		go (&renew.Renewer{
			CertPath:       cfg.TLSCertPath,
			KeyPath:        cfg.TLSKeyPath,
			CAPath:         cfg.TLSCAPath,
			ControlURL:     cfg.ControlURL,
			HTTPClient:     renewHTTP,
			Identity:       ca.URIIdentity{HostID: cfg.Hostname},
			Interval:       1 * time.Hour,
			RenewThreshold: 30 * 24 * time.Hour, // host TTL is 90d → renew at ~30d remaining
			Logger:         log.WithField("component", "cert-renew"),
		}).Run(ctx)
	}

	// Peer reconciler + iptables enforcer. Reconciler builds peer list
	// from `hosts` table every 5s; iptables follows the same list so a
	// peer drops out of both at once.
	go func() {
		err := wg.Run(ctx, wg.Config{
			IfaceName: "wg-hosts",
			PeerSource: func(ctx context.Context) ([]wg.Peer, error) {
				return buildWGPeers(ctx, repo, cfg.Hostname, cfg.WGPort)
			},
			Interval: 60 * time.Second,
			OnEnforce: func(peers []wg.Peer) {
				if err := wg.Enforce("wg-hosts", cfg.WGPort, peers); err != nil {
					log.Warnf("[wg] iptables: %v", err)
				}
			},
		})
		if err != nil {
			log.Errorf("[wg] reconciler exited: %v", err)
		}
	}()

	// Pre-flight orphan classification. "running" rows fall into
	// two buckets:
	//   - alive (route + live fc_pid) → rehydrate after NewManager
	//   - dead → marked destroyed in DB here
	// Alive VMs' IPs are reserved in the new IPAM so the NetPool
	// doesn't accidentally hand them out to a fresh create.
	reservedIPs, aliveRecords, pendingDestroyingRecords, err := reconcile(ctx, repo, cfg.Hostname)
	if err != nil {
		// Fail closed before overlay/netns/orphan cleanup. systemd retries
		// serve startup while the existing Firecracker processes continue
		// running and can be rehydrated once control is reachable again.
		return fmt.Errorf("startup reconcile: %w", err)
	}

	// Sweep overlays left behind by dead serve processes. The
	// OverlayPool keeps paths in an in-memory channel that doesn't
	// survive SIGKILL / reboot, so without this they accumulate
	// across restarts (we saw ~200+ pile up in testing). Must run
	// BEFORE NewManager because NewManager fills the fresh pool.
	//
	// Pin the overlays of rehydrated VMs in the keep-list. Without
	// this, a rehydrated VM's overlay file (named with its dead
	// parent serve's PID) gets unlinked here. Firecracker keeps
	// the inode via its open FD so reads/writes still work, but
	// any later path-based access (pause's archive.overlay,
	// reconcile's CleanupOrphan, etc.) hits ENOENT.
	keepOverlays := make([]string, 0, len(aliveRecords))
	for _, r := range aliveRecords {
		if r.OverlayPath != nil && *r.OverlayPath != "" {
			keepOverlays = append(keepOverlays, *r.OverlayPath)
		}
	}
	vm.GCStaleOverlays(keepOverlays...)

	// Collect ContainerIDs of VMs that survived into this process
	// (rehydrate targets) AND of destroying rows we're pinning. The
	// NetPool must not reap any of these netns: rehydrate targets
	// have live VMs in them, pinned destroyings will be processed by
	// the periodic tick which expects their netns intact until
	// MarkDestroyed succeeds.
	liveContainerIDs := make([]string, 0, len(aliveRecords)+len(pendingDestroyingRecords))
	for _, r := range aliveRecords {
		if r.ContainerID != nil && *r.ContainerID != "" {
			liveContainerIDs = append(liveContainerIDs, *r.ContainerID)
		}
	}
	for _, r := range pendingDestroyingRecords {
		if r.ContainerID != nil && *r.ContainerID != "" {
			liveContainerIDs = append(liveContainerIDs, *r.ContainerID)
		}
	}

	// Load the cross-vendor CPU template (if configured) before NewManager
	// builds the prewarm pool — prewarm boots inherit the template and
	// the resulting snapshots are cross-vendor portable. If the file is
	// missing or unparseable we fail loud rather than silently booting
	// without the template (which would leave a fleet with mixed
	// templated/native snapshots — pause/resume across them SIGILLs).
	if err := vm.SetCPUTemplatePath(cfg.CPUTemplatePath); err != nil {
		return fmt.Errorf("cpu template: %w", err)
	}
	if cfg.CPUTemplatePath != "" {
		fmt.Fprintf(os.Stderr, "[cpu-template] applying %s on every cold-create + prewarm boot\n", cfg.CPUTemplatePath)
	}
	if cfg.SeccompFilterPath != "" {
		if _, err := os.Stat(cfg.SeccompFilterPath); err != nil {
			return fmt.Errorf("seccomp filter: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[seccomp] applying %s on every firecracker spawn\n", cfg.SeccompFilterPath)
	}

	mgr, err := vm.NewManager(vm.ManagerConfig{
		KernelPath:               cfg.KernelPath,
		InitrdPath:               cfg.InitrdPath,
		Rootfses:                 cfg.Rootfses,
		DefaultRootfs:            cfg.DefaultRootfs,
		Subnet:                   assignedSubnet,
		Gateway:                  cfg.Gateway,
		PoolSize:                 cfg.PoolSize,
		NetPoolWorkers:           cfg.NetPoolWorkers,
		DiskSizeMB:               cfg.DiskSizeMB,
		ColdOnly:                 cfg.ColdOnly,
		SnapshotDir:              cfg.SnapshotDir,
		PrewarmAllRootfs:         cfg.PrewarmAllRootfs,
		MaxVMs:                   cfg.MaxVMs,
		FirecrackerUIDBase:       cfg.FirecrackerUIDBase,
		SeccompFilterPath:        cfg.SeccompFilterPath,
		ReservedVMIPs:            reservedIPs,
		LiveContainerIDs:         liveContainerIDs,
		PendingDestroyingRecords: pendingDestroyingRecords,
		UFFDMode:                 cfg.UFFD,
		HostID:                   cfg.Hostname,
		UnderlayIP:               underlayIP,
		ControlURL:               cfg.ControlURL,
		ControlHTTPClient:        newNetReconcilerClient(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath, crlVerify),
		AgentLivenessProbe:       cfg.AgentLivenessProbe,
		AgentProbeTransport:      cfg.AgentProbeTransport,
		Shapes:                   initialShapes,
	})
	if err != nil {
		return err
	}

	// OnSandboxDeath: when a firecracker process exits between our
	// invocations (crash, SIGKILL, OOM, guest kernel panic), the
	// Manager's per-VM watcher reclaims local resources and fires
	// this callback. We persist the resulting state to the DB so
	// users see the sandbox as destroyed within a few seconds,
	// rather than waiting for a serve restart's reconcile pass.
	mgr.OnSandboxDeath = func(id, reason string) {
		bg := context.Background()
		deathNote := "firecracker exited: " + reason
		if err := repo.MarkDestroyed(bg, id, time.Now().UTC(), &deathNote); err != nil {
			fmt.Fprintf(os.Stderr, "[death] MarkDestroyed(%s): %v\n", id, err)
		}
	}

	// Rehydrate surviving VMs: register each in Manager.Sandboxes
	// so the API can drive them (exec / files / destroy) exactly
	// as if this were the same process that originally spawned
	// them. Any row that fails rehydrate gets marked destroyed.
	freezeIntents := service.SnapshotFreezeIntents(cfg.Pause.PausedDir)
	for _, r := range aliveRecords {
		spec := vm.RehydrateSpec{
			ID:                    r.ID,
			FCPid:                 r.FCPid,
			VCPU:                  r.VCPU,
			MemMib:                r.MemMib,
			DiskMib:               r.DiskMib,
			Egress:                r.Egress,
			BandwidthQuota:        r.BandwidthQuotaBytes,
			BandwidthUsed:         r.BandwidthUsedBytes,
			BandwidthIngressBytes: r.BandwidthIngressBytes,
			BandwidthCapped:       r.BandwidthCapped,
			Envs:                  r.Envs,
		}
		if r.SecretToken != nil {
			spec.SecretToken = *r.SecretToken
		}
		if r.IP != nil {
			spec.IP = *r.IP
		}
		if r.MAC != nil {
			spec.MAC = *r.MAC
		}
		if r.ContainerID != nil {
			spec.ContainerID = *r.ContainerID
		}
		if r.APISock != nil {
			spec.APISock = *r.APISock
		}
		if r.OverlayPath != nil {
			spec.OverlayPath = *r.OverlayPath
		}
		if r.Rootfs != nil {
			spec.Rootfs = *r.Rootfs
		}
		spec.Freezing = freezeIntents[r.ID] == r.FCPid && r.FCPid > 0
		if err := mgr.Rehydrate(spec); err != nil {
			fmt.Fprintf(os.Stderr, "[rehydrate] %s failed: %v — marking destroyed\n", r.ID, err)
			rehydrateNote := "rehydrate failed: " + err.Error()
			_ = repo.MarkDestroyed(ctx, r.ID, time.Now().UTC(), &rehydrateNote)
			continue
		}
		// Pull the decrypted disk bundle from control so the in-memory
		// sandbox knows what's attached. Without this the disk status
		// poller would skip the VM (sb.Disks empty) and the UI would
		// keep showing 'pending' forever. The agent already has the
		// disks mounted from before the serve restart — we're just
		// repopulating host-side state to drive the poller.
		if disks, derr := repo.ResolveSandboxDisks(ctx, r.ID); derr == nil && len(disks) > 0 {
			mgr.SetDisks(r.ID, disks)
		}
	}

	// Catch-net for the tenant-create leak window: a firecracker child
	// whose serve parent died between fm.Start and the fc_pid DB write
	// is alive but unknown to the new serve. Rehydrate just populated
	// mgr.Sandboxes with every legitimate survivor; anything left over
	// is an orphan and gets SIGKILL'd. Prewarm templates were already
	// reaped earlier in NewManager. Defense-in-depth: Pdeathsig closes
	// the live window for prewarm, this sweep closes it for tenants
	// (where we can't use Pdeathsig without breaking rehydrate).
	mgr.ReapOrphanTenantFirecrackers()

	svc, err := service.New(ctx, mgr, repo, cfg.Hostname, cfg.Region)
	if err != nil {
		return err
	}
	svc.PauseCfg.PausedDir = cfg.Pause.PausedDir
	svc.RecoverSnapshotGuests(ctx)
	for _, r := range aliveRecords {
		if sb, ok := mgr.Lookup(r.ID); ok {
			svc.StartSelfSignal(sb)
		}
	}
	svc.HostPriv = hostPriv
	svc.SetMaxConcurrentBoots(cfg.MaxConcurrentBoots)
	// Stamp CPU identity once at startup so Create can persist it on
	// every new sandbox row (vendor lineage for future cpu_compat
	// scheduler filter; see internal/scheduler/plugins/cpu_compat.go).
	{
		hw := CollectHardware(cfg.SnapshotDir)
		svc.CPUVendor = hw.CPUVendor
		svc.CPUFamily = hw.CPUFamily
	}

	// Storage credentials come from control at register time — host
	// never persists S3 creds. controlStorage was nil-checked above.
	st, err := storage.NewR2(storage.R2Config{
		Endpoint:        controlStorage.Endpoint,
		Region:          controlStorage.Region,
		AccessKeyID:     controlStorage.AccessKeyID,
		SecretAccessKey: controlStorage.SecretAccessKey,
		Bucket:          controlStorage.Bucket,
		Secure:          controlStorage.Secure,
	})
	if err != nil {
		return fmt.Errorf("init R2 storage: %w", err)
	}
	pausedDir := cfg.Pause.PausedDir
	if err := os.MkdirAll(pausedDir, 0o711); err != nil {
		return fmt.Errorf("paused dir: %w", err)
	}
	// Slot UIDs need to traverse this parent, but must not list it.
	// MkdirAll preserves existing modes; correct drift without touching
	// the private per-sandbox directories or their contents.
	if err := os.Chmod(pausedDir, 0o711); err != nil {
		return fmt.Errorf("paused dir permissions: %w", err)
	}
	cached := &storage.LocalCache{Dir: pausedDir, Underlying: st}
	svc.Storage = cached
	// Cache initialization is optional: restores keep working without it.
	if err := svc.InitSnapshotDownloadCache(pausedDir, cfg.SnapshotDir); err != nil {
		log.Warnf("[snapshot-cache] disabled: %v", err)
	}
	pauseCfg := service.PauseConfig{
		HostID:            cfg.Hostname,
		PausedDir:         pausedDir,
		LocalRetain:       cfg.Pause.LocalRetain,
		LocalDiskBudget:   cfg.Pause.LocalDiskBudget,
		RetryBudget:       cfg.Pause.RetryBudget,
		ResumeMaxHosts:    cfg.Pause.ResumeMaxHosts,
		ZstdLevel:         cfg.Pause.ZstdLevel,
		ReconcileInterval: time.Minute,
	}
	if pauseCfg.RetryBudget <= 0 {
		pauseCfg.RetryBudget = 5
	}
	if pauseCfg.ResumeMaxHosts <= 0 {
		pauseCfg.ResumeMaxHosts = 3
	}
	if pauseCfg.ZstdLevel <= 0 {
		pauseCfg.ZstdLevel = 1
	}
	svc.PauseCfg = pauseCfg
	if err := svc.InitDiskBudget(); err != nil {
		return fmt.Errorf("disk budget: %w", err)
	}
	svc.RecoverSnapshotGuests(ctx)
	go svc.CacheReaperLoop(ctx)
	// Recover only this host's interrupted pause/resume operations. Pause
	// recovery verifies completed local bundles before upload; incomplete
	// captures fail, while operational errors retain artifacts for retry.
	// It runs synchronously with a five-minute bound. Resume recovery starts
	// background attempts from the durable bundle and verified local cache.
	{
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Minute)
		svc.RecoverStuckPauses(rctx)
		rcancel()
	}
	svc.RecoverStuckResumes(ctx)
	fmt.Fprintf(os.Stderr, "[pause] orchestrator enabled, bucket=%s paused_dir=%s\n", controlStorage.Bucket, pausedDir)

	// Template orchestrator. Reuses the same object-storage client + a dedicated
	// local-cache dir. Drives lazy ext4 fetches on first sandbox create
	// and the TTL+LRU reaper. All knobs follow the standard flag/env >
	// YAML > default precedence (see config.TemplatesFile / TEMPLATES_*
	// env vars).
	tplDir := cfg.Templates.Dir
	if tplDir == "" {
		tplDir = "/var/lib/createos/templates"
	}
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		return fmt.Errorf("templates dir: %w", err)
	}
	tplCached := &storage.LocalCache{Dir: tplDir, Underlying: st}
	// Templates share storage with pause — but if you want them on a
	// separate bucket later, this is the place. For now both ride on
	// svc.Storage (set above). The local cache wrapper is template-specific.
	_ = tplCached
	tplCfg := service.TemplateConfig{
		HostID:       cfg.Hostname,
		TemplatesDir: tplDir,
		TTL:          cfg.Templates.TTL,
		TTLOverrides: cfg.Templates.TTLOverrides,
		DiskBudget:   cfg.Templates.DiskBudgetMib * 1024 * 1024,
		ReapInterval: cfg.Templates.ReapInterval,
	}
	if tplCfg.TTL <= 0 {
		tplCfg.TTL = time.Hour
	}
	if tplCfg.ReapInterval <= 0 {
		tplCfg.ReapInterval = time.Minute
	}
	if tplCfg.TemplatesDir == "" {
		tplCfg.TemplatesDir = "/var/lib/createos/templates"
	}
	svc.TplCfg = tplCfg
	// tplInflight needs init (used by EnsureTemplate's coalescing map).
	svc.InitTplInflight()
	svc.ReconcileOnStartup(ctx)
	go svc.ReaperLoop(ctx)
	fmt.Fprintf(os.Stderr, "[tpl] orchestrator enabled, dir=%s ttl=%s budget=%dMiB\n",
		tplDir, cfg.Templates.TTL, cfg.Templates.DiskBudgetMib)

	// Memory dedup: VMs running the same rootfs share huge amounts
	// of identical pages. KSM merges them in the background. Best
	// effort — skip if kernel lacks CONFIG_KSM.
	if cfg.KSM {
		if err := vm.EnableKSM(0, 0); err != nil {
			fmt.Fprintf(os.Stderr, "[ksm] not enabled: %v (continuing)\n", err)
		}
	}

	// Reload any persisted snapshots so prewarm can skip them.
	if n, err := mgr.LoadSnapshots(); err != nil {
		fmt.Fprintf(os.Stderr, "load snapshots: %v\n", err)
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "[snapshot] loaded %d snapshot(s) from %s\n", n, cfg.SnapshotDir)
	}
	mgr.StartSnapshotJanitor(ctx)

	// Pre-warm snapshots for every catalog shape in the background.
	mgr.Prewarm(ctx)

	// Start the prometheus gauge-refresh loop. Cheap (in-mem reads
	// only), no-op when /metrics endpoint isn't enabled — the gauges
	// just don't get scraped.
	mgr.StartMetricsLoop(ctx, cfg.MemCapacity, 5*time.Second)

	// Start bandwidth meter loop. Reads iptables counters every 5s,
	// enforces the cap when quota is exceeded, and persists usage.
	mgr.StartMeterLoopWithIngress(ctx, func(id string, used int64, capped bool) {
		_ = repo.SetBandwidthUsed(ctx, id, used) // silent — poll will retry
		_ = repo.SetBandwidthCapped(ctx, id, capped)
	}, func(id string, ingressBytes int64) {
		_ = repo.UpdateBandwidthIngress(ctx, id, ingressBytes)
	}, 5*time.Second)

	// Disk status loop. Polls each running sandbox with attached disks
	// every 30 s via the agent's /disks/status endpoint and PATCHes
	// changed values back through control's DB proxy. Cheap when no
	// sandboxes hold disks (snapshot tick is O(1) under read lock).
	mgr.StartDiskStatusLoop(ctx, func(ctx context.Context, sbID, diskID, mountPath, status, errMsg string) error {
		return repo.SetSandboxDiskStatus(ctx, sbID, diskID, mountPath, status, errMsg)
	}, 30*time.Second)

	// Disk reconcile loop: for live sandboxes where the host already tracks
	// at least one disk, compare the host's disk set with control's
	// sandbox_disks rows and re-push MMDS when they differ. This repairs
	// partial attach/detach updates after disk participation has begun (for
	// example, a host-side detach succeeds but the DB delete fails). It does
	// not recover a failed forward of a sandbox's first disk: an empty local
	// disk set is deliberately skipped by the loop below.
	mgr.StartDiskReconcileLoop(ctx, repo.ResolveSandboxDisks, 60*time.Second)

	// Periodic reconciler: DB↔memory drift fixer. See reconcileTickLoop below.
	go reconcileTickLoop(ctx, repo, mgr, svc, cfg.Hostname)

	// The host API authenticates service peers with mTLS and checks their
	// SPIFFE roles at each route. CRL verification rejects revoked peers.
	srv := &api.Server{
		Svc:  svc,
		Addr: cfg.Addr,

		// mTLS is the sole auth gate on internal RPCs after the JWT path
		// retirement. The listener wraps in TLS 1.3 + RequireAndVerifyClientCert
		// when all three TLS paths are set.
		TLSCertPath: cfg.TLSCertPath,
		TLSKeyPath:  cfg.TLSKeyPath,
		TLSCAPath:   cfg.TLSCAPath,
		// CRL verifier runs on every inbound mTLS handshake — revoked
		// peers (control, ingress, gateway, another host) get rejected.
		VerifyPeerCertificate: crlVerify,
	}
	defer mgr.Shutdown()

	// Per-sandbox cgroup scraper: emits createos_sandbox_memory_bytes /
	// _limit_bytes / cpu_seconds_total at /metrics, labeled by sandbox_id.
	// 15s tick; series for destroyed sandboxes are dropped automatically.
	go metrics.ScrapeCgroupsLoop(ctx, mgr)

	// Orphan cgroup sweeper. RemoveVMCgroup retries EBUSY up to 3s,
	// but any leaf that stays busy past that budget is left for this
	// loop to reap. Also catches cgroups stranded by a crash between
	// firecracker exit and Manager.Destroy. 1 min cadence; empty-only
	// (never kills live processes).
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				live := make(map[string]struct{}, 64)
				for _, id := range mgr.LiveIDs() {
					live[id] = struct{}{}
				}
				vm.SweepOrphanCgroups(live)
				// Runtime dirs: skip live AND paused-on-this-host (cache
				// dir kept for locality). PausedDir lookup is best-effort
				// — failures skip the sweep this tick to stay safe.
				paused := make(map[string]struct{}, 32)
				if pausedDir != "" {
					if ents, err := os.ReadDir(pausedDir); err == nil {
						for _, e := range ents {
							if e.IsDir() && strings.HasPrefix(e.Name(), "sb-") {
								paused[e.Name()] = struct{}{}
							}
						}
					}
				}
				mgr.SweepOrphanRuntimeDirs(paused)
			}
		}
	}()

	// Cordon poll: refresh own cordon flag from the durable record
	// every 5s. See cordonPollLoop below.
	// TODO: Fold this refresh into the heartbeat response to avoid a separate poll.
	go cordonPollLoop(ctx, repo, srv, cfg.Hostname)

	// Heartbeat loop in the background. Initial register already
	// happened synchronously up-front (see registerHost above).
	go func() {
		if err := runHeartbeat(ctx, HeartbeatConfig{
			HostID:             cfg.Hostname,
			DiskPath:           cfg.SnapshotDir,
			SnapshotCacheHints: svc.SnapshotCacheHints,
		}, repo, &mgrStater{m: mgr}, mgr, func() { mgr.KickPrewarm(ctx) }); err != nil {
			fmt.Fprintf(os.Stderr, "heartbeat: %v\n", err)
		}
	}()

	// Start the overlay network reconciler
	mgr.StartNetReconciler(ctx)

	return srv.Run(ctx)
}
