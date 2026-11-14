package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

// ServeConfig holds the resolved configuration for the `serve` subcommand.
type ServeConfig struct {
	Addr       string
	KernelPath string
	InitrdPath string
	// Rootfses is the catalog of base images by name. Always non-empty after
	// resolution: a single --rootfs CLI flag is normalised into a 1-entry map.
	Rootfses         map[string]string
	DefaultRootfs    string
	PrewarmAllRootfs bool
	SnapshotDir      string
	Gateway          string
	PoolSize         int
	NetPoolWorkers   int
	RuntimeDir       string
	DiskSizeMB       int64
	ColdOnly         bool

	Hostname string
	// ControlURL is the mTLS endpoint of the control plane used for every
	// steady-state RPC (heartbeat, /v1/internal/db/*, tunnels, etc.). The
	// one-shot CSR exchange at install time goes to a separate
	// --bootstrap-control-url in install.sh (which doesn't and can't use
	// mTLS — the host has no cert yet) and is not part of runtime config.
	ControlURL  string
	MemCapacity int

	// Multi-dimensional oversubscription factors advertised to the
	// scheduler at register time. Integer 10ths (20 = 2.0×). 0 = use
	// scheduler defaults (cpu=20, mem=10, disk=50). Set per host based
	// on hardware: an NVMe host can run higher disk_overcommit; a
	// CPU-light memory-heavy box can run higher cpu_overcommit.
	CPUOvercommitX10  int
	MemOvercommitX10  int
	DiskOvercommitX10 int
	// Region pins this host to one regions.name. Required; control
	// refuses registration with empty/disabled region.
	Region string

	// AuthCacheTTL is the in-process registry cache lifetime per key.
	// 0 = the auth package's default (60s).
	AuthCacheTTL int

	// MaxVMs is the hard ceiling on concurrent sandboxes this host accepts.
	// Advertised at register; control's scheduler refuses to pick a host at
	// or above this cap. 0 = derive from the subnet's /31 pair count
	// (whatever the IPAM can hand out).
	MaxVMs int

	// MaxConcurrentBoots caps how many firecracker.Start calls run at the
	// same time on this host. Above this cap, additional create requests
	// queue inside the handler until a slot frees. Mitigates the nested-
	// virt PCI MMIO race on cloud-VM hosts. 0 disables the cap.
	MaxConcurrentBoots int

	// FirecrackerUIDBase is the per-slot UID base for unprivileged
	// firecracker execution. The host computes
	//   slotUID = FirecrackerUIDBase + slotIndex
	// and runs each firecracker as that UID via setresuid before
	// execve. Combined with chmod 0600 on per-VM files, this gives:
	//   - firecracker can never land as root if its process is RCE'd
	//   - one VM's firecracker cannot read another VM's snapshot/RAM
	//   - createos's config + signing keys stay invisible (dir 0700)
	//
	// Effective range: [FirecrackerUIDBase, FirecrackerUIDBase + 1024).
	// Default 100000 — the canonical safe choice on Linux distros
	// (above system uids, below typical login uids). Override to a
	// different base only when 100000+1024 would collide with
	// existing users on this host. Setting to 0 disables uid drop
	// entirely; only useful for debugging a host where kvm-group or
	// chown layout is broken.
	FirecrackerUIDBase int

	// Labels are operator-assigned key/value tags advertised at register
	// time and used by the scheduler's LabelSelectorFilter. Set via
	// repeatable --label key=value or `labels:` map in YAML.
	Labels map[string]string

	// KSM enables Kernel Same-page Merging at server start. Worth it
	// whenever many VMs run the same rootfs (page dedup → 30–50% RAM
	// saved). Default true. Set false for kernels without CONFIG_KSM.
	KSM bool

	// UFFD controls snapshot-restore memory backing. Values:
	//   "off" (default) — file-backed; restart-survivable
	//   "on"            — force UFFD on every VM
	//   "auto"          — UFFD on at ≥ 512 MiB, file-backed below
	// Default flipped from "auto" to "off" because the UFFD page server
	// lives inside this serve process — a serve restart kills the
	// goroutine and the next guest page fault blocks the vCPU forever,
	// silently breaking ~75% of UFFD VMs across deploys.
	UFFD string

	// CPUTemplatePath is the optional absolute path to a firecracker CPU
	// template JSON. When set, every cold-created VM (and every prewarm
	// template VM) gets a `PUT /cpu-config` with this body before boot.
	// Snapshots taken under the template are cross-vendor portable; the
	// template tax is the masked feature set (typically AVX-512 / SHA-NI
	// / AMX). Empty (default) = host-native CPUID, no portability.
	CPUTemplatePath string

	// SeccompFilterPath is the optional absolute path to a firecracker
	// seccomp filter JSON. When set, firecracker is launched with
	// --seccomp-filter <path>, restricting the VMM thread's syscalls to
	// an allowlist. Blocks PROT_EXEC on mmap/mprotect, preventing
	// shellcode injection via memory corruption. Empty (default) = use
	// firecracker's built-in default filter.
	SeccompFilterPath string

	// AgentLivenessProbe destroys a VM after five continuous minutes of failed
	// guest-agent connection probes. Successful probes, snapshot freezing, and
	// bandwidth capping reset the failure timer. Enabled by default.
	// Set agent_liveness_probe: false in serve.yaml to disable.
	AgentLivenessProbe bool

	// AgentProbeTransport selects how waitForAgent dials the guest
	// readiness signal. "tcp" is the historical default — works on
	// every host, pays the nested-virt packet-trap tax on cloud
	// VM hosts. "vsock" bypasses virtio-net entirely (host→guest goes
	// through a unix socket proxy in firecracker, no packet emulation),
	// dropping agent-phase latency 3-5× on nested-virt. Requires a
	// patched firecracker with vsock_override support (cherry-picked
	// from upstream main; not in stock v1.15.1) and the agent's vsock
	// listener (auto-bound in phase 1; falls back to TCP if guest
	// kernel lacks vsock).
	AgentProbeTransport string // "vsock" (default) | "tcp"

	// MetricsAddr is the TCP listen address for the prometheus /metrics
	// endpoint. Empty disables the endpoint. Recommend ":9091" — distinct
	// from the API port so /metrics is firewall-isolatable.
	MetricsAddr string
	// MetricsTokenFile points at a file containing the static bearer
	// token Prometheus must send. Empty = no auth (only OK in dev or
	// on a private interface).
	MetricsTokenFile string

	Pause PauseConfig

	// Templates is the host-side template ext4 cache config. Owns
	// where ext4 files land, how long an idle entry survives, and the
	// disk-budget LRU watermark.
	Templates TemplatesConfig

	// SigningKeyPath is the path to the host's Ed25519 private signing key
	// (32-byte raw seed file). If the file doesn't exist on first boot,
	// the host generates a fresh keypair and persists the seed there.
	// The corresponding public key is sent on /v1/internal/hosts/register
	// so control can verify host→control JWTs.
	// Default: <snapshot_dir>/host_signing.key.
	SigningKeyPath string

	// BootstrapToken is the operator-shared secret sent in
	// X-Bootstrap-Token on the very first /hosts/register call. After
	// register completes, all subsequent RPCs use JWTs and this secret
	// is unused for the lifetime of the host process. Required.
	// Prefer BootstrapTokenFile in prod — flag values leak via
	// /proc/<pid>/cmdline + ps.
	BootstrapToken     string
	BootstrapTokenFile string // path to file (mode 0600) holding the token

	// WGPort is the UDP port for the host-mesh WireGuard listener.
	// Default 51820. Each host accepts encrypted overlay traffic from
	// peers on this port; the iptables enforcer ACCEPTs only from
	// peer underlay IPs.
	WGPort int

	// WGSigningKey is the path to the host's WG mesh private-key file
	// (32-byte Curve25519). Generated on first boot if absent.
	// Default: <snapshot_dir>/wg_signing.key.
	WGSigningKey string

	// TLS server config — listener wraps in TLS 1.3 + RequireAndVerifyClientCert
	// when all three paths are set; empty paths leave it plain (dev only).
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string
}

// RootfsEntry is one rootfs catalog entry in YAML.
type RootfsEntry struct {
	Name    string `yaml:"name"`
	Path    string `yaml:"path"`
	Default bool   `yaml:"default"`
}

// ServeFile is the YAML schema for the `serve` subcommand.
// Pointer fields distinguish "unset" from "zero".
type ServeFile struct {
	Addr                *string           `yaml:"addr"`
	Kernel              *string           `yaml:"kernel"`
	Initrd              *string           `yaml:"initrd"`
	Rootfs              []RootfsEntry     `yaml:"rootfs"`
	PrewarmAllRootfs    *bool             `yaml:"prewarm_all_rootfs"`
	SnapshotDir         *string           `yaml:"snapshot_dir"`
	Gateway             *string           `yaml:"gateway"`
	Pool                *int              `yaml:"pool"`
	NetPoolWorkers      *int              `yaml:"netpool_workers"`
	RuntimeDir          *string           `yaml:"runtime_dir"`
	MaxConcurrentBoots  *int              `yaml:"max_concurrent_boots"`
	FirecrackerUIDBase  *int              `yaml:"firecracker_uid_base"`
	CPUOvercommitX10    *int              `yaml:"cpu_overcommit_x10"`
	MemOvercommitX10    *int              `yaml:"mem_overcommit_x10"`
	DiskOvercommitX10   *int              `yaml:"disk_overcommit_x10"`
	WGSigningKey        *string           `yaml:"wg_signing_key"`
	Disk                *int64            `yaml:"disk"`
	Cold                *bool             `yaml:"cold"`
	Hostname            *string           `yaml:"hostname"`
	ControlURL          *string           `yaml:"control_url"`
	Region              *string           `yaml:"region"`
	MemCapacityMib      *int              `yaml:"mem_capacity_mib"`
	Labels              map[string]string `yaml:"labels"`
	Auth                *AuthFile         `yaml:"auth"`
	UFFD                *string           `yaml:"uffd"`
	CPUTemplatePath     *string           `yaml:"cpu_template_path"`
	SeccompFilterPath   *string           `yaml:"seccomp_filter_path"`
	AgentLiveness       *bool             `yaml:"agent_liveness_probe"`
	AgentProbeTransport *string           `yaml:"agent_probe_transport"`
	Metrics             *MetricsFile      `yaml:"metrics"`
	Pause               *PauseFile        `yaml:"pause"`
	Templates           *TemplatesFile    `yaml:"templates"`
	TLSCert             *string           `yaml:"tls_cert"`
	TLSKey              *string           `yaml:"tls_key"`
	TLSCA               *string           `yaml:"tls_ca"`
}

// TemplatesConfig is the resolved host-side template-cache config.
type TemplatesConfig struct {
	Dir           string        // /var/lib/createos/templates
	TTL           time.Duration // 1h
	TTLOverrides  map[string]time.Duration
	DiskBudgetMib int64         // 0 = unlimited
	ReapInterval  time.Duration // 1m
}

// TemplatesFile is the YAML schema (templates: { ... }).
type TemplatesFile struct {
	Dir           *string           `yaml:"dir"`
	TTL           *string           `yaml:"ttl"`
	TTLOverrides  map[string]string `yaml:"ttl_overrides"`
	DiskBudgetMib *int64            `yaml:"disk_budget_mib"`
	ReapInterval  *string           `yaml:"reap_interval"`
}

// AuthFile is the YAML schema for the per-server auth section.
type AuthFile struct {
	MetricsToken            *string         `yaml:"metrics_token"`
	AdminToken              *string         `yaml:"admin_token"`
	BootstrapToken          *string         `yaml:"bootstrap_token"`
	BootstrapTokenFile      *string         `yaml:"bootstrap_token_file"`
	RelayBootstrapToken     *string         `yaml:"relay_bootstrap_token"`
	RelayBootstrapTokenFile *string         `yaml:"relay_bootstrap_token_file"`
	CacheTTLSeconds         *int            `yaml:"cache_ttl_seconds"`
	SigningKey              *string         `yaml:"signing_key"`
	Verify                  *AuthVerifyFile `yaml:"verify"`
}

// AuthVerifyFile is the per-actor static pubkey config block read by
// the control plane to verify inbound JWTs. Post-mTLS only two
// verifiers remain — every other internal hop authenticates via
// SPIFFE-URI client cert.
//
// `control_pubkey` was retired alongside the JWT-from-control path on
// hosts and the JWT-from-control path on scheduler. Older configs may
// still carry the key; strict YAML decoding rejects it. Remove retired
// fields before starting with an older config file.
type AuthVerifyFile struct {
	BuilderPubkey *string `yaml:"builder_pubkey"` // control verifies builder runner-pod JWTs
	BillingPubkey *string `yaml:"billing_pubkey"` // control verifies external billing reconcile JWTs
}

// Backwards-compatible alias for callers still using the old name.
type Config = ServeConfig

// ServeFlags returns the urfave/cli flags for the `serve` subcommand.
func ServeFlags() []cli.Flag {
	flags := []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file"},
		&cli.StringFlag{Name: "addr", Value: ":8080", Usage: "API listen address", EnvVars: []string{"ADDR"}},
		&cli.StringFlag{Name: "kernel", Value: "images/vmlinux", Usage: "kernel path", EnvVars: []string{"KERNEL"}},
		&cli.StringFlag{Name: "initrd", Value: "images/initrd.gz", Usage: "initrd path", EnvVars: []string{"INITRD"}},
		&cli.StringFlag{Name: "rootfs", Value: "images/rootfs.ext4", Usage: "single rootfs path (overrides YAML rootfs catalog)", EnvVars: []string{"ROOTFS"}},
		&cli.BoolFlag{Name: "prewarm-all-rootfs", Value: false, Usage: "prewarm snapshots for every rootfs (default: only the default rootfs)", EnvVars: []string{"PREWARM_ALL_ROOTFS"}},
		&cli.StringFlag{Name: "snapshot-dir", Value: "snapshots", Usage: "directory for persisted snapshot files", EnvVars: []string{"SNAPSHOT_DIR"}},
		&cli.StringFlag{Name: "gateway", Value: "", Usage: "host-owned gateway IP inside subnet (empty => .1)", EnvVars: []string{"GATEWAY"}},
		&cli.IntFlag{Name: "pool", Value: 10, Usage: "network pool size", EnvVars: []string{"POOL_SIZE"}},
		&cli.IntFlag{Name: "netpool-workers", Value: 8, Usage: "parallel workers that create and replenish network slots"},
		&cli.StringFlag{Name: "runtime-dir", Value: "/var/lib/createos/runtime", Usage: "host-local directory for transient per-VM runtime artifacts"},
		&cli.Int64Flag{Name: "disk", Value: 512, Usage: "overlay disk size in MB", EnvVars: []string{"DISK_MIB"}},
		&cli.BoolFlag{Name: "cold", Value: false, Usage: "disable snapshot, always cold-boot", EnvVars: []string{"COLD_ONLY"}},
		&cli.StringFlag{Name: "hostname", Value: "", Usage: "instance hostname (blank = os.Hostname)", EnvVars: []string{"HOSTNAME_OVERRIDE"}},
		&cli.StringFlag{Name: "control-url", Value: "", Usage: "control plane mTLS endpoint dialed for every steady-state RPC (required)", EnvVars: []string{"CONTROL_URL"}},
		&cli.StringFlag{Name: "region", Value: "", Usage: "region this host belongs to (required; must exist in regions table)", EnvVars: []string{"REGION"}},
		&cli.IntFlag{Name: "mem-capacity-mib", Value: 16384, Usage: "capacity (MiB) this host advertises to the control plane", EnvVars: []string{"MEM_CAPACITY_MIB"}},
		&cli.IntFlag{Name: "auth-cache-ttl", Value: 0, Usage: "auth registry cache TTL in seconds (0 = default 60)", EnvVars: []string{"AUTH_CACHE_TTL"}},
		&cli.StringFlag{Name: "bootstrap-token", Value: "", Usage: "shared secret on first /hosts/register (prefer --bootstrap-token-file; this flag leaks via /proc/<pid>/cmdline)", EnvVars: []string{"BOOTSTRAP_TOKEN"}},
		&cli.StringFlag{Name: "bootstrap-token-file", Value: "", Usage: "path to file (mode 0600) holding the bootstrap token; takes precedence over --bootstrap-token", EnvVars: []string{"BOOTSTRAP_TOKEN_FILE"}},
		&cli.StringFlag{Name: "signing-key", Value: "", Usage: "path to host's Ed25519 signing-key seed (default: <snapshot-dir>/host_signing.key)", EnvVars: []string{"SIGNING_KEY"}},
		&cli.IntFlag{Name: "max-vms", Value: 1024, Usage: "hard ceiling on concurrent VMs on this host (0 = derive from subnet)", EnvVars: []string{"MAX_VMS"}},
		&cli.IntFlag{Name: "max-concurrent-boots", Value: 20, Usage: "max firecracker.Start calls running at once; extra creates queue. 0 = unbounded.", EnvVars: []string{"MAX_CONCURRENT_BOOTS"}},
		&cli.IntFlag{Name: "firecracker-uid-base", Value: 100000, Usage: "per-slot UID base for unprivileged firecracker. Default 100000 — slot N runs as uid 100000+N. Set 0 to disable uid drop (debug only).", EnvVars: []string{"FIRECRACKER_UID_BASE"}},
		&cli.IntFlag{Name: "cpu-overcommit-x10", Value: 0, Usage: "scheduler multi-dim admission: vCPU oversubscription, integer 10ths (20 = 2.0×). 0 = scheduler default (20 = 2.0×).", EnvVars: []string{"CPU_OVERCOMMIT_X10"}},
		&cli.IntFlag{Name: "mem-overcommit-x10", Value: 0, Usage: "scheduler multi-dim admission: memory oversubscription, integer 10ths (10 = 1.0×). 0 = scheduler default (10 = 1.0×).", EnvVars: []string{"MEM_OVERCOMMIT_X10"}},
		&cli.IntFlag{Name: "disk-overcommit-x10", Value: 0, Usage: "scheduler multi-dim admission: disk oversubscription, integer 10ths (50 = 5.0×). 0 = scheduler default (50 = 5.0×).", EnvVars: []string{"DISK_OVERCOMMIT_X10"}},
		&cli.StringSliceFlag{Name: "label", Usage: "operator label, repeatable: --label key=value (e.g. --label gpu=l4 --label region=nyc1)", EnvVars: []string{"LABELS"}},
		&cli.BoolFlag{Name: "ksm", Value: true, Usage: "enable Kernel Same-page Merging (duplicate-page dedup across VMs)", EnvVars: []string{"KSM"}},
		&cli.StringFlag{Name: "uffd", Value: "off", Usage: "snapshot memory backing: off|on|auto (default off; auto/on break VMs across serve restarts)", EnvVars: []string{"UFFD"}},
		&cli.StringFlag{Name: "cpu-template-path", Value: "", Usage: "absolute path to firecracker custom CPU template JSON (cross-vendor snapshot portability; empty = host-native CPUID)", EnvVars: []string{"CPU_TEMPLATE_PATH"}},
		&cli.StringFlag{Name: "seccomp-filter-path", Value: "", Usage: "absolute path to firecracker seccomp filter JSON (restricts VMM syscalls; empty = firecracker built-in default)", EnvVars: []string{"SECCOMP_FILTER_PATH"}},
		&cli.BoolFlag{Name: "agent-liveness-probe", Value: true, Usage: "destroy a VM after five continuous minutes of failed guest-agent connection probes while firecracker is still alive"},
		&cli.StringFlag{Name: "agent-probe-transport", Value: "vsock", Usage: "how waitForAgent dials the guest readiness signal: vsock|tcp. vsock is the default — bypasses virtio-net, ~3-5× faster agent phase on nested-virt hosts. Requires patched firecracker (vsock_override).", EnvVars: []string{"AGENT_PROBE_TRANSPORT"}},
		&cli.StringFlag{Name: "metrics-addr", Value: "", Usage: "TCP listen address for the prometheus /metrics endpoint (e.g. :9091). Empty disables.", EnvVars: []string{"METRICS_ADDR"}},
		&cli.StringFlag{Name: "metrics-token-file", Value: "", Usage: "path to the required bearer token file when the metrics listener is enabled", EnvVars: []string{"METRICS_TOKEN_FILE"}},
		&cli.StringFlag{Name: "templates-dir", Value: "/var/lib/createos/templates", Usage: "where downloaded template ext4 files cache locally", EnvVars: []string{"TEMPLATES_DIR"}},
		&cli.DurationFlag{Name: "templates-ttl", Value: time.Hour, Usage: "idle TTL for cached template ext4 (eviction by reaper after this)", EnvVars: []string{"TEMPLATES_TTL"}},
		&cli.Int64Flag{Name: "templates-disk-budget-mib", Value: 51200, Usage: "max MiB of disk for the templates cache (LRU evicts past this; 0 = unlimited)", EnvVars: []string{"TEMPLATES_DISK_BUDGET_MIB"}},
		&cli.DurationFlag{Name: "templates-reap-interval", Value: time.Minute, Usage: "how often the templates reaper runs", EnvVars: []string{"TEMPLATES_REAP_INTERVAL"}},
		&cli.IntFlag{Name: "wg-port", Value: 51820, Usage: "UDP port for the host-mesh WireGuard listener", EnvVars: []string{"WG_PORT"}},
		&cli.StringFlag{Name: "wg-signing-key", Value: "", Usage: "path to the host's WireGuard private-key seed (default: <snapshot-dir>/wg_signing.key)", EnvVars: []string{"WG_SIGNING_KEY"}},
		&cli.StringFlag{Name: "tls-cert", Value: "", Usage: "path to the host's TLS server certificate (PEM)", EnvVars: []string{"TLS_CERT"}},
		&cli.StringFlag{Name: "tls-key", Value: "", Usage: "path to the host's TLS server private key (PEM)", EnvVars: []string{"TLS_KEY"}},
		&cli.StringFlag{Name: "tls-ca", Value: "", Usage: "path to the CA bundle (PEM) used to verify client certs", EnvVars: []string{"TLS_CA"}},
	}
	// Storage flags are deliberately NOT added here — host receives
	// storage config from control via the register response, never from
	// CLI/YAML. See internal/hosts/main.go controlStorage handling.
	return append(flags, PauseFlags()...)
}

// ServeFromContext resolves the final ServeConfig from defaults, optional
// YAML file, env vars, and CLI flags. Precedence: flag/env > YAML > default.
func ServeFromContext(c *cli.Context) (ServeConfig, error) {
	var f ServeFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return ServeConfig{}, err
	}

	rootfses, defaultRootfs, err := resolveRootfs(c, f.Rootfs)
	if err != nil {
		return ServeConfig{}, err
	}

	prewarmAll := false
	if f.PrewarmAllRootfs != nil {
		prewarmAll = *f.PrewarmAllRootfs
	}
	if c.IsSet("prewarm-all-rootfs") {
		prewarmAll = c.Bool("prewarm-all-rootfs")
	}

	cfg := ServeConfig{
		Addr:             pickStr(c, "addr", f.Addr),
		KernelPath:       pickStr(c, "kernel", f.Kernel),
		InitrdPath:       pickStr(c, "initrd", f.Initrd),
		Rootfses:         rootfses,
		NetPoolWorkers:   pickInt(c, "netpool-workers", f.NetPoolWorkers),
		RuntimeDir:       pickStr(c, "runtime-dir", f.RuntimeDir),
		DefaultRootfs:    defaultRootfs,
		PrewarmAllRootfs: prewarmAll,
		SnapshotDir:      pickStr(c, "snapshot-dir", f.SnapshotDir),
		Gateway:          pickStr(c, "gateway", f.Gateway),
		PoolSize:         pickInt(c, "pool", f.Pool),
		DiskSizeMB:       pickInt64(c, "disk", f.Disk),
		ColdOnly:         pickBool(c, "cold", f.Cold),
		Hostname:         pickStr(c, "hostname", f.Hostname),
		ControlURL:       pickStr(c, "control-url", f.ControlURL),
		Region:           pickStr(c, "region", f.Region),
		MemCapacity:      pickInt(c, "mem-capacity-mib", f.MemCapacityMib),
	}
	cfg.AgentProbeTransport = pickStr(c, "agent-probe-transport", f.AgentProbeTransport)
	switch cfg.AgentProbeTransport {
	case "", "vsock":
		cfg.AgentProbeTransport = "vsock"
	case "tcp":
		// valid
	default:
		return ServeConfig{}, fmt.Errorf("invalid agent_probe_transport %q (want vsock|tcp)", cfg.AgentProbeTransport)
	}
	var metricsAddrYAML, metricsTokenYAML *string
	if f.Metrics != nil {
		metricsAddrYAML = f.Metrics.Addr
		metricsTokenYAML = f.Metrics.TokenFile
	}
	cfg.MetricsAddr = pickStr(c, "metrics-addr", metricsAddrYAML)
	cfg.MetricsTokenFile = pickStr(c, "metrics-token-file", metricsTokenYAML)
	cfg.AgentLivenessProbe = c.Bool("agent-liveness-probe")
	if f.AgentLiveness != nil && !c.IsSet("agent-liveness-probe") {
		cfg.AgentLivenessProbe = *f.AgentLiveness
	}

	cfg.AuthCacheTTL = c.Int("auth-cache-ttl")
	if f.Auth != nil && f.Auth.CacheTTLSeconds != nil && !c.IsSet("auth-cache-ttl") {
		cfg.AuthCacheTTL = *f.Auth.CacheTTLSeconds
	}
	cfg.SigningKeyPath = c.String("signing-key")
	if f.Auth != nil && f.Auth.SigningKey != nil && !c.IsSet("signing-key") {
		cfg.SigningKeyPath = *f.Auth.SigningKey
	}
	if cfg.SigningKeyPath == "" {
		// Default lives next to snapshots so operators have one well-known
		// place for host-local persistent state.
		cfg.SigningKeyPath = cfg.SnapshotDir + "/host_signing.key"
	}
	cfg.BootstrapToken = c.String("bootstrap-token")
	if f.Auth != nil && f.Auth.BootstrapToken != nil && !c.IsSet("bootstrap-token") {
		cfg.BootstrapToken = *f.Auth.BootstrapToken
	}
	cfg.BootstrapTokenFile = c.String("bootstrap-token-file")
	if f.Auth != nil && f.Auth.BootstrapTokenFile != nil && !c.IsSet("bootstrap-token-file") {
		cfg.BootstrapTokenFile = *f.Auth.BootstrapTokenFile
	}
	if cfg.BootstrapTokenFile != "" {
		b, err := os.ReadFile(cfg.BootstrapTokenFile)
		if err != nil {
			return ServeConfig{}, fmt.Errorf("read bootstrap-token-file %s: %w", cfg.BootstrapTokenFile, err)
		}
		cfg.BootstrapToken = strings.TrimSpace(string(b))
	}
	cfg.MaxVMs = c.Int("max-vms")
	cfg.MaxConcurrentBoots = pickInt(c, "max-concurrent-boots", f.MaxConcurrentBoots)
	cfg.FirecrackerUIDBase = pickInt(c, "firecracker-uid-base", f.FirecrackerUIDBase)
	cfg.CPUOvercommitX10 = pickInt(c, "cpu-overcommit-x10", f.CPUOvercommitX10)
	cfg.MemOvercommitX10 = pickInt(c, "mem-overcommit-x10", f.MemOvercommitX10)
	cfg.DiskOvercommitX10 = pickInt(c, "disk-overcommit-x10", f.DiskOvercommitX10)
	cfg.Labels = mergeLabels(c.StringSlice("label"), f.Labels)
	cfg.KSM = c.Bool("ksm")
	cfg.UFFD = pickStr(c, "uffd", f.UFFD)
	switch cfg.UFFD {
	case "", "auto", "on", "off":
	default:
		return ServeConfig{}, fmt.Errorf("invalid uffd value %q (want auto|on|off)", cfg.UFFD)
	}
	cfg.CPUTemplatePath = pickStr(c, "cpu-template-path", f.CPUTemplatePath)
	cfg.SeccompFilterPath = pickStr(c, "seccomp-filter-path", f.SeccompFilterPath)
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}
	// Storage moved to control's register response — no host-side
	// resolution here. See internal/hosts/main.go controlStorage.
	cfg.Pause = f.Pause.Resolve(c)
	cfg.Templates = resolveTemplates(c, f.Templates)
	cfg.WGPort = c.Int("wg-port")
	cfg.WGSigningKey = c.String("wg-signing-key")
	if cfg.WGSigningKey == "" && f.WGSigningKey != nil && *f.WGSigningKey != "" {
		cfg.WGSigningKey = *f.WGSigningKey
	}
	if cfg.WGSigningKey == "" {
		cfg.WGSigningKey = cfg.SnapshotDir + "/wg_signing.key"
	}
	cfg.TLSCertPath = pickStr(c, "tls-cert", f.TLSCert)
	cfg.TLSKeyPath = pickStr(c, "tls-key", f.TLSKey)
	cfg.TLSCAPath = pickStr(c, "tls-ca", f.TLSCA)
	return cfg, nil
}

// resolveTemplates merges flag/env > YAML > default with the canonical
// precedence rule for the templates section.
func resolveTemplates(c *cli.Context, f *TemplatesFile) TemplatesConfig {
	out := TemplatesConfig{
		Dir:           c.String("templates-dir"),
		TTL:           c.Duration("templates-ttl"),
		DiskBudgetMib: c.Int64("templates-disk-budget-mib"),
		ReapInterval:  c.Duration("templates-reap-interval"),
	}
	if f == nil {
		return out
	}
	if f.Dir != nil && !c.IsSet("templates-dir") {
		out.Dir = *f.Dir
	}
	if f.TTL != nil && !c.IsSet("templates-ttl") {
		if d, err := time.ParseDuration(*f.TTL); err == nil {
			out.TTL = d
		}
	}
	if len(f.TTLOverrides) > 0 {
		out.TTLOverrides = make(map[string]time.Duration, len(f.TTLOverrides))
		for tplID, raw := range f.TTLOverrides {
			if d, err := time.ParseDuration(raw); err == nil && d > 0 {
				out.TTLOverrides[tplID] = d
			}
		}
	}
	if f.DiskBudgetMib != nil && !c.IsSet("templates-disk-budget-mib") {
		out.DiskBudgetMib = *f.DiskBudgetMib
	}
	if f.ReapInterval != nil && !c.IsSet("templates-reap-interval") {
		if d, err := time.ParseDuration(*f.ReapInterval); err == nil {
			out.ReapInterval = d
		}
	}
	return out
}

// mergeLabels combines repeated --label key=value flags with a YAML
// labels map. CLI entries override YAML on key collision. Empty/malformed
// CLI entries are silently skipped (logging would surface the issue at
// register time when capacity-mismatch errors fire).
func mergeLabels(cliPairs []string, yamlMap map[string]string) map[string]string {
	out := make(map[string]string, len(cliPairs)+len(yamlMap))
	for k, v := range yamlMap {
		out[k] = v
	}
	for _, kv := range cliPairs {
		eq := -1
		for i, c := range kv {
			if c == '=' {
				eq = i
				break
			}
		}
		if eq <= 0 || eq == len(kv)-1 {
			continue
		}
		out[kv[:eq]] = kv[eq+1:]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// resolveRootfs reconciles the YAML list and the single --rootfs CLI flag
// into a (catalog, default) pair. CLI flag wins if explicitly set.
func resolveRootfs(c *cli.Context, yamlEntries []RootfsEntry) (map[string]string, string, error) {
	// CLI explicit --rootfs collapses everything to a single-entry catalog.
	if c.IsSet("rootfs") {
		path := c.String("rootfs")
		return map[string]string{"default": path}, "default", nil
	}

	if len(yamlEntries) > 0 {
		catalog := make(map[string]string, len(yamlEntries))
		def := ""
		for _, e := range yamlEntries {
			if e.Name == "" || e.Path == "" {
				return nil, "", fmt.Errorf("rootfs entry needs both name and path")
			}
			if _, dup := catalog[e.Name]; dup {
				return nil, "", fmt.Errorf("duplicate rootfs name %q", e.Name)
			}
			catalog[e.Name] = e.Path
			if e.Default {
				if def != "" {
					return nil, "", fmt.Errorf("multiple rootfs entries marked default (%q and %q)", def, e.Name)
				}
				def = e.Name
			}
		}
		if def == "" {
			def = yamlEntries[0].Name
		}
		return catalog, def, nil
	}

	// Fall back to the flag's default value (always present from cli.StringFlag).
	path := c.String("rootfs")
	return map[string]string{"default": path}, "default", nil
}

// FromContext is kept for backwards compatibility. New code should use ServeFromContext.
func FromContext(c *cli.Context) ServeConfig {
	cfg, _ := ServeFromContext(c)
	return cfg
}

// ── Object-storage + pause config (shared by host + control) ─────────────

// StorageConfig holds the generic S3-compatible object-storage wiring.
// Used by pause/resume bundles AND template ext4 artifacts AND anything
// else in the system that needs the cluster's bucket. Bucket is
// required — the host refuses to start without one in production.
type StorageConfig struct {
	Bucket          string
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	Secure          bool
}

// MetricsFile is the YAML schema for the `metrics:` block.
type MetricsFile struct {
	Addr      *string `yaml:"addr"`
	TokenFile *string `yaml:"token_file"`
}

// StorageFile is the YAML schema for the `storage:` block.
type StorageFile struct {
	Bucket          *string `yaml:"bucket"`
	Endpoint        *string `yaml:"endpoint"`
	Region          *string `yaml:"region"`
	AccessKeyID     *string `yaml:"access_key_id"`
	SecretAccessKey *string `yaml:"secret_access_key"`
	Secure          *bool   `yaml:"secure"`
}

// PauseConfig holds resolved pause/resume tunables (locality cache,
// retry budgets, compression). The bucket itself lives in StorageConfig.
type PauseConfig struct {
	PausedDir       string
	LocalRetain     time.Duration
	LocalDiskBudget int64
	RetryBudget     int
	ResumeMaxHosts  int
	ZstdLevel       int
}

// PauseFile is the YAML schema for the `pause:` block (pause-only knobs).
type PauseFile struct {
	PausedDir       *string `yaml:"paused_dir"`
	LocalRetain     *string `yaml:"local_retain"`
	LocalDiskBudget *int64  `yaml:"local_disk_budget_mib"`
	RetryBudget     *int    `yaml:"retry_budget"`
	ResumeMaxHosts  *int    `yaml:"resume_max_hosts"`
	ZstdLevel       *int    `yaml:"zstd_level"`
}

// StorageFlags returns the urfave/cli flags for the storage block.
func StorageFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "storage-bucket", EnvVars: []string{"STORAGE_BUCKET"}, Usage: "object-storage bucket (empty = pause/templates disabled)"},
		&cli.StringFlag{Name: "storage-endpoint", EnvVars: []string{"STORAGE_ENDPOINT"}},
		&cli.StringFlag{Name: "storage-region", Value: "auto", EnvVars: []string{"STORAGE_REGION"}},
		&cli.StringFlag{Name: "storage-access-key-id", EnvVars: []string{"STORAGE_ACCESS_KEY_ID"}},
		&cli.StringFlag{Name: "storage-secret-access-key", EnvVars: []string{"STORAGE_SECRET_ACCESS_KEY"}},
		&cli.BoolFlag{Name: "storage-secure", EnvVars: []string{"STORAGE_SECURE"}},
	}
}

// PauseFlags returns the urfave/cli flags for the pause-only block.
func PauseFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "paused-dir", Value: "/var/lib/createos/paused", EnvVars: []string{"PAUSED_DIR"}},
		&cli.DurationFlag{Name: "pause-local-retain", Value: 6 * time.Hour, EnvVars: []string{"PAUSE_LOCAL_RETAIN"}, Usage: "how long pause keeps raw bundle locally for resume locality"},
		&cli.Int64Flag{Name: "pause-local-disk-budget-mib", Value: 102400, EnvVars: []string{"PAUSE_LOCAL_DISK_BUDGET_MIB"}, Usage: "local-cache disk budget (MiB); oldest evicted first"},
		&cli.IntFlag{Name: "pause-retry-budget", Value: 5, EnvVars: []string{"PAUSE_RETRY_BUDGET"}, Usage: "upload retries on transient errors"},
		&cli.IntFlag{Name: "resume-max-hosts", Value: 3, EnvVars: []string{"RESUME_MAX_HOSTS"}, Usage: "scheduler attempts before resume goes to error"},
		&cli.IntFlag{Name: "pause-zstd-level", Value: 1, EnvVars: []string{"PAUSE_ZSTD_LEVEL"}, Usage: "memfile zstd compression level"},
	}
}

// Resolve folds env, YAML, CLI, and defaults for the storage block.
// Env vars are STORAGE_* only — no R2_* compat. The cluster Secret
// (cd/r2-secret.yaml) ships STORAGE_* keys directly.
func (f *StorageFile) Resolve(c *cli.Context) StorageConfig {
	out := StorageConfig{Region: "auto"}
	if f != nil {
		// Empty strings in YAML are treated as "unset" so an operator's
		// `storage: { bucket: "" }` placeholder doesn't override the
		// env vars the Secret provides. Use the env-only path when the
		// YAML field is "".
		if f.Bucket != nil && *f.Bucket != "" {
			out.Bucket = *f.Bucket
		}
		if f.Endpoint != nil && *f.Endpoint != "" {
			out.Endpoint = *f.Endpoint
		}
		if f.Region != nil && *f.Region != "" {
			out.Region = *f.Region
		}
		if f.AccessKeyID != nil && *f.AccessKeyID != "" {
			out.AccessKeyID = *f.AccessKeyID
		}
		if f.SecretAccessKey != nil && *f.SecretAccessKey != "" {
			out.SecretAccessKey = *f.SecretAccessKey
		}
		if f.Secure != nil {
			out.Secure = *f.Secure
		}
	}
	if c != nil {
		if c.IsSet("storage-bucket") {
			out.Bucket = c.String("storage-bucket")
		}
		if c.IsSet("storage-endpoint") {
			out.Endpoint = c.String("storage-endpoint")
		}
		if c.IsSet("storage-region") {
			out.Region = c.String("storage-region")
		}
		if c.IsSet("storage-access-key-id") {
			out.AccessKeyID = c.String("storage-access-key-id")
		}
		if c.IsSet("storage-secret-access-key") {
			out.SecretAccessKey = c.String("storage-secret-access-key")
		}
		if c.IsSet("storage-secure") {
			out.Secure = c.Bool("storage-secure")
		}
	}
	return out
}

// Resolve folds env, YAML, CLI, and defaults for the pause block.
func (f *PauseFile) Resolve(c *cli.Context) PauseConfig {
	out := PauseConfig{
		PausedDir:       "/var/lib/createos/paused",
		LocalRetain:     6 * time.Hour,
		LocalDiskBudget: 102400 * 1024 * 1024,
		RetryBudget:     5,
		ResumeMaxHosts:  3,
		ZstdLevel:       1,
	}
	if f != nil {
		if f.PausedDir != nil {
			out.PausedDir = *f.PausedDir
		}
		if f.LocalRetain != nil {
			if d, err := time.ParseDuration(*f.LocalRetain); err == nil {
				out.LocalRetain = d
			}
		}
		if f.LocalDiskBudget != nil {
			out.LocalDiskBudget = *f.LocalDiskBudget * 1024 * 1024
		}
		if f.RetryBudget != nil {
			out.RetryBudget = *f.RetryBudget
		}
		if f.ResumeMaxHosts != nil {
			out.ResumeMaxHosts = *f.ResumeMaxHosts
		}
		if f.ZstdLevel != nil {
			out.ZstdLevel = *f.ZstdLevel
		}
	}
	if c != nil {
		if c.IsSet("paused-dir") {
			out.PausedDir = c.String("paused-dir")
		}
		if c.IsSet("pause-local-retain") {
			out.LocalRetain = c.Duration("pause-local-retain")
		}
		if c.IsSet("pause-local-disk-budget-mib") {
			out.LocalDiskBudget = c.Int64("pause-local-disk-budget-mib") * 1024 * 1024
		}
		if c.IsSet("pause-retry-budget") {
			out.RetryBudget = c.Int("pause-retry-budget")
		}
		if c.IsSet("resume-max-hosts") {
			out.ResumeMaxHosts = c.Int("resume-max-hosts")
		}
		if c.IsSet("pause-zstd-level") {
			out.ZstdLevel = c.Int("pause-zstd-level")
		}
	}
	return out
}
