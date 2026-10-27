# CreateOS Sandbox

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg?logo=go&logoColor=white)](./go.mod)
[![Docs](https://img.shields.io/badge/docs-createos.sh-black.svg)](https://createos.sh/docs/Sandbox/Overview)

Secure, fast Linux sandboxes for AI agents. Each sandbox is its own
[Firecracker](https://github.com/firecracker-microvm/firecracker) microVM with
its own kernel, so code you didn't write runs isolated from your machine and
from everyone else's.

This repository is the server side of [CreateOS Sandbox](https://createos.sh):
the control plane, the host service that runs the microVMs, the agent inside
every sandbox, and the tools that build sandbox images. It's written in Go and
licensed under Apache-2.0.

## What you get

- **Hardware isolation.** One microVM per sandbox. On the host, each one runs
  as its own unprivileged user, in its own cgroup, behind a seccomp filter.
- **Fast starts.** Sandboxes restore from pre-booted snapshots instead of
  booting a kernel. A warm pool keeps ready sandboxes waiting.
- **Pause, resume, and fork.** Pausing saves memory and disk to object
  storage. Resuming picks up where it left off, on any host. Forking clones a
  paused sandbox.
- **Run anything.** Run commands and stream their output, start long-running
  processes and terminals (PTYs), and upload or download files.
- **Egress control.** Allow only the domains and IPs a sandbox needs. Domain
  rules are matched on TLS SNI and HTTP Host.
- **Public URLs and SSH.** Expose any port at
  `https://<id>-<port>.<your-domain>`, or forward ports with `ssh -L`.
- **Private networks.** Connect sandboxes to each other across hosts over an
  encrypted WireGuard mesh, with eBPF enforcing which sandboxes can talk.
- **Templates and disks.** Build sandbox images from a Dockerfile, and mount
  S3-compatible buckets as disks.

## Use it

The quickest way to use CreateOS Sandbox is the hosted service. Get an API key
at [createos.sh](https://createos.sh), then use an SDK or the CLI:

```ts
import { CreateosSandboxClient } from "@nodeops-createos/sandbox";

const client = new CreateosSandboxClient(); // reads CREATEOS_SANDBOX_API_KEY
const sandbox = await client.createSandbox({ shape: "s-1vcpu-1gb", rootfs: "devbox:1" });
try {
  const { result } = await sandbox.runCommand("python3", ["-c", "print(6 * 7)"]);
  console.log(result.stdout); // "42\n"
} finally {
  await sandbox.destroy();
}
```

| Client | Install | Source |
| --- | --- | --- |
| TypeScript SDK | `npm install @nodeops-createos/sandbox` | [fc-sdk](https://github.com/NodeOps-app/fc-sdk) |
| Python SDK | `pip install createos-sandbox` | [createos-python-sdk](https://github.com/NodeOps-app/createos-python-sdk) |
| Go SDK | `go get github.com/NodeOps-app/createos-go-sdk` | [createos-go-sdk](https://github.com/NodeOps-app/createos-go-sdk) |
| Rust SDK | `cargo add createos` | [createos-rust-sdk](https://github.com/NodeOps-app/createos-rust-sdk) |
| C# SDK | `dotnet add package CreateOS.Sandbox` | [createos-csharp-sdk](https://github.com/NodeOps-app/createos-csharp-sdk) |
| Java SDK | Maven `sh.createos:createos-java-sdk` | [createos-java-sdk](https://github.com/NodeOps-app/createos-java-sdk) |
| CLI | `brew install nodeops-app/tap/createos` | [createos-cli](https://github.com/NodeOps-app/createos-cli) |

The HTTP API is described in [`openapi.yaml`](./openapi.yaml). Every other
guide, reference and integration is listed under [Links](#links).

## How it fits together

```
 SDK / CLI ──HTTPS──▶ control ──────────────▶ machine (one per host) ──▶ Firecracker microVM
                       │  API, scheduler,        │  runs microVMs, egress     └─ agent (PID 1)
                       │  gateway, ingress       │  proxy, eBPF policy           exec, files,
                       │                         │                               processes, PTY
                       ├── PostgreSQL            ├── WireGuard mesh to other hosts
                       └── object storage ◀──────┘  (snapshots, templates)

 browser ──https://<id>-<port>.<domain>──▶ ingress ──▶ owning host ──▶ agent ──▶ your port
 ssh -L  ─────────────────────────────────▶ gateway ──▶ owning host ──▶ agent ──▶ your port
```

One source tree builds five binaries, picked with Go build tags:

| Binary | Runs on | Job |
| --- | --- | --- |
| `control` | control plane | Public API, scheduler, SSH gateway, ingress, template builder, background workers |
| `machine` | every sandbox host | Runs the microVMs, their networking, and the egress proxy |
| `agent` | inside every sandbox | PID 1: exec, files, processes and PTYs, port tunnels. Standard library only |
| `image` | build machines | Turns a Docker or OCI image into a root filesystem, and builds the guest initrd |
| `admin` | operator laptop | Short-lived admin tasks such as issuing and revoking certificates |

Services talk to each other over mutual TLS. The control plane runs its own
small certificate authority for this.

## Build from source

You need Go (the version in [`go.mod`](./go.mod)). The code targets Linux, so
set `GOOS=linux` when you build on another OS:

```sh
GOOS=linux CGO_ENABLED=0 go build -tags=control -o bin/control ./cmd/control
GOOS=linux CGO_ENABLED=0 go build -tags=machine -o bin/machine ./cmd/machine
GOOS=linux CGO_ENABLED=0 go build -tags=agent   -o bin/agent   ./cmd/agent
GOOS=linux CGO_ENABLED=0 go build -tags=image   -o bin/image   ./cmd/image
GOOS=linux CGO_ENABLED=0 go build -tags=admin   -o bin/admin   ./cmd/admin
```

Running the `machine` binary needs a Linux host with KVM (`/dev/kvm`).
Running sandboxes on your own hardware or cloud account is offered to
enterprise customers: see [Run on your own infrastructure](https://createos.sh/docs/Sandbox/Self-Hosting)
or contact [business@nodeops.xyz](mailto:business@nodeops.xyz).

## Repository layout

| Path | What's there |
| --- | --- |
| `cmd/` | Entry points for the five binaries |
| `internal/apiserver/` | Public HTTP API |
| `internal/scheduler/` | Placement: picks a host for each sandbox |
| `internal/hosts/` | Host service: microVM lifecycle, networking, snapshots |
| `internal/agent/` | The in-sandbox agent |
| `internal/hosts/vm/bpf/` | eBPF programs for network policy and bandwidth metering |
| `database/` | PostgreSQL queries and migrations |
| `images/` | Dockerfiles for the built-in sandbox images |
| `kernel-build/` | Guest kernel config and build script |
| `resources/` | Seccomp filter for Firecracker |

## Links

**Docs**

- [Overview](https://createos.sh/docs/Sandbox/Overview) · [Quickstart](https://createos.sh/docs/Sandbox/Quickstart) · [Concepts](https://createos.sh/docs/Sandbox/Concepts) · [Security](https://createos.sh/docs/Sandbox/Security) · [Limits and defaults](https://createos.sh/docs/Sandbox/Limits)
- [SDK guide](https://createos.sh/docs/Sandbox/SDK/Overview): [quickstart](https://createos.sh/docs/Sandbox/SDK/Quickstart), [examples](https://createos.sh/docs/Sandbox/SDK/Examples), [reference](https://createos.sh/docs/Sandbox/SDK/Reference/Overview)
- [CLI](https://createos.sh/docs/Sandbox/CLI/Overview): [command reference](https://createos.sh/docs/Sandbox/CLI/Commands)
- [REST API](https://createos.sh/docs/Sandbox/REST-API/Overview)
- [Bring your own storage](https://createos.sh/docs/Sandbox/Bring-Your-Own-Storage) · [Run on your own infrastructure](https://createos.sh/docs/Sandbox/Self-Hosting) · [Claude Managed Agents](https://createos.sh/docs/Sandbox/Claude-Managed-Agents)
- For AI tools: [llms.txt](https://createos.sh/llms.txt)

**Agent and tool integrations** ([all integrations](https://createos.sh/docs/Sandbox/Integrations/Overview))

| Tool | Guide | Source |
| --- | --- | --- |
| Claude Code | [docs](https://createos.sh/docs/Sandbox/Integrations/Claude-Code) | [createos-plugin](https://github.com/NodeOps-app/createos-plugin/tree/main/packages/claude-code-plugin) |
| Codex | [docs](https://createos.sh/docs/Sandbox/Integrations/Codex) | [createos-plugin](https://github.com/NodeOps-app/createos-plugin/tree/main/packages/codex-plugin) |
| OpenCode | [docs](https://createos.sh/docs/Sandbox/Integrations/OpenCode) | [createos-plugin](https://github.com/NodeOps-app/createos-plugin/tree/main/packages/opencode-plugin) |
| Pi | [docs](https://createos.sh/docs/Sandbox/Integrations/Pi) | [createos-plugin](https://github.com/NodeOps-app/createos-plugin/tree/main/packages/pi-extension) |
| Herdr | [docs](https://createos.sh/docs/Sandbox/Integrations/Herdr) | [createos-plugin](https://github.com/NodeOps-app/createos-plugin/tree/main/packages/herdr-plugin) |
| Orca | [docs](https://createos.sh/docs/Sandbox/Integrations/Orca) | [createos-orca-plugin](https://github.com/NodeOps-app/createos-orca-plugin) |
| DeepSeek Harness | [docs](https://createos.sh/docs/Sandbox/Integrations/DeepSeek-Harness) | [createos-plugin](https://github.com/NodeOps-app/createos-plugin/tree/main/packages/dsh-createos) |
| Langflow | [docs](https://createos.sh/docs/Sandbox/Integrations/Langflow) | [createos-plugin](https://github.com/NodeOps-app/createos-plugin/tree/main/packages/langflow-sandbox-createos) |
| Amp | [docs](https://createos.sh/docs/Sandbox/Integrations/Amp) | [createos-cli](https://github.com/NodeOps-app/createos-cli) |
| AgentBox | [docs](https://createos.sh/docs/Sandbox/Integrations/AgentBox) | |
| n8n | [docs](https://createos.sh/docs/Sandbox/Integrations/n8n) | |
| Omnara | [docs](https://createos.sh/docs/Sandbox/Integrations/Omnara) | |

**More**

- [40+ runnable examples](https://github.com/NodeOps-app/fc-sdk/tree/main/examples): code interpreter, AI code agents, dev-server previews, browsers, MCP servers, S3 disks and more
- [createos-sandbox-ghar](https://github.com/NodeOps-app/createos-sandbox-ghar): throwaway GitHub Actions runners, one sandbox per job
- [awesome-ai-sandboxes](https://github.com/NodeOps-app/awesome-ai-sandboxes): a list of cloud sandbox providers for AI agents
- Packages: [npm](https://www.npmjs.com/package/@nodeops-createos/sandbox) · [PyPI](https://pypi.org/project/createos-sandbox/) · [pkg.go.dev](https://pkg.go.dev/github.com/NodeOps-app/createos-go-sdk) · [crates.io](https://crates.io/crates/createos) · [NuGet](https://www.nuget.org/packages/CreateOS.Sandbox)
- Community: [Discord](https://discord.gg/nodeops) · [X](https://x.com/createosai) · [createos.sh](https://createos.sh)

## Contributing

Issues are open to everyone. Pull requests are open to maintainers only. The
code here is synced weekly from the maintainers' development repository, so
outside pull requests can't be merged. See [CONTRIBUTING.md](./CONTRIBUTING.md).

Found a security problem? Don't open an issue. Report it privately as
described in [SECURITY.md](./SECURITY.md).

Everyone taking part follows the [Code of Conduct](./CODE_OF_CONDUCT.md).

## License

[Apache License 2.0](./LICENSE). The eBPF programs in
`internal/hosts/vm/bpf/*.bpf.c` are licensed GPL-2.0, as the Linux kernel
requires.
