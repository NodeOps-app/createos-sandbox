#!/usr/bin/env bash
# Build a firecracker guest kernel (uncompressed vmlinux) for createos,
# based on the firecracker reference config + VXLAN (overlay networking)
# + the netfilter/ipset/ipvs set k3s + kube-proxy need.
#
# Runs entirely in a Debian container so the host toolchain is untouched.
# Output: kernel-build/vmlinux  (copy to images/vmlinux when verified)
set -euo pipefail

KVER="${KVER:-6.12.95}"
KMAJ="6.x"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[kbuild] target: linux-${KVER}"

docker run --rm -v "$here":/out -w /build debian:13-slim bash -euo pipefail -c "
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends \
      bc bison flex build-essential libelf-dev libssl-dev \
      curl ca-certificates xz-utils kmod cpio >/dev/null
  echo '[kbuild] downloading linux-${KVER}'
  curl -fsSL https://cdn.kernel.org/pub/linux/kernel/v${KMAJ}/linux-${KVER}.tar.xz -o linux.tar.xz
  tar -xf linux.tar.xz
  cd linux-${KVER}

  echo '[kbuild] base config = firecracker reference (6.1) + olddefconfig forward-port'
  cp /out/fc-kconfig-6.1.config .config
  make olddefconfig >/dev/null

  echo '[kbuild] merging k8s netfilter fragment + VXLAN'
  ./scripts/kconfig/merge_config.sh -m .config /out/k8s-netfilter.fragment >/dev/null
  make olddefconfig >/dev/null

  echo '[kbuild] verifying critical options ended up =y (honest check)'
  fail=0
  for o in NETFILTER_ADVANCED NETFILTER_XT_MARK NETFILTER_XT_TARGET_MARK NETFILTER_XT_MATCH_MARK NETFILTER_XT_MATCH_COMMENT NETFILTER_XT_MATCH_MULTIPORT NETFILTER_XT_MATCH_STATISTIC NFT_COMPAT IP_SET IP_VS VXLAN IKCONFIG_PROC; do
    line=\$(grep -E \"^(CONFIG_\${o}=|# CONFIG_\${o} )\" .config || echo \"CONFIG_\${o} ABSENT\")
    echo \"    \${line}\"
    echo \"\${line}\" | grep -q \"=y\" || fail=1
  done
  [ \"\$fail\" = 0 ] || { echo '[kbuild] FAIL: one or more options not =y'; exit 1; }

  echo '[kbuild] compiling vmlinux (this is the slow part)'
  make -j\"\$(nproc)\" vmlinux >/dev/null

  echo '[kbuild] post-build: xt_mark in the built objects?'
  ls -la net/netfilter/xt_mark.o 2>&1 || echo 'xt_mark.o NOT BUILT'
  grep -E '^CONFIG_NETFILTER_XT_MARK' .config
  cp vmlinux /out/vmlinux
  ls -la /out/vmlinux
  echo '[kbuild] done'
"
echo "[kbuild] → kernel-build/vmlinux ready"
