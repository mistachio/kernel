#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

set -e

# wa for dubios ownership
git config --global --add safe.directory /linux/src
# root path of kernel source code in container
git clone /linux/src /linux/dest
cd /linux/dest

declare -A archs=(
  ["x86_64"]="amd64"
  ["aarch64"]="arm64"
)

arch=${archs[$(uname -m)]}
if [[ -z "$arch" ]]; then
  echo "Unknown arch: $(uname -m)"
  exit 1
fi

majorversion=$(grep -E "^VERSION = " Makefile | cut -d' ' -f3)
patchlevel=$(grep -E "^PATCHLEVEL = " Makefile | cut -d' ' -f3)
sublevel=$(grep -E "^SUBLEVEL = " Makefile | cut -d' ' -f3)
hash=$(git rev-parse --short HEAD)
version="$majorversion.$patchlevel.$sublevel-$hash"

if [[ -n "$BASE_PAGE" ]]; then
  version_suffix="-$BASE_PAGE"
fi

# build veLinux2 kernel with veLinux timestamp
if lsb_release -c | grep -q bookworm; then
  timestamp="veLinux $version $(date)"
else
  timestamp="Debian $version $(date)"
fi

cp config."$(uname -m)$version_suffix" .config
version="$version$version_suffix"

if [[ -n "$BUSINESS_KERNEL" ]]; then
  sed -i "/^CONFIG_BYTEDANCE/d" .config
  make olddefconfig
  version="${version//bsk/bsk.business}"
fi

if [[ -n "$SIGN_KERNEL" ]]; then
  sed -i "/^# *CONFIG_MODULE_SIG_FORCE */c\CONFIG_MODULE_SIG_FORCE=y" .config
  sed -i "/^# *CONFIG_MODULE_SIG_ALL */c\CONFIG_MODULE_SIG_ALL=y" .config
  sed -i "/^ *CONFIG_MODULE_SIG_KEY=/c\CONFIG_MODULE_SIG_KEY=\"kernel_key.pem\"" .config
  make olddefconfig
  version="$version-sign"
fi

if [[ -n "$KASAN_ARGS" ]]; then
  # enable kasan configs and fault injections
  sed -i "s/\(^CONFIG_KCOV=.*\|^# CONFIG_KCOV is not set\)/CONFIG_KCOV=y/g" .config
  sed -i "s/\(^CONFIG_DEBUG_INFO=.*\|^# CONFIG_DEBUG_INFO is not set\)/CONFIG_DEBUG_INFO=y/g" .config
  sed -i "s/\(^CONFIG_KASAN=.*\|^# CONFIG_KASAN is not set\)/CONFIG_KASAN=y/g" .config
  sed -i "s/\(^CONFIG_KASAN_INLINE=.*\|^# CONFIG_KASAN_INLINE is not set\)/CONFIG_KASAN_INLINE=y/g" .config
  sed -i "s/\(^CONFIG_CONFIGFS_FS=.*\|^# CONFIG_CONFIGFS_FS is not set\)/CONFIG_CONFIGFS_FS=y/g" .config
  sed -i "s/\(^CONFIG_SECURITYFS=.*\|^# CONFIG_SECURITYFS is not set\)/CONFIG_SECURITYFS=y/g" .config
  sed -i "s/\(^CONFIG_FAULT_INJECTION=.*\|^# CONFIG_FAULT_INJECTION is not set\)/CONFIG_FAULT_INJECTION=y/g" .config
  sed -i "s/\(^CONFIG_FAILSLAB=.*\|^# CONFIG_FAILSLAB is not set\)/CONFIG_FAILSLAB=y/g" .config
  sed -i "s/\(^CONFIG_FAIL_PAGE_ALLOC=.*\|^# CONFIG_FAIL_PAGE_ALLOC is not set\)/CONFIG_FAIL_PAGE_ALLOC=y/g" .config
  sed -i "s/\(^CONFIG_FAIL_MAKE_REQUEST=.*\|^# CONFIG_FAIL_MAKE_REQUEST is not set\)/CONFIG_FAIL_MAKE_REQUEST=y/g" .config
  sed -i "s/\(^CONFIG_FAIL_IO_TIMEOUT=.*\|^# CONFIG_FAIL_IO_TIMEOUT is not set\)/CONFIG_FAIL_IO_TIMEOUT=y/g" .config
  sed -i "s/\(^CONFIG_FAIL_FUTEX=.*\|^# CONFIG_FAIL_FUTEX is not set\)/CONFIG_FAIL_FUTEX=y/g" .config
  sed -i "s/\(^CONFIG_FAULT_INJECTION_DEBUG_FS=.*\|^# CONFIG_FAULT_INJECTION_DEBUG_FS is not set\)/CONFIG_FAULT_INJECTION_DEBUG_FS=y/g" .config
  sed -i "s/\(^CONFIG_FAIL_FUNCTION=.*\|^# CONFIG_FAIL_FUNCTION is not set\)/CONFIG_FAIL_FUNCTION=y/g" .config
  sed -i "s/\(^CONFIG_FAIL_MMC_REQUEST=.*\|^# CONFIG_FAIL_MMC_REQUEST is not set\)/CONFIG_FAIL_MMC_REQUEST=y/g" .config
  # make loadable module always install
  sed -i "s/=m/=y/g" .config

  # boot driver
  sed -i "s/\(^CONFIG_VIRTIO_PCI=.*\|^# CONFIG_VIRTIO_PCI is not set\)/CONFIG_VIRTIO_PCI=y/g" .config
  sed -i "s/\(^CONFIG_VIRTIO_NET=.*\|^# CONFIG_VIRTIO_NET is not set\)/CONFIG_VIRTIO_NET=y/g" .config
  sed -i "s/\(^CONFIG_VIRTIO_BLK=.*\|^# CONFIG_VIRTIO_BLK is not set\)/CONFIG_VIRTIO_BLK=y/g" .config
  sed -i "s/\(^CONFIG_EXT4_FS=.*\|^# CONFIG_EXT4_FS is not set\)/CONFIG_EXT4_FS=y/g" .config
  make olddefconfig
  version="$version-kasan"
fi

if ! lsb_release -c | grep -q jessie; then
  BUILD_CFLAGS="-Werror"
fi

localversion="$(echo $version | sed 's/^[0-9]\+\.[0-9]\+\.[0-9]\+//')"
krelease="$version-$arch"
make deb-pkg \
  BUILD_TOOLS=y \
  KDEB_PKGVERSION="$version" \
  KERNELRELEASE="$krelease" \
  LOCALVERSION="$localversion" \
  KBUILD_BUILD_TIMESTAMP="$timestamp" \
  KBUILD_BUILD_USER="STE-Kernel" \
  KBUILD_BUILD_HOST="ByteDance" \
  DPKG_FLAGS="-sn" \
  CFLAGS_KERNEL="$BUILD_CFLAGS" \
  CFLAGS_MODULE="$BUILD_CFLAGS" \
  KDEB_SOURCENAME="linux-$krelease" \
  "$@"

# copy deb packages out
cp /linux/*.deb /linux/output
