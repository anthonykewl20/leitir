#!/usr/bin/env bash
set -euo pipefail

# nsjail 3.6, pinned to the commit referenced by the upstream release tag.
# The full commit ID is intentional: the build never follows a mutable branch or tag.
readonly NSJAIL_REPOSITORY="https://github.com/google/nsjail.git"
readonly NSJAIL_COMMIT="f78475530b46d0186111a9096b30725f816b55fe"
# This golden executable hash is measured from the committed source/toolchain.
# Toolchain drift must fail loudly: an owner re-measures it on the supported
# runner, then updates this pin in a separately reviewable change.
readonly NSJAIL_EXECUTABLE_SHA256="2a740ac196d27176216788f6213d585cd5b5933f83f2c9bff31ce95cd64939d4"
readonly INSTALL_PATH="${NSJAIL_INSTALL_PATH:-/usr/bin/nsjail}"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'nsjail can only be built for this experiment on Linux\n' >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run this script as root (for apt and installation), for example: sudo %s\n' "$0" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  bison \
  ca-certificates \
  flex \
  g++ \
  gcc \
  git \
  libnl-3-dev \
  libnl-route-3-dev \
  libprotobuf-dev \
  make \
  pkg-config \
  protobuf-compiler

build_root="$(mktemp -d)"
version_output="$(mktemp)"
cleanup() {
  rm -rf -- "$build_root"
  rm -f -- "$version_output"
}
trap cleanup EXIT

git -C "$build_root" init --quiet
git -C "$build_root" remote add origin "$NSJAIL_REPOSITORY"
git -C "$build_root" fetch --quiet --depth=1 origin "$NSJAIL_COMMIT"
git -C "$build_root" checkout --quiet --detach FETCH_HEAD

actual_commit="$(git -C "$build_root" rev-parse HEAD)"
if [[ "$actual_commit" != "$NSJAIL_COMMIT" ]]; then
  printf 'fetched nsjail commit %s, expected %s\n' "$actual_commit" "$NSJAIL_COMMIT" >&2
  exit 1
fi

# Kafel is an upstream gitlink, so updating it after the pinned checkout also
# resolves to the exact submodule commit recorded by NSJAIL_COMMIT.
git -C "$build_root" submodule update --init --depth=1
make -C "$build_root" -j"$(nproc)"

install -D -m 0755 "$build_root/nsjail" "$INSTALL_PATH"

actual_executable_sha256="$(sha256sum "$INSTALL_PATH" | cut -d' ' -f1)"
if [[ "$actual_executable_sha256" != "$NSJAIL_EXECUTABLE_SHA256" ]]; then
  printf 'built nsjail executable SHA-256 %s, expected %s\n' \
    "$actual_executable_sha256" "$NSJAIL_EXECUTABLE_SHA256" >&2
  exit 1
fi

printf 'nsjail upstream commit: %s\n' "$NSJAIL_COMMIT"
printf 'nsjail installed path: %s\n' "$INSTALL_PATH"
printf 'nsjail executable SHA-256: '
sha256sum "$INSTALL_PATH" | cut -d' ' -f1

# exec_sandbox._verify_backend captures stdout and stderr together and hashes
# every byte, including the final newline. Preserve that exact representation.
set +e
"$INSTALL_PATH" --version >"$version_output" 2>&1
version_exit=$?
set -e
printf 'nsjail --version exit code: %s\n' "$version_exit"
printf 'nsjail --version merged output byte count: '
wc -c <"$version_output"
printf 'nsjail --version merged output SHA-256: '
sha256sum "$version_output" | cut -d' ' -f1
printf '%s\n' '----- nsjail --version exact merged output begins -----'
dd if="$version_output" status=none
printf '%s\n' '----- nsjail --version exact merged output ends -----'
printf 'nsjail --version merged output hex bytes:'
od -An -v -tx1 "$version_output" | tr -d '\n'
printf '\n'
