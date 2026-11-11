#!/usr/bin/env bash
# bench/openshell/setup.sh - install what the OpenShell measurement run needs on a fresh Ubuntu 24.04 VM.
#
# STATUS: UNTESTED. Written on macOS without Docker, OpenShell or an Ubuntu box. Reviewed with
# static analysis (the shellcheck tool) and by reading only. Every step logs what it does; read
# bench/openshell/RUNBOOK.md first.
#
# Run as a normal user with sudo:   bash bench/openshell/setup.sh
# Idempotent: re-running skips what is already installed at the pinned version.
#
# Touches, outside this directory, ONLY (all via sudo, all package/system prerequisites):
#   * apt packages (build tools, curl, python3, git, gnupg, xz-utils)
#   * Docker Engine 28.x from Docker's apt repo (key fingerprint verified) if Docker >= 28 is absent
#   * the pinned OpenShell .deb (sha256 verified)
#   * `usermod -aG docker $USER` and `loginctl enable-linger $USER` (OpenShell's gateway is a systemd USER
#     service that talks to the Docker socket and must outlive the login; docs/about/installation.mdx)
# Everything else (downloads, Rust toolchain, cargo caches, the translator build) stays under this directory.
#
# Deliberately NOT done here: starting/registering the gateway, building the sandbox image, editing
# /etc/hosts or creating the dummy interface. Those are separate, named steps in RUNBOOK.md.
#
# Install path: NOT `curl | sh`. This script performs the same steps as the project's install.sh
# (NVIDIA/OpenShell@v0.1.8 install.sh, install_linux_deb): download the release .deb, verify its checksum,
# `apt-get install` it. The checksum is PINNED below (taken from the v0.1.8 release's
# openshell-checksums-sha256.txt and the GitHub release asset digest, which agreed) and re-checked against the
# published checksums file at run time.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DL="$HERE/downloads"

# ---------------------------------------------------------------- pins
OS_TAG="v0.1.8"
OS_COMMIT="f3d976590d3eb1379690a2abaf0f0e26c21d487d"   # commit the v0.1.8 tag points at (git ls-remote, 2026-11-11)
OS_DEB_VERSION="0.1.8-1"
OS_BASE_URL="https://github.com/NVIDIA/OpenShell/releases/download/${OS_TAG}"
OS_CHECKSUMS="openshell-checksums-sha256.txt"
OS_DEB_SHA256_amd64="b3339527085d9b44afc0d5e4f835c2d34e44e33d0b67d6a4cac9d96f25a656b1"
OS_DEB_SHA256_arm64="3d53db93dc2f130ae570a838c2dd48fda626bd1ab964ea1de895e13a21a667a9"

RUST_VERSION="1.99.1"
RUST_SHA256_amd64="231fcae47ee950621374725b5fc3b5441d2fbda2955ac45dd7dc816d8876cfe7"   # static.rust-lang.org/dist/<file>.sha256
RUST_SHA256_arm64="a48fb1e853be56ce9b8e2751f5464dbd5e16440cd81e237920f3a5e7e806333e"

# Docker Engine >= 28.0 is OpenShell's documented minimum (docs/about/support-matrix.mdx). 5:28.5.2 is the last 28.x in
# Docker's noble repo as of 2026-11-11 (Packages index); override with DOCKER_PIN="" to take the newest.
DOCKER_PIN="${DOCKER_PIN-5:28.5.2-1~ubuntu.24.04~noble}"
DOCKER_KEY_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"   # Docker's published apt signing key

log() { printf '[setup] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------- preconditions
[ "$(id -u)" -ne 0 ] || die "run as a normal user with sudo, not as root (the gateway is a per-user systemd service)"
command -v sudo >/dev/null || die "sudo is required"
sudo -v || die "sudo authentication failed"

# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
  [ "${ALLOW_OTHER_OS:-0}" = "1" ] || die "tested target is Ubuntu 24.04, found ${PRETTY_NAME:-unknown}; set ALLOW_OTHER_OS=1 to try anyway"
fi
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
  amd64) RUST_TRIPLE="x86_64-unknown-linux-gnu";  OS_DEB_SHA256="$OS_DEB_SHA256_amd64"; RUST_SHA256="$RUST_SHA256_amd64" ;;
  arm64) RUST_TRIPLE="aarch64-unknown-linux-gnu"; OS_DEB_SHA256="$OS_DEB_SHA256_arm64"; RUST_SHA256="$RUST_SHA256_arm64" ;;
  *) die "no OpenShell .deb is published for architecture $ARCH" ;;
esac
OS_DEB="openshell_${OS_DEB_VERSION}_${ARCH}.deb"

# Kernel facilities the sandbox needs (docs/about/support-matrix.mdx, "Kernel Requirements"): Landlock ABI >= 3
# (Linux >= 6.2, Landlock enabled) and seccomp user notification. A disabled LSM makes sandbox launch fail closed.
KVER="$(uname -r)"
KMAJ="${KVER%%.*}"; KREST="${KVER#*.}"; KMIN="${KREST%%[!0-9]*}"
if [ "$KMAJ" -lt 6 ] || { [ "$KMAJ" -eq 6 ] && [ "$KMIN" -lt 2 ]; }; then
  die "kernel $KVER is older than 6.2 (Landlock ABI 3 needed)"
fi
if [ -r /sys/kernel/security/lsm ] && ! grep -qw landlock /sys/kernel/security/lsm; then
  [ "${SKIP_LANDLOCK_CHECK:-0}" = "1" ] || die "Landlock is not in the active LSM list ($(cat /sys/kernel/security/lsm)); sandboxes will refuse to start"
fi
mkdir -p "$DL"

# ---------------------------------------------------------------- apt packages
log "apt: installing build tools, curl, python3, git, gnupg, xz-utils"
sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg python3 git build-essential xz-utils iproute2

# ---------------------------------------------------------------- Docker Engine >= 28
docker_major() { sudo docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1; }
DM="$(docker_major || true)"
if [ -n "$DM" ] && [ "$DM" -ge 28 ] 2>/dev/null; then
  log "docker engine $(sudo docker version --format '{{.Server.Version}}') already installed; skipping"
else
  log "installing Docker Engine from Docker's apt repo (pin: ${DOCKER_PIN:-newest})"
  curl -fsSL --retry 3 -o "$DL/docker.gpg" https://download.docker.com/linux/ubuntu/gpg
  if ! gpg --show-keys --with-colons "$DL/docker.gpg" 2>/dev/null | awk -F: '$1 == "fpr" {print $10}' | grep -qx "$DOCKER_KEY_FPR"; then
    die "Docker apt key fingerprint is not $DOCKER_KEY_FPR; refusing to trust it"
  fi
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo install -m 0644 "$DL/docker.gpg" /etc/apt/keyrings/docker.asc
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME:-noble} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
  if [ -n "$DOCKER_PIN" ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      "docker-ce=${DOCKER_PIN}" "docker-ce-cli=${DOCKER_PIN}" containerd.io
  else
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io
  fi
fi
sudo systemctl enable --now docker
if ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
  log "adding $USER to the docker group (root-equivalent on this VM; it is a throwaway VM)"
  sudo usermod -aG docker "$USER"
  NEED_RELOGIN=1
fi
log "enabling linger for $USER so the systemd user gateway survives logout (docs/about/installation.mdx)"
sudo loginctl enable-linger "$USER"

# ---------------------------------------------------------------- OpenShell .deb (checksum-verified; not curl|sh)
if [ "$(dpkg-query -W -f='${Version}' openshell 2>/dev/null || true)" = "$OS_DEB_VERSION" ]; then
  log "openshell $OS_DEB_VERSION already installed; skipping"
else
  log "downloading $OS_DEB and the published checksum list for $OS_TAG"
  curl -fL --retry 3 --max-redirs 5 -sS -o "$DL/$OS_DEB" "$OS_BASE_URL/$OS_DEB"
  curl -fL --retry 3 --max-redirs 5 -sS -o "$DL/$OS_CHECKSUMS" "$OS_BASE_URL/$OS_CHECKSUMS"
  echo "$OS_DEB_SHA256  $DL/$OS_DEB" | sha256sum -c --quiet - || die "$OS_DEB does not match the pinned sha256 $OS_DEB_SHA256"
  PUBLISHED="$(awk -v n="$OS_DEB" '$2 == n || $2 == "*" n {print $1; exit}' "$DL/$OS_CHECKSUMS")"
  [ "$PUBLISHED" = "$OS_DEB_SHA256" ] || die "published checksum list says '$PUBLISHED' for $OS_DEB, pin says $OS_DEB_SHA256"
  log "sha256 verified (pinned and published agree): $OS_DEB_SHA256"
  chmod 0644 "$DL/$OS_DEB"
  # Same flags install.sh uses for the deb (install_deb_package).
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confnew "$DL/$OS_DEB"
fi

# ---------------------------------------------------------------- Rust toolchain (private, under this directory)
# Needed only to run `cargo run -p bollard-openshell` (the Bollard -> OpenShell policy translator). Official standalone
# tarball, checksum pinned, installed with the tarball's own install.sh into $HERE/toolchain: no rustup, no curl|sh.
export CARGO_HOME="$HERE/cargo-home" CARGO_TARGET_DIR="$HERE/target"
if [ -x "$HERE/toolchain/bin/rustc" ] && "$HERE/toolchain/bin/rustc" --version | grep -q "rustc $RUST_VERSION "; then
  log "rust $RUST_VERSION already installed under $HERE/toolchain; skipping"
else
  RT="rust-${RUST_VERSION}-${RUST_TRIPLE}.tar.xz"
  log "downloading $RT (~250 MB)"
  curl -fL --retry 3 -sS -o "$DL/$RT" "https://static.rust-lang.org/dist/$RT"
  echo "$RUST_SHA256  $DL/$RT" | sha256sum -c --quiet - || die "$RT does not match the pinned sha256"
  rm -rf "$DL/rust-src"; mkdir -p "$DL/rust-src"
  tar -xJf "$DL/$RT" -C "$DL/rust-src" --strip-components=1
  ( cd "$DL/rust-src" && ./install.sh --prefix="$HERE/toolchain" --components="rustc,cargo,rust-std-${RUST_TRIPLE}" --disable-ldconfig )
  rm -rf "$DL/rust-src"
fi
cat > "$HERE/env.sh" <<EOF
# generated by setup.sh; source it before running the driver:  . bench/openshell/env.sh
export PATH="$HERE/toolchain/bin:\$PATH"
export CARGO_HOME="$HERE/cargo-home"
export CARGO_TARGET_DIR="$HERE/target"
EOF
log "building the translator: cargo build --locked -p bollard-openshell (target dir $HERE/target)"
( cd "$ROOT" && PATH="$HERE/toolchain/bin:$PATH" cargo build --locked -p bollard-openshell )

# ---------------------------------------------------------------- versions
log "================ installed versions ================"
{
  echo "date:        $(date -u +%FT%TZ)"
  echo "os:          ${PRETTY_NAME}  kernel $KVER  arch $ARCH  glibc $(getconf GNU_LIBC_VERSION 2>/dev/null || echo '?')"
  echo "landlock:    $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'lsm list unreadable')"
  echo "docker:      $(sudo docker --version 2>/dev/null || echo missing)  server $(sudo docker version --format '{{.Server.Version}}' 2>/dev/null || echo ?)"
  echo "openshell:   $(openshell --version 2>&1 | head -1)  (deb $(dpkg-query -W -f='${Version}' openshell 2>/dev/null || echo missing), pinned tag $OS_TAG @ $OS_COMMIT)"
  echo "openshell deb sha256: $OS_DEB_SHA256"
  echo "gateway bin: $(command -v openshell-gateway || echo 'not on PATH')  $(openshell-gateway --version 2>&1 | head -1 || true)"
  echo "python3:     $(python3 --version 2>&1)"
  echo "curl:        $(curl --version | head -1)"
  echo "rustc:       $("$HERE/toolchain/bin/rustc" --version)"
  echo "cargo:       $("$HERE/toolchain/bin/cargo" --version)"
  echo "translator:  $HERE/target/debug/bollard-openshell (sha256 $(sha256sum "$HERE/target/debug/bollard-openshell" 2>/dev/null | cut -d' ' -f1))"
  echo "bollard HEAD: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"
} | tee "$HERE/versions.txt" >&2
log "wrote $HERE/versions.txt"
if [ "${NEED_RELOGIN:-0}" = "1" ]; then
  log "ACTION REQUIRED: $USER was just added to the docker group. Reboot the VM (sudo reboot) before RUNBOOK step 5: with linger on, the"
  log "systemd user manager that runs the OpenShell gateway keeps its old group list until it restarts."
fi
log "done. Next: RUNBOOK.md step 4."
