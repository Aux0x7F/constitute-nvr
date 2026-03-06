#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-nvr}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/constitute-nvr}"
SERVICE_NAME="${SERVICE_NAME:-constitute-nvr}"
TRY_RESTART=0
FORCE=0

# Compatibility with source-based updater invocation args.
SOURCE_DIR=""
BRANCH=""
REPO_URL=""

CURL_PROXY_URL="${CURL_PROXY_URL:-}"
USE_TOR=0
TOR_SOCKS_ADDR="${TOR_SOCKS_ADDR:-127.0.0.1:9050}"
TOR_CONTROL_ADDR="${TOR_CONTROL_ADDR:-127.0.0.1:9051}"
TOR_ROTATE_ON_RETRY=1

usage() {
  cat <<'EOF'
Usage: self-update-release.sh [options]

Update constitute-nvr from GitHub Releases and install when binary hash changes.

Options:
  --repo-owner <owner>       GitHub owner (default: Aux0x7F)
  --repo-name <name>         GitHub repo (default: constitute-nvr)
  --install-prefix <path>    Install prefix (default: /opt/constitute-nvr)
  --service-name <name>      systemd service name (default: constitute-nvr)
  --try-restart              Restart service when binary changed
  --force                    Reinstall even if binary hash is unchanged
  --proxy-url <url>          Use HTTP(S) proxy for release fetches
  --tor                      Use Tor SOCKS egress for release fetches
  --tor-socks <host:port>    Tor SOCKS endpoint (default: 127.0.0.1:9050)
  --tor-control <host:port>  Tor control endpoint (default: 127.0.0.1:9051)
  --no-tor-rotate            Disable NEWNYM attempt on retry

Compatibility no-op args:
  --source-dir <path>
  --branch <name>
  --repo-url <url>
EOF
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

build_curl_args() {
  CURL_ARGS=(-fsSL)
  if [[ -n "$CURL_PROXY_URL" ]]; then
    CURL_ARGS+=(--proxy "$CURL_PROXY_URL")
  fi
  if [[ "$USE_TOR" -eq 1 ]]; then
    CURL_ARGS+=(--proxy "socks5h://${TOR_SOCKS_ADDR}")
  fi
}

rotate_tor_exit() {
  [[ "$USE_TOR" -eq 1 ]] || return 0
  [[ "$TOR_ROTATE_ON_RETRY" -eq 1 ]] || return 0
  command -v nc >/dev/null 2>&1 || return 0

  local host="${TOR_CONTROL_ADDR%:*}"
  local port="${TOR_CONTROL_ADDR##*:}"
  [[ -n "$host" && -n "$port" && "$host" != "$port" ]] || return 0

  {
    printf 'AUTHENTICATE\r\n'
    printf 'SIGNAL NEWNYM\r\n'
    printf 'QUIT\r\n'
  } | nc -w 2 "$host" "$port" >/dev/null 2>&1 || true
}

verify_tor_proxy() {
  [[ "$USE_TOR" -eq 1 ]] || return 0
  if ! curl "${CURL_ARGS[@]}" --max-time 12 -I https://github.com >/dev/null 2>&1; then
    echo "Tor proxy check failed at socks5h://${TOR_SOCKS_ADDR}" >&2
    exit 1
  fi
}

download_with_retry() {
  local url="$1"
  local out="$2"
  local attempt
  for attempt in 1 2 3; do
    if curl "${CURL_ARGS[@]}" "$url" -o "$out"; then
      return 0
    fi
    rotate_tor_exit
    sleep "$attempt"
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-owner)
      REPO_OWNER="${2:?missing value for --repo-owner}"
      shift 2
      ;;
    --repo-name)
      REPO_NAME="${2:?missing value for --repo-name}"
      shift 2
      ;;
    --install-prefix)
      INSTALL_PREFIX="${2:?missing value for --install-prefix}"
      shift 2
      ;;
    --service-name)
      SERVICE_NAME="${2:?missing value for --service-name}"
      shift 2
      ;;
    --try-restart)
      TRY_RESTART=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --proxy-url)
      CURL_PROXY_URL="${2:?missing value for --proxy-url}"
      shift 2
      ;;
    --tor)
      USE_TOR=1
      shift
      ;;
    --tor-socks)
      USE_TOR=1
      TOR_SOCKS_ADDR="${2:?missing value for --tor-socks}"
      shift 2
      ;;
    --tor-control)
      TOR_CONTROL_ADDR="${2:?missing value for --tor-control}"
      shift 2
      ;;
    --no-tor-rotate)
      TOR_ROTATE_ON_RETRY=0
      shift
      ;;
    --source-dir)
      SOURCE_DIR="${2:-}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:-}"
      shift 2
      ;;
    --repo-url)
      REPO_URL="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_cmd curl
require_cmd grep
require_cmd sha256sum
require_cmd tar
build_curl_args
verify_tor_proxy

BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download"
LINUX_ASSET="constitute-nvr-linux-amd64.tar.gz"
SUMS_NAME="SHA256SUMS"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if ! download_with_retry "${BASE}/${LINUX_ASSET}" "${tmpdir}/${LINUX_ASSET}"; then
  echo "Failed to download ${LINUX_ASSET}" >&2
  exit 1
fi
if ! download_with_retry "${BASE}/${SUMS_NAME}" "${tmpdir}/${SUMS_NAME}"; then
  echo "Failed to download ${SUMS_NAME}" >&2
  exit 1
fi

if ! grep " ${LINUX_ASSET}$" "${tmpdir}/${SUMS_NAME}" | (cd "$tmpdir" && sha256sum -c -); then
  echo "Checksum verification failed for ${LINUX_ASSET}" >&2
  exit 1
fi

mkdir -p "$tmpdir/extract"
tar -C "$tmpdir/extract" -xzf "${tmpdir}/${LINUX_ASSET}"

incoming_bin="$tmpdir/extract/constitute-nvr"
incoming_update_script="$tmpdir/extract/scripts/linux/self-update-release.sh"

if [[ ! -f "$incoming_bin" ]]; then
  echo "Release artifact missing constitute-nvr binary" >&2
  exit 1
fi

installed_bin="${INSTALL_PREFIX}/bin/constitute-nvr"
needs_install=1
if [[ "$FORCE" -eq 0 && -f "$installed_bin" ]]; then
  current_hash="$(sha256sum "$installed_bin" | awk '{print $1}')"
  incoming_hash="$(sha256sum "$incoming_bin" | awk '{print $1}')"
  if [[ "$current_hash" == "$incoming_hash" ]]; then
    needs_install=0
    echo "[self-update] no binary change detected"
  fi
fi

if [[ "$needs_install" -eq 1 ]]; then
  run_sudo install -d "$INSTALL_PREFIX/bin"
  run_sudo install -m 0755 "$incoming_bin" "$installed_bin"
  run_sudo ln -sf "$installed_bin" /usr/local/bin/constitute-nvr

  if [[ -f "$incoming_update_script" ]]; then
    run_sudo install -m 0755 "$incoming_update_script" /usr/local/bin/constitute-nvr-self-update
  fi

  echo "[self-update] installed latest release"
  if [[ "$TRY_RESTART" -eq 1 ]]; then
    run_sudo systemctl restart "$SERVICE_NAME" || true
  fi
fi