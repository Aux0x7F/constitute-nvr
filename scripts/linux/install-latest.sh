#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-nvr}"
UPDATE_INTERVAL_SECS="${UPDATE_INTERVAL_SECS:-300}"
DEV_UPDATE_INTERVAL_SECS="${DEV_UPDATE_INTERVAL_SECS:-120}"
FORCE=0
FORWARD_NON_INTERACTIVE=0

CURL_PROXY_URL="${CURL_PROXY_URL:-}"
USE_TOR=0
TOR_SOCKS_ADDR="${TOR_SOCKS_ADDR:-127.0.0.1:9050}"
TOR_CONTROL_ADDR="${TOR_CONTROL_ADDR:-127.0.0.1:9051}"
TOR_ROTATE_ON_RETRY=1

CONFIG_MUTATING=0
WIZARD_ARGS=()

usage() {
  cat <<'EOF'
Usage: install-latest.sh [options]

Install/update constitute-nvr from GitHub Releases.
Auto-update remains enabled by default via constitute-nvr-update.timer.

Options:
  --repo-owner <owner>       GitHub owner (default: Aux0x7F)
  --repo-name <name>         GitHub repo (default: constitute-nvr)
  --update-interval <secs>   NVR self-update poll interval seconds (default: 300)
  --non-interactive          No prompts when install-time configuration is applied
  --dev-poll                 Use fast dev update interval (default: 120s)
  --force                    Reinstall even when binary hash is unchanged
  --proxy-url <url>          Use HTTP(S) proxy for release fetches
  --tor                      Use Tor SOCKS egress for release fetches
  --tor-socks <host:port>    Tor SOCKS endpoint (default: 127.0.0.1:9050)
  --tor-control <host:port>  Tor control endpoint (default: 127.0.0.1:9051)
  --no-tor-rotate            Disable NEWNYM attempt on retry

Pass-through (install context):
  --identity-id <id>
  --authorized-device-pk <pk>  (repeatable)
  --zone-key <key>             (repeatable)
  --swarm-peer <host:port>     (repeatable)
  --public-ws-url <url>
  --allow-unsigned-debug-hello | --require-signed-hello
  --pair-identity <label>
  --pair-code <code>
  --pair-code-hash <hash>
  --enable-reolink-autoprovision | --disable-reolink-autoprovision
  --reolink-username <name>
  --reolink-password <pass>
  --reolink-desired-password <pass>
  --reolink-generate-password
  --reolink-hint-ip <ip>
  --storage-root <path>
  --apply-hardening | --skip-hardening
  --camera-iface <iface>
  --camera-cidr <cidr>
  --onvif-ports <csv>
  --rtsp-ports <csv>
  --no-ntp-host

Examples:
  curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-latest.sh | bash
  curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-latest.sh | \
    bash -s -- --identity-id abc --swarm-peer 127.0.0.1:4040 --zone-key z1 --pair-identity myid --pair-code 1234 --pair-code-hash deadbeef
EOF
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

parse_passthrough_flag() {
  local flag="$1"
  shift
  case "$flag" in
    --identity-id|--authorized-device-pk|--zone-key|--swarm-peer|--public-ws-url|--pair-identity|--pair-code|--pair-code-hash|--reolink-username|--reolink-password|--reolink-desired-password|--reolink-hint-ip|--storage-root|--camera-iface|--camera-cidr|--onvif-ports|--rtsp-ports)
      local value="${1:-}"
      if [[ -z "$value" ]]; then
        echo "missing value for ${flag}" >&2
        exit 1
      fi
      WIZARD_ARGS+=("$flag" "$value")
      CONFIG_MUTATING=1
      echo 2
      return 0
      ;;
    --allow-unsigned-debug-hello|--require-signed-hello|--enable-reolink-autoprovision|--disable-reolink-autoprovision|--reolink-generate-password|--apply-hardening|--skip-hardening|--no-ntp-host)
      WIZARD_ARGS+=("$flag")
      CONFIG_MUTATING=1
      echo 1
      return 0
      ;;
    *)
      echo "Unknown argument: ${flag}" >&2
      usage
      exit 1
      ;;
  esac
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
    --update-interval)
      UPDATE_INTERVAL_SECS="${2:?missing value for --update-interval}"
      shift 2
      ;;
    --dev-poll)
      UPDATE_INTERVAL_SECS="$DEV_UPDATE_INTERVAL_SECS"
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
    --non-interactive)
      FORWARD_NON_INTERACTIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      consumed="$(parse_passthrough_flag "$@")"
      shift "$consumed"
      ;;
  esac
done

if ! [[ "$UPDATE_INTERVAL_SECS" =~ ^[0-9]+$ ]]; then
  echo "update interval must be integer seconds" >&2
  exit 1
fi

require_cmd bash
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

installer="${tmpdir}/extract/scripts/linux/install-wizard.sh"
binary="${tmpdir}/extract/constitute-nvr"
update_script="${tmpdir}/extract/scripts/linux/self-update-release.sh"
config_template="${tmpdir}/extract/config.example.json"

if [[ ! -f "$installer" ]]; then
  echo "Release artifact missing scripts/linux/install-wizard.sh" >&2
  exit 1
fi
if [[ ! -f "$binary" ]]; then
  echo "Release artifact missing constitute-nvr binary" >&2
  exit 1
fi
if [[ ! -f "$update_script" ]]; then
  echo "Release artifact missing scripts/linux/self-update-release.sh" >&2
  exit 1
fi
if [[ ! -f "$config_template" ]]; then
  echo "Release artifact missing config.example.json" >&2
  exit 1
fi

skip_install=0
installed_bin="/usr/local/bin/constitute-nvr"
if [[ "$FORCE" -eq 0 && "$CONFIG_MUTATING" -eq 0 && -f "$installed_bin" ]]; then
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^constitute-nvr\.service'; then
    current_hash="$(sha256sum "$installed_bin" | awk '{print $1}')"
    incoming_hash="$(sha256sum "$binary" | awk '{print $1}')"
    if [[ "$current_hash" == "$incoming_hash" ]]; then
      skip_install=1
      echo "No binary change detected; skipping reinstall/restart."
    fi
  fi
fi

if [[ "$skip_install" -eq 0 ]]; then
  install_args=(
    --binary "$binary"
    --self-update-script "$update_script"
    --config-template "$config_template"
    --update-interval "$UPDATE_INTERVAL_SECS"
  )
  if [[ "$FORWARD_NON_INTERACTIVE" -eq 1 ]]; then
    install_args+=(--non-interactive)
  fi
  install_args+=("${WIZARD_ARGS[@]}")
  bash "$installer" "${install_args[@]}"
fi

echo "Install/update complete: constitute-nvr"
