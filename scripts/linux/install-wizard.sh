#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-nvr}"
REF="${REF:-main}"
REPO_URL="${REPO_URL:-https://github.com/${REPO_OWNER}/${REPO_NAME}.git}"
NON_INTERACTIVE=0
APPLY_HARDENING="ask"
CAMERA_IFACE=""
CAMERA_CIDR=""
ONVIF_PORTS="80,443,8000,8080,8899"
RTSP_PORTS="554"
ALLOW_NTP_HOST=1
INSTALL_PREFIX="/opt/constitute-nvr"
SOURCE_DIR="/opt/constitute-nvr-src"
BIN_LINK="/usr/local/bin/constitute-nvr"
SELF_UPDATE_BIN="/usr/local/bin/constitute-nvr-self-update"
SERVICE_NAME="constitute-nvr"
SERVICE_USER="constitute-nvr"
NOLOGIN_PATH="$(command -v nologin || echo /sbin/nologin)"
STORAGE_ROOT="/mnt/REPLACE_WITH_STORAGE_MOUNT/constitute-nvr"
UPDATE_INTERVAL_SECS=300

usage() {
  cat <<'EOF'
Usage: install-wizard.sh [options]

Build and install constitute-nvr as a Fedora/Linux systemd service,
configure self-update timer, and optionally apply camera-interface hardening.

Options:
  --repo-owner <owner>       GitHub owner (default: Aux0x7F)
  --repo-name <name>         GitHub repo (default: constitute-nvr)
  --repo-url <url>           Git URL override
  --ref <git-ref>            Git ref to build (default: main)
  --source-dir <path>        Source clone location (default: /opt/constitute-nvr-src)
  --storage-root <path>      Storage root path (default placeholder)
  --update-interval <secs>   Self-update poll interval in seconds (default: 300)
  --non-interactive          No prompts
  --apply-hardening          Apply camera hardening
  --skip-hardening           Skip camera hardening
  --camera-iface <iface>     Camera interface (e.g. enp2s0)
  --camera-cidr <cidr>       Camera subnet (e.g. 10.60.0.0/24)
  --onvif-ports <csv>        ONVIF TCP ports (default: 80,443,8000,8080,8899)
  --rtsp-ports <csv>         RTSP TCP ports (default: 554)
  --no-ntp-host              Do not allow camera->host UDP/123
  -h, --help                 Show help
EOF
}

log() {
  echo "[install-nvr] $*"
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
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

confirm() {
  local prompt="$1"
  local default_yes="$2"

  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    [[ "$default_yes" -eq 1 ]] && return 0 || return 1
  fi

  local suffix="[y/N]"
  [[ "$default_yes" -eq 1 ]] && suffix="[Y/n]"
  read -r -p "$prompt $suffix " reply

  if [[ -z "$reply" ]]; then
    [[ "$default_yes" -eq 1 ]] && return 0 || return 1
  fi

  case "$reply" in
    [Yy]|[Yy][Ee][Ss]) return 0 ;;
    *) return 1 ;;
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
    --repo-url)
      REPO_URL="${2:?missing value for --repo-url}"
      shift 2
      ;;
    --ref)
      REF="${2:?missing value for --ref}"
      shift 2
      ;;
    --source-dir)
      SOURCE_DIR="${2:?missing value for --source-dir}"
      shift 2
      ;;
    --storage-root)
      STORAGE_ROOT="${2:?missing value for --storage-root}"
      shift 2
      ;;
    --update-interval)
      UPDATE_INTERVAL_SECS="${2:?missing value for --update-interval}"
      shift 2
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --apply-hardening)
      APPLY_HARDENING=1
      shift
      ;;
    --skip-hardening)
      APPLY_HARDENING=0
      shift
      ;;
    --camera-iface)
      CAMERA_IFACE="${2:?missing value for --camera-iface}"
      shift 2
      ;;
    --camera-cidr)
      CAMERA_CIDR="${2:?missing value for --camera-cidr}"
      shift 2
      ;;
    --onvif-ports)
      ONVIF_PORTS="${2:?missing value for --onvif-ports}"
      shift 2
      ;;
    --rtsp-ports)
      RTSP_PORTS="${2:?missing value for --rtsp-ports}"
      shift 2
      ;;
    --no-ntp-host)
      ALLOW_NTP_HOST=0
      shift
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

if [[ "$APPLY_HARDENING" == "ask" ]]; then
  if confirm "Apply camera-network hardening (RTSP/ONVIF-only + optional NTP lane)?" 1; then
    APPLY_HARDENING=1
  else
    APPLY_HARDENING=0
  fi
fi

if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
  read -r -p "Storage root path [${STORAGE_ROOT}]: " input_storage
  if [[ -n "$input_storage" ]]; then
    STORAGE_ROOT="$input_storage"
  fi

  read -r -p "Self-update interval seconds [${UPDATE_INTERVAL_SECS}]: " input_interval
  if [[ -n "$input_interval" ]]; then
    UPDATE_INTERVAL_SECS="$input_interval"
  fi
fi

if [[ "$APPLY_HARDENING" -eq 1 ]]; then
  if [[ -z "$CAMERA_IFACE" && "$NON_INTERACTIVE" -eq 0 ]]; then
    read -r -p "Camera interface (e.g. enp2s0): " CAMERA_IFACE
  fi
  if [[ -z "$CAMERA_CIDR" && "$NON_INTERACTIVE" -eq 0 ]]; then
    read -r -p "Camera subnet CIDR (e.g. 10.60.0.0/24): " CAMERA_CIDR
  fi
  if [[ -z "$CAMERA_IFACE" || -z "$CAMERA_CIDR" ]]; then
    echo "camera interface and CIDR are required when hardening is enabled" >&2
    exit 1
  fi
fi

if ! [[ "$UPDATE_INTERVAL_SECS" =~ ^[0-9]+$ ]]; then
  echo "update interval must be integer seconds" >&2
  exit 1
fi

require_cmd git
require_cmd systemctl
require_cmd curl
require_cmd python3

if ! command -v cargo >/dev/null 2>&1; then
  log "cargo not found"
  if confirm "Install Rust toolchain with rustup now?" 1; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
  else
    echo "cargo is required" >&2
    exit 1
  fi
fi

SRC_DIR=""
TMP_DIR=""

if [[ -f "./Cargo.toml" && -f "./src/main.rs" ]]; then
  SRC_DIR="$(pwd)"
  log "using local repository: $SRC_DIR"
else
  TMP_DIR="$(mktemp -d)"
  SRC_DIR="$TMP_DIR/repo"
  log "cloning source: $REPO_URL"
  git clone --depth 1 --branch "$REF" "$REPO_URL" "$SRC_DIR"
fi

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

log "syncing source clone at ${SOURCE_DIR}"
run_sudo mkdir -p "$(dirname "$SOURCE_DIR")"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  run_sudo git clone --depth 1 --branch "$REF" "$REPO_URL" "$SOURCE_DIR"
else
  run_sudo git -C "$SOURCE_DIR" fetch --depth 1 origin "$REF"
  run_sudo git -C "$SOURCE_DIR" checkout "$REF"
  run_sudo git -C "$SOURCE_DIR" reset --hard "origin/$REF"
fi

log "building release binary"
(
  cd "$SRC_DIR"
  cargo build --release --locked
)

BIN_SRC="$SRC_DIR/target/release/constitute-nvr"
if [[ ! -x "$BIN_SRC" ]]; then
  echo "build succeeded but binary not found at $BIN_SRC" >&2
  exit 1
fi

log "installing binary to ${INSTALL_PREFIX}"
run_sudo install -d "$INSTALL_PREFIX/bin"
run_sudo install -m 0755 "$BIN_SRC" "$INSTALL_PREFIX/bin/constitute-nvr"
run_sudo ln -sf "$INSTALL_PREFIX/bin/constitute-nvr" "$BIN_LINK"

log "installing self-update helper"
run_sudo install -m 0755 "$SRC_DIR/scripts/linux/self-update.sh" "$SELF_UPDATE_BIN"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  log "creating service user: $SERVICE_USER"
  run_sudo useradd --system --no-create-home --home-dir "$INSTALL_PREFIX" --shell "$NOLOGIN_PATH" "$SERVICE_USER"
fi

run_sudo install -d -o "$SERVICE_USER" -g "$SERVICE_USER" /var/lib/constitute-nvr
run_sudo install -d /etc/constitute-nvr
run_sudo install -d "$STORAGE_ROOT"
run_sudo chown "$SERVICE_USER":"$SERVICE_USER" "$STORAGE_ROOT"

if [[ ! -f /etc/constitute-nvr/config.json && -f "$SRC_DIR/config.example.json" ]]; then
  log "installing config template to /etc/constitute-nvr/config.json"
  run_sudo install -m 0644 "$SRC_DIR/config.example.json" /etc/constitute-nvr/config.json
fi

log "patching config defaults"
run_sudo python3 - <<PY
import json
from pathlib import Path

path = Path('/etc/constitute-nvr/config.json')
raw = json.loads(path.read_text(encoding='utf-8'))
raw.setdefault('storage', {})['root'] = '${STORAGE_ROOT}'
raw.setdefault('update', {})['enabled'] = True
raw['update']['interval_secs'] = int('${UPDATE_INTERVAL_SECS}')
raw['update']['source_dir'] = '${SOURCE_DIR}'
raw['update']['branch'] = '${REF}'
raw['update']['script_path'] = '${SELF_UPDATE_BIN}'
path.write_text(json.dumps(raw, indent=2) + '\n', encoding='utf-8')
PY

UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
log "writing systemd unit: ${UNIT_PATH}"
cat <<EOF | run_sudo tee "$UNIT_PATH" >/dev/null
[Unit]
Description=Constitute NVR Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=/var/lib/constitute-nvr
ExecStart=${BIN_LINK}
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/constitute-nvr /etc/constitute-nvr ${STORAGE_ROOT}

[Install]
WantedBy=multi-user.target
EOF

UPD_SERVICE="/etc/systemd/system/${SERVICE_NAME}-update.service"
UPD_TIMER="/etc/systemd/system/${SERVICE_NAME}-update.timer"

cat <<EOF | run_sudo tee "$UPD_SERVICE" >/dev/null
[Unit]
Description=Constitute NVR Self Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SELF_UPDATE_BIN} --source-dir ${SOURCE_DIR} --branch ${REF} --service-name ${SERVICE_NAME} --try-restart
EOF

cat <<EOF | run_sudo tee "$UPD_TIMER" >/dev/null
[Unit]
Description=Constitute NVR Self Update Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${UPDATE_INTERVAL_SECS}s
Unit=${SERVICE_NAME}-update.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

run_sudo systemctl daemon-reload
run_sudo systemctl enable --now "$SERVICE_NAME"
run_sudo systemctl enable --now "${SERVICE_NAME}-update.timer"

if [[ "$APPLY_HARDENING" -eq 1 ]]; then
  log "applying camera hardening"
  harden_args=(
    --apply
    --iface "$CAMERA_IFACE"
    --camera-cidr "$CAMERA_CIDR"
    --onvif-ports "$ONVIF_PORTS"
    --rtsp-ports "$RTSP_PORTS"
  )
  if [[ "$ALLOW_NTP_HOST" -eq 0 ]]; then
    harden_args+=(--no-ntp-host)
  fi
  run_sudo bash "$SRC_DIR/scripts/linux/harden-camera-interface.sh" "${harden_args[@]}"
fi

log "installation complete"
run_sudo systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,20p' || true
run_sudo systemctl --no-pager --full status "${SERVICE_NAME}-update.timer" | sed -n '1,20p' || true
cat <<'EOF'

Manual test quick checks:
1) systemctl status constitute-nvr
2) journalctl -u constitute-nvr -n 100 --no-pager
3) systemctl list-timers | grep constitute-nvr-update
4) curl -s http://127.0.0.1:8456/health
EOF
