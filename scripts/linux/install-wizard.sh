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
ONVIF_PORTS="80,443,8000,8080,8899,9000"
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
EXTERNAL_BINARY=""
EXTERNAL_UPDATE_SCRIPT=""
EXTERNAL_CONFIG_TEMPLATE=""

IDENTITY_ID=""
PUBLIC_WS_URL=""
SWARM_PEERS=()
ALLOW_UNSIGNED_HELLO_MVP=1
AUTHORIZED_DEVICE_PKS=()
ZONE_KEYS=()
PAIR_IDENTITY=""
PAIR_CODE=""
PAIR_CODE_HASH=""
REOLINK_AUTOPROVISION="ask"
REOLINK_USERNAME="admin"
REOLINK_PASSWORD=""
REOLINK_DESIRED_PASSWORD=""
REOLINK_GENERATE_PASSWORD=0
REOLINK_HINT_IP=""
CAMERA_HOST_IP=""
CAMERA_DHCP_RANGE_START=""
CAMERA_DHCP_RANGE_END=""
UPDATE_MODE="release_artifact"
UPDATE_BUILD_USER="${SUDO_USER:-${USER:-}}"

usage() {
  cat <<'EOF'
Usage: install-wizard.sh [options]

Build and install constitute-nvr as a Fedora/Linux systemd service,
configure self-update timer, bootstrap the camera subnet with DHCP,
and optionally apply camera-interface hardening.

Options:
  --repo-owner <owner>       GitHub owner (default: Aux0x7F)
  --repo-name <name>         GitHub repo (default: constitute-nvr)
  --repo-url <url>           Git URL override
  --ref <git-ref>            Git ref to build (default: main)
  --source-dir <path>        Source clone location (default: /opt/constitute-nvr-src)
  --binary <path>            Use prebuilt binary (skip source build)
  --self-update-script <path> Custom self-update script to install
  --config-template <path>   Config template path for first install
  --storage-root <path>      Storage root path (default placeholder)
  --update-interval <secs>   Self-update poll interval in seconds (default: 300)
  --non-interactive          No prompts
  --apply-hardening          Apply camera hardening
  --skip-hardening           Skip camera hardening
  --camera-iface <iface>     Camera interface (e.g. enp2s0)
  --camera-cidr <cidr>       Camera subnet (auto-selects non-colliding /24 when omitted)
  --onvif-ports <csv>        Camera control TCP ports (default: 80,443,8000,8080,8899,9000)
  --rtsp-ports <csv>         RTSP TCP ports (default: 554)
  --no-ntp-host              Do not allow camera->host UDP/123
  --identity-id <id>         Bind NVR session auth to identity id
  --authorized-device-pk <pk> Add authorized identity device pk (repeatable)
  --zone-key <key>           Join zone key for swarm announcements (repeatable)
  --swarm-peer <host:port>   Gateway swarm UDP peer endpoint (repeatable)
  --public-ws-url <url>      Public websocket URL for /session
  --allow-unsigned-hello-mvp Allow unsigned hello proof mode (default)
  --require-signed-hello     Require signed hello proof
  --pair-identity <label>    Pairing identity label for auto-associate
  --pair-code <code>         Pairing enrollment code
  --pair-code-hash <hash>    Pairing enrollment code hash (base64url)
  --enable-reolink-autoprovision Enable Reolink auto-provision at startup
  --disable-reolink-autoprovision Disable Reolink auto-provision
  --reolink-username <name>  Reolink admin username (default: admin)
  --reolink-password <pass>  Reolink current password
  --reolink-desired-password <pass> Reolink desired password
  --reolink-generate-password Generate random Reolink password
  --reolink-hint-ip <ip>     Hint IP for Reolink discovery
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
    --binary)
      EXTERNAL_BINARY="${2:?missing value for --binary}"
      shift 2
      ;;
    --self-update-script)
      EXTERNAL_UPDATE_SCRIPT="${2:?missing value for --self-update-script}"
      shift 2
      ;;
    --config-template)
      EXTERNAL_CONFIG_TEMPLATE="${2:?missing value for --config-template}"
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
    --identity-id)
      IDENTITY_ID="${2:?missing value for --identity-id}"
      shift 2
      ;;
    --authorized-device-pk)
      AUTHORIZED_DEVICE_PKS+=("${2:?missing value for --authorized-device-pk}")
      shift 2
      ;;
    --zone-key)
      ZONE_KEYS+=("${2:?missing value for --zone-key}")
      shift 2
      ;;
    --swarm-peer)
      SWARM_PEERS+=("${2:?missing value for --swarm-peer}")
      shift 2
      ;;
    --public-ws-url)
      PUBLIC_WS_URL="${2:?missing value for --public-ws-url}"
      shift 2
      ;;
    --allow-unsigned-hello-mvp)
      ALLOW_UNSIGNED_HELLO_MVP=1
      shift
      ;;
    --require-signed-hello)
      ALLOW_UNSIGNED_HELLO_MVP=0
      shift
      ;;
    --pair-identity)
      PAIR_IDENTITY="${2:?missing value for --pair-identity}"
      shift 2
      ;;
    --pair-code)
      PAIR_CODE="${2:?missing value for --pair-code}"
      shift 2
      ;;
    --pair-code-hash)
      PAIR_CODE_HASH="${2:?missing value for --pair-code-hash}"
      shift 2
      ;;
    --enable-reolink-autoprovision)
      REOLINK_AUTOPROVISION=1
      shift
      ;;
    --disable-reolink-autoprovision)
      REOLINK_AUTOPROVISION=0
      shift
      ;;
    --reolink-username)
      REOLINK_USERNAME="${2:?missing value for --reolink-username}"
      shift 2
      ;;
    --reolink-password)
      REOLINK_PASSWORD="${2:?missing value for --reolink-password}"
      shift 2
      ;;
    --reolink-desired-password)
      REOLINK_DESIRED_PASSWORD="${2:?missing value for --reolink-desired-password}"
      shift 2
      ;;
    --reolink-generate-password)
      REOLINK_GENERATE_PASSWORD=1
      shift
      ;;
    --reolink-hint-ip)
      REOLINK_HINT_IP="${2:?missing value for --reolink-hint-ip}"
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

  if [[ -z "$IDENTITY_ID" ]]; then
    read -r -p "Identity id (required for session auth): " IDENTITY_ID
  fi

  if [[ ${#SWARM_PEERS[@]} -eq 0 ]]; then
    read -r -p "Gateway swarm peer host:port (optional): " first_swarm_peer
    if [[ -n "$first_swarm_peer" ]]; then
      SWARM_PEERS+=("$first_swarm_peer")
    fi
  fi

  if [[ ${#ZONE_KEYS[@]} -eq 0 ]]; then
    read -r -p "Zone key to join (optional): " first_zone_key
    if [[ -n "$first_zone_key" ]]; then
      ZONE_KEYS+=("$first_zone_key")
    fi
  fi

  if [[ -z "$PUBLIC_WS_URL" ]]; then
    read -r -p "Public websocket URL (optional, example ws://host:8456/session): " PUBLIC_WS_URL
  fi
fi

if [[ "$REOLINK_AUTOPROVISION" == "ask" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    REOLINK_AUTOPROVISION=0
  elif confirm "Enable Reolink auto-provision at service startup?" 0; then
    REOLINK_AUTOPROVISION=1
  else
    REOLINK_AUTOPROVISION=0
  fi
fi

if [[ "$REOLINK_AUTOPROVISION" -eq 1 && "$NON_INTERACTIVE" -eq 0 ]]; then
  if [[ -z "$REOLINK_USERNAME" ]]; then
    read -r -p "Reolink username [admin]: " input_reolink_user
    REOLINK_USERNAME="${input_reolink_user:-admin}"
  fi
  if [[ -z "$REOLINK_PASSWORD" && "$REOLINK_GENERATE_PASSWORD" -eq 0 ]]; then
    read -r -s -p "Reolink current password (required unless generate-password): " input_reolink_pass
    echo
    REOLINK_PASSWORD="$input_reolink_pass"
  fi
  if [[ "$REOLINK_GENERATE_PASSWORD" -eq 0 ]] && confirm "Generate new random camera password during setup?" 0; then
    REOLINK_GENERATE_PASSWORD=1
  fi
  if [[ "$REOLINK_GENERATE_PASSWORD" -eq 0 && -z "$REOLINK_DESIRED_PASSWORD" ]]; then
    read -r -s -p "Reolink desired password (optional, leave blank to keep current): " input_reolink_desired
    echo
    REOLINK_DESIRED_PASSWORD="$input_reolink_desired"
  fi
  if [[ -z "$REOLINK_HINT_IP" ]]; then
    read -r -p "Reolink hint IP (optional): " REOLINK_HINT_IP
  fi
fi

if ! [[ "$UPDATE_INTERVAL_SECS" =~ ^[0-9]+$ ]]; then
  echo "update interval must be integer seconds" >&2
  exit 1
fi

if [[ -z "$IDENTITY_ID" ]]; then
  echo "identity id is required (use --identity-id or interactive prompt)" >&2
  exit 1
fi

if [[ "$REOLINK_AUTOPROVISION" -eq 1 && -z "$REOLINK_USERNAME" ]]; then
  REOLINK_USERNAME="admin"
fi

if [[ "$REOLINK_AUTOPROVISION" -eq 1 && "$REOLINK_GENERATE_PASSWORD" -eq 0 && -z "$REOLINK_PASSWORD" && -z "$REOLINK_DESIRED_PASSWORD" ]]; then
  echo "reolink auto-provision enabled but no password material provided" >&2
  exit 1
fi

require_cmd systemctl
require_cmd curl
require_cmd python3

SRC_DIR=""
TMP_DIR=""
BIN_SRC=""
UPDATE_SCRIPT_SRC=""
CONFIG_TEMPLATE_SRC=""
HARDEN_SCRIPT_SRC=""
BOOTSTRAP_SCRIPT_SRC=""

if [[ -n "$EXTERNAL_BINARY" ]]; then
  UPDATE_MODE="release_artifact"
  if [[ ! -f "$EXTERNAL_BINARY" ]]; then
    echo "binary not found: $EXTERNAL_BINARY" >&2
    exit 1
  fi
  BIN_SRC="$EXTERNAL_BINARY"

  if [[ -n "$EXTERNAL_UPDATE_SCRIPT" ]]; then
    if [[ ! -f "$EXTERNAL_UPDATE_SCRIPT" ]]; then
      echo "self-update script not found: $EXTERNAL_UPDATE_SCRIPT" >&2
      exit 1
    fi
    UPDATE_SCRIPT_SRC="$EXTERNAL_UPDATE_SCRIPT"
  elif [[ -f "$(dirname "$0")/self-update-release.sh" ]]; then
    UPDATE_SCRIPT_SRC="$(dirname "$0")/self-update-release.sh"
  elif [[ -f "$(dirname "$0")/self-update.sh" ]]; then
    UPDATE_SCRIPT_SRC="$(dirname "$0")/self-update.sh"
  else
    echo "unable to resolve self-update script source" >&2
    exit 1
  fi

  if [[ -n "$EXTERNAL_CONFIG_TEMPLATE" ]]; then
    if [[ ! -f "$EXTERNAL_CONFIG_TEMPLATE" ]]; then
      echo "config template not found: $EXTERNAL_CONFIG_TEMPLATE" >&2
      exit 1
    fi
    CONFIG_TEMPLATE_SRC="$EXTERNAL_CONFIG_TEMPLATE"
  elif [[ -f "$(dirname "$0")/../../config.example.json" ]]; then
    CONFIG_TEMPLATE_SRC="$(dirname "$0")/../../config.example.json"
  fi

  if [[ -f "$(dirname "$0")/harden-camera-interface.sh" ]]; then
    HARDEN_SCRIPT_SRC="$(dirname "$0")/harden-camera-interface.sh"
  fi
  if [[ -f "$(dirname "$0")/bootstrap-camera-network.sh" ]]; then
    BOOTSTRAP_SCRIPT_SRC="$(dirname "$0")/bootstrap-camera-network.sh"
  fi

  log "using provided binary: $BIN_SRC"
else
  UPDATE_MODE="source_build"
  require_cmd git
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
  UPDATE_SCRIPT_SRC="$SRC_DIR/scripts/linux/self-update.sh"
  CONFIG_TEMPLATE_SRC="$SRC_DIR/config.example.json"
  HARDEN_SCRIPT_SRC="$SRC_DIR/scripts/linux/harden-camera-interface.sh"
  BOOTSTRAP_SCRIPT_SRC="$SRC_DIR/scripts/linux/bootstrap-camera-network.sh"
fi

if [[ ! -x "$BIN_SRC" ]]; then
  echo "binary not executable: $BIN_SRC" >&2
  exit 1
fi
if [[ ! -f "$UPDATE_SCRIPT_SRC" ]]; then
  echo "self-update script source missing: $UPDATE_SCRIPT_SRC" >&2
  exit 1
fi
if [[ -n "$CONFIG_TEMPLATE_SRC" && ! -f "$CONFIG_TEMPLATE_SRC" ]]; then
  echo "config template source missing: $CONFIG_TEMPLATE_SRC" >&2
  exit 1
fi
if [[ "$APPLY_HARDENING" -eq 1 && ( -z "$HARDEN_SCRIPT_SRC" || ! -f "$HARDEN_SCRIPT_SRC" ) ]]; then
  echo "hardening script source missing" >&2
  exit 1
fi
if [[ -z "$BOOTSTRAP_SCRIPT_SRC" || ! -f "$BOOTSTRAP_SCRIPT_SRC" ]]; then
  echo "camera bootstrap script source missing" >&2
  exit 1
fi

log "installing binary to ${INSTALL_PREFIX}"
run_sudo install -d "$INSTALL_PREFIX/bin"
run_sudo install -m 0755 "$BIN_SRC" "$INSTALL_PREFIX/bin/constitute-nvr"
run_sudo ln -sf "$INSTALL_PREFIX/bin/constitute-nvr" "$BIN_LINK"

log "installing self-update helper"
run_sudo install -m 0755 "$UPDATE_SCRIPT_SRC" "$SELF_UPDATE_BIN"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  log "creating service user: $SERVICE_USER"
  run_sudo useradd --system --no-create-home --home-dir "$INSTALL_PREFIX" --shell "$NOLOGIN_PATH" "$SERVICE_USER"
fi

run_sudo install -d -o "$SERVICE_USER" -g "$SERVICE_USER" /var/lib/constitute-nvr
run_sudo install -d /etc/constitute-nvr
run_sudo install -d "$STORAGE_ROOT"
run_sudo chown "$SERVICE_USER":"$SERVICE_USER" "$STORAGE_ROOT"

CONFIG_WAS_INSTALLED=0
if [[ ! -f /etc/constitute-nvr/config.json && -n "$CONFIG_TEMPLATE_SRC" ]]; then
  log "installing config template to /etc/constitute-nvr/config.json"
  run_sudo install -m 0644 "$CONFIG_TEMPLATE_SRC" /etc/constitute-nvr/config.json
  CONFIG_WAS_INSTALLED=1
fi

if [[ -f /etc/constitute-nvr/config.json && ( -z "$CAMERA_IFACE" || -z "$CAMERA_CIDR" ) ]]; then
  existing_camera="$(
    run_sudo python3 - <<'PY'
import json
from pathlib import Path

path = Path('/etc/constitute-nvr/config.json')
raw = json.loads(path.read_text(encoding='utf-8'))
camera = raw.get('camera_network') or {}
print((camera.get('interface') or '').strip())
print((camera.get('subnet_cidr') or '').strip())
PY
  )"
  if [[ -z "$CAMERA_IFACE" ]]; then
    CAMERA_IFACE="$(printf '%s\n' "$existing_camera" | sed -n '1p')"
  fi
  if [[ -z "$CAMERA_CIDR" ]]; then
    CAMERA_CIDR="$(printf '%s\n' "$existing_camera" | sed -n '2p')"
  fi
fi

log "bootstrapping camera network"
bootstrap_args=(--apply --print-env)
if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
  bootstrap_args+=(--non-interactive)
fi
if [[ -n "$CAMERA_IFACE" ]]; then
  bootstrap_args+=(--camera-iface "$CAMERA_IFACE")
fi
if [[ -n "$CAMERA_CIDR" ]]; then
  bootstrap_args+=(--camera-cidr "$CAMERA_CIDR")
fi

bootstrap_output="$(run_sudo bash "$BOOTSTRAP_SCRIPT_SRC" "${bootstrap_args[@]}")"
while IFS='=' read -r key value; do
  case "$key" in
    CAMERA_IFACE) CAMERA_IFACE="$value" ;;
    CAMERA_CIDR) CAMERA_CIDR="$value" ;;
    CAMERA_HOST_IP) CAMERA_HOST_IP="$value" ;;
    CAMERA_DHCP_RANGE_START) CAMERA_DHCP_RANGE_START="$value" ;;
    CAMERA_DHCP_RANGE_END) CAMERA_DHCP_RANGE_END="$value" ;;
  esac
done <<<"$bootstrap_output"

log "patching config defaults"
authorized_joined=""
if [[ ${#AUTHORIZED_DEVICE_PKS[@]} -gt 0 ]]; then
  authorized_joined="$(IFS='|'; echo "${AUTHORIZED_DEVICE_PKS[*]}")"
fi
zone_keys_joined=""
if [[ ${#ZONE_KEYS[@]} -gt 0 ]]; then
  zone_keys_joined="$(IFS='|'; echo "${ZONE_KEYS[*]}")"
fi
swarm_peers_joined=""
if [[ ${#SWARM_PEERS[@]} -gt 0 ]]; then
  swarm_peers_joined="$(IFS='|'; echo "${SWARM_PEERS[*]}")"
fi

run_sudo env \
  CFG_STORAGE_ROOT="${STORAGE_ROOT}" \
  CFG_UPDATE_INTERVAL="${UPDATE_INTERVAL_SECS}" \
  CFG_UPDATE_MODE="${UPDATE_MODE}" \
  CFG_SOURCE_DIR="${SOURCE_DIR}" \
  CFG_REF="${REF}" \
  CFG_UPDATE_SCRIPT="${SELF_UPDATE_BIN}" \
  CFG_UPDATE_BUILD_USER="${UPDATE_BUILD_USER}" \
  CFG_IDENTITY_ID="${IDENTITY_ID}" \
  CFG_PUBLIC_WS_URL="${PUBLIC_WS_URL}" \
  CFG_SWARM_PEERS="${swarm_peers_joined}" \
  CFG_ALLOW_UNSIGNED_HELLO_MVP="${ALLOW_UNSIGNED_HELLO_MVP}" \
  CFG_AUTHORIZED_DEVICE_PKS="${authorized_joined}" \
  CFG_ZONE_KEYS="${zone_keys_joined}" \
  CFG_PAIR_IDENTITY="${PAIR_IDENTITY}" \
  CFG_PAIR_CODE="${PAIR_CODE}" \
  CFG_PAIR_CODE_HASH="${PAIR_CODE_HASH}" \
  CFG_REOLINK_AUTOPROVISION="${REOLINK_AUTOPROVISION}" \
  CFG_REOLINK_USERNAME="${REOLINK_USERNAME}" \
  CFG_REOLINK_PASSWORD="${REOLINK_PASSWORD}" \
  CFG_REOLINK_DESIRED_PASSWORD="${REOLINK_DESIRED_PASSWORD}" \
  CFG_REOLINK_GENERATE_PASSWORD="${REOLINK_GENERATE_PASSWORD}" \
  CFG_REOLINK_HINT_IP="${REOLINK_HINT_IP}" \
  CFG_CAMERA_IFACE="${CAMERA_IFACE}" \
  CFG_CAMERA_CIDR="${CAMERA_CIDR}" \
  CFG_CAMERA_HOST_IP="${CAMERA_HOST_IP}" \
  CFG_CAMERA_DHCP_RANGE_START="${CAMERA_DHCP_RANGE_START}" \
  CFG_CAMERA_DHCP_RANGE_END="${CAMERA_DHCP_RANGE_END}" \
  CFG_FIRST_INSTALL="${CONFIG_WAS_INSTALLED}" \
  python3 - <<'PY'
import base64
import hashlib
import json
import os
from pathlib import Path

path = Path('/etc/constitute-nvr/config.json')
raw = json.loads(path.read_text(encoding='utf-8'))

storage_root = os.environ.get('CFG_STORAGE_ROOT', '').strip()
update_interval = int(os.environ.get('CFG_UPDATE_INTERVAL', '300') or '300')
update_mode = os.environ.get('CFG_UPDATE_MODE', 'release_artifact').strip() or 'release_artifact'
source_dir = os.environ.get('CFG_SOURCE_DIR', '').strip()
ref = os.environ.get('CFG_REF', '').strip()
update_script = os.environ.get('CFG_UPDATE_SCRIPT', '').strip()
update_build_user = os.environ.get('CFG_UPDATE_BUILD_USER', '').strip()
identity_id = os.environ.get('CFG_IDENTITY_ID', '').strip()
public_ws_url = os.environ.get('CFG_PUBLIC_WS_URL', '').strip()
swarm_peers = [x.strip() for x in os.environ.get('CFG_SWARM_PEERS', '').split('|') if x.strip()]
allow_unsigned = os.environ.get('CFG_ALLOW_UNSIGNED_HELLO_MVP', '1').strip() == '1'
authorized = [x.strip() for x in os.environ.get('CFG_AUTHORIZED_DEVICE_PKS', '').split('|') if x.strip()]
zone_keys = [x.strip() for x in os.environ.get('CFG_ZONE_KEYS', '').split('|') if x.strip()]
pair_identity = os.environ.get('CFG_PAIR_IDENTITY', '').strip()
pair_code = os.environ.get('CFG_PAIR_CODE', '').strip()
pair_code_hash = os.environ.get('CFG_PAIR_CODE_HASH', '').strip()
reolink_enabled = os.environ.get('CFG_REOLINK_AUTOPROVISION', '0').strip() == '1'
reolink_username = os.environ.get('CFG_REOLINK_USERNAME', 'admin').strip() or 'admin'
reolink_password = os.environ.get('CFG_REOLINK_PASSWORD', '').strip()
reolink_desired_password = os.environ.get('CFG_REOLINK_DESIRED_PASSWORD', '').strip()
reolink_generate_password = os.environ.get('CFG_REOLINK_GENERATE_PASSWORD', '0').strip() == '1'
reolink_hint_ip = os.environ.get('CFG_REOLINK_HINT_IP', '').strip()
camera_iface = os.environ.get('CFG_CAMERA_IFACE', '').strip()
camera_cidr = os.environ.get('CFG_CAMERA_CIDR', '').strip()
camera_host_ip = os.environ.get('CFG_CAMERA_HOST_IP', '').strip()
camera_dhcp_range_start = os.environ.get('CFG_CAMERA_DHCP_RANGE_START', '').strip()
camera_dhcp_range_end = os.environ.get('CFG_CAMERA_DHCP_RANGE_END', '').strip()
first_install = os.environ.get('CFG_FIRST_INSTALL', '0').strip() == '1'

def looks_like_template_camera(camera: dict) -> bool:
    if not isinstance(camera, dict):
        return False
    onvif_host = str(camera.get('onvif_host', '')).strip()
    rtsp_url = str(camera.get('rtsp_url', '')).strip()
    source_id = str(camera.get('source_id', '')).strip()
    username = str(camera.get('username', '')).strip()
    password = str(camera.get('password', '')).strip()
    return (
        onvif_host == '10.60.0.11'
        or '@10.60.0.11:' in rtsp_url
        or (source_id == 'cam-reolink-e1' and username == 'user' and password == 'pass')
    )

raw.setdefault('storage', {})['root'] = storage_root
raw.setdefault('update', {})['enabled'] = True
raw['update']['interval_secs'] = update_interval
raw['update']['mode'] = update_mode
raw['update']['source_dir'] = source_dir
raw['update']['branch'] = ref
raw['update']['script_path'] = update_script
raw['update']['build_user'] = update_build_user

raw.setdefault('api', {})['identity_id'] = identity_id
raw['api']['allow_unsigned_hello_mvp'] = allow_unsigned
if public_ws_url:
    raw['api']['public_ws_url'] = public_ws_url
if authorized:
    raw['api']['authorized_device_pks'] = sorted(set(authorized))

swarm = raw.setdefault('swarm', {})
if swarm_peers:
    peers = [x for x in swarm.get('peers', []) if isinstance(x, str)]
    for peer in swarm_peers:
        if peer not in peers:
            peers.append(peer)
    swarm['peers'] = peers

if zone_keys:
    swarm['zones'] = [{'key': key, 'name': 'Configured Zone'} for key in zone_keys]

if pair_identity:
    raw['pair_identity_label'] = pair_identity
if pair_code:
    raw['pair_code'] = pair_code
if not pair_code_hash and pair_identity and pair_code:
    digest = hashlib.sha256(f"{pair_identity}|{pair_code}".encode('utf-8')).digest()
    pair_code_hash = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
if pair_code_hash:
    raw['pair_code_hash'] = pair_code_hash
raw.setdefault('pair_request_interval_secs', 15)
raw.setdefault('pair_request_attempts', 24)

autop = raw.setdefault('autoprovision', {})
autop['reolink_enabled'] = reolink_enabled
autop['reolink_username'] = reolink_username
autop['reolink_password'] = reolink_password
autop['reolink_desired_password'] = reolink_desired_password
autop['reolink_generate_password'] = reolink_generate_password
autop.setdefault('reolink_discover_timeout_secs', 3)
autop['reolink_hint_ip'] = reolink_hint_ip

camera_network = raw.setdefault('camera_network', {})
camera_network['managed'] = True
camera_network['interface'] = camera_iface
camera_network['subnet_cidr'] = camera_cidr
camera_network['host_ip'] = camera_host_ip
camera_network['dhcp_enabled'] = True
camera_network['dhcp_range_start'] = camera_dhcp_range_start
camera_network['dhcp_range_end'] = camera_dhcp_range_end

if first_install or (
    isinstance(raw.get('cameras'), list)
    and raw['cameras']
    and all(looks_like_template_camera(item) for item in raw['cameras'])
):
    raw['cameras'] = []

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
ExecStart=${SELF_UPDATE_BIN} --mode ${UPDATE_MODE} --build-user ${UPDATE_BUILD_USER} --source-dir ${SOURCE_DIR} --branch ${REF} --service-name ${SERVICE_NAME} --try-restart
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
run_sudo systemctl enable "$SERVICE_NAME"
if run_sudo systemctl is-active --quiet "$SERVICE_NAME"; then
  run_sudo systemctl restart "$SERVICE_NAME"
else
  run_sudo systemctl start "$SERVICE_NAME"
fi
run_sudo systemctl enable "${SERVICE_NAME}-update.timer"
if run_sudo systemctl is-active --quiet "${SERVICE_NAME}-update.timer"; then
  run_sudo systemctl restart "${SERVICE_NAME}-update.timer"
else
  run_sudo systemctl start "${SERVICE_NAME}-update.timer"
fi

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
  run_sudo bash "$HARDEN_SCRIPT_SRC" "${harden_args[@]}"
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
