#!/usr/bin/env bash
set -euo pipefail

APPLY=0
NON_INTERACTIVE=0
PRINT_ENV=0
CAMERA_IFACE=""
CAMERA_CIDR=""
HOST_IP=""
DHCP_RANGE_START=""
DHCP_RANGE_END=""
DNSMASQ_CONF="/etc/dnsmasq.d/constitute-nvr-camera.conf"

usage() {
  cat <<'EOF'
Usage: bootstrap-camera-network.sh [options]

Provision a dedicated constitute-nvr camera network:
- choose or confirm a dedicated camera NIC
- assign a persistent static IPv4 on that NIC
- install/configure dnsmasq DHCP bound only to that NIC

Options:
  --apply                     Apply changes (default is dry selection only)
  --non-interactive          Do not prompt; require explicit or unambiguous NIC selection
  --camera-iface <iface>     Dedicated camera interface
  --camera-cidr <cidr>       Camera subnet CIDR (defaults to first non-colliding candidate)
  --host-ip <ip>             Host IP on camera subnet (default: .1)
  --dhcp-range-start <ip>    DHCP pool start (default: .50)
  --dhcp-range-end <ip>      DHCP pool end (default: .199)
  --print-env                Emit CAMERA_* shell assignments on success
  -h, --help                 Show help
EOF
}

log() {
  echo "[camera-bootstrap] $*" >&2
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      shift
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
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
    --host-ip)
      HOST_IP="${2:?missing value for --host-ip}"
      shift 2
      ;;
    --dhcp-range-start)
      DHCP_RANGE_START="${2:?missing value for --dhcp-range-start}"
      shift 2
      ;;
    --dhcp-range-end)
      DHCP_RANGE_END="${2:?missing value for --dhcp-range-end}"
      shift 2
      ;;
    --print-env)
      PRINT_ENV=1
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

require_cmd ip
require_cmd python3

default_iface="$(
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
)"

mapfile -t ethernet_ifaces < <(
  ip -o link show | awk -F': ' '
    {
      iface=$2
      sub(/@.*/, "", iface)
      if (iface == "lo") next
      print iface
    }
  '
)

mapfile -t candidate_ifaces < <(
  printf '%s\n' "${ethernet_ifaces[@]}" | awk -v default_iface="$default_iface" '
    NF && $0 != default_iface { print }
  '
)

select_camera_iface() {
  if [[ -n "$CAMERA_IFACE" ]]; then
    if ! ip link show "$CAMERA_IFACE" >/dev/null 2>&1; then
      echo "camera interface not found: $CAMERA_IFACE" >&2
      exit 1
    fi
    return
  fi

  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    if [[ "${#candidate_ifaces[@]}" -eq 1 ]]; then
      CAMERA_IFACE="${candidate_ifaces[0]}"
      return
    fi
    echo "unable to auto-select camera interface; use --camera-iface" >&2
    echo "candidates: ${candidate_ifaces[*]:-<none>}" >&2
    exit 1
  fi

  if [[ "${#candidate_ifaces[@]}" -eq 0 ]]; then
    echo "no non-default-route interfaces available for camera network" >&2
    exit 1
  fi

  echo "Available camera network interfaces:" >&2
  local idx=1
  for iface in "${candidate_ifaces[@]}"; do
    echo "  ${idx}) ${iface}" >&2
    idx=$((idx + 1))
  done
  read -r -p "Select camera interface [1-${#candidate_ifaces[@]}]: " reply
  if ! [[ "$reply" =~ ^[0-9]+$ ]] || (( reply < 1 || reply > ${#candidate_ifaces[@]} )); then
    echo "invalid interface selection" >&2
    exit 1
  fi
  CAMERA_IFACE="${candidate_ifaces[$((reply - 1))]}"
}

derive_network_values() {
  local json
  json="$(python3 - <<'PY'
import ipaddress
import json
import os
import subprocess
import sys

requested = os.environ.get("CAMERA_CIDR", "").strip()
existing = set()

try:
    output = subprocess.check_output(
        ["ip", "-4", "-o", "route", "show"],
        stderr=subprocess.DEVNULL,
        text=True,
    )
except Exception:
    output = ""

for line in output.splitlines():
    parts = line.split()
    if not parts:
        continue
    token = parts[0].strip()
    if token == "default":
        continue
    try:
        existing.add(str(ipaddress.ip_network(token, strict=False)))
    except Exception:
        pass

candidates = [
    "192.168.250.0/24",
    "192.168.251.0/24",
    "192.168.252.0/24",
    "192.168.253.0/24",
    "192.168.254.0/24",
    "172.31.250.0/24",
]

if requested:
    candidates = [requested] + [c for c in candidates if c != requested]

chosen = None
for candidate in candidates:
    net = ipaddress.ip_network(candidate, strict=False)
    if any(net.overlaps(ipaddress.ip_network(item, strict=False)) for item in existing):
        continue
    chosen = net
    break

if chosen is None:
    print("unable to choose non-colliding camera subnet", file=sys.stderr)
    sys.exit(1)

data = {
    "camera_cidr": str(chosen),
    "host_ip": str(chosen.network_address + 1),
    "dhcp_range_start": str(chosen.network_address + 50),
    "dhcp_range_end": str(chosen.network_address + 199),
    "prefix": chosen.prefixlen,
}
print(json.dumps(data))
PY
)"

  CAMERA_CIDR="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["camera_cidr"])' <<<"$json")"
  [[ -n "$HOST_IP" ]] || HOST_IP="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["host_ip"])' <<<"$json")"
  [[ -n "$DHCP_RANGE_START" ]] || DHCP_RANGE_START="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["dhcp_range_start"])' <<<"$json")"
  [[ -n "$DHCP_RANGE_END" ]] || DHCP_RANGE_END="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["dhcp_range_end"])' <<<"$json")"
  NETWORK_PREFIX="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["prefix"])' <<<"$json")"
}

ensure_dnsmasq() {
  if command -v dnsmasq >/dev/null 2>&1; then
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    log "installing dnsmasq via dnf"
    run_sudo dnf install -y dnsmasq >/dev/null
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    log "installing dnsmasq via yum"
    run_sudo yum install -y dnsmasq >/dev/null
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    log "installing dnsmasq via apt-get"
    run_sudo apt-get update >/dev/null
    run_sudo apt-get install -y dnsmasq >/dev/null
    return
  fi

  echo "unable to install dnsmasq automatically; install it manually" >&2
  exit 1
}

apply_networkmanager_config() {
  require_cmd nmcli
  local connection_name="constitute-camera-${CAMERA_IFACE}"
  local existing_name
  existing_name="$(
    nmcli -t -f NAME,DEVICE connection show 2>/dev/null | awk -F: -v iface="$CAMERA_IFACE" '$2 == iface { print $1; exit }'
  )"
  if [[ -n "$existing_name" ]]; then
    connection_name="$existing_name"
  else
    run_sudo nmcli connection add \
      type ethernet \
      ifname "$CAMERA_IFACE" \
      con-name "$connection_name" \
      >/dev/null
  fi

  run_sudo nmcli connection modify "$connection_name" \
    connection.interface-name "$CAMERA_IFACE" \
    connection.autoconnect yes \
    ipv4.method manual \
    ipv4.addresses "${HOST_IP}/${NETWORK_PREFIX}" \
    ipv4.never-default yes \
    ipv6.method disabled \
    >/dev/null
  run_sudo ip -4 addr flush dev "$CAMERA_IFACE" >/dev/null 2>&1 || true
  run_sudo nmcli connection up "$connection_name" ifname "$CAMERA_IFACE" >/dev/null
}

write_dnsmasq_config() {
  run_sudo mkdir -p "$(dirname "$DNSMASQ_CONF")"
  cat <<EOF | run_sudo tee "$DNSMASQ_CONF" >/dev/null
port=0
bind-interfaces
interface=${CAMERA_IFACE}
dhcp-authoritative
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},255.255.255.0,12h
EOF
  run_sudo systemctl enable --now dnsmasq >/dev/null
  run_sudo systemctl restart dnsmasq >/dev/null
}

emit_env() {
  cat <<EOF
CAMERA_IFACE=${CAMERA_IFACE}
CAMERA_CIDR=${CAMERA_CIDR}
CAMERA_HOST_IP=${HOST_IP}
CAMERA_DHCP_RANGE_START=${DHCP_RANGE_START}
CAMERA_DHCP_RANGE_END=${DHCP_RANGE_END}
EOF
}

select_camera_iface
derive_network_values

log "camera iface: ${CAMERA_IFACE}"
log "camera subnet: ${CAMERA_CIDR}"
log "camera host ip: ${HOST_IP}"
log "camera dhcp range: ${DHCP_RANGE_START}-${DHCP_RANGE_END}"

if [[ "$APPLY" -eq 1 ]]; then
  ensure_dnsmasq
  apply_networkmanager_config
  write_dnsmasq_config
fi

if [[ "$PRINT_ENV" -eq 1 ]]; then
  emit_env
fi
