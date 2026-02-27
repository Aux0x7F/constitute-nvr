#!/usr/bin/env bash
set -euo pipefail

APPLY=0
IFACE=""
CAMERA_CIDR=""
ONVIF_PORTS="80,443,8000,8080,8899"
RTSP_PORTS="554"
ALLOW_NTP_HOST=1
ALLOW_ONVIF_DISCOVERY=1
NO_EGRESS_LOCK=0
ZONE_NAME="constitute-camera"
NFT_TABLE="constitute_nvr_cam"

usage() {
  cat <<'EOF'
Usage: harden-camera-interface.sh [options]

Audit/apply camera-network hardening for constitute-nvr.

Goals:
- bind the camera NIC to a drop-by-default firewalld zone
- allow only explicit camera->host ingress (optional NTP)
- lock host egress over that NIC to ONVIF/RTSP (+ optional WS-Discovery + NTP)

Options:
  --apply                     Apply changes (default is audit-only)
  --iface <name>              Camera network interface (required with --apply)
  --camera-cidr <CIDR>        Camera subnet CIDR (required with --apply)
  --onvif-ports <csv>         ONVIF TCP port list (default: 80,443,8000,8080,8899)
  --rtsp-ports <csv>          RTSP TCP port list (default: 554)
  --no-ntp-host               Do not allow camera->host UDP/123
  --no-onvif-discovery        Do not allow host->camera UDP/3702
  --no-egress-lock            Skip nftables egress restriction stage
  -h, --help                  Show help

Examples:
  ./scripts/linux/harden-camera-interface.sh
  sudo ./scripts/linux/harden-camera-interface.sh --apply --iface enp2s0 --camera-cidr 10.60.0.0/24
EOF
}

log() {
  echo "[harden-camera] $*"
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
    log "missing dependency: $cmd"
    return 1
  fi
}

normalize_csv_ports() {
  local csv="$1"
  local -a raw
  local -a clean=()
  IFS=',' read -r -a raw <<<"$csv"

  if [[ "${#raw[@]}" -eq 0 ]]; then
    return 1
  fi

  for p in "${raw[@]}"; do
    p="${p//[[:space:]]/}"
    [[ -z "$p" ]] && continue
    if ! [[ "$p" =~ ^[0-9]+$ ]]; then
      return 1
    fi
    if (( p < 1 || p > 65535 )); then
      return 1
    fi
    clean+=("$p")
  done

  if [[ "${#clean[@]}" -eq 0 ]]; then
    return 1
  fi

  printf '%s\n' "${clean[@]}" | sort -n -u | paste -sd, -
}

merge_csv_ports() {
  local a="$1"
  local b="$2"
  {
    echo "$a"
    echo "$b"
  } | tr "," "\n" | sed '/^$/d' | sort -n -u | paste -sd, -
}


while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      shift
      ;;
    --iface)
      IFACE="${2:?missing value for --iface}"
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
    --no-onvif-discovery)
      ALLOW_ONVIF_DISCOVERY=0
      shift
      ;;
    --no-egress-lock)
      NO_EGRESS_LOCK=1
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

if ! ONVIF_PORTS="$(normalize_csv_ports "$ONVIF_PORTS")"; then
  echo "Invalid ONVIF ports list" >&2
  exit 1
fi
if ! RTSP_PORTS="$(normalize_csv_ports "$RTSP_PORTS")"; then
  echo "Invalid RTSP ports list" >&2
  exit 1
fi
ALLOWED_TCP_PORTS="$(merge_csv_ports "$ONVIF_PORTS" "$RTSP_PORTS")"

if [[ "$APPLY" -eq 1 ]]; then
  if [[ -z "$IFACE" || -z "$CAMERA_CIDR" ]]; then
    echo "--iface and --camera-cidr are required with --apply" >&2
    exit 1
  fi
  if ! [[ "$CAMERA_CIDR" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
    echo "--camera-cidr must be IPv4 CIDR format (example: 10.60.0.0/24)" >&2
    exit 1
  fi
fi

log "mode: $([[ "$APPLY" -eq 1 ]] && echo apply || echo audit)"
log "iface: ${IFACE:-<unset>}"
log "camera-cidr: ${CAMERA_CIDR:-<unset>}"
log "allowed tcp ports (ONVIF+RTSP): $ALLOWED_TCP_PORTS"
log "camera->host ntp: $([[ "$ALLOW_NTP_HOST" -eq 1 ]] && echo enabled || echo disabled)"
log "host->camera ws-discovery (udp/3702): $([[ "$ALLOW_ONVIF_DISCOVERY" -eq 1 ]] && echo enabled || echo disabled)"
log "egress lock: $([[ "$NO_EGRESS_LOCK" -eq 0 ]] && echo enabled || echo disabled)"

if [[ "$APPLY" -eq 0 ]]; then
  if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
      log "firewalld active"
      firewall-cmd --get-active-zones || true
    else
      log "firewalld installed but inactive"
    fi
  else
    log "firewalld not installed"
  fi

  if command -v nft >/dev/null 2>&1; then
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
      log "nft table $NFT_TABLE present"
      nft list table inet "$NFT_TABLE" || true
    else
      log "nft table $NFT_TABLE not present"
    fi
  else
    log "nft not installed"
  fi

  exit 0
fi

require_cmd firewall-cmd >/dev/null
require_cmd nft >/dev/null

if ! systemctl is-active --quiet firewalld; then
  echo "firewalld must be active for --apply" >&2
  exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "Interface $IFACE not found" >&2
  exit 1
fi

if ! run_sudo firewall-cmd --permanent --get-zones | tr ' ' '\n' | grep -qx "$ZONE_NAME"; then
  log "creating firewalld zone: $ZONE_NAME"
  run_sudo firewall-cmd --permanent --new-zone="$ZONE_NAME" >/dev/null
fi

log "setting zone target DROP: $ZONE_NAME"
run_sudo firewall-cmd --permanent --zone="$ZONE_NAME" --set-target=DROP >/dev/null

if ! run_sudo firewall-cmd --permanent --zone="$ZONE_NAME" --query-interface="$IFACE" >/dev/null 2>&1; then
  log "binding interface $IFACE to zone $ZONE_NAME"
  run_sudo firewall-cmd --permanent --zone="$ZONE_NAME" --add-interface="$IFACE" >/dev/null
fi

ntp_rule="rule family=\"ipv4\" source address=\"${CAMERA_CIDR}\" port protocol=\"udp\" port=\"123\" accept"
run_sudo firewall-cmd --permanent --zone="$ZONE_NAME" --remove-rich-rule="$ntp_rule" >/dev/null 2>&1 || true
if [[ "$ALLOW_NTP_HOST" -eq 1 ]]; then
  log "allowing camera->host NTP (udp/123) from $CAMERA_CIDR"
  run_sudo firewall-cmd --permanent --zone="$ZONE_NAME" --add-rich-rule="$ntp_rule" >/dev/null
fi

log "reloading firewalld"
run_sudo firewall-cmd --reload >/dev/null

log "configuring nft egress restrictions"
run_sudo nft "add table inet ${NFT_TABLE}" >/dev/null 2>&1 || true
run_sudo nft "delete chain inet ${NFT_TABLE} output" >/dev/null 2>&1 || true
run_sudo nft "add chain inet ${NFT_TABLE} output { type filter hook output priority 0; policy accept; }"

run_sudo nft "add rule inet ${NFT_TABLE} output oifname \"${IFACE}\" ip daddr ${CAMERA_CIDR} tcp dport { ${ALLOWED_TCP_PORTS//,/ , } } accept"
if [[ "$ALLOW_ONVIF_DISCOVERY" -eq 1 ]]; then
  run_sudo nft "add rule inet ${NFT_TABLE} output oifname \"${IFACE}\" ip daddr ${CAMERA_CIDR} udp dport 3702 accept"
fi
if [[ "$ALLOW_NTP_HOST" -eq 1 ]]; then
  run_sudo nft "add rule inet ${NFT_TABLE} output oifname \"${IFACE}\" ip daddr ${CAMERA_CIDR} udp dport 123 accept"
fi
if [[ "$NO_EGRESS_LOCK" -eq 0 ]]; then
  run_sudo nft "add rule inet ${NFT_TABLE} output oifname \"${IFACE}\" ip daddr ${CAMERA_CIDR} drop"
fi

log "applied"
run_sudo firewall-cmd --zone="$ZONE_NAME" --list-all || true
run_sudo nft list table inet "$NFT_TABLE" || true

