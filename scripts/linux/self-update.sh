#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Aux0x7F/constitute-nvr.git}"
SOURCE_DIR="${SOURCE_DIR:-/opt/constitute-nvr-src}"
BRANCH="${BRANCH:-main}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/constitute-nvr}"
SERVICE_NAME="${SERVICE_NAME:-constitute-nvr}"
TRY_RESTART=0
FORCE=0

usage() {
  cat <<'EOF'
Usage: self-update.sh [options]

Update constitute-nvr from git source, rebuild, and install binary.

Options:
  --repo-url <url>           Git repo URL (default: Aux0x7F/constitute-nvr)
  --source-dir <path>        Local source clone path
  --branch <name>            Git branch to track (default: main)
  --install-prefix <path>    Install prefix (default: /opt/constitute-nvr)
  --service-name <name>      systemd service to restart (default: constitute-nvr)
  --try-restart              Restart service when binary changed
  --force                    Rebuild/install even if commit unchanged
  -h, --help                 Show help
EOF
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url)
      REPO_URL="${2:?missing value for --repo-url}"
      shift 2
      ;;
    --source-dir)
      SOURCE_DIR="${2:?missing value for --source-dir}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:?missing value for --branch}"
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

if ! command -v git >/dev/null 2>&1; then
  echo "git is required" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required" >&2
  exit 1
fi

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  run_sudo mkdir -p "$(dirname "$SOURCE_DIR")"
  run_sudo git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$SOURCE_DIR"
fi

run_sudo git -C "$SOURCE_DIR" fetch --depth 1 origin "$BRANCH"
local_rev="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
remote_rev="$(git -C "$SOURCE_DIR" rev-parse "origin/$BRANCH")"

if [[ "$FORCE" -ne 1 && "$local_rev" == "$remote_rev" ]]; then
  echo "[self-update] no new commit on $BRANCH ($local_rev)"
  exit 0
fi

run_sudo git -C "$SOURCE_DIR" checkout "$BRANCH"
run_sudo git -C "$SOURCE_DIR" reset --hard "origin/$BRANCH"

echo "[self-update] building $remote_rev"
run_sudo bash -lc "cd '$SOURCE_DIR' && cargo build --release --locked"

BIN_SRC="$SOURCE_DIR/target/release/constitute-nvr"
if [[ ! -f "$BIN_SRC" ]]; then
  echo "build succeeded but binary missing: $BIN_SRC" >&2
  exit 1
fi

run_sudo install -d "$INSTALL_PREFIX/bin"
run_sudo install -m 0755 "$BIN_SRC" "$INSTALL_PREFIX/bin/constitute-nvr"
run_sudo ln -sf "$INSTALL_PREFIX/bin/constitute-nvr" /usr/local/bin/constitute-nvr

echo "[self-update] installed $remote_rev"
if [[ "$TRY_RESTART" -eq 1 ]]; then
  run_sudo systemctl restart "$SERVICE_NAME" || true
fi
