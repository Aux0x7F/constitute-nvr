#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BIN_PATH="${BIN_PATH:-$REPO_ROOT/target/release/constitute-nvr}"
ARTIFACT_NAME="${ARTIFACT_NAME:-constitute-nvr-linux-amd64.tar.gz}"
STAGE_DIR="${STAGE_DIR:-$REPO_ROOT/dist/linux}"

artifact_path="$ARTIFACT_NAME"
if [[ "$artifact_path" != /* ]]; then
  artifact_path="$REPO_ROOT/$artifact_path"
fi

if [[ ! -f "$BIN_PATH" ]]; then
  if [[ -f "${BIN_PATH}.exe" ]]; then
    echo "Found Windows release binary at ${BIN_PATH}.exe; Linux artifact packaging must run on Linux/WSL." >&2
    echo "Build first on Linux/WSL: cargo build --release" >&2
    exit 1
  fi
  echo "Binary not found: $BIN_PATH" >&2
  echo "Build first: cargo build --release" >&2
  exit 1
fi

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

install -m 0755 "$BIN_PATH" "$STAGE_DIR/constitute-nvr"
install -m 0644 "$REPO_ROOT/config.example.json" "$STAGE_DIR/config.example.json"
install -m 0644 "$REPO_ROOT/README.md" "$STAGE_DIR/README.md"
cp -R "$REPO_ROOT/scripts" "$STAGE_DIR/scripts"
find "$STAGE_DIR/scripts" -type f -name "*.sh" -exec chmod 0755 {} \;

rm -f "$artifact_path"
tar -C "$STAGE_DIR" -czf "$artifact_path" .

echo "Packaged: $artifact_path"