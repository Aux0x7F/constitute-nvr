# Constitute NVR

`constitute-nvr` is the native NVR workload for Constitution.

It runs as a Fedora/Linux service, joins swarm as `role=native` with `service=nvr`, ingests camera streams, encrypts retained segments, and serves authorized identity-bound clients over a negotiated symmetric session.

## Current Iteration Scope
- ONVIF WS-Discovery probe path + source lifecycle commands
- RTSP ingest via `ffmpeg` segment recorder with restart/backoff state machine
- encrypted segment store (`.cnv` blobs)
- swarm-native UDP presence announcements with UI module advertisement + service metrics
- identity-gated websocket session with ECDH + symmetric payload channel (`list_source_states`, `upsert_source`, `remove_source`, `setup_reolink`)
- systemd self-update timer flow
- Reolink onboarding for MVP using LAN discovery + HTTP CGI setup/read/apply (RTSP/ONVIF enable, P2P disable) while native `9000` replacement remains under R&D

## Quick Install (Opinionated Wizard)

```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-latest.sh | bash
```

Installer behavior:
- downloads the latest GitHub release artifact and verifies `SHA256SUMS`
- skips reinstall/restart when installed binary hash is unchanged
- installs systemd service and self-update timer by default
- updater keeps config/state out of release paths and rolls back binary on failed restart/health check
- optionally applies camera-interface hardening (RTSP/ONVIF + NTP lane)

When copied from `constitute` Appliances panel, the command includes install-time context:
- identity binding (`--identity-id`, authorized device PKs)
- gateway swarm peer (`--swarm-peer`) + zone keys (`--zone-key`)
- auto-associate enrollment (`--pair-identity`, `--pair-code`, `--pair-code-hash`)

Optional auto-provision flags:
- `--enable-reolink-autoprovision`
- `--reolink-username`, `--reolink-password` / `--reolink-desired-password`
- `--reolink-generate-password`, `--reolink-hint-ip`

## Persistence Contract
- Config path: `/etc/constitute-nvr/config.json`
- Runtime state: `/var/lib/constitute-nvr`
- Retained encrypted media: `storage.root` (operator mount, recommended separate volume)
- Release updates replace executable payload only; identity/session config and retained data are preserved.

## Runtime Overview
- Swarm transport: UDP, client mode (`native` + `nvr` capability)
- Control/serving surface: websocket at `api.bind` (`/session`)
- Health endpoint: `GET /health`
- Config path default: `/etc/constitute-nvr/config.json`
- Reolink runtime default: CGI-first (`setup_reolink`, `read_reolink_state`, `apply_reolink_state`), with `setup_reolink` auto-upserting a recorder source on success
- Optional bridge toggle: set `CONSTITUTE_NVR_USE_SDK_BRIDGE=1` to try Windows SDK bridge fallback for lab work

## Config Highlights
`config.example.json` includes:
- `swarm.bind`, `swarm.peers`, `swarm.zones`
- `api.identity_id`, `api.authorized_device_pks`, `api.public_ws_url`, `api.allow_unsigned_hello_mvp` (MVP mode for web shell launch without shipping identity secret)
- `storage.root`, `storage.encryption_key_hex`
- `update.interval_secs`
- `ui.repo`, `ui.ref`, `ui.manifest_url`, `ui.entry`
- `cameras[]` ONVIF/RTSP source definitions

## Security Model (Current)
- Segment-at-rest encryption uses service storage key.
- Device session channel uses X25519 ECDH + HKDF-derived symmetric key.
- Session admission requires:
  - matching `identity_id`
  - optional device allowlist (`authorized_device_pks`)
  - HMAC proof over hello envelope (`identity_secret_hex`) unless `allow_unsigned_hello_mvp=true`
- Unsigned MVP mode is for local integration bring-up only; disable it for non-lab deployments.
- Camera network hardening is operator-controlled and scriptable.

## Local Dev

```bash
cargo test
cargo run -- --config ./config.json --once
cargo run -- --config ./config.json --discover-onvif
cargo run -- --discover-reolink --discover-reolink-hint-ip 192.168.1.20
cargo run -- --probe-reolink-ip 192.168.1.20
cargo run -- --setup-reolink-ip 192.168.1.20 --setup-reolink-password test1234
cargo run -- --setup-reolink-ip 192.168.1.20 --setup-reolink-password test1234 --setup-reolink-generate-password
sudo cargo run -- --bootstrap-reolink-server-ip 192.168.1.10 --bootstrap-reolink-target-mac EC:71:DB:32:0A:8F --setup-reolink-generate-password
```

## Docs
- `ARCHITECTURE.md`
- `docs/PROTOCOL.md`
- `docs/OPERATIONS.md`
- `docs/ROADMAP.md`
- `docs/CAMERA_COMPAT.md`

## Status
POC-grade for manual lab validation. Not production-ready.

