# Constitute NVR

`constitute-nvr` is the native NVR workload for Constitution.

It runs as a Fedora/Linux service, joins swarm as `role=native` with `service=nvr`, ingests camera streams, encrypts retained segments, and serves authorized identity-bound clients over a negotiated symmetric session.

## Current Iteration Scope
- ONVIF WS-Discovery probe path + source lifecycle commands
- RTSP ingest via `ffmpeg` segment recorder with restart/backoff state machine
- encrypted segment store (`.cnv` blobs)
- swarm-native UDP presence announcements with UI module advertisement + service metrics
- identity-gated websocket session with ECDH + symmetric payload channel (`list_source_states`, `upsert_source`, `remove_source`)
- systemd self-update timer flow

## Quick Install (Opinionated Wizard)

```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-wizard.sh | bash
```

Wizard behavior:
- builds and installs `constitute-nvr`
- prompts for storage root path (default placeholder)
- installs systemd service and self-update timer
- optionally applies camera-interface hardening (RTSP/ONVIF + NTP lane)

## Runtime Overview
- Swarm transport: UDP, client mode (`native` + `nvr` capability)
- Control/serving surface: websocket at `api.bind` (`/session`)
- Health endpoint: `GET /health`
- Config path default: `/etc/constitute-nvr/config.json`

## Config Highlights
`config.example.json` includes:
- `swarm.bind`, `swarm.peers`, `swarm.zones`
- `api.identity_id`, `api.authorized_device_pks`, `api.public_ws_url`
- `storage.root`, `storage.encryption_key_hex`
- `update.interval_secs`\n- `ui.repo`, `ui.ref`, `ui.manifest_url`, `ui.entry`
- `cameras[]` ONVIF/RTSP source definitions

## Security Model (Current)
- Segment-at-rest encryption uses service storage key.
- Device session channel uses X25519 ECDH + HKDF-derived symmetric key.
- Session admission requires:
  - matching `identity_id`
  - optional device allowlist (`authorized_device_pks`)
  - HMAC proof over hello envelope (`identity_secret_hex`)
- Camera network hardening is operator-controlled and scriptable.

## Local Dev

```bash
cargo test
cargo run -- --config ./config.json --once
cargo run -- --config ./config.json --discover-onvif
```

## Docs
- `ARCHITECTURE.md`
- `docs/PROTOCOL.md`
- `docs/OPERATIONS.md`
- `docs/ROADMAP.md`
- `docs/CAMERA_COMPAT.md`

## Status
POC-grade for manual lab validation. Not production-ready.

