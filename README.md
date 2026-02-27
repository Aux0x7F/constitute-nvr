# Constitute NVR

`constitute-nvr` is the video-ingest and retention service for the Constitution ecosystem.

It is a service-layer repo. It depends on converged contracts from:
- `constitute-gateway` (transport + discovery substrate)
- `constitute` (web client control and identity UX)

## Status
- Iteration 0: scaffold complete
- Iteration 1 direction: Fedora-hosted service + ONVIF-first ingest
- Not production-ready

## Scope
In scope:
- ONVIF camera ingest adapters (first protocol target)
- encrypted recording and retention policy
- publish discoverable service capability for authorized clients
- provide control/read APIs through ecosystem contracts
- Fedora systemd service baseline for operator deployment

Out of scope:
- replacing gateway transport primitives
- redefining identity/discovery contracts
- browser UI implementation
- non-Fedora packaging in iteration-1

## Target Platform
- Primary host target: Fedora (systemd service)
- First supported ingest path: ONVIF cameras

Initial camera validation targets:
- Anypiz IPC-B8743-S (4MP PoE U series)
- Reolink E1 Outdoor SE PoE Pan Cam

See `docs/CAMERA_COMPAT.md` for compatibility tracking.

## Naming
- Repo: `constitute-nvr`
- Service capability: `nvr`
- Runtime role: `native` with service capability metadata

## Architecture
See `ARCHITECTURE.md`.

## Docs
- `docs/ROADMAP.md`
- `docs/PROTOCOL.md`
- `docs/CAMERA_COMPAT.md`

## Local Dev
```bash
cargo run
```

## License
TBD
