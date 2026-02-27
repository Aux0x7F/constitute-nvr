# Constitute NVR

`constitute-nvr` is the video-ingest and retention service for the Constitution ecosystem.

It is a service-layer repo. It depends on converged contracts from:
- `constitute-gateway` (transport + discovery substrate)
- `constitute` (web client control and identity UX)

## Status
- Iteration 0: scaffold
- Contract-first planning in progress
- Not production-ready

## Scope
In scope:
- camera ingest adapters
- encrypted recording and retention policy
- publish discoverable service capability for authorized clients
- provide control/read APIs through ecosystem contracts

Out of scope:
- replacing gateway transport primitives
- redefining identity/discovery contracts
- browser UI implementation

## Naming
- Repo: `constitute-nvr`
- Service capability: `nvr`
- Runtime role: `native` with service capability metadata

## Architecture
See `ARCHITECTURE.md`.

## Docs
- `docs/ROADMAP.md`
- `docs/PROTOCOL.md`

## Local Dev
```bash
cargo run
```

## License
TBD
