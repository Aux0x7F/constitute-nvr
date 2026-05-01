# Roadmap

## Iteration 0: Scaffold
- [x] repo skeleton
- [x] project architecture baseline
- [x] initial project tracking issues

## Iteration 1: Contract + Native Service Baseline
- [x] capability + control contract draft (`docs/PROTOCOL.md`)
- [x] Fedora systemd service baseline wizard
- [x] camera-interface hardening script (RTSP/ONVIF + optional NTP lane)
- [x] swarm-native client bootstrap path (`role=native`, `service=nvr`)
- [x] identity-bound symmetric websocket session negotiation
- [x] encrypted segment-at-rest storage pass

## Iteration 2: Ingest Reliability
- [x] ONVIF source lifecycle (register/update/remove) with explicit state machine
- [x] reconnect/backoff policy with bounded retries and observability
- [ ] ingest validation on target camera matrix
- [x] service metrics publication in swarm records
- [x] Reolink DHCP bootstrap + proprietary discovery + standards-readiness probe

## Iteration 3: Managed Launch + Live Preview
- [x] service-backed device metadata parity with gateway/web
- [x] gateway-issued launch/session authorization
- [x] WebRTC signaling and session admission
- [x] H.264 live preview path for camera grid
- [ ] recorded retrieval preserved alongside live preview (`docs/issues/nvr-history-incomplete.md`)
- [ ] same-LAN and NAT-friendly path validation

## Iteration 4: Productionization
- [ ] signed/provenance verification for release artifacts (beyond SHA256 file checks)
- [x] GitHub release artifact update path with SHA256 verification (source-build path no longer default)
- [x] dedicated camera-network bootstrap with collision-aware `/24` selection + DHCP on the camera NIC
- [x] health/output redaction for camera credentials and credential-bearing RTSP URLs
- [ ] complete decentralized gateway-capable TURN fallback after the shared-worker/browser runtime refactor
- [ ] hardware-backed key options and sealed secret handling
- [ ] vendor-specific P2P disable automation hooks (where camera APIs allow)
- [ ] Reolink `9000` control-plane reversal for zero-manual RTSP/ONVIF/P2P toggles
- [ ] full operator runbooks for fedora lab + vps deployment profiles

## Current / Planned Later Architecture Direction

The product-surface split is current local convergence work. Host capability adoption remains planned later.

The next NVR/Physical Security architecture slice after current convergence is cryptographic media projection:
- keep a warm low-resolution/browser-safe preview projection where host policy allows
- let live preview attach to an existing projection instead of always waking a cold RTSP/ffmpeg path
- let recording/history consume the same projection boundary instead of duplicating ingest assumptions
- keep `camera_device` as device truth and `media` as planning/ffmpeg strategy
- audit launch/signaling/session material for signed-versus-encrypted boundaries
- treat camera-to-NVR ingest as hostile camera-network traffic unless proven otherwise

## Backlog Product Surface Follow-Ups
- [ ] assign mounted camera devices to operator-facing locations and use the location name instead of the generic `Cameras` heading where appropriate (`#21`)
- [ ] group live preview into location sections when multiple assigned locations are present (`#21`)

### Iteration 5: Host Capability Adoption
- [ ] introduce media projection as a first-class NVR runtime boundary before burying stream warmth in live or recording
- [ ] measure cold/warm direct-entry path from account/runtime attach through first browser track
- [ ] define cryptographic service capability shape beyond transitional short-lived launch token semantics
- [ ] emit structured event truth for `constitute-logging` before Cybersecurity or Physical Security consume NVR timelines
- [ ] consume `constitute-cybersec` capability leases for hostile camera-network policy and anomaly/reporting integration instead of treating camera-interface hardening as only local script posture
- [ ] consume `constitute-storage` capability leases for durable encrypted object/archive semantics where shared storage behavior matters
- [ ] expose NVR projections cleanly enough that future `constitute-physec` can consume cameras/history without owning camera drivers or media projection internals
- [ ] keep service-local config/control state and ephemeral working/runtime state local even after storage capability adoption

### Iteration 6: Platform Product-Surface Convergence
- [ ] keep NVR launch/auth assumptions aligned with direct app entry through account/session/grant flows
- [ ] keep hosted-service UX aligned with the current split between `constitute-account` and `constitute-gateway-ui`
