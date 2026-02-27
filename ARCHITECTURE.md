# Constitute NVR Architecture

## Position In Ecosystem
- `constitute-gateway`: mesh backbone and gateway relay substrate
- `constitute` (web): identity UX and browser app layer
- `constitute-nvr`: native service workload for camera ingest + retention + serving

`constitute-nvr` does not replace gateway transport. It joins swarm as a native client service.

## Runtime Layers
1. Swarm Client Layer
- UDP swarm participation (`role=native`, `service=nvr`)
- signed device + zone presence records
- zone-scoped peer announcements, no public Nostr relay requirement for bootstrap in this mode

2. Ingest Layer
- ONVIF WS-Discovery probe support
- camera source registry from config
- RTSP ingest execution via `ffmpeg` segment loop per source

3. Secure Storage Layer
- segment files written under `storage.root/segments/<source_id>/`
- background encryption pass converts `.mp4` to encrypted `.cnv`
- plaintext segment files removed after encryption

4. Session/API Layer
- health endpoint: `GET /health`
- websocket session endpoint: `GET /session`
- identity-bound session negotiation:
  - client hello + HMAC proof
  - X25519 server/client key agreement
  - HKDF-derived symmetric session key
- encrypted command channel for source listing, discovery, segment listing, segment retrieval

5. Update/Operations Layer
- systemd service runtime (`constitute-nvr.service`)
- systemd timer-driven self-update (`constitute-nvr-update.timer`)
- update helper script rebuilds from tracked branch and restarts service

## Network and Trust Boundaries
- camera network is expected to be isolated (camera jail)
- optional hardening script enforces:
  - drop-by-default camera interface inbound
  - host egress restricted to ONVIF/RTSP (+ optional discovery/NTP)
- transport metadata is observable; identity/content confidentiality remains app/session layer responsibility

## Current Constraints
- ingest path depends on host `ffmpeg`
- encrypted storage is service-key based (no HSM integration yet)
- session serving currently segment-oriented (not full live stream relay)
- gateway/web integration surface needs iterative parity checks as contracts evolve

## Near-Term Completion Targets
1. stabilize ONVIF source lifecycle and reconnect behavior
2. finalize identity-device authorization semantics with web contract
3. add integration tests with gateway/web swarm records
4. promote update flow from source-build to signed release artifacts
