# Constitute NVR Architecture

## Position In Ecosystem
- `constitute-gateway`: browser control boundary, hosted-service inventory owner, signaling broker
- `constitute-account`: browser identity/session/grant authority and shared runtime owner
- `constitute-gateway-ui`: gateway host and hosted-service management surface
- `constitute-nvr-ui`: Pages-hosted NVR app surface
- `constitute-nvr`: native service workload for camera ingest, retention, and managed live preview

`constitute-nvr` does not replace gateway transport. It is a hosted service-backed device and should be reached through gateway service-access authorization in the canonical path.

Future `constitute-physec` may consume NVR camera/media/history projections as a Physical Security app. NVR remains the camera/media workload and does not own armed modes, incident response, sensor fusion, or physical-security product workflows.

## Runtime Layers

### 1. Service Identity Layer
- publishes as a service-backed device
- `deviceKind = service`
- `service = nvr`
- `hostGatewayPk` identifies the owning/hosting gateway
- signed discovery and freshness records

### 2. Ingest Layer
- ONVIF WS-Discovery probe support
- camera source registry from config plus control-plane mutations
- RTSP ingest execution via `ffmpeg` with explicit runtime state machine and restart/backoff
- substream preference where camera capabilities allow

### 3. Secure Storage Layer
- segment files written under `storage.root/segments/<source_id>/`
- background encryption pass converts `.mp4` to encrypted `.cnv`
- plaintext segment files removed after encryption

### 4. Live Preview Layer
- managed live preview uses WebRTC
- gateway-issued CAAC service capability is required in the canonical path
- H.264 preview tracks are exposed for browser consumption
- live preview and recorded retrieval remain separate paths

### 4a. Media Projection Layer
Media projection is now a first-class runtime boundary and is exposed through `/health.mediaProjection`.

Media projection owns or is actively converging toward:
- warm camera ingest where host policy allows
- browser-safe preview projection
- stream normalization and projection fanout
- projection health/backoff/resource policy
- encryption/key-policy hooks for live and future storage consumers

It consumes `camera_device` stream truth and `media` plans.
It feeds `live`, `recording`, and future encrypted storage output.
It should emit structured event truth for future `constitute-logging`.
It should expose posture facts cleanly enough for future `constitute-cybersec`.
It must not become camera driver truth, gateway signaling, cybersecurity policy, Physical Security product workflow, or storage implementation.

### 5. Recorded Session/API Layer
- health endpoint: `GET /health`
- command/session surface for discovery, source lifecycle, and archive retrieval
- recorded segment listing and retrieval remain supported
- direct/manual debug mode may use the encrypted websocket session

### 6. Update/Operations Layer
- systemd service runtime (`constitute-nvr.service`)
- systemd timer-driven self-update (`constitute-nvr-update.timer`)
- update helper script rebuilds from tracked branch and restarts service

## Network and Trust Boundaries
- camera network is expected to be isolated
- camera network should be treated as hostile ingress by default
- optional hardening script restricts camera-interface exposure
- future `constitute-cybersec` should own hostile-ingress policy, flow classification, quarantine/block decisions, and related notifications
- transport metadata remains observable
- gateway is the canonical browser auth/signaling boundary
- app surfaces should not be asked to carry long-lived identity secrets in the normal path
- WebRTC live media is encrypted in transit through DTLS-SRTP
- camera-to-NVR RTSP ingest must not be assumed encrypted

## Managed Access Model
Canonical flow:
1. a first-party app surface selects an owned gateway and target NVR service
2. gateway validates device membership and capability
3. gateway issues short-lived service access/session authorization
4. app surface redeems that context and negotiates signaling
5. NVR decrypts and validates the gateway-issued CAAC service capability before admitting WebRTC live preview

Direct/manual debug mode remains available but is not the canonical managed path.

Current service access authorization uses `constitute-protocol` CAAC service capabilities. NVR decrypts and validates the gateway-issued capability before offer/control/admin/close handling. Sensitive capability claims are encrypted to the gateway and service; the browser carries `serviceCapability` opaquely. Relay-facing browser/gateway service-access and service-signal metadata is sealed through CAAC before account surfaces receive local decrypted projections.

## Current Constraints
- ingest path depends on host `ffmpeg`
- encrypted storage is service-key based (no HSM integration yet)
- live preview WebRTC path is the active implementation slice
- guaranteed hard-NAT fallback awaits operator TURN or later relay/TURN completion

## Near-Term Completion Targets
1. close and main the current `camera_device + media + live + recording + storage` refactor
2. keep managed live preview recovery and camera drift reconcile verified
3. preserve recorded segment retrieval while live preview continues to evolve
4. measure cold/warm service access penalties from runtime attach through first browser track
5. keep warm media projection workers healthy across camera down/up recovery and prove first-track timing against the warmed path
6. keep NVR projections clean for future Physical Security consumption without moving Physical Security ownership into NVR
