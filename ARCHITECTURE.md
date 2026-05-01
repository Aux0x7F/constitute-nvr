# Constitute NVR Architecture

## Position In Ecosystem
- `constitute-gateway`: browser control boundary, hosted-service inventory owner, signaling broker
- `constitute-account`: browser identity/session/grant authority and shared runtime owner
- `constitute-gateway-ui`: gateway host and hosted-service management surface
- `constitute-nvr-ui`: Pages-hosted NVR app surface
- `constitute-nvr`: native service workload for camera ingest, retention, and managed live preview

`constitute-nvr` does not replace gateway transport. It is a hosted service-backed device and should be reached through gateway-managed launch/auth in the canonical path.

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
- gateway-issued short-lived authorization is required in the canonical path
- H.264 preview tracks are exposed for browser consumption
- live preview and recorded retrieval remain separate paths

### 4a. Planned Media Projection Layer
The next architecture slice introduces media projection as a first-class runtime boundary.

Media projection will own:
- warm camera ingest where host policy allows
- browser-safe preview projection
- stream normalization and projection fanout
- projection health/backoff/resource policy
- encryption/key-policy hooks for live and future storage consumers

It will consume `camera_device` stream truth and `media` plans.
It will feed `live`, `recording`, and future encrypted storage output.
It must not become camera driver truth, gateway signaling, or storage implementation.

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
- transport metadata remains observable
- gateway is the canonical browser auth/signaling boundary
- app surfaces should not be asked to carry long-lived identity secrets in the normal path
- WebRTC live media is encrypted in transit through DTLS-SRTP
- camera-to-NVR RTSP ingest must not be assumed encrypted

## Managed Access Model
Canonical flow:
1. a first-party app surface selects an owned gateway and target NVR service
2. gateway validates device membership and capability
3. gateway issues short-lived launch/session authorization
4. app surface redeems that context and negotiates signaling
5. NVR validates the gateway-issued authorization before admitting WebRTC live preview

Direct/manual debug mode remains available but is not the canonical managed path.

Current launch authorization is a transitional bearer-style capability.
The target model is explicit cryptographic service capability state bound to identity, device, gateway, service, scope, expiry, and replay protection, with sensitive session material encrypted to intended principals/devices.

## Current Constraints
- ingest path depends on host `ffmpeg`
- encrypted storage is service-key based (no HSM integration yet)
- live preview WebRTC path is the active implementation slice
- guaranteed hard-NAT fallback awaits operator TURN or later relay/TURN completion

## Near-Term Completion Targets
1. close and main the current `camera_device + media + live + recording + storage` refactor
2. keep managed live preview recovery and camera drift reconcile verified
3. preserve recorded segment retrieval while live preview continues to evolve
4. measure cold/warm launch penalties from runtime attach through first browser track
5. introduce media projection planning for warm preview streams and future recording/storage consumers
