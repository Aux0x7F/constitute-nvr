# Roadmap

## Iteration 0: Scaffold
- [x] repo skeleton
- [x] project architecture baseline
- [x] initial project tracking issues

## Iteration 1: Contract + Service POC
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
- [ ] service-backed device metadata parity with gateway/web
- [ ] gateway-issued launch/session authorization
- [ ] WebRTC signaling and session admission
- [ ] H.264 live preview path for camera grid
- [ ] recorded retrieval preserved alongside live preview
- [ ] same-LAN and NAT-friendly path validation

## Iteration 4: Productionization
- [ ] signed/provenance verification for release artifacts (beyond SHA256 file checks)
- [x] GitHub release artifact update path with SHA256 verification (source-build path no longer default)
- [ ] hardware-backed key options and sealed secret handling
- [ ] vendor-specific P2P disable automation hooks (where camera APIs allow)
- [ ] Reolink `9000` control-plane reversal for zero-manual RTSP/ONVIF/P2P toggles
- [ ] full operator runbooks for fedora lab + vps deployment profiles
