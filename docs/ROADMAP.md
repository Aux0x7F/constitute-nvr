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

## Iteration 3: Web/Gateway Convergence
- [ ] exact identity/device auth parity with `constitute` + `constitute-gateway`
- [ ] browser client integration test for encrypted session channel
- [ ] segment retrieval UX/API convergence in web repo
- [ ] zone routing and discovery resilience test matrix

## Iteration 4: Productionization
- [ ] signed release artifact update path (replace source-build updater default)
- [ ] hardware-backed key options and sealed secret handling
- [ ] vendor-specific P2P disable automation hooks (where camera APIs allow)
- [ ] full operator runbooks for fedora lab + vps deployment profiles

