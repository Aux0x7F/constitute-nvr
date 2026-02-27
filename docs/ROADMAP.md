# Roadmap

## Iteration 0: Scaffold
- [x] repo skeleton
- [x] project architecture baseline
- [x] initial project tracking issues

## Iteration 1: Fedora + ONVIF Contract Freeze
- [ ] define capability advertisement fields for `nvr`
- [ ] define control-plane request/response contract draft
- [ ] define ONVIF source model and auth boundary
- [ ] define camera compatibility matrix and validation criteria

## Iteration 2: ONVIF Ingest + Secure Storage Core
- [ ] ONVIF ingest adapter trait and mock adapter
- [ ] ONVIF discovery/profile negotiation baseline
- [ ] encrypted segment/index store abstraction
- [ ] retention policy engine and pruning behavior

## Iteration 3: Fedora Service + Integration
- [ ] Fedora systemd service profile and operator runbook
- [ ] control endpoints with auth checks
- [ ] gateway/web integration tests
- [ ] camera validation pass for initial target models
