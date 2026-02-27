# Constitute NVR Architecture

This repository defines the NVR service layer for Constitution.

## Position In Ecosystem
- `constitute-gateway`: network/discovery backbone
- `constitute`: browser client and identity UX
- `constitute-nvr`: service workload for video ingest/retention/control

## Design Rule
`constitute-nvr` consumes shared contracts; it does not create parallel identity or transport stacks.

## Layer Responsibilities
1. Ingest
- accept camera/media feeds from local adapters
- normalize stream metadata

2. Secure Storage
- encrypt retained media and index metadata
- enforce retention and deletion policy

3. Capability Publication
- advertise service capability (`nvr`) in discovery-friendly records
- publish only required metadata

4. Service Control Surface
- authenticated control endpoints for:
  - source registration
  - retention policy
  - health/status
  - stream/clip listing and retrieval authorization

## Security Baseline
- no plaintext secrets in repo
- key material managed by trusted host keystore path
- minimize metadata leakage in service advertisements
- assume hostile network observation; confidentiality is an application-layer responsibility

## Convergence Constraints
Before feature-complete NVR behavior:
- gateway/web contract parity should be stable enough for client integration
- role/capability publication contracts should be frozen for iteration

## Near-Term Build Order
1. Contract skeleton and capability schema
2. Ingest adapter trait + test harness
3. Encrypted storage abstraction + retention policy engine
4. Control-plane endpoints and authorization model
5. Integration tests with gateway/web surfaces
