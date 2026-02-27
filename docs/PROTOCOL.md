# Protocol Notes (Draft)

This file defines iteration-1 NVR contract intent.

## Direction
- Host baseline: Fedora systemd service
- Ingest baseline: ONVIF-first

## Capability Advertisement (Draft)
Planned capability record fields:
- `service`: `nvr`
- `version`
- `controlEndpoint` (if exposed)
- `ingestProtocols`: `['onvif']`
- `zones`
- `healthSummary` (optional)

## Source Registration Contract (Draft)
Planned required fields:
- `sourceId`
- `protocol` (`onvif`)
- `endpoint` (host/IP/port)
- `authRef` (reference handle, not raw secret)
- `zoneScope`
- `retentionPolicyId`

## Retention Policy Contract (Draft)
Planned required fields:
- `policyId`
- `maxAge`
- `maxStorage`
- `pruneMode`

## Control Plane (Draft)
Planned operations:
- `source.add`
- `source.update`
- `source.remove`
- `retention.set`
- `status.get`
- `recording.list`

## Auth Envelope
- signed request metadata expected
- no plaintext long-term secrets in control payloads
- service-side authorization must be explicit and test-backed

## Guardrail
Protocol additions here must remain compatible with Constitution shared contracts and should be reviewed against:
- `constitute-gateway/docs/PROTOCOL.md`
- `constitute` swarm and identity event handling
