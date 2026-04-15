# Protocol Notes (Active Draft)

## Purpose
Define the active contract surface for `constitute-nvr` managed integration.

## Service Identity
- runtime role: `native`
- service capability: `nvr`
- service-backed device fields:
  - `deviceKind = service`
  - `service = nvr`
  - `hostGatewayPk`
  - `serviceVersion`
  - `ingestProtocols` (`onvif`, `rtsp`)
  - `capabilities` (`nvr.view`, `nvr.manage`)
  - live service metrics (`uptimeSec`, peer counts, camera counts)

## Swarm Transport (Native)
- channel: UDP
- protocol version: `v=1`
- message kinds:
  - `hello`
  - `ack`
  - `record`

### `hello`
```json
{
  "kind": "hello",
  "v": 1,
  "node_id": "nvr-...",
  "device_pk": "<nostr pubkey>",
  "zones": ["<zone-key>"],
  "ts": 1700000000000
}
```

### `record`
Carries signed Nostr event payloads for:
- device discovery (`kind=30078`, `t=swarm_discovery`, `type=device`, `role=native`, `deviceKind=service`, `service=nvr`)
- zone presence (`kind=1`, `t=constitute`, `z=<zone>`)
- optional install enrollment signal (`record_type=signal`, payload `type=pair_request`) when `pair_identity_label` + `pair_code_hash` are configured

## ONVIF Discovery + Source Lifecycle
- WS-Discovery probe to `239.255.255.250:3702`
- ONVIF endpoint extraction from `XAddrs`
- source lifecycle command surface:
  - `upsert_source`
  - `remove_source`
  - `list_source_states`
  - `setup_reolink` (successful setup also auto-upserts/starts a source)
- recorder state machine:
  - `starting` -> `running` -> `backoff` -> retry
  - terminal `failed` on non-recoverable runtime failures (for example, `ffmpeg` missing)

## Reolink Bootstrap (Current)
- temporary DHCP lease responder on UDP/67 for first-boot cameras that only request DHCP
- proprietary LAN discovery probe: UDP broadcast `aaaa0000` to port `2000`, replies observed from camera `2000 -> client 3000`
- readiness probe checks:
  - proprietary control port `9000`
  - RTSP port `554`
  - ONVIF service port `8000`
- standards-ready means:
  - `554/tcp` open
  - `8000/tcp` open
  - ONVIF XAddr resolves to `http://<ip>:8000/onvif/device_service`

## Managed Live Preview Negotiation
Canonical managed path:
1. browser shell obtains gateway-issued launch authorization for the target NVR service
2. Pages-hosted app surface redeems launch context
3. gateway brokers signaling between browser and NVR
4. NVR validates launch token and admits WebRTC session

Launch token requirements:
- signed by gateway
- short-lived
- bound to:
  - `gatewayPk`
  - `servicePk`
  - `identityId`
  - requesting `devicePk`
  - requested capability

Signaling message types:
- `offer`
- `answer`
- `ice_candidate`
- `ice_complete`
- `session_close`

Media direction:
- WebRTC
- H.264 preview
- camera substream / low-resolution path preferred for grid viewing where available

## Direct Debug Session Negotiation (`/session`)

### 1) Client hello (plaintext frame)
```json
{
  "type": "hello",
  "identityId": "<identity>",
  "devicePk": "<client-device-pk>",
  "clientKey": "<base64 x25519 pubkey>",
  "ts": 1700000000,
  "proof": "<hex hmac-sha256>"
}
```

Proof input material:
- `identityId|devicePk|clientKey|ts`
- key: `api.identity_secret_hex`

Admission checks:
- identity match (`api.identity_id`)
- optional allowlist match (`api.authorized_device_pks`)
- timestamp skew <= 300s
- valid HMAC proof

### 2) Server ack (plaintext frame)
```json
{
  "type": "hello_ack",
  "sessionId": "<uuid>",
  "serverKey": "<base64 x25519 pubkey>",
  "ts": 1700000000000
}
```

### 3) Encrypted command envelope
```json
{
  "type": "cipher",
  "nonce": "<base64 24-byte nonce>",
  "data": "<base64 xchacha20poly1305 ciphertext>"
}
```

Session key derivation:
- X25519 shared secret (server static secret + client key)
- HKDF-SHA256 with `identity_secret_hex` as salt
- context: `constitute-nvr:<identity>:<sessionId>`

## Encrypted Commands
- `list_sources`
- `list_source_states`
- `discover_onvif`
- `discover_reolink`
- `probe_reolink` (`ip`)
- `read_reolink_state` (`request`)
- `apply_reolink_state` (`request`)
- `setup_reolink` (`request`)
- `bootstrap_reolink` (`request`)
- `upsert_source` (source definition)
- `remove_source` (`sourceId`)
- `list_segments` (`sourceId`, `limit`)
- `get_segment` (`sourceId`, `name`)

## Storage Contract
- segment root: `storage.root/segments/<source_id>/`
- plaintext extension: `.mp4`
- encrypted extension: `.cnv`
- encrypted blob format: `CNRV1 || nonce(24) || ciphertext`

## Compatibility Guardrail
Any breaking changes to session/swarm payloads must be version-gated and coordinated with:
- `constitute-gateway/docs/PROTOCOL.md`
- `constitute` shell launch/signaling handling
- `constitute-nvr-ui` managed launch/bootstrap handling
