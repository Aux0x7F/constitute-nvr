# Protocol Notes (Iteration-1 Draft)

## Purpose
Define the active contract surface for `constitute-nvr` POC integration.

## Service Identity
- runtime role: `native`
- service capability: `nvr`
- swarm records include:
  - `role`
  - `service`
  - `serviceVersion`

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
- device discovery (`kind=30078`, `t=swarm_discovery`, `type=device`, `role=native`, `service=nvr`)
- zone presence (`kind=1`, `t=constitute`, `z=<zone>`)

## ONVIF Discovery
- WS-Discovery probe to `239.255.255.250:3702`
- ONVIF endpoint extraction from `XAddrs`
- command surface supports discovery trigger from authenticated session

## Session Negotiation (`/session`)

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
- `discover_onvif`
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
- `constitute` swarm client handling
