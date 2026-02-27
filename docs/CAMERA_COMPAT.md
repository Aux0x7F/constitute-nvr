# Camera Compatibility Matrix

Status legend:
- `Planned`: model is in scope but not validated
- `In Test`: active validation in progress
- `Validated`: baseline ingest works for iteration criteria
- `Blocked`: model-specific blocker tracked in issue

## Iteration-1 Target Models (ONVIF)

| Vendor | Model | Protocol | Status | Notes |
|---|---|---|---|---|
| Anypiz | IPC-B8743-S (4MP PoE U series) | ONVIF | Planned | First-pass target for fixed PoE stream ingest |
| Reolink | E1 Outdoor SE PoE Pan Cam | ONVIF | Planned | First-pass target for PTZ-capable stream ingest |

## Validation Criteria (Baseline)
- ONVIF discovery/connection succeeds with configured credentials.
- Primary stream is ingestible for sustained test interval.
- Basic metadata (codec/resolution/framerate) is captured.
- Stream reconnect behavior is deterministic after interruption.
- No plaintext credentials are persisted.

## Tracking
Camera-specific defects should be filed as separate issues and linked to the iteration umbrella.
