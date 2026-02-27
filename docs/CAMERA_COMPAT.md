# Camera Compatibility Matrix (Iteration-1)

## Validation Target Models

### Anypiz IPC-B8743-S (4MP PoE U series)
- ONVIF discovery: pending lab validation
- ONVIF service endpoint auth: pending
- RTSP ingest: pending
- Recommended status: test candidate

### Reolink E1 Outdoor SE PoE Pan Cam
- ONVIF port surfaced in probe observations: yes
- Reolink cloud/P2P endpoint behavior observed: yes (expected vendor default)
- RTSP ingest path: pending lab validation in this repo
- Recommended status: test candidate with camera-jail policy enabled

## Validation Gates
A model is considered **supported for iteration-1** when all pass:
1. ONVIF WS-Discovery returns stable endpoint(s)
2. ONVIF auth works with configured credentials
3. RTSP ingest records continuous segments for >= 20 minutes
4. encrypted segment conversion pass succeeds without data loss
5. retrieval command returns decrypted segment bytes to authorized session client

## Security Notes
- Vendor cloud/P2P features should be disabled when camera firmware allows.
- Regardless of vendor settings, enforce camera network isolation + egress policy.
