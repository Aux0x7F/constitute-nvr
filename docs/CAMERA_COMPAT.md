# Camera Compatibility Matrix (Iteration-1)

## Validation Target Models

### Anypiz IPC-B8743-S (4MP PoE U series)
- ONVIF discovery: pending lab validation
- ONVIF service endpoint auth: pending
- RTSP ingest: pending
- Recommended status: test candidate

### Reolink E1 Outdoor SE PoE Pan Cam
- First boot requires DHCP lease before the camera exposes an address
- Proprietary LAN discovery observed on UDP `2000/3000`
- Proprietary control plane observed on TCP `9000`
- Native HTTP CGI control plane observed at `http://<ip>:80/cgi-bin/api.cgi`
- ONVIF service observed at `http://<ip>:8000/onvif/device_service` after native enablement
- RTSP port observed on `554/tcp` after native enablement
- Reolink cloud/P2P endpoint behavior observed: yes (`p2p.reolink.com`, `devices-apis.reolink.com`)
- RTSP ingest path: pending sustained validation in this repo
- Interim PTZ status: native `9000` pose readback works, but native `SetPtzPos` is still not a trustworthy actuation path on the lab `E1 Outdoor SE`; the attempted CGI pulse fallback is also currently hitting camera-side login/session exhaustion (`rspCode -5: max session`), so PTZ UI is hidden for now while session reuse/cleanup and real fulfillment are sorted out
- Current automation status: native DHCP bootstrap is implemented; configured-camera control can fall back to native CGI for ports/P2P, but first-boot provisioning still depends on the proprietary 9000 path and remains the blocking native-Rust gap
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
