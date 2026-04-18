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
- Interim PTZ status: native `9000` pose readback works, but native `SetPtzPos` is still not a trustworthy actuation path on the lab `E1 Outdoor SE`, so PTZ UI remains hidden while real fulfillment is revisited
- Reolink presentation/name apply status: verified live on `2026-04-16`
  - CGI session cleanup now closes camera-side login slots after each operation instead of leaking them
  - camera name / OSD overlay apply was proven on the lab camera by driving `Reolink E1 Outdoor SE` -> `Carport` -> `Test` -> `Carport`
  - requested-field verification is now based on real camera readback, not desired-value fallback
- Reolink site-time policy status: active for current pass
  - site-wide NTP/timezone policy now belongs to `camera_network`, not to per-camera settings
  - ONVIF is the authority for normalized time fields (`time_mode`, `ntp_server`, `timezone`)
  - CGI remains the authority for OSD/name and raw clock-display format write/readback
  - current driver policy hardcodes the on-camera clock display to `MM/DD/YYYY` plus 24-hour time with seconds
  - live feed proof on `2026-04-17` showed that changing `camera_network.timezone` updates the baked timestamp in the camera image through the CGI time payload:
    - `UTC` produced `04/18/2026 12:14:27 am SAT`
    - `America/Phoenix` produced `04/17/2026 05:14:56 pm FRI`
  - implication: feed-truth for clock presentation is the Reolink CGI time payload (`timeZone`, `timeFmt`, `hourFmt`, `isDst`), not the ONVIF timezone label
  - current verification matches that split:
    - `time_mode` / `ntp_server` verify from ONVIF
    - `timezone` verifies from the feed-facing CGI time payload
  - follow-up live proof on `2026-04-17`:
    - the lab Fedora host required `confdir /etc/chrony.d` in `/etc/chrony.conf` before the bootstrap-written chrony drop-in was actually loaded and UDP `123` was served on the camera NIC
    - Reolink apply now also seeds the current site-local wall clock in the CGI time payload while leaving NTP enabled, so the baked feed clock converges immediately instead of waiting for the camera's next poll
    - final feed proof after the fix showed `04/17/2026 18:05:44 FRI`
  - current proven format state on this model:
    - `MM/DD/YYYY`
    - 24-hour time with seconds
    - weekday suffix still present
  - no surfaced Reolink `GetTime` / `SetTime` or OSD control has been proven for hiding or reordering weekday on this model
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
