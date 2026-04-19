# Camera Compatibility Matrix (Iteration-1)

Driver-model-specific implementation notes now belong primarily in:
- `src/camera_device/drivers/<driver>/driver.rs`
- `src/camera_device/drivers/<driver>/identification.rs`

This file stays at operator/compatibility-summary level.

## Validation Target Models

### Anypiz IPC-B8743-S (4MP PoE U series)
- ONVIF discovery: pending lab validation
- ONVIF service endpoint auth: pending
- RTSP ingest: pending
- Recommended status: test candidate

### XM / NetSurveillance 40E
- Lab discovery address: `192.168.0.201` (factory-static, off the managed `192.168.250.0/24` subnet)
- Discovery requirement: host camera NIC must carry an explicit onboarding alias on the matching `/24` (for example `192.168.0.2/24`)
- HTTP/web UI fingerprint:
  - `Server: gSOAP/2.8`
  - legacy plugin UI assets such as `api_pluginPlay/api_plugin.js`, `raw_player.js`, and `IPCConfigCtrl`
- Live model fingerprint:
  - `fsVersion="40E_19_DL_c1_V3-A-RTMP-H5 V3.4.0.3 build 2025-01-09 17:38:27"`
  - serial `EF00000006092ABD`
- RTSP ingest path: verified live on `2026-04-17`
  - `rtsp://admin:123456@192.168.0.201:554/user=admin_password=123456_channel=1_stream=0.sdp?real_stream`
- Stream facts proved on the lab camera:
  - main stream: HEVC `2560x1440`
  - substream: HEVC `640x360`
  - tested RTSP profile variants on `2026-04-17` remained HEVC-only; no H.264 profile was found in the validated live paths
- Current driver status:
  - supported as `xm_40e`
  - discovery, probe, ingest, live preview, baked-title apply, and site-time apply are in scope
  - live service proof on `2026-04-18`:
    - mounted as `xm-192-168-0-201` on the lab host
    - `/health` reported the XM source `running`
    - recorded segments were created under `/data/constitute-nvr/segments/xm-192-168-0-201`
    - baked feed title was driven `Front Door -> Test -> Front Door`
    - baked feed clock was verified live with:
      - NTP mode
      - NTP server `192.168.0.2`
      - 24-hour time
      - weekday hidden
  - recorder note:
    - this model exposes `pcm_mulaw` audio alongside HEVC video
    - iteration-1 ingest records video-only MP4 segments because copying `pcm_mulaw` audio into MP4 is not container-safe
  - preview note:
    - live preview depends on host HEVC decode because the validated RTSP profiles are HEVC
    - installer/runtime now treat decoder-capable `ffmpeg` as part of the supported contract
    - temporary hard down/up should resume live preview without relaunch once the camera becomes reachable again
  - XM-specific management notes:
    - baked feed title is controlled by `TitleOverlay.TitleUtf8`
    - site time is controlled by `/setTimeConfig` with manual seed -> NTP transition
    - the effective NTP alias for this camera is `192.168.0.2`
    - a second XM `UserOverlay` lane can leak stale text into the lower-left corner; the active driver now clears that lane on apply so the feed only shows the main title and clock
    - service-side reconcile is expected to reassert baked title and site NTP/time settings after reboot-driven drift when the camera is reachable again
- PTZ is not supported on this model
- Recommended status: supported for discovery, ingest, live preview, baked title, and site time when an onboarding alias exists on the camera NIC

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
  - service-side reconcile is expected to reoffer supported site-time settings after reboot-driven drift when the camera is reachable again
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
