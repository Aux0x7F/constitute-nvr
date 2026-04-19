# Operations (POC)

## 1) Install

```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-latest.sh | bash
```

Web-driven install (from `constitute` Appliances panel) passes context flags similar to:

```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-latest.sh | bash -s -- \
  --identity-id '<identity-id>' \
  --authorized-device-pk '<device-pk>' \
  --swarm-peer '<gateway-host:4040>' \
  --zone-key '<zone-key>' \
  --pair-identity '<identity-label>' \
  --pair-code '<code>' \
  --pair-code-hash '<code-hash>' \
  --allow-unsigned-hello-mvp
```

Install flow notes:
- release tarball is verified against `SHA256SUMS`
- unchanged binary hash skips reinstall/restart (unless install context flags are provided)
- auto-update timer is enabled by default (`constitute-nvr-update.timer`)
- updater rolls back binary when restart/health validation fails
- installer now requires decoder-capable host `ffmpeg`; on Fedora-class hosts it provisions RPM Fusion codec support when HEVC decode is missing
- install bootstrap now provisions the dedicated camera NIC, selects a non-colliding `/24`, and binds `dnsmasq` DHCP on that NIC
- camera bootstrap must also leave the host serving NTP on the camera NIC
  - when chrony drop-ins are used, bootstrap now ensures the matching `confdir` line is present in `/etc/chrony.conf` so Fedora-class hosts actually load `/etc/chrony.d`
- factory-static cameras on off-subnet defaults can be reached by provisioning explicit camera-NIC onboarding aliases (for example `192.168.0.2/24`)
- source-build/dev installs are expected to update through `constitute-nvr-update.timer`; in-process source updates are intentionally skipped

## 2) Service Checks

```bash
systemctl status constitute-nvr
journalctl -u constitute-nvr -n 100 --no-pager
systemctl status constitute-nvr-update.timer
systemctl list-timers | grep constitute-nvr-update
chronyd -p -f /etc/chrony.conf
ss -ulpn | grep ':123 '
```

## Persistence Contract
- Config is persistent at `/etc/constitute-nvr/config.json`.
- Runtime state is persistent at `/var/lib/constitute-nvr`.
- Media retention is persistent at `storage.root` (recommended dedicated data mount).
- Update scripts must not delete config/state/media roots.

## 3) Config Checks
File:
- `/etc/constitute-nvr/config.json`

Critical fields before ingest:
- `api.identity_id`
- `api.authorized_device_pks`
- `swarm.peers`
- `swarm.zones[]`
- `pair_identity_label` / `pair_code_hash` (if auto-associate was armed)
- `storage.root`
- `camera_network.interface`
- `camera_network.subnet_cidr`
- `camera_network.host_ip`
- `camera_network.dhcp_enabled`
- `camera_network.ntp_enabled`
- `camera_network.ntp_server`
- `camera_network.timezone`
- `autoprovision.reolink_*` (when auto-provision enabled)
- `camera_devices[]`

Camera-NIC onboarding aliases:
- use `bootstrap-camera-network.sh --onboarding-alias <cidr>` to add explicit extra `/24` addresses on the dedicated camera NIC for factory-static cameras
- when `--camera-cidr` is specified explicitly, bootstrap now honors that exact subnet instead of silently reselecting a neighboring `/24`
- current discovery scans `/24` subnets already assigned to the camera NIC; it does not invent off-subnet reachability on its own

## 4) ONVIF Discovery Smoke

```bash
constitute-nvr --config /etc/constitute-nvr/config.json --discover-onvif
```

## 5) Reolink First-Boot Bootstrap (Camera Jail / No DHCP LAN)
Use this only for first-boot cameras that request DHCP but do not yet expose RTSP/ONVIF.

```bash
sudo constitute-nvr --bootstrap-reolink-server-ip 192.168.1.10 --bootstrap-reolink-lease-ip 192.168.1.20 --bootstrap-reolink-target-mac EC:71:DB:32:0A:8F
constitute-nvr --discover-reolink --discover-reolink-hint-ip 192.168.1.20
constitute-nvr --probe-reolink-ip 192.168.1.20
```

Notes:
- Binding UDP/67 generally requires root or `CAP_NET_BIND_SERVICE`.
- Current automation covers lease + vendor discovery + standards readiness checks.
- After bootstrap, verify host NTP serving for the camera subnet:
  - `chronyd -p -f /etc/chrony.conf` should include the camera-subnet `allow` / `local` directives
  - `ss -ulpn | grep ':123 '` should show `chronyd` listening on UDP `123`
- CGI setup path covers RTSP/ONVIF/P2P toggles when HTTP API is available; proprietary `9000` path remains fallback/R&D for HTTP-disabled devices.
- For cheap generic/XM cameras that ship static on another `/24`, use onboarding aliases instead of this Reolink-only bootstrap path.
- XM / NetSurveillance `40E` note:
  - active driver is `xm_40e`, not the old generic `xm_rtsp` placeholder
  - current recording uses video-only MP4 segmentation because the validated lab camera exposes `pcm_mulaw` audio that cannot be copied directly into MP4
  - live preview for this camera requires HEVC decode on the host because the validated RTSP profiles are HEVC, not H.264
  - site time for the lab XM camera is served from the host-side onboarding alias `192.168.0.2`
  - the baked feed title is driven through `TitleOverlay.TitleUtf8`
  - the hidden XM `UserOverlay` lane must stay cleared so stale lower-left text does not leak into the baked feed

## 6) Health Endpoint

```bash
curl -s http://127.0.0.1:8456/health | jq .
```

Notes:
- `/health` is intentionally redacted; camera credentials and raw credential-bearing RTSP URLs are never returned.
- `/health` uses `cameraDevices` as the active pre-prod NVR camera payload key.
- `cameraNetwork` should reflect the provisioned camera NIC, DHCP range, and active site-time policy (`ntp_enabled`, `ntp_server`, `timezone`).
- temporary live-preview source loss should self-heal inside the running service; routine camera/network blips should not require relaunching the NVR page to resume tiles
- verified supported drift after camera reboot should self-heal inside the running service; drift should not remain a permanent operator burden when the device is reachable again

## 7) Camera Hardening Script
Audit-only:

```bash
sudo bash scripts/linux/harden-camera-interface.sh
```

Apply:

```bash
sudo bash scripts/linux/harden-camera-interface.sh \
  --apply \
  --iface enp2s0 \
  --camera-cidr 10.60.0.0/24
```

Expected effect:
- camera NIC zone target `DROP`
- camera->host DHCP remains allowed on the isolated segment
- host egress on camera NIC restricted to DHCP/camera-control/RTSP (+ Reolink discovery UDP `2000/3000`, optional WS-Discovery, optional NTP); default control allowlist includes Reolink `9000/tcp`

## 8) Manual Session Protocol Test (Identity-bound)
Connect websocket to `/session` and perform:
1. plaintext `hello`
2. receive `hello_ack`
3. switch to encrypted `cipher` envelopes
4. issue `list_sources`, `list_source_states`, then `list_segments`

Use the configured values:
- `api.identity_id`
- `api.identity_secret_hex`
- `api.server_secret_hex`

## 9) Self-Update
Manual run:

```bash
sudo /usr/local/bin/constitute-nvr-self-update --service-name constitute-nvr --try-restart
```

## Known POC Limits
- depends on installer-managed host `ffmpeg`; install now fails if HEVC decode support cannot be provisioned
- release checksums are hash-verified but not signature-verified yet
- TURN remains a documented stub; same-LAN and NAT-friendly direct ICE paths are the active target for this iteration

