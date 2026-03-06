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

## 2) Service Checks

```bash
systemctl status constitute-nvr
journalctl -u constitute-nvr -n 100 --no-pager
systemctl status constitute-nvr-update.timer
systemctl list-timers | grep constitute-nvr-update
```

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
- `autoprovision.reolink_*` (when auto-provision enabled)
- `cameras[]`

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
- CGI setup path covers RTSP/ONVIF/P2P toggles when HTTP API is available; proprietary `9000` path remains fallback/R&D for HTTP-disabled devices.

## 6) Health Endpoint

```bash
curl -s http://127.0.0.1:8456/health | jq .
```

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
- host egress on camera NIC restricted to ONVIF/RTSP (+ optional WS-Discovery, optional NTP)

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
- depends on host `ffmpeg`
- release checksums are hash-verified but not signature-verified yet
- segment-serving path implemented before live stream relay path

