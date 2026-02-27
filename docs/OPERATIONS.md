# Operations (POC)

## 1) Install

```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-wizard.sh | bash
```

Wizard prompts for:
- storage root path (default placeholder)
- self-update timer interval
- optional camera hardening settings

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
- `swarm.peers`
- `swarm.zones[]`
- `storage.root`
- `cameras[]`

## 4) ONVIF Discovery Smoke

```bash
constitute-nvr --config /etc/constitute-nvr/config.json --discover-onvif
```

## 5) Health Endpoint

```bash
curl -s http://127.0.0.1:8456/health | jq .
```

## 6) Camera Hardening Script
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

## 7) Manual Session Protocol Test (Identity-bound)
Connect websocket to `/session` and perform:
1. plaintext `hello`
2. receive `hello_ack`
3. switch to encrypted `cipher` envelopes
4. issue `list_sources` and `list_segments`

Use the configured values:
- `api.identity_id`
- `api.identity_secret_hex`
- `api.server_secret_hex`

## 8) Self-Update
Manual run:

```bash
sudo /usr/local/bin/constitute-nvr-self-update --source-dir /opt/constitute-nvr-src --branch main --service-name constitute-nvr --try-restart
```

## Known POC Limits
- depends on host `ffmpeg`
- source-build update flow (no signed release artifact path yet)
- segment-serving path implemented before live stream relay path
