# FGUARD UTC — Update Repository

This repository is the official OTA (Over-The-Air) update source for **FGUARD UTC** installations.

> Current release: see [`version.json`](./version.json)

---

## How Updates Work

1. Each FGUARD UTC server checks this repository **once daily** for a newer `version.json`
2. If a newer version is found, a notification appears in **System → Updates** in the web UI
3. The administrator clicks **Download** to fetch the update package
4. When ready, they click **Apply** — the server updates and restarts the service automatically

> Updates only apply to **licensed** FGUARD UTC installations.

---

## Repository Structure

```
UPDATE-FGUARD/
├── core/          # Backend modules (network_manager, geoblock, web_filter, etc.)
├── web/           # API routes and Jinja2 templates
├── db/            # Database layer
├── build/
│   ├── post-update.sh      # Runs automatically after each update is applied
│   ├── wg-watchdog.sh      # WireGuard DDNS watchdog script
│   ├── wg-watchdog.service # Systemd unit
│   └── wg-watchdog.timer   # Systemd timer (runs every 2 minutes)
└── version.json   # Release metadata (version, date, product name)
```

Only the files that changed are included in each release — existing files not listed here are left untouched.

---

## Protected Paths

The update system **never overwrites** the following paths on the target server:

| Path | Reason |
|------|--------|
| `firewall.db` | Live configuration database |
| `pki/` | SSL/TLS certificates and keys |
| `vpn-configs/` | VPN client configurations |
| `version.json` | Managed by the update system itself |

---

## Changelog

### v1.0.11 — 2026-08-16
- Feat: VLAN DHCP now supports custom gateway, DNS1, DNS2 per VLAN
- Automatic DB migration (ALTER TABLE vlans) for existing installations
- Fallback: if not set, uses the VLAN IP as gateway and DNS
- Fix: install.sh MOTD now shows dynamic version from version.json

### v1.0.10
- Fix: traffic baseline resets automatically after server reboot (psutil < baseline → new baseline)

### v1.0.9
- Dynamic version display: sidebar footer and login page show version from version.json

### v1.0.8
- GeoBlock: removed IPSec ports (500/4500) from always-open list
- GeoBlock: `_install_persistence()` now creates all three boot services correctly
- Dashboard stats reset every 72 hours (logs, traffic baseline, IPS alerts, DDoS blocked set)

### v1.0.7
- SSL VPN: start/stop/status now use `openvpn-server@server.service` instead of subprocess

### v1.0.6
- DHCP relay: replaced isc-dhcp-relay with custom Python relay using `SO_BINDTODEVICE`

### v1.0.5
- WireGuard DDNS watchdog (wg-watchdog.sh + .service + .timer)
- post-update.sh framework for post-update hooks

---

## Related Repositories

| Repo | Purpose |
|------|---------|
| [test-fguard](https://github.com/stelios2610/test-fguard) | Primary install source for new servers |
| [AegisGuard](https://github.com/stelios2610/AegisGuard) | Mirror backup of test-fguard |
| [UPDATE-FGUARD](https://github.com/stelios2610/UPDATE-FGUARD) | OTA update packages (this repo) |

---

## License

Proprietary. All rights reserved.  
Contact the developer for licensing information.
