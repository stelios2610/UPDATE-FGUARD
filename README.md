# FGUARD — Network Security Gateway

**FGUARD** is a professional-grade network security gateway with a full web-based management interface. Built on Linux, it provides enterprise firewall features for small and medium businesses, branch offices, and home labs.

> Current version: **v1.0.12**

---

## Features

### Network & Firewall
- Stateful firewall with custom inbound/outbound rules
- VLAN support (802.1Q subinterfaces) with per-VLAN DHCP, gateway, and DNS
- Multi-WAN and policy-based routing
- QoS traffic shaping (CAKE algorithm)
- NAT / IP masquerading

### VPN
- **SSL VPN** (OpenVPN) — remote access for clients
- **WireGuard** site-to-site tunnels with DDNS watchdog (auto-updates endpoints when WAN IP changes)
- **IPSec** site-to-site VPN (runs over WireGuard for extra security)

### Security
- **GeoIP Blocking** — block traffic by country using ipset
- **Web Filter** — DNS-based content filtering with DoH and QUIC blocking
- **IPS** — Intrusion Prevention System
- **Application Control** — per-application policy enforcement
- **DLP** — Data Loss Prevention
- **Reputation filtering** — block known malicious IPs
- **Spam filter**
- **ClamAV** Gateway Antivirus (optional)

### Management
- Web UI accessible via HTTPS (nginx reverse proxy)
- Dashboard with real-time traffic stats (72-hour rolling window)
- Network discovery
- Certificate management (PKI)
- High Availability (HA) manager
- Logs viewer
- **OTA Updates** — pull and apply updates from the UPDATE-FGUARD repository
- License system (HMAC-SHA256, MAC-bound, lifetime or timed)

---

## Architecture

```
Internet (WAN)
      │
   [ens1]  ←── WAN interface (DHCP from ISP)
      │
 [FGUARD Server]
      │
   [eth1]  ←── LAN trunk (802.1Q)
      ├── eth1.10  (VLAN 10 — main LAN, 192.168.0.x)
      └── eth1.20  (VLAN 20 — secondary LAN, 192.168.20.x)
      │
   [tun0]  ←── OpenVPN SSL VPN (10.8.0.0/24)
   [wg0]   ←── WireGuard site-to-site (10.100.0.x)
```

**Stack:**
- OS: Ubuntu Server 24.04 LTS
- Backend: Python 3 / FastAPI
- Frontend: Jinja2 templates + vanilla JS
- DB: SQLite (`firewall.db`)
- Proxy: nginx (HTTPS)
- DNS/DHCP: dnsmasq

---

## Installation

On a fresh Ubuntu 24.04 server:

```bash
curl -fsSL https://raw.githubusercontent.com/stelios2610/test-fguard/main/install.sh | sudo bash
```

The installer will:
1. Install all dependencies (Python 3, nginx, dnsmasq, OpenVPN, WireGuard, strongSwan, iptables-persistent, etc.)
2. Clone this repository to `/opt/fguard`
3. Create a Python virtual environment and install requirements
4. Configure nginx for HTTPS
5. Generate a self-signed SSL certificate
6. Set up and enable the `fguard.service` systemd unit
7. Configure NAT, dnsmasq, QoS, and boot persistence

After installation, access the web UI at:
```
https://<server-ip>:8080
```
Default credentials: `admin / admin`

---

## Directory Structure

```
/opt/fguard/
├── core/               # Backend modules
│   ├── network_manager.py   # VLAN, DHCP, NAT, QoS
│   ├── rules_engine.py      # Firewall rules
│   ├── ssl_vpn.py           # OpenVPN management
│   ├── vpn_manager.py       # WireGuard management
│   ├── ipsec_manager.py     # IPSec management
│   ├── geoblock.py          # GeoIP blocking
│   ├── web_filter.py        # DNS content filtering
│   ├── ips.py               # Intrusion Prevention
│   ├── updater.py           # OTA update system
│   └── license_manager.py   # License validation
├── web/
│   ├── api.py               # FastAPI routes
│   ├── auth.py              # Authentication
│   └── templates/           # Jinja2 HTML templates
├── db/
│   └── database.py          # SQLite ORM
├── build/
│   ├── first-boot.sh        # Post-install initialization
│   ├── post-update.sh       # Post-update hooks
│   ├── wg-watchdog.sh       # WireGuard DDNS watchdog
│   └── wsl_build_fguard.sh  # Custom ISO build script
├── main.py                  # Application entry point
├── version.json             # Current installed version
└── requirements.txt
```

---

## License System

Each installation requires a license file at `/etc/fguard/license.key`.

- Licenses are **MAC-address bound** (tied to the NIC of the server)
- Signed with HMAC-SHA256
- Durations: 6 months, 12 months, 24 months, or **Lifetime**
- Features gated by license: Web Filter, Application Control, GeoIP Blocking, OTA Updates
- Features always available (no license required): Firewall rules, VPN, Logging, Dashboard

---

## OTA Update System

FGUARD supports over-the-air updates from the [UPDATE-FGUARD](https://github.com/stelios2610/UPDATE-FGUARD) repository.

1. Go to **System → Updates** in the web UI
2. Click **Check Now** — the system compares `version.json` with the upstream release
3. If a newer version is available, click **Download** then **Apply**
4. The server restarts automatically after applying the update

Updates never overwrite: `firewall.db`, `pki/`, `vpn-configs/`, `version.json`.

---

## Requirements

- Ubuntu Server 24.04 LTS (clean install recommended)
- 2 network interfaces minimum (WAN + LAN)
- 2 GB RAM minimum (4 GB recommended)
- 20 GB disk minimum
- Internet access during installation

---

## Security Notes

- The web UI is served over HTTPS with a self-signed certificate — accept the browser warning on first access
- SSH from WAN is blocked by default (iptables INPUT DROP on WAN interface)
- All firewall rules persist across reboots via `netfilter-persistent`
- The default admin password should be changed immediately after first login

---

## Related Repositories

| Repo | Purpose |
|------|---------|
| [test-fguard](https://github.com/stelios2610/test-fguard) | Primary — install source for new servers |
| [FGUARD](https://github.com/stelios2610/AegisGuard) | Mirror backup of test-fguard |
| [UPDATE-FGUARD](https://github.com/stelios2610/UPDATE-FGUARD) | OTA update packages |

---

## License

Proprietary. All rights reserved. This software is not open source.
Contact the developer for licensing information.
