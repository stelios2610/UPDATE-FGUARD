# FGUARD — Network Security Gateway

**FGUARD** is a professional-grade network security gateway with a full web-based management interface. Built on Linux, it provides enterprise firewall features for small and medium businesses, branch offices, and home labs.

> Current version: **v1.0.43**

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
- **Web Filter** — DNS blocking for custom domains and small built-in category lists, plus DoH and QUIC blocking. It does not decrypt HTTPS.
- **Traffic Security** — optional Suricata IPS on LAN-to-WAN client traffic, Emerging Threats open signatures, application identification, URL categories in DNS and on TLS names, ClamAV on extracted and decrypted files, and HTTPS inspection. All of these stay off until an administrator enables them. HTTPS inspection also requires an explicit confirmation, bypasses updates and banks, and blocks QUIC. A stopped IPS fails open. These feeds are not FortiGuard and this is not a certified throughput rating.
- **Policy push** — send the traffic switches to other FGUARD nodes. It does not turn on HTTPS inspection remotely.
- **IPS** — host and half-open connection heuristics (port scan, floods, brute force), separate from the optional Suricata path.
- **Application Control** — block applications by port, address, and TLS server name
- **DLP, file type checks, spam, and ClamAV** — on-demand scans of content you submit. The download antivirus on Traffic Security is the path that scans files extracted from client traffic.
- **Reputation filtering** — block known malicious IPs

### Management
- Web UI accessible via HTTPS (nginx reverse proxy)
- Dashboard with real-time traffic stats (72-hour rolling window)
- Network discovery
- Certificate management (PKI)
- High Availability (HA) manager with optional connection sync when conntrackd is installed
- Read-only health view of other FGUARD nodes. It does not push policy.
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

On a fresh Ubuntu 24.04 server, install from a checkout you have reviewed:

```bash
git clone https://github.com/stelios2610/test-fguard.git
cd test-fguard
sudo bash install.sh
```

The first web sign-in must set a new administrator password. Until that happens the rest of the UI stays closed. Image builds write a one-time console password beside the ISO and expire it at first login.

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
The first sign-in uses the factory account `admin` / `admin`. The UI then requires a different password before any other page opens.

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
- Signed with Ed25519. The private key stays off the firewall.
- Durations: 6 months, 12 months, 24 months, or **Lifetime**
- Features gated by license: Web Filter, Application Control, GeoIP Blocking, OTA Updates
- Features always available (no license required): Firewall rules, VPN, Logging, Dashboard

---

## OTA Update System

FGUARD installs an update only when `version.json` is signed by the license private key and the downloaded archive matches the sha256 inside that signature. The private key stays on the machine that publishes updates (`~/.fguard/license-private.pem`).

1. Build the update zip. It must contain one top-level directory.
2. Sign it: `python sign_update.py --zip dist/fguard.zip --url https://example.com/fguard.zip --version-file version.json --out-dir publish/`
3. Publish `publish/version.json` and `publish/version.json.sig` where the appliance already looks (`UPDATE-FGUARD` raw `main`), and publish the zip at the https URL you signed.
4. In the web UI, open **System → Updates**, then **Check Now**, **Download**, and **Apply**.

An unsigned manifest is refused. Updates never overwrite: `firewall.db`, `pki/`, `vpn-configs/`, `version.json` (the installed version is taken from the signed manifest).

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
- The factory admin password cannot be kept. The UI requires a new one before any other page opens.

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
