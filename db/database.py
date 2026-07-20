import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "firewall.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize():
    conn = get_connection()
    c = conn.cursor()

    # ── Firewall rules ────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK')),
            direction TEXT NOT NULL CHECK(direction IN ('IN','OUT','BOTH')),
            protocol TEXT NOT NULL DEFAULT 'ANY',
            local_ip TEXT DEFAULT '',
            remote_ip TEXT DEFAULT '',
            local_port TEXT DEFAULT '',
            remote_port TEXT DEFAULT '',
            interface TEXT DEFAULT '',
            log_match INTEGER DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 100,
            created_at TEXT NOT NULL,
            description TEXT DEFAULT ''
        )
    """)

    # ── Event logs ────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            direction TEXT,
            protocol TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            process TEXT,
            rule_name TEXT,
            details TEXT
        )
    """)

    # ── Network interfaces ─────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL DEFAULT 'LAN' CHECK(role IN ('WAN','LAN','DMZ','OPTIONAL','MGMT')),
            description TEXT DEFAULT '',
            ip_mode TEXT NOT NULL DEFAULT 'static' CHECK(ip_mode IN ('static','dhcp','pppoe')),
            ip_address TEXT DEFAULT '',
            netmask TEXT DEFAULT '',
            gateway TEXT DEFAULT '',
            mtu INTEGER DEFAULT 1500,
            speed TEXT DEFAULT 'auto',
            enabled INTEGER DEFAULT 1,
            vlan_id INTEGER DEFAULT 0,
            pppoe_user TEXT DEFAULT '',
            pppoe_pass TEXT DEFAULT '',
            mac_override TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── Static routes ─────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            destination TEXT NOT NULL,
            netmask TEXT NOT NULL,
            gateway TEXT NOT NULL,
            interface TEXT DEFAULT '',
            metric INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── VLANs (802.1Q) ────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS vlans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vlan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            parent_interface TEXT NOT NULL,
            ip_address TEXT DEFAULT '',
            netmask TEXT DEFAULT '255.255.255.0',
            gateway TEXT DEFAULT '',
            zone TEXT DEFAULT 'OPTIONAL' CHECK(zone IN ('LAN','DMZ','OPTIONAL','TRUSTED','EXTERNAL')),
            dhcp_enabled INTEGER DEFAULT 0,
            dhcp_start TEXT DEFAULT '',
            dhcp_end TEXT DEFAULT '',
            mtu INTEGER DEFAULT 1500,
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── DMZ config ────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS dmz_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface TEXT NOT NULL UNIQUE,
            ip_address TEXT DEFAULT '',
            netmask TEXT DEFAULT '255.255.255.0',
            allowed_ports TEXT DEFAULT '80,443',
            block_dmz_to_lan INTEGER DEFAULT 1,
            log_all INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 1,
            updated_at TEXT NOT NULL
        )
    """)

    # ── DHCP server config per interface ─────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS dhcp_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface TEXT NOT NULL UNIQUE,
            enabled INTEGER DEFAULT 1,
            start_ip TEXT NOT NULL,
            end_ip TEXT NOT NULL,
            subnet_mask TEXT NOT NULL,
            gateway TEXT DEFAULT '',
            dns1 TEXT DEFAULT '1.1.1.1',
            dns2 TEXT DEFAULT '8.8.8.8',
            lease_time INTEGER DEFAULT 86400,
            domain TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── DHCP static leases ────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS dhcp_leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL UNIQUE,
            ip TEXT NOT NULL,
            hostname TEXT DEFAULT '',
            interface TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── DHCP Relay ────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS dhcp_relay (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER DEFAULT 0,
            server_ip TEXT NOT NULL DEFAULT '',
            interfaces TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── DNS settings ──────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS dns_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            primary_dns TEXT DEFAULT '1.1.1.1',
            secondary_dns TEXT DEFAULT '8.8.8.8',
            tertiary_dns TEXT DEFAULT '9.9.9.9',
            search_domain TEXT DEFAULT '',
            enable_caching INTEGER DEFAULT 1,
            enable_dnssec INTEGER DEFAULT 0,
            block_rebind INTEGER DEFAULT 1,
            local_domain TEXT DEFAULT 'aegis.local',
            updated_at TEXT NOT NULL
        )
    """)

    # ── NAT rules ─────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS nat_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('SNAT','DNAT','PAT','1-to-1')),
            external_ip TEXT DEFAULT '',
            external_port TEXT DEFAULT '',
            internal_ip TEXT NOT NULL,
            internal_port TEXT DEFAULT '',
            protocol TEXT DEFAULT 'TCP',
            interface TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── QoS / Traffic Shaping ─────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS qos_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            priority TEXT DEFAULT 'NORMAL' CHECK(priority IN ('HIGHEST','HIGH','NORMAL','LOW','LOWEST')),
            protocol TEXT DEFAULT 'ANY',
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            src_port TEXT DEFAULT '',
            dst_port TEXT DEFAULT '',
            bandwidth_limit INTEGER DEFAULT 0,
            bandwidth_unit TEXT DEFAULT 'kbps',
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── Application control ───────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS app_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            exe_path TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK')),
            direction TEXT NOT NULL DEFAULT 'BOTH',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            description TEXT DEFAULT ''
        )
    """)

    # ── Web filter ────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS web_filter (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            category TEXT DEFAULT 'Custom',
            action TEXT NOT NULL DEFAULT 'BLOCK',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            description TEXT DEFAULT ''
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS web_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    """)

    # ── HTTP/HTTPS Proxy ──────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS proxy_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('HTTP','HTTPS','SMTP','DNS','FTP')),
            action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK','INSPECT')),
            pattern TEXT DEFAULT '',
            content_type TEXT DEFAULT '',
            max_size INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── VPN profiles (OpenVPN / WireGuard) ────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS vpn_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('OpenVPN','WireGuard')),
            config_path TEXT NOT NULL,
            server TEXT DEFAULT '',
            public_key TEXT DEFAULT '',
            private_key TEXT DEFAULT '',
            status TEXT DEFAULT 'Disconnected',
            auto_connect INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_connected TEXT DEFAULT ''
        )
    """)

    # ── IPSec site-to-site tunnels ────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS ipsec_tunnels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            local_subnet TEXT NOT NULL,
            remote_gateway TEXT NOT NULL,
            remote_subnet TEXT NOT NULL,
            psk TEXT NOT NULL,
            ike_version TEXT DEFAULT 'IKEv2',
            ike_cipher TEXT DEFAULT 'AES256',
            ike_hash TEXT DEFAULT 'SHA256',
            dh_group TEXT DEFAULT 'DH14',
            esp_cipher TEXT DEFAULT 'AES256',
            esp_hash TEXT DEFAULT 'SHA256',
            dpd_enabled INTEGER DEFAULT 1,
            dpd_interval INTEGER DEFAULT 30,
            status TEXT DEFAULT 'Down',
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            description TEXT DEFAULT ''
        )
    """)

    # ── SSL VPN server config ─────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS ssl_vpn_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER DEFAULT 0,
            port INTEGER DEFAULT 1194,
            protocol TEXT DEFAULT 'udp',
            interface TEXT DEFAULT '',
            server_subnet TEXT DEFAULT '10.8.0.0',
            server_netmask TEXT DEFAULT '255.255.255.0',
            dns1 TEXT DEFAULT '1.1.1.1',
            dns2 TEXT DEFAULT '8.8.8.8',
            cipher TEXT DEFAULT 'AES-256-GCM',
            auth TEXT DEFAULT 'SHA256',
            tls_version TEXT DEFAULT '1.2',
            redirect_gateway INTEGER DEFAULT 1,
            compress INTEGER DEFAULT 1,
            pki_dir TEXT DEFAULT '',
            ca_cert TEXT DEFAULT '',
            server_cert TEXT DEFAULT '',
            server_key TEXT DEFAULT '',
            dh_params TEXT DEFAULT '',
            ta_key TEXT DEFAULT '',
            extra_opts TEXT DEFAULT '',
            status TEXT DEFAULT 'Stopped',
            updated_at TEXT NOT NULL
        )
    """)

    # ── SSL VPN push routes ───────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS ssl_vpn_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL,
            netmask TEXT NOT NULL,
            description TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1
        )
    """)

    # ── VPN users (connect to SSL VPN or BOV) ─────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS vpn_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT DEFAULT '',
            email TEXT DEFAULT '',
            group_name TEXT DEFAULT 'vpn-users',
            tunnel_ip TEXT DEFAULT '',
            cert_path TEXT DEFAULT '',
            key_path TEXT DEFAULT '',
            config_path TEXT DEFAULT '',
            mfa_secret TEXT DEFAULT '',
            mfa_enabled INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            max_connections INTEGER DEFAULT 1,
            bandwidth_limit INTEGER DEFAULT 0,
            allowed_networks TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            last_connected TEXT DEFAULT '',
            expires_at TEXT DEFAULT ''
        )
    """)

    # ── Branch Office VPN (Site-to-Site) ──────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS bov_tunnels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL CHECK(type IN ('IKEv2','IKEv1','L2TP-IPSec','SSL-OpenVPN','WireGuard','GRE')),
            status TEXT DEFAULT 'Down',
            enabled INTEGER DEFAULT 1,
            -- Common fields
            local_gateway TEXT DEFAULT '',
            local_subnets TEXT DEFAULT '',
            remote_gateway TEXT NOT NULL,
            remote_subnets TEXT NOT NULL,
            -- IPSec (IKEv1/IKEv2/L2TP)
            psk TEXT DEFAULT '',
            ike_version TEXT DEFAULT 'IKEv2',
            ike_cipher TEXT DEFAULT 'AES256',
            ike_hash TEXT DEFAULT 'SHA256',
            ike_dh TEXT DEFAULT 'DH14',
            ike_lifetime INTEGER DEFAULT 28800,
            esp_cipher TEXT DEFAULT 'AES256',
            esp_hash TEXT DEFAULT 'SHA256',
            esp_lifetime INTEGER DEFAULT 3600,
            pfs_group TEXT DEFAULT 'DH14',
            dpd_enabled INTEGER DEFAULT 1,
            dpd_interval INTEGER DEFAULT 30,
            dpd_timeout INTEGER DEFAULT 120,
            -- L2TP specific
            l2tp_local_ip TEXT DEFAULT '',
            l2tp_remote_ip TEXT DEFAULT '',
            -- SSL/OpenVPN specific
            ssl_port INTEGER DEFAULT 1194,
            ssl_protocol TEXT DEFAULT 'udp',
            ssl_cipher TEXT DEFAULT 'AES-256-GCM',
            ssl_ca_cert TEXT DEFAULT '',
            ssl_cert TEXT DEFAULT '',
            ssl_key TEXT DEFAULT '',
            ssl_ta_key TEXT DEFAULT '',
            -- WireGuard specific
            wg_private_key TEXT DEFAULT '',
            wg_public_key TEXT DEFAULT '',
            wg_peer_pubkey TEXT DEFAULT '',
            wg_preshared_key TEXT DEFAULT '',
            wg_port INTEGER DEFAULT 51820,
            wg_keepalive INTEGER DEFAULT 25,
            -- NAT/routing
            nat_traversal INTEGER DEFAULT 1,
            aggressive_mode INTEGER DEFAULT 0,
            -- Stats
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0,
            last_up TEXT DEFAULT '',
            -- Meta
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── Authentication users ──────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS auth_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT DEFAULT '',
            email TEXT DEFAULT '',
            role TEXT DEFAULT 'user' CHECK(role IN ('admin','user','readonly','vpn-only')),
            group_name TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT DEFAULT ''
        )
    """)

    # ── Authentication groups ─────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS auth_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            policy TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── Certificates ──────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT DEFAULT 'self-signed' CHECK(type IN ('self-signed','imported','ca','vpn')),
            subject TEXT DEFAULT '',
            issuer TEXT DEFAULT '',
            not_before TEXT DEFAULT '',
            not_after TEXT DEFAULT '',
            fingerprint TEXT DEFAULT '',
            cert_pem TEXT DEFAULT '',
            key_pem TEXT DEFAULT '',
            usage TEXT DEFAULT 'general',
            created_at TEXT NOT NULL
        )
    """)

    # ── System settings ───────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # ── Scheduled tasks / cron ────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            schedule TEXT NOT NULL,
            action TEXT NOT NULL,
            last_run TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    # ── Syslog / remote logging ───────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS log_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER DEFAULT 514,
            protocol TEXT DEFAULT 'UDP',
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    # ── Multi-WAN links ───────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS wan_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            interface TEXT NOT NULL,
            gateway TEXT NOT NULL,
            weight INTEGER DEFAULT 1,
            priority INTEGER DEFAULT 1,
            mode TEXT DEFAULT 'failover' CHECK(mode IN ('failover','loadbalance')),
            enabled INTEGER DEFAULT 1,
            -- Health check
            check_ip TEXT DEFAULT '8.8.8.8',
            check_interval INTEGER DEFAULT 10,
            check_timeout INTEGER DEFAULT 3,
            check_failures INTEGER DEFAULT 3,
            -- State (runtime, not persisted)
            status TEXT DEFAULT 'unknown',
            latency_ms INTEGER DEFAULT 0,
            last_check TEXT DEFAULT '',
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # ── High Availability (keepalived VRRP) ──────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS ha_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER DEFAULT 0,
            role TEXT DEFAULT 'MASTER' CHECK(role IN ('MASTER','BACKUP')),
            interface TEXT DEFAULT 'eth1',
            virtual_ip TEXT DEFAULT '',
            virtual_ip_mask INTEGER DEFAULT 24,
            router_id INTEGER DEFAULT 51,
            priority INTEGER DEFAULT 100,
            advert_interval REAL DEFAULT 1,
            auth_pass TEXT DEFAULT '',
            peer_ip TEXT DEFAULT '',
            preempt INTEGER DEFAULT 1,
            sync_enabled INTEGER DEFAULT 1,
            sync_peer TEXT DEFAULT '',
            sync_interval INTEGER DEFAULT 30,
            updated_at TEXT NOT NULL
        )
    """)

    # ── Default HA config row ─────────────────────────────────────────────────
    c.execute("INSERT OR IGNORE INTO ha_config (id, updated_at) VALUES (1, ?)",
              (datetime.now().isoformat(),))

    # ── DLP custom patterns ───────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS dlp_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pattern TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'MEDIUM',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    # ── SSL VPN schema migrations ─────────────────────────────────────────────
    try:
        c.execute("ALTER TABLE ssl_vpn_config ADD COLUMN dns_domain TEXT DEFAULT ''")
    except Exception:
        pass

    # ── Default SSL VPN config row ────────────────────────────────────────────
    c.execute("INSERT OR IGNORE INTO ssl_vpn_config (id, updated_at) VALUES (1, ?)",
              (datetime.now().isoformat(),))

    # ── Default settings ──────────────────────────────────────────────────────
    defaults = [
        ("firewall_enabled", "1"),
        ("default_policy", "BLOCK"),           # SECURE DEFAULT: block all
        ("log_allowed", "0"),
        ("log_blocked", "1"),
        ("max_log_entries", "50000"),
        ("app_control_enabled", "1"),
        ("web_filter_enabled", "1"),
        ("web_filter_use_hosts", "1"),
        ("ips_enabled", "1"),
        ("nat_enabled", "1"),
        ("router_mode", "0"),
        ("wan_interface", ""),
        ("lan_interface", ""),
        ("hostname", "aegisguard"),
        ("timezone", "UTC"),
        ("admin_password_hash", ""),
        ("web_ui_port", "8080"),
        ("web_ui_https", "0"),
        ("web_ui_cert_id", ""),
        ("ntp_server", "pool.ntp.org"),
        ("syslog_enabled", "0"),
        ("smtp_alerts_enabled", "0"),
        ("smtp_host", ""),
        ("smtp_port", "587"),
        ("smtp_user", ""),
        ("smtp_to", ""),
        ("vpn_openvpn_path", "/usr/sbin/openvpn"),
        ("vpn_wireguard_path", "/usr/bin/wg-quick"),
        ("setup_complete", "0"),
    ]
    for key, value in defaults:
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))

    # ── Default web filter categories ─────────────────────────────────────────
    for cat in ["Adult Content", "Gambling", "Malware", "Phishing",
                "Social Media", "Streaming", "Gaming", "Ads & Tracking",
                "Anonymizers", "Hacking", "Custom"]:
        c.execute("INSERT OR IGNORE INTO web_categories (name) VALUES (?)", (cat,))

    # ── Default DNS row ───────────────────────────────────────────────────────
    c.execute("INSERT OR IGNORE INTO dns_settings (id, updated_at) VALUES (1, ?)",
              (datetime.now().isoformat(),))

    conn.commit()
    conn.close()

    _seed_default_rules()
    _seed_default_app_rules()
    _seed_default_interfaces()


def _seed_default_rules():
    """Insert hardened default firewall rules (deny-all with essential exceptions)."""
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
    conn.close()
    if count > 0:
        return  # Already seeded

    now = datetime.now().isoformat()
    rules = [
        # ── Priority 1-10: System essentials (always allow) ──────────────────
        ("Allow Loopback",          "ALLOW", "BOTH", "ANY",  "127.0.0.0/8", "",  "", "", 1,  "Loopback interface traffic"),
        ("Allow Established",       "ALLOW", "IN",   "TCP",  "", "",  "", "", 2,  "Allow established/related TCP sessions"),
        # ── Priority 10-30: Management access ────────────────────────────────
        ("Allow SSH from LAN",      "ALLOW", "IN",   "TCP",  "10.0.0.0/24", "", "",  "22", 10, "SSH management from LAN only"),
        ("Allow Web UI from LAN",   "ALLOW", "IN",   "TCP",  "10.0.0.0/24", "", "",  "8080", 11, "FGUARD UTC web UI from LAN only"),
        ("Block Web UI from WAN",   "BLOCK", "IN",   "TCP",  "", "", "",  "8080", 12, "Block web UI from WAN"),
        ("Block SSH from WAN",      "BLOCK", "IN",   "TCP",  "", "", "",  "22", 13, "Block SSH from WAN"),
        # ── Priority 20-30: Outbound essential services ───────────────────────
        ("Allow DNS Out",           "ALLOW", "OUT",  "UDP",  "", "", "", "53",  20, "DNS resolution"),
        ("Allow DNS TCP Out",       "ALLOW", "OUT",  "TCP",  "", "", "", "53",  21, "DNS over TCP"),
        ("Allow DHCP",              "ALLOW", "BOTH", "UDP",  "", "", "67-68", "67-68", 22, "DHCP lease negotiation"),
        ("Allow NTP Out",           "ALLOW", "OUT",  "UDP",  "", "", "", "123", 23, "NTP time sync"),
        ("Allow HTTP Out",          "ALLOW", "OUT",  "TCP",  "", "", "", "80",  30, "HTTP outbound"),
        ("Allow HTTPS Out",         "ALLOW", "OUT",  "TCP",  "", "", "", "443", 31, "HTTPS outbound"),
        # ── Priority 40: ICMP (limited) ───────────────────────────────────────
        ("Allow ICMP Ping Out",     "ALLOW", "OUT",  "ICMP", "", "", "", "", 40, "Allow outbound ping"),
        ("Allow ICMP Ping In LAN",  "ALLOW", "IN",   "ICMP", "192.168.0.0/16", "", "", "", 41, "Allow ping from LAN"),
        # ── Priority 50: VPN traffic ──────────────────────────────────────────
        ("Allow OpenVPN Out",       "ALLOW", "OUT",  "UDP",  "", "", "", "1194", 50, "OpenVPN client"),
        ("Allow WireGuard Out",     "ALLOW", "OUT",  "UDP",  "", "", "", "51820", 51, "WireGuard client"),
        ("Allow IPSec IKE",         "ALLOW", "BOTH", "UDP",  "", "", "", "500",  52, "IPSec IKE negotiation"),
        ("Allow IPSec NAT-T",       "ALLOW", "BOTH", "UDP",  "", "", "", "4500", 53, "IPSec NAT-Traversal"),
        # ── Priority 9000: Block dangerous ports ─────────────────────────────
        ("Block Telnet",            "BLOCK", "BOTH", "TCP",  "", "", "", "23",   9000, "Telnet is insecure"),
        ("Block FTP",               "BLOCK", "BOTH", "TCP",  "", "", "", "21",   9001, "FTP is insecure"),
        ("Block TFTP",              "BLOCK", "BOTH", "UDP",  "", "", "", "69",   9002, "TFTP is insecure"),
        ("Block rlogin",            "BLOCK", "BOTH", "TCP",  "", "", "", "513",  9003, "rlogin is insecure"),
        ("Block rsh",               "BLOCK", "BOTH", "TCP",  "", "", "", "514",  9004, "rsh is insecure"),
        ("Block NetBIOS UDP",       "BLOCK", "BOTH", "UDP",  "", "", "", "137-139", 9005, "NetBIOS from WAN"),
        ("Block SMB from WAN",      "BLOCK", "IN",   "TCP",  "", "0.0.0.0/0", "", "445", 9006, "Block SMB from internet"),
        ("Block RDP from WAN",      "BLOCK", "IN",   "TCP",  "", "0.0.0.0/0", "", "3389", 9007, "RDP exposed to internet"),
        ("Block WinRM from WAN",    "BLOCK", "IN",   "TCP",  "", "0.0.0.0/0", "", "5985-5986", 9008, "WinRM from internet"),
        ("Block UPnP",              "BLOCK", "BOTH", "UDP",  "", "", "", "1900", 9009, "UPnP discovery"),
        ("Block mDNS from WAN",     "BLOCK", "IN",   "UDP",  "", "", "", "5353", 9010, "mDNS from WAN"),
        # ── Priority 9999: Default deny all ──────────────────────────────────
        ("Default Block All IN",    "BLOCK", "IN",   "ANY",  "", "", "", "", 9999, "Default deny inbound - change only if needed"),
        ("Default Block All OUT",   "BLOCK", "OUT",  "ANY",  "", "", "", "", 9999, "Default deny outbound - add ALLOW rules above"),
    ]

    conn = get_connection()
    for name, action, direction, proto, lip, rip, lport, rport, priority, desc in rules:
        conn.execute("""
            INSERT INTO rules (name, action, direction, protocol, local_ip, remote_ip,
                local_port, remote_port, priority, enabled, created_at, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, (name, action, direction, proto, lip, rip, lport, rport, priority, now, desc))
    conn.commit()
    conn.close()


def _seed_default_app_rules():
    """Pre-built application control rules for common software."""
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM app_rules").fetchone()[0]
    conn.close()
    if count > 0:
        return

    now = datetime.now().isoformat()
    # (name, exe_path, action, direction, description)
    apps = [
        # Block P2P / torrents
        ("Block BitTorrent",  "/usr/bin/bittorrent",     "BLOCK", "BOTH", "P2P torrent client"),
        ("Block qBittorrent", "/usr/bin/qbittorrent",    "BLOCK", "BOTH", "P2P torrent client"),
        ("Block Transmission","/usr/bin/transmission",   "BLOCK", "BOTH", "P2P torrent client"),
        ("Block Deluge",      "/usr/bin/deluge",          "BLOCK", "BOTH", "P2P torrent client"),
        # Block remote access tools (non-managed)
        ("Block TeamViewer",  "/usr/bin/teamviewer",     "BLOCK", "BOTH", "Unauthorized remote access"),
        ("Block AnyDesk",     "/usr/bin/anydesk",        "BLOCK", "BOTH", "Unauthorized remote access"),
        # Block cryptocurrency mining
        ("Block XMRig",       "/usr/bin/xmrig",          "BLOCK", "BOTH", "Cryptominer"),
        # Windows equivalents (for mixed environments)
        ("Block uTorrent",    "C:\\Users\\*\\AppData\\Roaming\\uTorrent\\uTorrent.exe", "BLOCK", "BOTH", "P2P torrent"),
        ("Block BitTorrent W","C:\\Users\\*\\AppData\\Roaming\\BitTorrent\\BitTorrent.exe","BLOCK","BOTH","P2P torrent"),
        ("Block TeamViewer W","C:\\Program Files (x86)\\TeamViewer\\TeamViewer.exe","BLOCK","BOTH","Remote access"),
        ("Block AnyDesk W",   "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe","BLOCK","BOTH","Remote access"),
    ]

    conn = get_connection()
    for name, exe, action, direction, desc in apps:
        conn.execute("""
            INSERT INTO app_rules (name, exe_path, action, direction, enabled, created_at, description)
            VALUES (?, ?, ?, ?, 1, ?, ?)
        """, (name, exe, action, direction, now, desc))
    conn.commit()
    conn.close()


def _seed_default_interfaces():
    """Seed default network layout: eth0=WAN(DHCP), eth1=LAN(10.0.0.1/24)."""
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM interfaces").fetchone()[0]
    conn.close()
    if count > 0:
        return

    now = datetime.now().isoformat()
    conn = get_connection()
    # eth0 — WAN, DHCP from ISP
    conn.execute("""
        INSERT INTO interfaces (name, role, description, ip_mode, ip_address, netmask,
            gateway, mtu, enabled, created_at)
        VALUES ('eth0','WAN','WAN - Internet (DHCP from ISP)','dhcp','','',
                '',1500,1,?)
    """, (now,))
    # eth1 — LAN, static 10.0.0.1/24
    conn.execute("""
        INSERT INTO interfaces (name, role, description, ip_mode, ip_address, netmask,
            gateway, mtu, enabled, created_at)
        VALUES ('eth1','LAN','LAN - Internal network','static','10.0.0.1','255.255.255.0',
                '',1500,1,?)
    """, (now,))
    conn.commit()
    conn.close()

    # Default DHCP pool on LAN (eth1)
    save_dhcp_config(
        interface="eth1",
        start_ip="10.0.0.100",
        end_ip="10.0.0.200",
        subnet_mask="255.255.255.0",
        gateway="10.0.0.1",
        dns1="1.1.1.1",
        dns2="8.8.8.8",
        lease_time=86400,
        domain="aegis.local",
        enabled=1,
    )

    # Save WAN/LAN interface names and enable router mode
    conn = get_connection()
    for key, val in [("wan_interface", "eth0"), ("lan_interface", "eth1"), ("router_mode", "1")]:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, val))
    conn.commit()
    conn.close()


# ─── Firewall Rules ───────────────────────────────────────────────────────────

def get_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM rules ORDER BY priority ASC, id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_rule(name, action, direction, protocol="ANY", local_ip="", remote_ip="",
             local_port="", remote_port="", enabled=1, priority=100, description="",
             interface="", log_match=0):
    conn = get_connection()
    conn.execute("""
        INSERT INTO rules (name, action, direction, protocol, local_ip, remote_ip,
            local_port, remote_port, interface, log_match, enabled, priority, created_at, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, action, direction, protocol, local_ip, remote_ip,
          local_port, remote_port, interface, log_match, enabled, priority,
          datetime.now().isoformat(), description))
    conn.commit()
    conn.close()


def update_rule(rule_id, **kwargs):
    allowed = {"name", "action", "direction", "protocol", "local_ip", "remote_ip",
               "local_port", "remote_port", "enabled", "priority", "description",
               "interface", "log_match"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [rule_id]
    conn = get_connection()
    conn.execute(f"UPDATE rules SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_rule(rule_id):
    conn = get_connection()
    conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


# ─── Logs ─────────────────────────────────────────────────────────────────────

def add_log(action, direction="", protocol="", src_ip="", dst_ip="",
            src_port=None, dst_port=None, process="", rule_name="", details=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO logs (timestamp, action, direction, protocol, src_ip, dst_ip,
            src_port, dst_port, process, rule_name, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), action, direction, protocol, src_ip, dst_ip,
          src_port, dst_port, process, rule_name, details))
    conn.commit()
    conn.close()


def get_logs(limit=500, action_filter=None, search=None):
    conn = get_connection()
    query = "SELECT * FROM logs"
    params = []
    conditions = []
    if action_filter:
        conditions.append("action = ?")
        params.append(action_filter)
    if search:
        conditions.append("(src_ip LIKE ? OR dst_ip LIKE ? OR process LIKE ? OR rule_name LIKE ? OR details LIKE ?)")
        params.extend([f"%{search}%"] * 5)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_logs():
    conn = get_connection()
    conn.execute("DELETE FROM logs")
    conn.commit()
    conn.close()


def prune_logs(max_bytes=2_147_483_648):
    """Delete oldest log entries until the logs table is under max_bytes (default 2GB).
    Also enforces the max_log_entries setting as a secondary limit."""
    conn = get_connection()

    # Check row-count limit first (fast)
    try:
        max_entries = int(get_setting("max_log_entries", "500000"))
    except (TypeError, ValueError):
        max_entries = 500_000

    count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    if count > max_entries:
        # Delete oldest N rows to get back to 80% of max
        keep = int(max_entries * 0.8)
        delete_count = count - keep
        conn.execute("""
            DELETE FROM logs WHERE id IN (
                SELECT id FROM logs ORDER BY id ASC LIMIT ?
            )
        """, (delete_count,))
        conn.commit()

    # Check disk size: SQLite page_count * page_size gives DB file size
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    page_size  = conn.execute("PRAGMA page_size").fetchone()[0]
    db_bytes   = page_count * page_size

    if db_bytes > max_bytes:
        # Estimate log fraction: delete oldest 20% of rows repeatedly until under limit
        while True:
            count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            if count == 0:
                break
            delete_batch = max(1, count // 5)
            conn.execute("""
                DELETE FROM logs WHERE id IN (
                    SELECT id FROM logs ORDER BY id ASC LIMIT ?
                )
            """, (delete_batch,))
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            if page_count * page_size <= max_bytes * 0.85:
                break

        # Reclaim space
        conn.execute("VACUUM")

    conn.close()


def get_log_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as c FROM logs").fetchone()["c"]
    blocked = conn.execute("SELECT COUNT(*) as c FROM logs WHERE action IN ('BLOCK','DROP','THREAT')").fetchone()["c"]
    allowed = conn.execute("SELECT COUNT(*) as c FROM logs WHERE action='ALLOW'").fetchone()["c"]
    today = datetime.now().date().isoformat()
    today_count = conn.execute(
        "SELECT COUNT(*) as c FROM logs WHERE timestamp LIKE ?", (f"{today}%",)
    ).fetchone()["c"]
    conn.close()
    return {"total": total, "blocked": blocked, "allowed": allowed, "today": today_count}


# ─── Network Interfaces ───────────────────────────────────────────────────────

def get_interfaces():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM interfaces ORDER BY role, name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_interface(name, role, ip_mode="static", ip_address="", netmask="255.255.255.0",
                  gateway="", mtu=1500, description="", enabled=1, vlan_id=0,
                  pppoe_user="", pppoe_pass="", mac_override=""):
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO interfaces
            (name, role, description, ip_mode, ip_address, netmask, gateway,
             mtu, enabled, vlan_id, pppoe_user, pppoe_pass, mac_override, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, role, description, ip_mode, ip_address, netmask, gateway,
          mtu, enabled, vlan_id, pppoe_user, pppoe_pass, mac_override,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_interface(iface_id, **kwargs):
    allowed = {"name", "role", "description", "ip_mode", "ip_address", "netmask",
               "gateway", "mtu", "enabled", "vlan_id", "pppoe_user", "pppoe_pass",
               "mac_override", "speed"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [iface_id]
    conn = get_connection()
    conn.execute(f"UPDATE interfaces SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_interface(iface_id):
    conn = get_connection()
    conn.execute("DELETE FROM interfaces WHERE id = ?", (iface_id,))
    conn.commit()
    conn.close()


# ─── Static Routes ────────────────────────────────────────────────────────────

def get_routes():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM routes ORDER BY metric, destination").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_route(destination, netmask, gateway, interface="", metric=1, enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO routes (destination, netmask, gateway, interface, metric, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (destination, netmask, gateway, interface, metric, enabled, description,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_route(route_id):
    conn = get_connection()
    conn.execute("DELETE FROM routes WHERE id = ?", (route_id,))
    conn.commit()
    conn.close()


# ─── DHCP ─────────────────────────────────────────────────────────────────────

def get_dhcp_configs():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM dhcp_config ORDER BY interface").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_dhcp_config(interface, start_ip, end_ip, subnet_mask, gateway="",
                     dns1="1.1.1.1", dns2="8.8.8.8", lease_time=86400,
                     domain="", enabled=1):
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO dhcp_config
            (interface, enabled, start_ip, end_ip, subnet_mask, gateway, dns1, dns2, lease_time, domain, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (interface, enabled, start_ip, end_ip, subnet_mask, gateway, dns1, dns2,
          lease_time, domain, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def get_dhcp_leases():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM dhcp_leases ORDER BY interface, ip").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_dhcp_lease(mac, ip, hostname="", interface=""):
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO dhcp_leases (mac, ip, hostname, interface, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (mac, ip, hostname, interface, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_dhcp_lease(lease_id):
    conn = get_connection()
    conn.execute("DELETE FROM dhcp_leases WHERE id = ?", (lease_id,))
    conn.commit()
    conn.close()


def delete_dhcp_config(interface):
    conn = get_connection()
    conn.execute("DELETE FROM dhcp_config WHERE interface = ?", (interface,))
    conn.commit()
    conn.close()


# ── DHCP Relay ────────────────────────────────────────────────────────────────

def get_dhcp_relay():
    conn = get_connection()
    row = conn.execute("SELECT * FROM dhcp_relay ORDER BY id LIMIT 1").fetchone()
    conn.close()
    if row:
        return dict(row)
    return {"enabled": 0, "server_ip": "", "interfaces": ""}


def save_dhcp_relay(enabled, server_ip, interfaces):
    conn = get_connection()
    existing = conn.execute("SELECT id FROM dhcp_relay LIMIT 1").fetchone()
    if existing:
        conn.execute(
            "UPDATE dhcp_relay SET enabled=?, server_ip=?, interfaces=? WHERE id=?",
            (1 if enabled else 0, server_ip, interfaces, existing["id"])
        )
    else:
        conn.execute(
            "INSERT INTO dhcp_relay (enabled, server_ip, interfaces, created_at) VALUES (?,?,?,?)",
            (1 if enabled else 0, server_ip, interfaces, datetime.now().isoformat())
        )
    conn.commit()
    conn.close()
    conn.execute("DELETE FROM dhcp_leases WHERE id = ?", (lease_id,))
    conn.commit()
    conn.close()


# ─── DNS ──────────────────────────────────────────────────────────────────────

def get_dns_settings():
    conn = get_connection()
    row = conn.execute("SELECT * FROM dns_settings WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else {}


def save_dns_settings(**kwargs):
    allowed = {"primary_dns", "secondary_dns", "tertiary_dns", "search_domain",
               "enable_caching", "enable_dnssec", "block_rebind", "local_domain"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    fields["updated_at"] = datetime.now().isoformat()
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values())
    conn = get_connection()
    conn.execute(f"UPDATE dns_settings SET {sets} WHERE id = 1", values)
    conn.commit()
    conn.close()


# ─── NAT Rules ────────────────────────────────────────────────────────────────

def get_nat_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM nat_rules ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_nat_rule(name, nat_type, internal_ip, external_ip="", external_port="",
                 internal_port="", protocol="TCP", interface="", enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO nat_rules (name, type, external_ip, external_port, internal_ip,
            internal_port, protocol, interface, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, nat_type, external_ip, external_port, internal_ip, internal_port,
          protocol, interface, enabled, description, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_nat_rule(rule_id):
    conn = get_connection()
    conn.execute("DELETE FROM nat_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


# ─── QoS ──────────────────────────────────────────────────────────────────────

def get_qos_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM qos_rules ORDER BY priority, id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_qos_rule(name, priority="NORMAL", protocol="ANY", src_ip="", dst_ip="",
                 src_port="", dst_port="", bandwidth_limit=0, bandwidth_unit="kbps",
                 enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO qos_rules (name, priority, protocol, src_ip, dst_ip, src_port, dst_port,
            bandwidth_limit, bandwidth_unit, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, priority, protocol, src_ip, dst_ip, src_port, dst_port,
          bandwidth_limit, bandwidth_unit, enabled, description, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_qos_rule(rule_id):
    conn = get_connection()
    conn.execute("DELETE FROM qos_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


# ─── App Control ──────────────────────────────────────────────────────────────

def get_app_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM app_rules ORDER BY name ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_app_rule(name, exe_path, action, direction="BOTH", enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO app_rules (name, exe_path, action, direction, enabled, created_at, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (name, exe_path, action, direction, enabled, datetime.now().isoformat(), description))
    conn.commit()
    conn.close()


def update_app_rule(rule_id, **kwargs):
    allowed = {"name", "exe_path", "action", "direction", "enabled", "description"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [rule_id]
    conn = get_connection()
    conn.execute(f"UPDATE app_rules SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_app_rule(rule_id):
    conn = get_connection()
    conn.execute("DELETE FROM app_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


# ─── Web Filter ───────────────────────────────────────────────────────────────

def get_web_filters():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM web_filter ORDER BY category, pattern").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_web_filter(pattern, category="Custom", action="BLOCK", enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO web_filter (pattern, category, action, enabled, created_at, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (pattern, category, action, enabled, datetime.now().isoformat(), description))
    conn.commit()
    conn.close()


def update_web_filter(filter_id, **kwargs):
    allowed = {"pattern", "category", "action", "enabled", "description"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [filter_id]
    conn = get_connection()
    conn.execute(f"UPDATE web_filter SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_web_filter(filter_id):
    conn = get_connection()
    conn.execute("DELETE FROM web_filter WHERE id = ?", (filter_id,))
    conn.commit()
    conn.close()


def get_web_categories():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM web_categories ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_web_category(name, enabled):
    conn = get_connection()
    conn.execute("UPDATE web_categories SET enabled = ? WHERE name = ?", (int(enabled), name))
    conn.commit()
    conn.close()


# ─── VPN Profiles ─────────────────────────────────────────────────────────────

def get_vpn_profiles():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM vpn_profiles ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_vpn_profile(name, vpn_type, config_path, server="", auto_connect=0,
                    public_key="", private_key=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO vpn_profiles (name, type, config_path, server, auto_connect,
            public_key, private_key, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, vpn_type, config_path, server, auto_connect,
          public_key, private_key, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_vpn_profile(profile_id, **kwargs):
    allowed = {"name", "type", "config_path", "server", "status", "auto_connect",
               "last_connected", "public_key", "private_key"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [profile_id]
    conn = get_connection()
    conn.execute(f"UPDATE vpn_profiles SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_vpn_profile(profile_id):
    conn = get_connection()
    conn.execute("DELETE FROM vpn_profiles WHERE id = ?", (profile_id,))
    conn.commit()
    conn.close()


# ─── IPSec Tunnels ────────────────────────────────────────────────────────────

def get_ipsec_tunnels():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM ipsec_tunnels ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_ipsec_tunnel(name, local_subnet, remote_gateway, remote_subnet, psk,
                     ike_version="IKEv2", ike_cipher="AES256", ike_hash="SHA256",
                     dh_group="DH14", esp_cipher="AES256", esp_hash="SHA256",
                     enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO ipsec_tunnels
            (name, local_subnet, remote_gateway, remote_subnet, psk, ike_version,
             ike_cipher, ike_hash, dh_group, esp_cipher, esp_hash, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, local_subnet, remote_gateway, remote_subnet, psk, ike_version,
          ike_cipher, ike_hash, dh_group, esp_cipher, esp_hash, enabled, description,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_ipsec_tunnel(tunnel_id):
    conn = get_connection()
    conn.execute("DELETE FROM ipsec_tunnels WHERE id = ?", (tunnel_id,))
    conn.commit()
    conn.close()


def update_ipsec_tunnel(tunnel_id, **kwargs):
    allowed = {"name", "local_subnet", "remote_gateway", "remote_subnet", "psk",
               "ike_version", "ike_cipher", "ike_hash", "dh_group", "esp_cipher",
               "esp_hash", "enabled", "status", "description"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [tunnel_id]
    conn = get_connection()
    conn.execute(f"UPDATE ipsec_tunnels SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


# ─── Authentication ───────────────────────────────────────────────────────────

def get_users():
    conn = get_connection()
    rows = conn.execute("SELECT id,username,full_name,email,role,group_name,enabled,created_at,last_login FROM auth_users ORDER BY username").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_user(username, password_hash, full_name="", email="", role="user",
             group_name="", enabled=1):
    conn = get_connection()
    conn.execute("""
        INSERT INTO auth_users (username, password_hash, full_name, email, role, group_name, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, password_hash, full_name, email, role, group_name, enabled,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_user(user_id, **kwargs):
    allowed = {"username", "password_hash", "full_name", "email", "role",
               "group_name", "enabled", "last_login"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [user_id]
    conn = get_connection()
    conn.execute(f"UPDATE auth_users SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = get_connection()
    conn.execute("DELETE FROM auth_users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_groups():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM auth_groups ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Certificates ─────────────────────────────────────────────────────────────

def get_certificates():
    conn = get_connection()
    rows = conn.execute("SELECT id,name,type,subject,issuer,not_before,not_after,fingerprint,usage,created_at FROM certificates ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_certificate(name, cert_type, subject="", issuer="", not_before="", not_after="",
                    fingerprint="", cert_pem="", key_pem="", usage="general"):
    conn = get_connection()
    conn.execute("""
        INSERT INTO certificates (name, type, subject, issuer, not_before, not_after,
            fingerprint, cert_pem, key_pem, usage, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, cert_type, subject, issuer, not_before, not_after,
          fingerprint, cert_pem, key_pem, usage, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_certificate(cert_id):
    conn = get_connection()
    conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
    conn.commit()
    conn.close()


# ─── NAT Rules ────────────────────────────────────────────────────────────────

def get_nat_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM nat_rules ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Proxy Rules ──────────────────────────────────────────────────────────────

def get_proxy_rules():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM proxy_rules ORDER BY type, name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_proxy_rule(name, proxy_type, action, pattern="", content_type="",
                   max_size=0, enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO proxy_rules (name, type, action, pattern, content_type, max_size, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, proxy_type, action, pattern, content_type, max_size, enabled, description,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_proxy_rule(rule_id):
    conn = get_connection()
    conn.execute("DELETE FROM proxy_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


# ─── Log Servers ──────────────────────────────────────────────────────────────

def get_log_servers():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM log_servers ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_log_server(name, host, port=514, protocol="UDP", enabled=1):
    conn = get_connection()
    conn.execute("""
        INSERT INTO log_servers (name, host, port, protocol, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, host, port, protocol, enabled, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_log_server(server_id):
    conn = get_connection()
    conn.execute("DELETE FROM log_servers WHERE id = ?", (server_id,))
    conn.commit()
    conn.close()


# ─── Settings ─────────────────────────────────────────────────────────────────

def get_setting(key, default=None):
    conn = get_connection()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_connection()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()


def get_all_settings():
    conn = get_connection()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


# ─── VLANs ────────────────────────────────────────────────────────────────────

def get_vlans():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM vlans ORDER BY parent_interface, vlan_id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_vlan(vlan_id, name, parent_interface, ip_address="", netmask="255.255.255.0",
             gateway="", zone="OPTIONAL", dhcp_enabled=0, dhcp_start="", dhcp_end="",
             mtu=1500, enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO vlans (vlan_id, name, parent_interface, ip_address, netmask, gateway,
            zone, dhcp_enabled, dhcp_start, dhcp_end, mtu, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (vlan_id, name, parent_interface, ip_address, netmask, gateway, zone,
          dhcp_enabled, dhcp_start, dhcp_end, mtu, enabled, description,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_vlan(vlan_db_id, **kwargs):
    allowed = {"vlan_id", "name", "parent_interface", "ip_address", "netmask", "gateway",
               "zone", "dhcp_enabled", "dhcp_start", "dhcp_end", "mtu", "enabled", "description"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [vlan_db_id]
    conn = get_connection()
    conn.execute(f"UPDATE vlans SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_vlan(vlan_db_id):
    conn = get_connection()
    conn.execute("DELETE FROM vlans WHERE id = ?", (vlan_db_id,))
    conn.commit()
    conn.close()


# ─── DMZ ──────────────────────────────────────────────────────────────────────

def get_dmz_configs():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM dmz_config ORDER BY interface").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_dmz_config(interface, ip_address="", netmask="255.255.255.0",
                    allowed_ports="80,443", block_dmz_to_lan=1, log_all=1, enabled=1):
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO dmz_config
            (interface, ip_address, netmask, allowed_ports, block_dmz_to_lan, log_all, enabled, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (interface, ip_address, netmask, allowed_ports, block_dmz_to_lan,
          log_all, enabled, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def delete_dmz_config(dmz_id):
    conn = get_connection()
    conn.execute("DELETE FROM dmz_config WHERE id = ?", (dmz_id,))
    conn.commit()
    conn.close()


# ─── SSL VPN ───────────────────────────────────────────────────────────────────

def get_ssl_vpn_config():
    conn = get_connection()
    row = conn.execute("SELECT * FROM ssl_vpn_config WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else {}


def save_ssl_vpn_config(**kwargs):
    allowed = {
        "enabled", "port", "protocol", "interface", "server_subnet", "server_netmask",
        "dns1", "dns2", "cipher", "auth", "tls_version", "redirect_gateway", "compress",
        "pki_dir", "ca_cert", "server_cert", "server_key", "dh_params", "ta_key",
        "extra_opts", "status"
    }
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    fields["updated_at"] = datetime.now().isoformat()
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values())
    conn = get_connection()
    conn.execute(f"UPDATE ssl_vpn_config SET {sets} WHERE id = 1", values)
    conn.commit()
    conn.close()


# ─── SSL VPN Push Routes ─────────────────────────────────────────────────────

def get_ssl_vpn_routes():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM ssl_vpn_routes ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_ssl_vpn_route(network: str, netmask: str, description: str = ""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO ssl_vpn_routes (network, netmask, description) VALUES (?, ?, ?)",
        (network, netmask, description)
    )
    conn.commit()
    conn.close()


def delete_ssl_vpn_route(route_id: int):
    conn = get_connection()
    conn.execute("DELETE FROM ssl_vpn_routes WHERE id = ?", (route_id,))
    conn.commit()
    conn.close()


# ─── VPN Users ────────────────────────────────────────────────────────────────

def get_vpn_users():
    conn = get_connection()
    rows = conn.execute(
        "SELECT id,username,full_name,email,group_name,tunnel_ip,mfa_enabled,"
        "enabled,max_connections,bandwidth_limit,allowed_networks,created_at,"
        "last_connected,expires_at FROM vpn_users ORDER BY username"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_vpn_user(username, password_hash, full_name="", email="", group_name="vpn-users",
                 tunnel_ip="", enabled=1, max_connections=1, bandwidth_limit=0,
                 allowed_networks="", expires_at=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO vpn_users
            (username, password_hash, full_name, email, group_name, tunnel_ip,
             enabled, max_connections, bandwidth_limit, allowed_networks, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, password_hash, full_name, email, group_name, tunnel_ip,
          enabled, max_connections, bandwidth_limit, allowed_networks, expires_at,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_vpn_user(user_id, **kwargs):
    allowed = {
        "username", "password_hash", "full_name", "email", "group_name", "tunnel_ip",
        "cert_path", "key_path", "config_path", "mfa_secret", "mfa_enabled",
        "enabled", "max_connections", "bandwidth_limit", "allowed_networks",
        "last_connected", "expires_at"
    }
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [user_id]
    conn = get_connection()
    conn.execute(f"UPDATE vpn_users SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_vpn_user(user_id):
    conn = get_connection()
    conn.execute("DELETE FROM vpn_users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_vpn_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM vpn_users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ─── Branch Office VPN (BOV) ──────────────────────────────────────────────────

def get_bov_tunnels():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM bov_tunnels ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_bov_tunnel(name, tunnel_type, remote_gateway, remote_subnets,
                   local_subnets="", local_gateway="", psk="",
                   ike_version="IKEv2", ike_cipher="AES256", ike_hash="SHA256",
                   ike_dh="DH14", ike_lifetime=28800,
                   esp_cipher="AES256", esp_hash="SHA256", esp_lifetime=3600,
                   pfs_group="DH14", dpd_enabled=1, dpd_interval=30, dpd_timeout=120,
                   nat_traversal=1, aggressive_mode=0,
                   l2tp_local_ip="", l2tp_remote_ip="",
                   ssl_port=1194, ssl_protocol="udp", ssl_cipher="AES-256-GCM",
                   ssl_ca_cert="", ssl_cert="", ssl_key="", ssl_ta_key="",
                   wg_private_key="", wg_public_key="", wg_peer_pubkey="",
                   wg_preshared_key="", wg_port=51820, wg_keepalive=25,
                   enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO bov_tunnels
            (name, type, remote_gateway, remote_subnets, local_subnets, local_gateway,
             psk, ike_version, ike_cipher, ike_hash, ike_dh, ike_lifetime,
             esp_cipher, esp_hash, esp_lifetime, pfs_group, dpd_enabled, dpd_interval,
             dpd_timeout, nat_traversal, aggressive_mode, l2tp_local_ip, l2tp_remote_ip,
             ssl_port, ssl_protocol, ssl_cipher, ssl_ca_cert, ssl_cert, ssl_key, ssl_ta_key,
             wg_private_key, wg_public_key, wg_peer_pubkey, wg_preshared_key,
             wg_port, wg_keepalive, enabled, description, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (name, tunnel_type, remote_gateway, remote_subnets, local_subnets, local_gateway,
          psk, ike_version, ike_cipher, ike_hash, ike_dh, ike_lifetime,
          esp_cipher, esp_hash, esp_lifetime, pfs_group, dpd_enabled, dpd_interval,
          dpd_timeout, nat_traversal, aggressive_mode, l2tp_local_ip, l2tp_remote_ip,
          ssl_port, ssl_protocol, ssl_cipher, ssl_ca_cert, ssl_cert, ssl_key, ssl_ta_key,
          wg_private_key, wg_public_key, wg_peer_pubkey, wg_preshared_key,
          wg_port, wg_keepalive, enabled, description, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_bov_tunnel(tunnel_id, **kwargs):
    allowed = {
        "name", "type", "status", "enabled", "local_gateway", "local_subnets",
        "remote_gateway", "remote_subnets", "psk", "ike_version", "ike_cipher",
        "ike_hash", "ike_dh", "ike_lifetime", "esp_cipher", "esp_hash", "esp_lifetime",
        "pfs_group", "dpd_enabled", "dpd_interval", "dpd_timeout", "nat_traversal",
        "aggressive_mode", "l2tp_local_ip", "l2tp_remote_ip", "ssl_port", "ssl_protocol",
        "ssl_cipher", "ssl_ca_cert", "ssl_cert", "ssl_key", "ssl_ta_key",
        "wg_private_key", "wg_public_key", "wg_peer_pubkey", "wg_preshared_key",
        "wg_port", "wg_keepalive", "bytes_in", "bytes_out", "last_up", "description"
    }
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [tunnel_id]
    conn = get_connection()
    conn.execute(f"UPDATE bov_tunnels SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_bov_tunnel(tunnel_id):
    conn = get_connection()
    conn.execute("DELETE FROM bov_tunnels WHERE id = ?", (tunnel_id,))
    conn.commit()
    conn.close()


# ─── Multi-WAN Links ──────────────────────────────────────────────────────────

def get_wan_links():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM wan_links ORDER BY priority ASC, id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_wan_link(name, interface, gateway, weight=1, priority=1, mode="failover",
                 check_ip="8.8.8.8", check_interval=10, check_timeout=3,
                 check_failures=3, enabled=1, description=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO wan_links (name, interface, gateway, weight, priority, mode,
            check_ip, check_interval, check_timeout, check_failures,
            enabled, description, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (name, interface, gateway, weight, priority, mode,
          check_ip, check_interval, check_timeout, check_failures,
          enabled, description, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_wan_link(link_id, **kwargs):
    allowed = {"name","interface","gateway","weight","priority","mode","check_ip",
               "check_interval","check_timeout","check_failures","enabled",
               "status","latency_ms","last_check","description"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [link_id]
    conn = get_connection()
    conn.execute(f"UPDATE wan_links SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_wan_link(link_id):
    conn = get_connection()
    conn.execute("DELETE FROM wan_links WHERE id = ?", (link_id,))
    conn.commit()
    conn.close()


# ─── HA Config ────────────────────────────────────────────────────────────────

def get_ha_config():
    conn = get_connection()
    row = conn.execute("SELECT * FROM ha_config WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else {}


def save_ha_config(**kwargs):
    allowed = {"enabled","role","interface","virtual_ip","virtual_ip_mask",
               "router_id","priority","advert_interval","auth_pass","peer_ip",
               "preempt","sync_enabled","sync_peer","sync_interval"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    fields["updated_at"] = datetime.now().isoformat()
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values())
    conn = get_connection()
    conn.execute(f"UPDATE ha_config SET {sets} WHERE id = 1", values)
    conn.commit()
    conn.close()


# ─── DLP custom patterns ──────────────────────────────────────────────────────

def get_dlp_patterns():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM dlp_patterns ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_dlp_pattern(name, pattern, severity="MEDIUM", enabled=1):
    conn = get_connection()
    conn.execute(
        "INSERT INTO dlp_patterns (name, pattern, severity, enabled, created_at) VALUES (?,?,?,?,?)",
        (name, pattern, severity, enabled, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def update_dlp_pattern(pattern_id, **kwargs):
    allowed = {"name", "pattern", "severity", "enabled"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k} = ?" for k in fields)
    conn = get_connection()
    conn.execute(f"UPDATE dlp_patterns SET {sets} WHERE id = ?",
                 list(fields.values()) + [pattern_id])
    conn.commit()
    conn.close()


def delete_dlp_pattern(pattern_id):
    conn = get_connection()
    conn.execute("DELETE FROM dlp_patterns WHERE id = ?", (pattern_id,))
    conn.commit()
    conn.close()
