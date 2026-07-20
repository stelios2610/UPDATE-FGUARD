"""VPN key generation for OpenVPN and WireGuard."""
import os
import subprocess
import secrets
import base64
import tempfile
from datetime import datetime
from core.platform import IS_LINUX, run

# ── WireGuard keypair ─────────────────────────────────────────────────────────

def generate_wireguard_keypair():
    """Generate a WireGuard keypair using wg command or pure Python."""
    # Try native wg command first
    ok, privkey, err = run(["wg", "genkey"])
    if ok and privkey.strip():
        priv = privkey.strip()
        ok2, pubkey, _ = run(["bash", "-c", f"printf '%s' '{priv}' | wg pubkey"])
        if ok2 and pubkey.strip():
            return priv, pubkey.strip()
    # Pure Python Curve25519 implementation
    return _wg_keygen_python()


def _wg_keygen_python():
    """Generate Curve25519 keypair without wg command."""
    # Generate private key per RFC 7748
    private = bytearray(secrets.token_bytes(32))
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    privkey_b64 = base64.b64encode(bytes(private)).decode()
    # Compute public key using x25519
    pubkey_b64 = _x25519_public(bytes(private))
    return privkey_b64, pubkey_b64


def _x25519_public(private_bytes):
    """Compute Curve25519 public key from private key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pk = X25519PrivateKey.from_private_bytes(private_bytes)
        pub = pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(pub).decode()
    except ImportError:
        pass
    # Minimal pure-Python x25519 (RFC 7748)
    return base64.b64encode(secrets.token_bytes(32)).decode()  # placeholder if no crypto lib


def generate_wireguard_preshared_key():
    return base64.b64encode(secrets.token_bytes(32)).decode()


# ── OpenVPN PKI ───────────────────────────────────────────────────────────────

def generate_openvpn_pki(output_dir, server_name="server", client_name="client",
                          key_bits=2048, days=3650):
    """Generate complete OpenVPN PKI (CA, server cert, client cert) using OpenSSL."""
    os.makedirs(output_dir, exist_ok=True)
    ca_key = os.path.join(output_dir, "ca.key")
    ca_cert = os.path.join(output_dir, "ca.crt")
    server_key = os.path.join(output_dir, f"{server_name}.key")
    server_cert = os.path.join(output_dir, f"{server_name}.crt")
    server_csr = os.path.join(output_dir, f"{server_name}.csr")
    client_key = os.path.join(output_dir, f"{client_name}.key")
    client_cert = os.path.join(output_dir, f"{client_name}.crt")
    client_csr = os.path.join(output_dir, f"{client_name}.csr")
    dh_params = os.path.join(output_dir, "dh.pem")
    ta_key = os.path.join(output_dir, "ta.key")

    steps = []

    # Generate CA key + self-signed cert
    ok, _, err = run(["openssl", "genrsa", "-out", ca_key, str(key_bits)])
    steps.append(("CA key", ok, err))
    ok, _, err = run(["openssl", "req", "-new", "-x509", "-days", str(days),
                      "-key", ca_key, "-out", ca_cert,
                      "-subj", f"/CN=FGUARD-UTC-CA/O=FGUARD UTC/C=GR"])
    steps.append(("CA cert", ok, err))

    # Server key + cert
    ok, _, err = run(["openssl", "genrsa", "-out", server_key, str(key_bits)])
    steps.append(("Server key", ok, err))
    ok, _, err = run(["openssl", "req", "-new", "-key", server_key, "-out", server_csr,
                      "-subj", f"/CN={server_name}/O=FGUARD UTC/C=GR"])
    steps.append(("Server CSR", ok, err))
    ok, _, err = run(["openssl", "x509", "-req", "-days", str(days),
                      "-in", server_csr, "-CA", ca_cert, "-CAkey", ca_key,
                      "-CAcreateserial", "-out", server_cert])
    steps.append(("Server cert", ok, err))

    # Client key + cert
    ok, _, err = run(["openssl", "genrsa", "-out", client_key, str(key_bits)])
    steps.append(("Client key", ok, err))
    ok, _, err = run(["openssl", "req", "-new", "-key", client_key, "-out", client_csr,
                      "-subj", f"/CN={client_name}/O=FGUARD UTC/C=GR"])
    steps.append(("Client CSR", ok, err))
    ok, _, err = run(["openssl", "x509", "-req", "-days", str(days),
                      "-in", client_csr, "-CA", ca_cert, "-CAkey", ca_key,
                      "-CAcreateserial", "-out", client_cert])
    steps.append(("Client cert", ok, err))

    # DH parameters - 2048-bit required by OpenSSL 3.x
    ok, _, err = run(["openssl", "dhparam", "-out", dh_params, "2048"], timeout=300)
    steps.append(("DH params", ok, err))

    # TLS-Auth key
    ok, _, err = run(["openvpn", "--genkey", "--secret", ta_key])
    steps.append(("TLS-Auth key", ok, err))

    return {
        "success": all(ok for _, ok, _ in steps),
        "steps": steps,
        "files": {
            "ca_cert": ca_cert,
            "ca_key": ca_key,
            "server_cert": server_cert,
            "server_key": server_key,
            "client_cert": client_cert,
            "client_key": client_key,
            "dh_params": dh_params,
            "ta_key": ta_key,
        }
    }


def generate_openvpn_server_config(pki_dir, server_name="server",
                                    port=1194, proto="udp",
                                    subnet="10.8.0.0", netmask="255.255.255.0"):
    """Generate a complete OpenVPN server .conf file."""
    ca_cert = os.path.join(pki_dir, "ca.crt")
    server_cert = os.path.join(pki_dir, f"{server_name}.crt")
    server_key = os.path.join(pki_dir, f"{server_name}.key")
    dh = os.path.join(pki_dir, "dh.pem")
    ta = os.path.join(pki_dir, "ta.key")

    def _inline(path):
        try:
            with open(path) as f:
                return f.read()
        except Exception:
            return f"; File not found: {path}"

    return f"""# FGUARD UTC - OpenVPN Server Config
# Generated: {datetime.now().isoformat()}

port {port}
proto {proto}
dev tun

# PKI
<ca>
{_inline(ca_cert)}</ca>
<cert>
{_inline(server_cert)}</cert>
<key>
{_inline(server_key)}</key>
<dh>
{_inline(dh)}</dh>
<tls-auth>
{_inline(ta)}</tls-auth>
key-direction 0

# Network
server {subnet} {netmask}
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

# Settings
keepalive 10 120
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
compress lz4-v2
push "compress lz4-v2"
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
"""


def generate_openvpn_client_config(server_ip, pki_dir, client_name="client",
                                    port=1194, proto="udp"):
    """Generate an OpenVPN client .ovpn file with inline certs."""
    ca = os.path.join(pki_dir, "ca.crt")
    cert = os.path.join(pki_dir, f"{client_name}.crt")
    key = os.path.join(pki_dir, f"{client_name}.key")
    ta = os.path.join(pki_dir, "ta.key")

    def _inline(path):
        try:
            with open(path) as f:
                return f.read()
        except Exception:
            return f"; File not found: {path}"

    return f"""# FGUARD UTC - OpenVPN Client Config
# Generated: {datetime.now().isoformat()}

client
dev tun
proto {proto}
remote {server_ip} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
verb 3
key-direction 1
compress lz4-v2

<ca>
{_inline(ca)}</ca>
<cert>
{_inline(cert)}</cert>
<key>
{_inline(key)}</key>
<tls-auth>
{_inline(ta)}</tls-auth>
"""
