"""Site-to-Site IPSec VPN Manager using Windows built-in IKEv2/IPSec."""
import subprocess
import json
from db import database


def _ps(script, timeout=15):
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return False, "", str(e)


# ─── Site-to-Site IPSec (Windows built-in via netsh/PowerShell) ──────────────

def create_ipsec_tunnel(name, local_ip, remote_ip, psk, local_subnet, remote_subnet,
                         ike_cipher="AES256", ike_hash="SHA256", dh_group="DH14",
                         esp_cipher="AES256", esp_hash="SHA256"):
    """
    Create a Site-to-Site IPSec tunnel using Windows IKEv2.
    Requires elevated privileges.
    """
    # Create IKE main mode policy
    script = f"""
$mmCrypto = New-NetIPsecMainModeCryptoSet -Name "AegisGuard-MM-{name}" `
    -DisplayName "AegisGuard MM {name}" `
    -Proposal (New-NetIPsecMainModeCryptoProposal `
        -Encryption {ike_cipher} `
        -Hash {ike_hash} `
        -KeyExchange {dh_group})

$qmCrypto = New-NetIPsecQuickModeCryptoSet -Name "AegisGuard-QM-{name}" `
    -DisplayName "AegisGuard QM {name}" `
    -Proposal (New-NetIPsecQuickModeCryptoProposal `
        -Encryption {esp_cipher} `
        -ESPHash {esp_hash} `
        -Encapsulation ESP)

$auth = New-NetIPsecAuthProposal -Machine -PreSharedKey "{psk}"
$authSet = New-NetIPsecPhase1AuthSet -Name "AegisGuard-Auth-{name}" `
    -DisplayName "AegisGuard Auth {name}" `
    -Proposal $auth

New-NetIPsecRule -Name "AegisGuard-IPSec-{name}" `
    -DisplayName "AegisGuard IPSec {name}" `
    -LocalAddress {local_subnet} `
    -RemoteAddress {remote_subnet} `
    -Phase1AuthSet "AegisGuard-Auth-{name}" `
    -InboundSecurity Require `
    -OutboundSecurity Require `
    -KeyModule IKEv2 `
    -MainModeCryptoSet "AegisGuard-MM-{name}" `
    -QuickModeCryptoSet "AegisGuard-QM-{name}"
"""
    ok, out, err = _ps(script, timeout=30)
    if ok or "already exists" in err.lower():
        database.add_log("INFO", details=f"IPSec tunnel created: {name} ({local_subnet} <-> {remote_subnet})")
        return True, "IPSec tunnel created"
    return False, err or out


def remove_ipsec_tunnel(name):
    script = f"""
Remove-NetIPsecRule -Name "AegisGuard-IPSec-{name}" -ErrorAction SilentlyContinue
Remove-NetIPsecMainModeCryptoSet -Name "AegisGuard-MM-{name}" -ErrorAction SilentlyContinue
Remove-NetIPsecQuickModeCryptoSet -Name "AegisGuard-QM-{name}" -ErrorAction SilentlyContinue
Remove-NetIPsecPhase1AuthSet -Name "AegisGuard-Auth-{name}" -ErrorAction SilentlyContinue
"""
    ok, out, err = _ps(script)
    database.add_log("INFO", details=f"IPSec tunnel removed: {name}")
    return True, "Removed"


def get_ipsec_tunnels():
    script = """
Get-NetIPsecRule | Where-Object {$_.Name -like 'AegisGuard-IPSec-*'} |
    Select-Object Name, DisplayName, Enabled, PrimaryStatus |
    ConvertTo-Json
"""
    ok, out, err = _ps(script)
    if ok and out:
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return data
        except json.JSONDecodeError:
            pass
    return []


def get_ipsec_sa():
    """Get active IPSec Security Associations."""
    script = """
Get-NetIPsecMainModeSA | Select-Object LocalAddress, RemoteAddress, State |
    ConvertTo-Json -ErrorAction SilentlyContinue
"""
    ok, out, err = _ps(script)
    if ok and out:
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return data
        except json.JSONDecodeError:
            pass
    return []


def enable_ipsec_tunnel(name):
    ok, out, err = _ps(f'Set-NetIPsecRule -Name "AegisGuard-IPSec-{name}" -Enabled True')
    return ok, err or out


def disable_ipsec_tunnel(name):
    ok, out, err = _ps(f'Set-NetIPsecRule -Name "AegisGuard-IPSec-{name}" -Enabled False')
    return ok, err or out


def generate_psk(length=32):
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(alphabet) for _ in range(length))
