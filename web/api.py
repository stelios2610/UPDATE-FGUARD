"""FGUARD UTC Web API - Complete FastAPI backend."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List
import io
import psutil
from web.auth import (require_auth, attempt_login, create_session,
                      delete_session, get_session_user, ensure_default_admin,
                      hash_password, is_rate_limited, COOKIE_NAME, SESSION_HOURS)

from db import database
from core import (monitor, ips, rules_engine, web_filter, app_control,
                  vpn_manager, network_manager, gateway_av, reputation,
                  spam_filter, network_discovery, dlp, vpn_keygen, mfa,
                  ssl_vpn, bov_manager)
from core.platform import IS_LINUX, is_root, run
from core import multiwan_manager, ha_manager
from core.ipsec_manager import (create_ipsec_tunnel, remove_ipsec_tunnel,
                                 get_ipsec_tunnels, get_ipsec_sa, generate_psk)
from core.mfa import hash_password
from core import license_manager
from core import updater

database.initialize()
ensure_default_admin()
ips.start()
reputation.init()
multiwan_manager.start()
ha_manager.start_sync()

# Ensure AEGISGUARD iptables chains exist at startup with safe base rules
from core.platform import IS_LINUX as _IS_LINUX
if _IS_LINUX:
    try:
        rules_engine._ensure_chains()
    except Exception:
        pass

# Re-apply web filter iptables rules on every startup so they survive reboots.
# Must run AFTER _ensure_chains() so our DROP rules land at position 1
# (before the ACCEPT rules that _ensure_chains sets up).
if _IS_LINUX:
    try:
        if database.get_setting("web_filter_enabled", "1") == "1":
            web_filter.apply_filters()
    except Exception:
        pass

# Apply DHCP config to dnsmasq on every startup so fresh installs work
if _IS_LINUX:
    try:
        network_manager.write_dhcp_config()
    except Exception:
        pass

# Re-apply BOV tunnels after power outage / restart
if _IS_LINUX:
    try:
        bov_manager.restore_tunnels_on_boot()
    except Exception:
        pass

# Re-apply SSL VPN internet NAT rules on startup (needed on new servers)
if _IS_LINUX:
    try:
        _ssl_cfg = database.get_ssl_vpn_config()
        if _ssl_cfg and _ssl_cfg.get("redirect_gateway", 1) and ssl_vpn.is_pki_initialized():
            ssl_vpn.apply_vpn_internet_nat()
    except Exception:
        pass

# ── Background log pruning (every hour, 2 GB limit) ──────────────────────────
import threading as _threading

def _log_pruner():
    import time
    while True:
        time.sleep(3600)
        try:
            database.prune_logs(max_bytes=2_147_483_648)
        except Exception:
            pass

_threading.Thread(target=_log_pruner, daemon=True).start()

# ── Daily update checker ──────────────────────────────────────────────────────
updater.start_daily_check()

# ── License enforcement — unapply rules when license is not active ────────────
def _license_enforcer():
    """Runs at startup and every hour. If license is expired/missing/invalid,
    automatically removes webfilter (dnsmasq + hosts) and GeoIP iptables rules."""
    import time
    from core import license_manager as _lm
    from core import web_filter as _wf
    from core import geoblock as _gb

    _last_status = [None]  # track status changes

    def _enforce():
        if not _IS_LINUX:
            return
        status, _ = _lm.validate_license(force=True)
        if status not in ("valid", "expiring"):
            # Only run cleanup if status changed (or first run)
            if _last_status[0] != status:
                try:
                    _wf.remove_filters()
                    _wf.flush_dns()
                except Exception:
                    pass
                try:
                    _gb.remove_geoblock()
                except Exception:
                    pass
        _last_status[0] = status

    # Check immediately at startup (small delay to let service init)
    time.sleep(5)
    _enforce()

    while True:
        time.sleep(3600)
        _enforce()

if _IS_LINUX:
    _threading.Thread(target=_license_enforcer, daemon=True).start()

app = FastAPI(title="AegisGuard", version="1.0.0", docs_url=None,
             openapi_url=None)  # disable openapi exposure

# ── Security headers middleware ───────────────────────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        if "server" in response.headers:
            del response.headers["server"]
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ── Auth middleware — protects all HTML pages ─────────────────────────────────
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        redirect = require_auth(request)
        if redirect:
            return redirect
        return await call_next(request)

app.add_middleware(AuthMiddleware)

BASE_DIR = os.path.dirname(__file__)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def _auto_vpn_rules(vpn_name: str, protocol: str, port: str):
    """Auto-create firewall ALLOW rules for a VPN service."""
    existing = [r["name"] for r in database.get_rules()]
    rule_name = f"Allow {vpn_name} ({protocol}/{port})"
    if rule_name not in existing:
        database.add_rule(
            name=rule_name,
            action="ALLOW", direction="IN",
            protocol=protocol,
            remote_port=port,
            enabled=1, priority=50,
            description=f"Auto-created by {vpn_name} setup"
        )
        # Apply to system immediately
        rules = database.get_rules()
        new_rule = next((r for r in rules if r["name"] == rule_name), None)
        if new_rule:
            rules_engine.sync_rule_to_system(new_rule)


def _require_license(feature: str = "This feature"):
    """Raise HTTP 403 if license is expired or missing."""
    if IS_LINUX and not license_manager.is_licensed():
        raise HTTPException(
            status_code=403,
            detail=f"{feature} requires an active FGUARD UTC license. Please contact your provider to renew."
        )


def _ctx(request, **kw):
    stats = database.get_log_stats()
    alerts = ips.get_alerts(5)
    vpn_statuses = vpn_manager.get_all_statuses()
    connected_vpns = sum(1 for s in vpn_statuses.values() if s.get("status") == "Connected")
    lic_status, lic_info = license_manager.validate_license() if IS_LINUX else ("valid", {"days_remaining": 9999, "customer": "", "expires": ""})
    return templates.TemplateResponse(request, kw.pop("template"), {
        "stats": stats,
        "threat_count": len(alerts),
        "is_linux": IS_LINUX,
        "is_root": is_root(),
        "connected_vpns": connected_vpns,
        "lic_status": lic_status,
        "lic_days": lic_info.get("days_remaining", 0),
        "lic_customer": lic_info.get("customer", ""),
        "lic_expires": lic_info.get("expires", ""),
        "update_available": updater.get_status().get("available", False),
        **kw
    })


# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "", next: str = "/"):
    if get_session_user(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": error})

@app.post("/login")
async def login_submit(request: Request,
                       username: str = Form(...),
                       password: str = Form(...),
                       next: str = Form(default="/")):
    client_ip = request.client.host if request.client else "unknown"
    if is_rate_limited(client_ip):
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Too many login attempts. Try again later."},
                                          status_code=429)
    if attempt_login(username, password):
        token = create_session(username)
        # Only allow relative redirects to prevent open redirect attacks
        safe_next = next if (next and next.startswith("/") and not next.startswith("//")) else "/"
        response = RedirectResponse(url=safe_next, status_code=302)
        response.set_cookie(
            COOKIE_NAME, token,
            httponly=True, samesite="lax", secure=True,
            max_age=SESSION_HOURS * 3600
        )
        return response
    return templates.TemplateResponse(request, "login.html",
                                      {"error": "Invalid username or password"},
                                      status_code=401)

@app.post("/logout")
async def logout(request: Request):
    delete_session(request)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response


# ══════════════════════════════════════════════════════════════════════════════
# HTML PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    conns = monitor.get_connections()
    net = monitor.get_network_stats()
    alerts = ips.get_alerts(10)
    ddos = reputation.get_ddos_stats()
    return _ctx(request, template="dashboard.html", connections=conns[:30],
                net_stats=net, alerts=alerts, conn_count=len(conns),
                ddos_blocked=ddos["blocked_count"])

@app.get("/firewall", response_class=HTMLResponse)
async def firewall_page(request: Request):
    rules = database.get_rules()
    return _ctx(request, template="firewall.html", rules=rules)

@app.get("/appcontrol", response_class=HTMLResponse)
async def appcontrol_page(request: Request):
    return _ctx(request, template="appcontrol.html",
                rules=database.get_app_rules(),
                running=app_control.get_running_apps(),
                predefined_apps=app_control.PREDEFINED_APPS,
                app_block_status=app_control.get_app_block_status())

@app.get("/webfilter", response_class=HTMLResponse)
async def webfilter_page(request: Request):
    wf_state, wf_count = web_filter.get_hosts_status()
    return _ctx(request, template="webfilter.html",
                filters=database.get_web_filters(),
                categories=database.get_web_categories(),
                wf_state=wf_state, wf_count=wf_count)

@app.get("/ips", response_class=HTMLResponse)
async def ips_page(request: Request):
    return _ctx(request, template="ips.html",
                signatures=ips.get_signatures(), alerts=ips.get_alerts(100))

@app.get("/vpn", response_class=HTMLResponse)
async def vpn_page(request: Request):
    profiles = database.get_vpn_profiles()
    for p in profiles:
        p["live_status"] = vpn_manager.get_status(p["id"]).get("status", "Disconnected")
    bov_tunnels = database.get_bov_tunnels()
    ssl_config = database.get_ssl_vpn_config()
    vpn_users = database.get_vpn_users()
    ipsec_sa = get_ipsec_sa()
    return _ctx(request, template="vpn.html",
                profiles=profiles,
                bov_tunnels=bov_tunnels,
                ssl_config=ssl_config,
                ssl_initialized=ssl_vpn.is_pki_initialized(),
                vpn_users=vpn_users,
                ipsec_sa=ipsec_sa)

@app.get("/blocked", response_class=HTMLResponse)
async def blocked_page(request: Request):
    ip_rules = [r for r in database.get_rules() if r["name"].startswith("Block-IP:")]
    domain_rules = [f for f in database.get_web_filters() if f["action"] == "BLOCK"]
    return _ctx(request, template="blocked.html", ip_rules=ip_rules, domain_rules=domain_rules)

@app.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request):
    return _ctx(request, template="monitor.html",
                connections=monitor.get_connections(),
                ifaces=monitor.get_per_interface_stats())

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, action: Optional[str] = None,
                    search: Optional[str] = None, limit: int = 250):
    logs = database.get_logs(limit=limit, action_filter=action or None, search=search or None)
    return _ctx(request, template="logs.html", logs=logs, action=action,
                search=search, limit=limit)

@app.get("/network", response_class=HTMLResponse)
async def network_page(request: Request, tab: Optional[str] = "interfaces"):
    return _ctx(request, template="network.html",
                active_tab=tab,
                interfaces=database.get_interfaces(),
                sys_ifaces=network_manager.get_system_interfaces(),
                routes=database.get_routes(),
                sys_routes=network_manager.get_system_routes(),
                dhcp_configs=database.get_dhcp_configs(),
                dhcp_leases=database.get_dhcp_leases(),
                nat_rules=database.get_nat_rules(),
                qos_rules=database.get_qos_rules(),
                dns=database.get_dns_settings(),
                vlans=database.get_vlans(),
                dmz_configs=database.get_dmz_configs())

@app.get("/security", response_class=HTMLResponse)
async def security_page(request: Request):
    bl_stats = reputation.get_blocklist_stats()
    ddos = reputation.get_ddos_stats()
    av_stats = gateway_av.get_stats()
    av_available = gateway_av.is_clamav_available()
    dlp_patterns = dlp.get_patterns()
    blocked_countries = reputation.get_blocked_countries()
    return _ctx(request, template="security.html",
                bl_stats=bl_stats, ddos=ddos, av_stats=av_stats,
                av_available=av_available, dlp_patterns=dlp_patterns,
                blocked_countries=blocked_countries)

@app.get("/discovery", response_class=HTMLResponse)
async def discovery_page(request: Request):
    results = network_discovery.get_scan_results()
    arp = network_discovery.get_arp_table()
    scanning = network_discovery.is_scanning()
    return _ctx(request, template="discovery.html",
                results=results, arp=arp, scanning=scanning,
                nmap_available=network_discovery.is_nmap_available())

@app.get("/auth", response_class=HTMLResponse)
async def auth_page(request: Request):
    return _ctx(request, template="auth.html",
                users=database.get_users(), groups=database.get_groups())

@app.get("/certificates", response_class=HTMLResponse)
async def certs_page(request: Request):
    return _ctx(request, template="certificates.html",
                certs=database.get_certificates())

@app.get("/ha", response_class=HTMLResponse)
async def ha_page(request: Request):
    return _ctx(request, template="ha.html",
                ha=database.get_ha_config())

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    settings = database.get_all_settings()
    wf_status = rules_engine.get_firewall_status()
    log_servers = database.get_log_servers()
    return _ctx(request, template="settings.html",
                settings=settings, wf_status=wf_status, log_servers=log_servers)

@app.get("/proxies", response_class=HTMLResponse)
async def proxies_page(request: Request):
    return _ctx(request, template="proxies.html",
                proxy_rules=database.get_proxy_rules())

@app.get("/updates", response_class=HTMLResponse)
async def updates_page(request: Request):
    return _ctx(request, template="updates.html",
                local_version=updater.get_local_version(),
                licensed=license_manager.is_licensed(),
                status=updater.get_status())


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Updates
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/update/check")
async def api_update_check():
    st = updater.check_for_update()
    return st

@app.post("/api/update/download")
async def api_update_download():
    ok, msg = updater.download_update()
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/update/apply")
async def api_update_apply():
    ok, msg = updater.apply_update()
    return {"status": "ok" if ok else "error", "message": msg}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Dashboard
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/dashboard")
async def api_dashboard():
    conns = monitor.get_connections()
    stats = database.get_log_stats()
    net = monitor.get_network_stats()
    alerts = ips.get_alerts(100)
    ddos = reputation.get_ddos_stats()
    try:
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
    except Exception:
        cpu, mem, disk = 0, None, None
    return {
        "connections": len(conns),
        "blocked_today": stats["today"],
        "threats": len(alerts),
        "total_logs": stats["total"],
        "bytes_sent": net["bytes_sent"],
        "bytes_recv": net["bytes_recv"],
        "bytes_sent_fmt": monitor.format_bytes(net["bytes_sent"]),
        "bytes_recv_fmt": monitor.format_bytes(net["bytes_recv"]),
        "cpu_percent": cpu,
        "mem_percent": mem.percent if mem else 0,
        "disk_percent": disk.percent if disk else 0,
        "ddos_blocked": ddos["blocked_count"],
        "bl_ips": reputation.get_blocklist_stats()["total_ips"],
    }


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Firewall Rules
# ══════════════════════════════════════════════════════════════════════════════

class RuleCreate(BaseModel):
    name: str; action: str; direction: str; protocol: str = "ANY"
    local_ip: str = ""; remote_ip: str = ""; local_port: str = ""
    remote_port: str = ""; enabled: int = 1; priority: int = 100
    description: str = ""; interface: str = ""; log_match: int = 0

@app.get("/api/rules")
async def api_get_rules():
    return database.get_rules()
@app.post("/api/rules")
async def api_add_rule(rule: RuleCreate):
    database.add_rule(**rule.model_dump())
    rules = database.get_rules()
    new_rule = max(rules, key=lambda r: r["id"])
    ok, msg = rules_engine.sync_rule_to_system(new_rule)
    return {"status": "ok", "applied": ok, "message": msg}

@app.put("/api/rules/{rule_id}")
async def api_update_rule(rule_id: int, rule: RuleCreate):
    database.update_rule(rule_id, **rule.model_dump())
    updated = next((r for r in database.get_rules() if r["id"] == rule_id), None)
    if updated:
        rules_engine.remove_rule_from_system(updated)
        rules_engine.sync_rule_to_system(updated)
    return {"status": "ok"}

@app.delete("/api/rules/{rule_id}")
async def api_delete_rule(rule_id: int):
    rule = next((r for r in database.get_rules() if r["id"] == rule_id), None)
    if rule: rules_engine.remove_rule_from_system(rule)
    database.delete_rule(rule_id); return {"status": "ok"}

@app.post("/api/rules/{rule_id}/toggle")
async def api_toggle_rule(rule_id: int):
    rule = next((r for r in database.get_rules() if r["id"] == rule_id), None)
    if not rule: raise HTTPException(404)
    new_enabled = 0 if rule["enabled"] else 1
    database.update_rule(rule_id, enabled=new_enabled)
    updated = next((r for r in database.get_rules() if r["id"] == rule_id), None)
    if updated:
        rules_engine.remove_rule_from_system(updated)
        if new_enabled:
            rules_engine.sync_rule_to_system(updated)
    return {"status": "ok"}
@app.post("/api/rules/sync")
async def api_sync_rules():
    r = rules_engine.sync_all_rules()
    return {"synced": sum(1 for _,ok,_ in r if ok), "total": len(r)}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Network Interfaces
# ══════════════════════════════════════════════════════════════════════════════

class IfaceCreate(BaseModel):
    name: str; role: str = "LAN"; ip_mode: str = "static"
    ip_address: str = ""; netmask: str = "255.255.255.0"; gateway: str = ""
    mtu: int = 1500; description: str = ""; enabled: int = 1
    vlan_id: int = 0; pppoe_user: str = ""; pppoe_pass: str = ""; mac_override: str = ""

@app.get("/api/network/interfaces")
async def api_get_ifaces():
    db_ifaces = {i["name"]: i for i in database.get_interfaces()}
    sys_ifaces = network_manager.get_system_interfaces()
    for si in sys_ifaces:
        if si["name"] in db_ifaces:
            si["db"] = db_ifaces[si["name"]]
    return sys_ifaces

@app.post("/api/network/interfaces")
async def api_add_iface(iface: IfaceCreate):
    database.add_interface(**iface.model_dump()); return {"status": "ok"}

@app.get("/api/network/interfaces/{iface_id}")
async def api_get_iface(iface_id: int):
    conn = database.get_connection()
    row = conn.execute("SELECT * FROM interfaces WHERE id=?", (iface_id,)).fetchone()
    conn.close()
    if not row: raise HTTPException(status_code=404, detail="Not found")
    return dict(row)

@app.put("/api/network/interfaces/{iface_id}")
async def api_update_iface(iface_id: int, iface: IfaceCreate):
    database.update_interface(iface_id, **iface.model_dump()); return {"status": "ok"}

@app.delete("/api/network/interfaces/{iface_id}")
async def api_delete_iface(iface_id: int):
    database.delete_interface(iface_id); return {"status": "ok"}

@app.post("/api/network/interfaces/{iface_id}/apply")
async def api_apply_iface(iface_id: int):
    ifaces = database.get_interfaces()
    iface = next((i for i in ifaces if i["id"] == iface_id), None)
    if not iface: raise HTTPException(404)
    ok, msg = network_manager.apply_interface(iface)
    if ok:
        network_manager.write_dhcp_config()
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/network/apply-all")
async def api_apply_all_ifaces():
    ifaces = database.get_interfaces()
    ok, msg = network_manager.write_network_config(ifaces)
    return {"status": "ok" if ok else "error", "message": msg}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — VLANs
# ══════════════════════════════════════════════════════════════════════════════

class VlanCreate(BaseModel):
    vlan_id: int; name: str; parent_interface: str
    ip_address: str = ""; netmask: str = "255.255.255.0"; gateway: str = ""
    zone: str = "OPTIONAL"; dhcp_enabled: int = 0; dhcp_start: str = ""; dhcp_end: str = ""
    mtu: int = 1500; enabled: int = 1; description: str = ""

@app.get("/api/network/vlans")
async def api_get_vlans():
    return database.get_vlans()

@app.post("/api/network/vlans")
async def api_add_vlan(v: VlanCreate):
    database.add_vlan(**v.model_dump()); return {"status": "ok"}

@app.put("/api/network/vlans/{vid}")
async def api_update_vlan(vid: int, v: VlanCreate):
    database.update_vlan(vid, **v.model_dump()); return {"status": "ok"}

@app.delete("/api/network/vlans/{vid}")
async def api_del_vlan(vid: int):
    database.delete_vlan(vid); return {"status": "ok"}

@app.post("/api/network/vlans/apply")
async def api_apply_vlans():
    from core import network_manager
    ok, msg = network_manager.apply_vlans()
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "ok", "message": msg}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — DMZ
# ══════════════════════════════════════════════════════════════════════════════

class DmzConfig(BaseModel):
    interface: str; ip_address: str = ""; netmask: str = "255.255.255.0"
    allowed_ports: str = "80,443"; block_dmz_to_lan: int = 1
    log_all: int = 1; enabled: int = 1

@app.get("/api/network/dmz")
async def api_get_dmz():
    return database.get_dmz_configs()

@app.post("/api/network/dmz")
async def api_add_dmz(d: DmzConfig):
    database.save_dmz_config(**d.model_dump()); return {"status": "ok"}

@app.put("/api/network/dmz/{did}")
async def api_update_dmz(did: int, d: DmzConfig):
    database.save_dmz_config(**d.model_dump()); return {"status": "ok"}

@app.delete("/api/network/dmz/{did}")
async def api_del_dmz(did: int):
    database.delete_dmz_config(did); return {"status": "ok"}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Routes
# ══════════════════════════════════════════════════════════════════════════════

class RouteCreate(BaseModel):
    destination: str; netmask: str; gateway: str
    interface: str = ""; metric: int = 1; enabled: int = 1; description: str = ""

@app.get("/api/network/routes")
async def api_get_routes():
    return database.get_routes()
@app.post("/api/network/routes")
async def api_add_route(r: RouteCreate):
    database.add_route(**r.model_dump()); return {"status": "ok"}
@app.delete("/api/network/routes/{route_id}")
async def api_del_route(route_id: int):
    database.delete_route(route_id); return {"status": "ok"}
@app.post("/api/network/routes/apply")
async def api_apply_routes():
    ok, msg = network_manager.apply_routes(); return {"status": "ok" if ok else "error", "message": msg}
@app.get("/api/network/routes/system")
async def api_sys_routes(): return {"routes": network_manager.get_system_routes()}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — DHCP
# ══════════════════════════════════════════════════════════════════════════════

class DhcpConfig(BaseModel):
    interface: str; start_ip: str; end_ip: str; subnet_mask: str
    gateway: str = ""; dns1: str = "1.1.1.1"; dns2: str = "8.8.8.8"
    lease_time: int = 86400; domain: str = ""; enabled: int = 1

class DhcpLease(BaseModel):
    mac: str; ip: str; hostname: str = ""; interface: str = ""

@app.get("/api/dhcp/config")
async def api_dhcp_config():
    return database.get_dhcp_configs()
@app.post("/api/dhcp/config")
async def api_save_dhcp(c: DhcpConfig):
    database.save_dhcp_config(**c.model_dump())
    network_manager.write_dhcp_config()
    return {"status": "ok"}
@app.delete("/api/dhcp/config/{iface}")
async def api_delete_dhcp(iface: str):
    database.delete_dhcp_config(iface)
    network_manager.write_dhcp_config()
    return {"status": "ok"}
@app.post("/api/dhcp/apply")
async def api_apply_dhcp():
    ok, msg = network_manager.write_dhcp_config(); return {"status":"ok" if ok else "error","message":msg}
@app.get("/api/dhcp/leases")
async def api_dhcp_leases():
    return database.get_dhcp_leases()
@app.get("/api/dhcp/active")
async def api_dhcp_active():
    return network_manager.get_dhcp_active_leases()
@app.post("/api/dhcp/leases")
async def api_add_lease(l: DhcpLease):
    database.add_dhcp_lease(**l.model_dump()); return {"status":"ok"}
@app.delete("/api/dhcp/leases/{lid}")
async def api_del_lease(lid: int):
    database.delete_dhcp_lease(lid); return {"status":"ok"}


# ── DHCP Relay ────────────────────────────────────────────────────────────────

@app.get("/api/dhcp/relay")
async def api_get_dhcp_relay():
    return database.get_dhcp_relay()

class DhcpRelayConfig(BaseModel):
    enabled: int = 0
    server_ip: str = ""
    interfaces: str = ""

@app.post("/api/dhcp/relay")
async def api_save_dhcp_relay(cfg: DhcpRelayConfig):
    database.save_dhcp_relay(cfg.enabled, cfg.server_ip, cfg.interfaces)
    return {"status": "ok"}

@app.post("/api/dhcp/relay/apply")
async def api_apply_dhcp_relay():
    ok, msg = network_manager.apply_dhcp_relay()
    return {"status": "ok" if ok else "error", "message": msg}

@app.get("/api/dhcp/relay/status")
async def api_dhcp_relay_status():
    return network_manager.get_dhcp_relay_status()


# ══════════════════════════════════════════════════════════════════════════════
# REST API — DNS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/dns")
async def api_get_dns():
    return database.get_dns_settings()
@app.post("/api/dns")
async def api_save_dns(request: Request):
    data = await request.json()
    database.save_dns_settings(**data); return {"status":"ok"}
@app.post("/api/dns/apply")
async def api_apply_dns():
    ok, msg = network_manager.apply_dns_settings(); return {"status":"ok" if ok else "error","message":msg}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — NAT
# ══════════════════════════════════════════════════════════════════════════════

class NatRule(BaseModel):
    name: str; nat_type: str; internal_ip: str
    external_ip: str = ""; external_port: str = ""; internal_port: str = ""
    protocol: str = "TCP"; interface: str = ""; enabled: int = 1; description: str = ""

@app.get("/api/nat")
async def api_get_nat():
    return database.get_nat_rules()

@app.post("/api/nat")
async def api_add_nat(r: NatRule):
    database.add_nat_rule(**r.model_dump())
    # Auto-apply the new rule immediately
    rules = database.get_nat_rules()
    new_rule = max(rules, key=lambda x: x["id"])
    if new_rule["type"] == "1-to-1":
        ok, msg = network_manager._apply_static_nat(new_rule)
    else:
        ok, msg = network_manager.apply_nat_rules()
    return {"status": "ok", "applied": ok, "message": msg}

@app.delete("/api/nat/{rid}")
async def api_del_nat(rid: int):
    rule = next((r for r in database.get_nat_rules() if r["id"] == rid), None)
    if rule and rule["type"] == "1-to-1":
        network_manager.remove_static_nat(rule)
    database.delete_nat_rule(rid)
    return {"status": "ok"}

@app.post("/api/nat/apply")
async def api_apply_nat():
    ok, msg = network_manager.apply_nat_rules()
    return {"status": "ok" if ok else "error", "message": msg}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — QoS
# ══════════════════════════════════════════════════════════════════════════════

class QosRule(BaseModel):
    name: str; priority: str = "NORMAL"; protocol: str = "ANY"
    src_ip: str = ""; dst_ip: str = ""; src_port: str = ""; dst_port: str = ""
    bandwidth_limit: int = 0; bandwidth_unit: str = "kbps"; enabled: int = 1; description: str = ""

@app.get("/api/qos")
async def api_get_qos():
    return database.get_qos_rules()
@app.post("/api/qos")
async def api_add_qos(r: QosRule):
    database.add_qos_rule(**r.model_dump()); return {"status":"ok"}
@app.delete("/api/qos/{rid}")
async def api_del_qos(rid: int):
    database.delete_qos_rule(rid); return {"status":"ok"}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — App Control
# ══════════════════════════════════════════════════════════════════════════════

class AppRuleCreate(BaseModel):
    name: str; exe_path: str; action: str; direction: str = "BOTH"; enabled: int = 1; description: str = ""

@app.get("/api/appcontrol/rules")
async def api_get_app_rules():
    return database.get_app_rules()
@app.post("/api/appcontrol/rules")
async def api_add_app_rule(r: AppRuleCreate):
    _require_license("Application Control")
    database.add_app_rule(**r.model_dump()); return {"status":"ok"}
@app.delete("/api/appcontrol/rules/{rid}")
async def api_del_app_rule(rid: int):
    _require_license("Application Control")
    rule = next((r for r in database.get_app_rules() if r["id"]==rid), None)
    if rule: app_control.remove_app_rule(rule)
    database.delete_app_rule(rid); return {"status":"ok"}
@app.post("/api/appcontrol/sync")
async def api_sync_app():
    _require_license("Application Control")
    r = app_control.sync_all_app_rules()
    return {"synced": sum(1 for _,ok,_ in r if ok), "total": len(r)}
@app.get("/api/appcontrol/running")
async def api_running():
    return app_control.get_running_apps()

@app.post("/api/appcontrol/block/{app_name}")
async def api_block_app(app_name: str):
    _require_license("Application Control")
    ok, msg = app_control.apply_app_block(app_name)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "ok", "message": msg}

@app.delete("/api/appcontrol/block/{app_name}")
async def api_unblock_app(app_name: str):
    _require_license("Application Control")
    ok, msg = app_control.remove_app_block(app_name)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "ok", "message": msg}

@app.get("/api/appcontrol/blocks")
async def api_get_blocks():
    return app_control.get_app_block_status()


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Web Filter
# ══════════════════════════════════════════════════════════════════════════════

class WFCreate(BaseModel):
    pattern: str; category: str = "Custom"; action: str = "BLOCK"; enabled: int = 1; description: str = ""

@app.get("/api/webfilter")
async def api_get_wf():
    return database.get_web_filters()
@app.post("/api/webfilter")
async def api_add_wf(f: WFCreate):
    _require_license("Web Filter")
    database.add_web_filter(**f.model_dump()); return {"status":"ok"}
@app.delete("/api/webfilter/{fid}")
async def api_del_wf(fid: int):
    _require_license("Web Filter")
    database.delete_web_filter(fid); return {"status":"ok"}
@app.post("/api/webfilter/apply")
async def api_apply_wf():
    _require_license("Web Filter")
    ok, msg = web_filter.apply_filters(); web_filter.flush_dns()
    return {"status":"ok" if ok else "error","message":msg}
@app.post("/api/webfilter/remove")
async def api_remove_wf():
    _require_license("Web Filter")
    ok, msg = web_filter.remove_filters(); return {"status":"ok" if ok else "error","message":msg}

class CategoryToggle(BaseModel):
    name: str; enabled: int

@app.post("/api/webfilter/category")
async def api_toggle_category(c: CategoryToggle):
    _require_license("Web Filter")
    database.update_web_category(c.name, c.enabled)
    ok, msg = web_filter.apply_filters(); web_filter.flush_dns()
    return {"status":"ok" if ok else "error","message":msg}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — VPN
# ══════════════════════════════════════════════════════════════════════════════

class VPNCreate(BaseModel):
    name: str; vpn_type: str; config_path: str; server: str = ""; auto_connect: int = 0

@app.get("/api/vpn/profiles")
async def api_get_vpn():
    p = database.get_vpn_profiles()
    for x in p: x["live_status"] = vpn_manager.get_status(x["id"]).get("status","Disconnected")
    return p

@app.post("/api/vpn/profiles")
async def api_add_vpn(p: VPNCreate):
    database.add_vpn_profile(**p.model_dump()); return {"status":"ok"}

@app.delete("/api/vpn/profiles/{pid}")
async def api_del_vpn(pid: int):
    database.delete_vpn_profile(pid); return {"status":"ok"}

@app.post("/api/vpn/{pid}/connect")
async def api_vpn_connect(pid: int):
    profile = next((p for p in database.get_vpn_profiles() if p["id"]==pid), None)
    if not profile: raise HTTPException(404)
    ok, msg = vpn_manager.connect(profile)
    return {"status":"ok" if ok else "error","message":msg}

@app.post("/api/vpn/{pid}/disconnect")
async def api_vpn_disconnect(pid: int):
    profile = next((p for p in database.get_vpn_profiles() if p["id"]==pid), None)
    if not profile: raise HTTPException(404)
    ok, msg = vpn_manager.disconnect(profile)
    return {"status":"ok" if ok else "error","message":msg}

@app.post("/api/vpn/wireguard/keygen")
async def api_wg_keygen():
    priv, pub = vpn_keygen.generate_wireguard_keypair()
    psk = vpn_keygen.generate_wireguard_preshared_key()
    return {"private_key": priv, "public_key": pub, "preshared_key": psk}

# ── OpenVPN Public IP ─────────────────────────────────────────────────────────

@app.get("/api/vpn/openvpn/public-ip")
async def api_get_public_ip():
    # wan_ip is the key used by ssl_vpn.generate_user_config
    saved = database.get_setting("wan_ip", "") or database.get_setting("openvpn_public_ip", "")
    return {"public_ip": saved}

@app.post("/api/vpn/openvpn/public-ip")
async def api_set_public_ip(request: Request):
    data = await request.json()
    ip = data.get("public_ip", "").strip()
    if not ip:
        raise HTTPException(400, "IP is required")
    # Save to wan_ip — used by ssl_vpn.generate_user_config
    database.set_setting("wan_ip", ip)
    database.set_setting("openvpn_public_ip", ip)
    # Regenerate all existing user .ovpn configs with new IP
    try:
        users = database.get_vpn_users()
        for u in users:
            ssl_vpn.generate_user_config(u, server_ip=ip)
    except Exception:
        pass
    database.add_log("INFO", details=f"VPN public IP updated: {ip}")
    return {"status": "ok", "public_ip": ip,
            "message": f"IP saved and {len(users) if 'users' in dir() else 0} client configs regenerated"}

@app.get("/api/vpn/openvpn/detect-ip")
async def api_detect_public_ip():
    for service in ["api4.ipify.org", "ipv4.icanhazip.com", "ifconfig.me"]:
        ok, ip, _ = run(["curl", "-s", "-4", "--max-time", "5", "--connect-timeout", "4",
                          f"https://{service}"])
        ip = (ip or "").strip()
        if ok and ip and ":" not in ip and len(ip) <= 15:
            return {"public_ip": ip}
    raise HTTPException(500, "Cannot detect public IP — check internet connection")

# ── OpenVPN Server Start / Stop (uses ssl_vpn module) ────────────────────────

@app.get("/api/vpn/openvpn/server/status")
async def api_ovpn_server_status():
    status = ssl_vpn.get_server_status()
    active = (status == "Running")
    return {"status": status, "active": active,
            "initialized": ssl_vpn.is_pki_initialized()}

@app.post("/api/vpn/openvpn/server/start")
async def api_ovpn_server_start():
    if not ssl_vpn.is_pki_initialized():
        return {"status": "error",
                "message": "PKI not initialized. Press 'Auto Setup SSL VPN' first."}
    ok, msg = ssl_vpn.start_server()
    if ok:
        _auto_vpn_rules("SSL-VPN", "UDP", "1194")
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/vpn/openvpn/server/stop")
async def api_ovpn_server_stop():
    ok, msg = ssl_vpn.stop_server()
    return {"status": "ok" if ok else "error", "message": msg}

# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/vpn/openvpn/pki/generate")
async def api_openvpn_pki(request: Request):
    data = await request.json()
    output_dir = data.get("output_dir", "/etc/aegisguard/pki")
    result = vpn_keygen.generate_openvpn_pki(output_dir,
                                              server_name=data.get("server_name","server"),
                                              client_name=data.get("client_name","client"))
    return result

@app.get("/api/vpn/openvpn/server-config")
async def api_ovpn_server_cfg(pki_dir: str = "/etc/aegisguard/pki",
                               server_ip: str = "0.0.0.0", port: int = 1194):
    conf = vpn_keygen.generate_openvpn_server_config(pki_dir, port=port)
    return StreamingResponse(io.StringIO(conf), media_type="text/plain",
                             headers={"Content-Disposition": "attachment; filename=server.conf"})

@app.get("/api/vpn/openvpn/client-config")
async def api_ovpn_client_cfg(server_ip: str = "", pki_dir: str = "/etc/aegisguard/pki", port: int = 1194):
    # Use saved public IP if not provided
    if not server_ip:
        server_ip = database.get_setting("openvpn_public_ip", "")
    if not server_ip:
        raise HTTPException(400, "Public IP not set. Go to VPN → OpenVPN Server → set Public IP first.")
    conf = vpn_keygen.generate_openvpn_client_config(server_ip, pki_dir, port=port)
    return StreamingResponse(io.StringIO(conf), media_type="text/plain",
                             headers={"Content-Disposition": "attachment; filename=aegisguard-client.ovpn"})

@app.get("/api/vpn/wireguard/generate-config")
async def api_wg_config(endpoint: str, server_pubkey: str, client_privkey: str,
                         client_address: str, dns: str = "1.1.1.1"):
    conf = vpn_manager.generate_wireguard_config(endpoint, server_pubkey, client_privkey, client_address, dns)
    return StreamingResponse(io.StringIO(conf), media_type="text/plain",
                             headers={"Content-Disposition": "attachment; filename=wg0.conf"})

@app.get("/api/vpn/wireguard/peers")
async def api_wg_peers():
    return vpn_manager.get_wireguard_peers()

# IPSec
class IPSecCreate(BaseModel):
    name: str; local_subnet: str; remote_gateway: str; remote_subnet: str; psk: str
    ike_version: str = "IKEv2"; ike_cipher: str = "AES256"; ike_hash: str = "SHA256"
    dh_group: str = "DH14"; esp_cipher: str = "AES256"; esp_hash: str = "SHA256"
    enabled: int = 1; description: str = ""

@app.get("/api/vpn/ipsec")
async def api_ipsec_list():
    return database.get_ipsec_tunnels()
@app.post("/api/vpn/ipsec")
async def api_add_ipsec(t: IPSecCreate):
    database.add_ipsec_tunnel(**t.model_dump()); return {"status":"ok"}
@app.delete("/api/vpn/ipsec/{tid}")
async def api_del_ipsec(tid: int):
    tunnel = next((t for t in database.get_ipsec_tunnels() if t["id"]==tid), None)
    if tunnel: remove_ipsec_tunnel(tunnel["name"])
    database.delete_ipsec_tunnel(tid); return {"status":"ok"}
@app.post("/api/vpn/ipsec/psk")
async def api_gen_psk():
    return {"psk": generate_psk()}
@app.get("/api/vpn/ipsec/sa")
async def api_ipsec_sa():
    return get_ipsec_sa()


# ══════════════════════════════════════════════════════════════════════════════
# REST API — IPS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ips/alerts")
async def api_ips_alerts():
    return ips.get_alerts(200)
@app.get("/api/ips/signatures")
async def api_ips_sigs():
    return ips.get_signatures()
@app.post("/api/ips/clear")
async def api_ips_clear(): ips.clear_alerts(); return {"status":"ok"}
@app.get("/api/ips/blocked")
async def api_ips_blocked(): return {"blocked": ips.get_blocked_ips()}
@app.post("/api/ips/unblock/{ip}")
async def api_ips_unblock(ip: str): ips.unblock_ip(ip); return {"status":"ok"}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Security Services (RED, AV, DLP, Spam, Geo)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/security/reputation")
async def api_rep_stats():
    return reputation.get_blocklist_stats()
@app.post("/api/security/reputation/update")
async def api_rep_update():
    results = reputation.update_blocklists()
    return {"status":"ok","results":results}

@app.post("/api/security/reputation/check")
async def api_rep_check(request: Request):
    data = await request.json()
    ip = data.get("ip","")
    blocked = reputation.is_ip_blocked(ip)
    geo = reputation.lookup_ip(ip)
    return {"ip":ip,"blocked":blocked,"geo":geo}

@app.get("/api/security/ddos")
async def api_ddos_stats():
    return reputation.get_ddos_stats()
@app.post("/api/security/ddos/unblock/{ip}")
async def api_ddos_unblock(ip: str): reputation.unblock_ip(ip); return {"status":"ok"}

@app.post("/api/security/ddos/unblock-all")
async def api_ddos_unblock_all():
    for ip in list(reputation.get_ddos_blocked()):
        reputation.unblock_ip(ip)
    return {"status": "ok", "message": "All blocked IPs cleared"}

@app.post("/api/security/geoip")
async def api_save_geoip(request: Request):
    _require_license("GeoIP Blocking")
    import json as _json
    data = await request.json()
    codes = data.get("blocked_countries", [])
    database.set_setting("blocked_countries", _json.dumps(codes))
    return {"status": "ok"}

@app.post("/api/security/ddos/config")
async def api_ddos_config(request: Request):
    data = await request.json(); reputation.update_ddos_config(**data); return {"status":"ok"}

@app.get("/api/security/geo/blocked")
async def api_geo_blocked():
    return reputation.get_blocked_countries()
@app.post("/api/security/geo/blocked")
async def api_set_geo(request: Request):
    _require_license("GeoIP Blocking")
    data = await request.json()
    import json as _json
    database.set_setting("blocked_countries", _json.dumps(data.get("countries",[])))
    return {"status":"ok"}
@app.post("/api/security/geo/lookup")
async def api_geo_lookup(request: Request):
    data = await request.json(); return reputation.lookup_ip(data.get("ip",""))

@app.post("/api/security/geo/apply")
async def api_geoblock_apply():
    _require_license("GeoIP Blocking")
    from core import geoblock
    ok, msg = geoblock.apply_geoblock()
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/security/geo/remove")
async def api_geoblock_remove():
    _require_license("GeoIP Blocking")
    from core import geoblock
    ok, msg = geoblock.remove_geoblock()
    return {"status": "ok" if ok else "error", "message": msg}

@app.get("/api/security/geo/status")
async def api_geoblock_status():
    from core import geoblock
    return geoblock.get_status()

@app.get("/api/security/av")
async def api_av_stats():
    return gateway_av.get_stats()
@app.post("/api/security/av/update")
async def api_av_update():
    ok, msg = gateway_av.update_definitions(); return {"status":"ok" if ok else "error","message":msg}
@app.post("/api/security/av/scan")
async def api_av_scan(file: UploadFile = File(...)):
    data = await file.read()
    clean, threat = gateway_av.scan_bytes(data, file.filename)
    return {"clean":clean,"threat":threat,"filename":file.filename}

@app.get("/api/security/dlp/patterns")
async def api_dlp_patterns():
    return dlp.get_patterns()
@app.post("/api/security/dlp/scan")
async def api_dlp_scan(request: Request):
    data = await request.json()
    findings = dlp.scan_content(data.get("content",""), source="api")
    return {"findings":findings}

@app.post("/api/security/dlp/patterns")
async def api_add_dlp_pattern(request: Request):
    data = await request.json()
    dlp.add_custom_pattern(
        name=data.get("name", ""),
        pattern=data.get("pattern", ""),
        severity=data.get("severity", "MEDIUM"),
        enabled=bool(data.get("enabled", 1))
    )
    return {"status": "ok"}

@app.post("/api/security/dlp/patterns/{pid}/toggle")
async def api_toggle_dlp_pattern(pid: int):
    patterns = database.get_dlp_patterns()
    row = next((p for p in patterns if p["id"] == pid), None)
    if not row:
        raise HTTPException(404)
    database.update_dlp_pattern(pid, enabled=0 if row["enabled"] else 1)
    return {"status": "ok"}

@app.delete("/api/security/dlp/patterns/{pid}")
async def api_del_dlp_pattern(pid: int):
    database.delete_dlp_pattern(pid)
    return {"status": "ok"}

@app.post("/api/security/spam/check")
async def api_spam_check(request: Request):
    data = await request.json()
    result = spam_filter.check_email(data.get("content",""))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Network Discovery
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/discovery/scan")
async def api_scan(request: Request):
    data = await request.json()
    ok, msg = network_discovery.scan_network(data.get("subnet","192.168.1.0/24"),
                                              data.get("type","quick"))
    return {"status":"ok" if ok else "error","message":msg}

@app.get("/api/discovery/results")
async def api_disc_results():
    return network_discovery.get_scan_results()
@app.get("/api/discovery/arp")
async def api_arp():
    return network_discovery.get_arp_table()
@app.get("/api/discovery/status")
async def api_disc_status():
    return {"scanning":network_discovery.is_scanning()}

@app.post("/api/discovery/scan/stop")
async def api_scan_stop():
    network_discovery.stop_scan()
    return {"status": "ok"}

@app.post("/api/discovery/ping")
async def api_ping(request: Request):
    data = await request.json()
    ok, rtt = network_discovery.ping_host(data.get("ip",""))
    return {"reachable":ok,"rtt_ms":rtt}

@app.post("/api/discovery/traceroute")
async def api_traceroute(request: Request):
    data = await request.json()
    return {"output": network_discovery.traceroute(data.get("ip",""))}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Authentication
# ══════════════════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str; password: str; full_name: str = ""; email: str = ""
    role: str = "user"; group_name: str = ""; enabled: int = 1

@app.get("/api/auth/users")
async def api_get_users():
    return database.get_users()
@app.post("/api/auth/users")
async def api_add_user(u: UserCreate):
    h = mfa.hash_password(u.password)
    database.add_user(u.username, h, u.full_name, u.email, u.role, u.group_name, u.enabled)
    return {"status":"ok"}
@app.delete("/api/auth/users/{uid}")
async def api_del_user(uid: int):
    database.delete_user(uid); return {"status":"ok"}

@app.post("/api/auth/users/{uid}/toggle")
async def api_toggle_user(uid: int):
    conn = database.get_connection()
    row = conn.execute("SELECT enabled FROM auth_users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    database.update_user(uid, enabled=0 if row["enabled"] else 1)
    return {"status": "ok"}

@app.post("/api/auth/users/{uid}/mfa/disable")
async def api_disable_mfa(uid: int):
    # Clear MFA by resetting password_hash prefix (mfa:<secret> -> empty hash)
    conn = database.get_connection()
    row = conn.execute("SELECT password_hash FROM auth_users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    if row["password_hash"] and row["password_hash"].startswith("mfa:"):
        database.update_user(uid, password_hash="")
    return {"status": "ok"}

@app.post("/api/auth/users/{uid}/mfa/verify")
async def api_verify_mfa(uid: int, request: Request):
    data = await request.json()
    code = str(data.get("code", ""))
    conn = database.get_connection()
    row = conn.execute("SELECT password_hash FROM auth_users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row or not (row["password_hash"] or "").startswith("mfa:"):
        raise HTTPException(400, "MFA not enabled for this user")
    secret = row["password_hash"][4:]  # strip "mfa:" prefix
    ok = mfa.verify_totp(secret, code)
    return {"status": "ok" if ok else "error", "valid": ok}

@app.post("/api/auth/users/{uid}/mfa/enable")
async def api_enable_mfa(uid: int):
    secret = mfa.enable_mfa_for_user(uid)
    return {"secret": secret, "qr_uri": mfa.get_qr_code_uri(f"user_{uid}", secret)}

@app.get("/api/auth/groups")
async def api_get_groups():
    return database.get_groups()


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Certificates
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/certificates")
async def api_get_certs():
    return database.get_certificates()
@app.delete("/api/certificates/{cid}")
async def api_del_cert(cid: int): database.delete_certificate(cid); return {"status":"ok"}

@app.post("/api/certificates/import")
async def api_import_cert(request: Request):
    data = await request.json()
    name = data.get("name", "Imported")
    cert_pem = data.get("cert_pem", "")
    key_pem  = data.get("key_pem", "")
    if not cert_pem:
        raise HTTPException(400, "cert_pem required")
    import subprocess, tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".crt", delete=False, mode='w') as f:
        f.write(cert_pem); tmp = f.name
    try:
        r = subprocess.run(["openssl", "x509", "-noout", "-subject", "-in", tmp],
                           capture_output=True, text=True, timeout=5)
        subject = r.stdout.strip().replace("subject=", "") if r.returncode == 0 else ""
    except Exception:
        subject = ""
    finally:
        try: os.unlink(tmp)
        except: pass
    database.add_certificate(name, "imported", subject=subject, cert_pem=cert_pem, key_pem=key_pem)
    return {"status": "ok"}

@app.get("/api/certificates/{cid}/export")
async def api_export_cert(cid: int):
    conn = database.get_connection()
    row = conn.execute("SELECT name, cert_pem, key_pem FROM certificates WHERE id=?", (cid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    pem = (row["cert_pem"] or "") + ("\n" + row["key_pem"] if row["key_pem"] else "")
    name = (row["name"] or f"cert-{cid}").replace(" ", "_")
    return StreamingResponse(io.StringIO(pem), media_type="application/x-pem-file",
                             headers={"Content-Disposition": f"attachment; filename={name}.pem"})

@app.post("/api/certificates/generate-self-signed")
async def api_gen_cert(request: Request):
    data = await request.json()
    cn = data.get("cn", "AegisGuard")
    days = data.get("days", 3650)
    from core.platform import run
    import tempfile, os
    key_f = tempfile.mktemp(suffix=".key")
    cert_f = tempfile.mktemp(suffix=".crt")
    ok, _, err = run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                      "-keyout", key_f, "-out", cert_f, "-days", str(days),
                      "-nodes", "-subj", f"/CN={cn}/O=AegisGuard/C=GR"])
    if not ok:
        return {"status":"error","message":err}
    with open(cert_f) as f: cert_pem = f.read()
    with open(key_f) as f: key_pem = f.read()
    try: os.unlink(key_f); os.unlink(cert_f)
    except: pass
    database.add_certificate(cn, "self-signed", subject=f"CN={cn}",
                              cert_pem=cert_pem, key_pem=key_pem)
    return {"status":"ok","cert_pem": cert_pem}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Proxy Rules
# ══════════════════════════════════════════════════════════════════════════════

class ProxyRule(BaseModel):
    name: str; proxy_type: str; action: str; pattern: str = ""
    content_type: str = ""; max_size: int = 0; enabled: int = 1; description: str = ""

@app.get("/api/proxies")
async def api_get_proxies():
    return database.get_proxy_rules()
@app.post("/api/proxies")
async def api_add_proxy(r: ProxyRule):
    database.add_proxy_rule(**r.model_dump()); return {"status":"ok"}
@app.delete("/api/proxies/{rid}")
async def api_del_proxy(rid: int): database.delete_proxy_rule(rid); return {"status":"ok"}

@app.post("/api/proxies/{pid}/toggle")
async def api_toggle_proxy(pid: int):
    conn = database.get_connection()
    row = conn.execute("SELECT enabled FROM proxy_rules WHERE id=?", (pid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    conn2 = database.get_connection()
    conn2.execute("UPDATE proxy_rules SET enabled=? WHERE id=?",
                  (0 if row["enabled"] else 1, pid))
    conn2.commit()
    conn2.close()
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Monitor + Logs + Settings
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/monitor/connections")
async def api_conns():
    return monitor.get_connections()
@app.get("/api/monitor/stats")
async def api_net_stats():
    n = monitor.get_network_stats()
    return {**n,"bytes_sent_fmt":monitor.format_bytes(n["bytes_sent"]),"bytes_recv_fmt":monitor.format_bytes(n["bytes_recv"])}
@app.get("/api/monitor/interfaces")
async def api_ifaces(): return [{"name":k,**v} for k,v in monitor.get_per_interface_stats().items()]

@app.get("/api/logs")
async def api_logs(limit:int=100, action:Optional[str]=None, search:Optional[str]=None):
    return database.get_logs(limit=limit, action_filter=action, search=search)
@app.get("/api/logs/stats")
async def api_log_stats():
    return database.get_log_stats()
@app.post("/api/logs/clear")
async def api_clear_logs():
    database.clear_logs(); return {"status":"ok"}

@app.get("/api/settings")
async def api_get_settings():
    return database.get_all_settings()
@app.post("/api/settings")
async def api_save_settings(request: Request):
    data = await request.json()
    for k,v in data.items(): database.set_setting(k,v)
    return {"status":"ok"}
@app.post("/api/settings/sync-firewall")
async def api_sync_fw():
    r = rules_engine.sync_all_rules()
    return {"synced":sum(1 for _,ok,_ in r if ok),"total":len(r)}

@app.post("/api/settings/change-password")
async def api_change_password(request: Request):
    data = await request.json()
    current = data.get("current_password", "")
    new_pw  = data.get("new_password", "")
    if not new_pw or len(new_pw) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    stored_hash = database.get_setting("admin_password_hash", "")
    from web.auth import verify_password
    if not verify_password(current, stored_hash):
        raise HTTPException(401, "Current password is incorrect")
    database.set_setting("admin_password_hash", hash_password(new_pw))
    return {"status": "ok"}

# Log servers
class LogServer(BaseModel):
    name:str; host:str; port:int=514; protocol:str="UDP"; enabled:int=1

@app.get("/api/logging/servers")
async def api_log_servers():
    return database.get_log_servers()
@app.post("/api/logging/servers")
async def api_add_log_server(s: LogServer):
    database.add_log_server(**s.model_dump()); return {"status":"ok"}
@app.delete("/api/logging/servers/{sid}")
async def api_del_log_server(sid:int): database.delete_log_server(sid); return {"status":"ok"}

# Syslog test
@app.post("/api/logging/servers/{sid}/test")
async def api_test_log_server(sid: int):
    servers = database.get_log_servers()
    srv = next((s for s in servers if s["id"] == sid), None)
    if not srv:
        raise HTTPException(404, "Server not found")
    import socket
    try:
        if srv.get("protocol", "UDP").upper() == "TCP":
            with socket.create_connection((srv["host"], srv["port"]), timeout=3):
                pass
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"<14>AegisGuard test message", (srv["host"], srv["port"]))
        return {"status": "ok", "message": f"Connected to {srv['host']}:{srv['port']}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Factory reset
@app.post("/api/settings/factory-reset")
async def api_factory_reset():
    database.clear_logs()
    rules_engine.flush_all_rules()
    return {"status": "ok", "message": "Factory reset complete. Please reboot."}

# Firewall status
@app.get("/api/settings/fw-status")
async def api_fw_status():
    rules = database.get_rules()
    return {"total_rules": len(rules), "enabled": sum(1 for r in rules if r.get("enabled")), "synced": True}

# Clear all firewall rules
@app.post("/api/rules/clear-all")
async def api_clear_all_rules():
    rules = database.get_rules()
    for r in rules:
        rules_engine.remove_rule_from_system(r)
        database.delete_rule(r["id"])
    return {"status": "ok"}

# Test email
@app.post("/api/settings/test-email")
async def api_test_email():
    import smtplib
    host = database.get_setting("email_host", "")
    port = int(database.get_setting("email_port", "587"))
    user = database.get_setting("email_user", "")
    pw   = database.get_setting("email_password", "")
    to   = database.get_setting("email_to", "")
    if not host or not to:
        return {"status": "error", "message": "Email not configured"}
    try:
        with smtplib.SMTP(host, port, timeout=5) as s:
            if port in (587, 465):
                s.starttls()
            if user:
                s.login(user, pw)
            s.sendmail(user or "aegisguard@localhost", to,
                       f"Subject: AegisGuard Test\r\n\r\nTest email from AegisGuard.")
        return {"status": "ok", "message": f"Test email sent to {to}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Blocked sites convenience
@app.post("/api/blocked/ip")
async def api_block_ip(request: Request):
    data = await request.json(); ip = data.get("ip","").strip()
    if not ip: raise HTTPException(400)
    database.add_rule(f"Block-IP:{ip}","BLOCK","BOTH","ANY","",ip,"","",1,10)
    return {"status":"ok"}
@app.delete("/api/blocked/ip/{rid}")
async def api_unblock_ip(rid:int):
    rule = next((r for r in database.get_rules() if r["id"]==rid),None)
    if rule: rules_engine.remove_rule_from_system(rule); database.delete_rule(rid)
    return {"status":"ok"}
@app.post("/api/blocked/domain")
async def api_block_domain(request: Request):
    data = await request.json(); domain = data.get("domain","").strip()
    if not domain: raise HTTPException(400)
    database.add_web_filter(domain,"Custom","BLOCK"); return {"status":"ok"}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — SSL VPN
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/vpn/ssl/config")
async def api_ssl_config():
    return database.get_ssl_vpn_config()

@app.post("/api/vpn/ssl/config")
async def api_save_ssl_config(request: Request):
    data = await request.json()
    database.save_ssl_vpn_config(**data)
    ssl_vpn.write_server_config()
    import threading
    threading.Thread(target=ssl_vpn.reload_systemd_server, daemon=True).start()
    return {"status": "ok"}

@app.post("/api/vpn/ssl/setup")
async def api_ssl_setup(request: Request):
    data = await request.json()
    port = data.get("port", 1194)
    proto = data.get("proto", "udp")
    subnet = data.get("server_subnet", "10.8.0.0")
    dns1 = data.get("dns1", "1.1.1.1")
    ok, msg = ssl_vpn.quick_setup(port=port, proto=proto, server_subnet=subnet, dns1=dns1)
    if ok:
        _auto_vpn_rules("SSL-VPN", proto.upper(), str(port))
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/vpn/ssl/start")
async def api_ssl_start():
    ok, msg = ssl_vpn.start_server()
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/vpn/ssl/stop")
async def api_ssl_stop():
    ok, msg = ssl_vpn.stop_server()
    return {"status": "ok" if ok else "error", "message": msg}

@app.get("/api/vpn/ssl/status")
async def api_ssl_status():
    return {"status": ssl_vpn.get_server_status(), "initialized": ssl_vpn.is_pki_initialized()}

@app.get("/api/vpn/ssl/clients")
async def api_ssl_clients():
    return ssl_vpn.get_connected_clients()

@app.get("/api/vpn/ssl/server-config")
async def api_ssl_server_conf():
    ssl_vpn.write_server_config()
    cfg = database.get_ssl_vpn_config()
    conf = ssl_vpn.write_server_config()
    try:
        with open(ssl_vpn.SERVER_CONF) as f:
            content = f.read()
    except Exception:
        content = "# Config file not yet generated. Run 'Start Server' first."
    return StreamingResponse(io.StringIO(content), media_type="text/plain",
                             headers={"Content-Disposition": "attachment; filename=aegisguard-ssl-vpn.conf"})

@app.get("/api/vpn/ssl/routes")
async def api_get_ssl_routes():
    return database.get_ssl_vpn_routes()

@app.post("/api/vpn/ssl/routes")
async def api_add_ssl_route(request: Request):
    data = await request.json()
    network = data.get("network", "").strip()
    netmask = data.get("netmask", "").strip()
    description = data.get("description", "").strip()
    if not network or not netmask:
        raise HTTPException(400, "network and netmask are required")
    database.add_ssl_vpn_route(network, netmask, description)
    ssl_vpn.apply_push_route_rules(network, netmask)
    ssl_vpn.refresh_server_conf()
    return {"status": "ok"}

@app.delete("/api/vpn/ssl/routes/{rid}")
async def api_del_ssl_route(rid: int):
    conn = database.get_connection()
    row = conn.execute("SELECT network, netmask FROM ssl_vpn_routes WHERE id=?", (rid,)).fetchone()
    conn.close()
    if row:
        ssl_vpn.remove_push_route_rules(row["network"], row["netmask"])
    database.delete_ssl_vpn_route(rid)
    ssl_vpn.refresh_server_conf()
    return {"status": "ok"}

@app.get("/api/vpn/users/{uid}/config")
async def api_vpn_user_config(uid: int):
    content = ssl_vpn.get_user_config_content(uid)
    if not content:
        raise HTTPException(404, "User or config not found")
    conn = database.get_connection()
    row = conn.execute("SELECT username FROM vpn_users WHERE id=?", (uid,)).fetchone()
    conn.close()
    username = row["username"] if row else f"user{uid}"
    return StreamingResponse(io.StringIO(content), media_type="text/plain",
                             headers={"Content-Disposition": f"attachment; filename={username}.ovpn"})


# ══════════════════════════════════════════════════════════════════════════════
# REST API — VPN Users
# ══════════════════════════════════════════════════════════════════════════════

class VPNUserCreate(BaseModel):
    username: str
    password: str
    full_name: str = ""
    email: str = ""
    group_name: str = "vpn-users"
    tunnel_ip: str = ""
    max_connections: int = 1
    bandwidth_limit: int = 0
    allowed_networks: str = ""
    expires_at: str = ""

@app.get("/api/vpn/users")
async def api_get_vpn_users():
    return database.get_vpn_users()

@app.post("/api/vpn/users")
async def api_add_vpn_user(u: VPNUserCreate):
    h = hash_password(u.password)
    database.add_vpn_user(
        username=u.username, password_hash=h, full_name=u.full_name,
        email=u.email, group_name=u.group_name, tunnel_ip=u.tunnel_ip,
        max_connections=u.max_connections, bandwidth_limit=u.bandwidth_limit,
        allowed_networks=u.allowed_networks, expires_at=u.expires_at
    )
    # Auto-generate .ovpn config
    user = database.get_vpn_user_by_username(u.username)
    if user:
        ssl_vpn.generate_user_config(user)
    return {"status": "ok"}

@app.delete("/api/vpn/users/{uid}")
async def api_del_vpn_user(uid: int):
    database.delete_vpn_user(uid)
    return {"status": "ok"}

@app.post("/api/vpn/users/{uid}/toggle")
async def api_toggle_vpn_user(uid: int):
    conn = database.get_connection()
    row = conn.execute("SELECT enabled FROM vpn_users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    database.update_vpn_user(uid, enabled=0 if row["enabled"] else 1)
    return {"status": "ok"}

@app.put("/api/vpn/users/{uid}/password")
async def api_change_vpn_user_password(uid: int, request: Request):
    data = await request.json()
    h = hash_password(data.get("password", ""))
    database.update_vpn_user(uid, password_hash=h)
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Branch Office VPN (BOV)
# ══════════════════════════════════════════════════════════════════════════════

class BOVCreate(BaseModel):
    name: str
    tunnel_type: str
    remote_gateway: str
    remote_subnets: str
    local_gateway: str = ""
    local_subnets: str = ""
    description: str = ""
    enabled: int = 1
    # IPSec
    psk: str = ""
    ike_version: str = "IKEv2"
    ike_cipher: str = "AES256"
    ike_hash: str = "SHA256"
    ike_dh: str = "DH14"
    ike_lifetime: int = 28800
    esp_cipher: str = "AES256"
    esp_hash: str = "SHA256"
    esp_lifetime: int = 3600
    pfs_group: str = "DH14"
    dpd_enabled: int = 1
    dpd_interval: int = 30
    dpd_timeout: int = 120
    nat_traversal: int = 1
    aggressive_mode: int = 0
    l2tp_local_ip: str = ""
    l2tp_remote_ip: str = ""
    # WireGuard
    wg_private_key: str = ""
    wg_public_key: str = ""
    wg_peer_pubkey: str = ""
    wg_preshared_key: str = ""
    wg_port: int = 51820
    wg_keepalive: int = 25
    # SSL
    ssl_port: int = 1194
    ssl_protocol: str = "udp"
    ssl_cipher: str = "AES-256-GCM"
    ssl_ca_cert: str = ""
    ssl_cert: str = ""
    ssl_key: str = ""
    ssl_ta_key: str = ""

@app.get("/api/vpn/bov")
async def api_get_bov():
    return database.get_bov_tunnels()

@app.post("/api/vpn/bov")
async def api_add_bov(t: BOVCreate):
    # Auto-create firewall rules based on tunnel type
    if t.tunnel_type == "WireGuard":
        _auto_vpn_rules("WireGuard-BOV", "UDP", str(t.wg_port or 51820))
    elif t.tunnel_type in ("IKEv2", "IKEv1", "L2TP-IPSec"):
        _auto_vpn_rules("IPSec-IKE", "UDP", "500")
        _auto_vpn_rules("IPSec-NAT-T", "UDP", "4500")
    elif t.tunnel_type == "SSL-OpenVPN":
        _auto_vpn_rules("SSL-BOV", "UDP", str(t.ssl_port or 1194))
    database.add_bov_tunnel(
        name=t.name, tunnel_type=t.tunnel_type,
        remote_gateway=t.remote_gateway, remote_subnets=t.remote_subnets,
        local_subnets=t.local_subnets, local_gateway=t.local_gateway,
        psk=t.psk, ike_version=t.ike_version, ike_cipher=t.ike_cipher,
        ike_hash=t.ike_hash, ike_dh=t.ike_dh, ike_lifetime=t.ike_lifetime,
        esp_cipher=t.esp_cipher, esp_hash=t.esp_hash, esp_lifetime=t.esp_lifetime,
        pfs_group=t.pfs_group, dpd_enabled=t.dpd_enabled, dpd_interval=t.dpd_interval,
        dpd_timeout=t.dpd_timeout, nat_traversal=t.nat_traversal,
        aggressive_mode=t.aggressive_mode, l2tp_local_ip=t.l2tp_local_ip,
        l2tp_remote_ip=t.l2tp_remote_ip, ssl_port=t.ssl_port, ssl_protocol=t.ssl_protocol,
        ssl_cipher=t.ssl_cipher, ssl_ca_cert=t.ssl_ca_cert, ssl_cert=t.ssl_cert,
        ssl_key=t.ssl_key, ssl_ta_key=t.ssl_ta_key, wg_private_key=t.wg_private_key,
        wg_public_key=t.wg_public_key, wg_peer_pubkey=t.wg_peer_pubkey,
        wg_preshared_key=t.wg_preshared_key, wg_port=t.wg_port,
        wg_keepalive=t.wg_keepalive, enabled=t.enabled, description=t.description
    )
    return {"status": "ok"}

@app.delete("/api/vpn/bov/{tid}")
async def api_del_bov(tid: int):
    tunnel = next((t for t in database.get_bov_tunnels() if t["id"] == tid), None)
    if tunnel:
        bov_manager.delete_tunnel(tunnel)
    database.delete_bov_tunnel(tid)
    return {"status": "ok"}

@app.post("/api/vpn/bov/{tid}/connect")
async def api_bov_connect(tid: int):
    tunnel = next((t for t in database.get_bov_tunnels() if t["id"] == tid), None)
    if not tunnel:
        raise HTTPException(404)
    ok, msg = bov_manager.connect_tunnel(tunnel)
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/vpn/bov/{tid}/disconnect")
async def api_bov_disconnect(tid: int):
    tunnel = next((t for t in database.get_bov_tunnels() if t["id"] == tid), None)
    if not tunnel:
        raise HTTPException(404)
    ok, msg = bov_manager.disconnect_tunnel(tunnel)
    return {"status": "ok" if ok else "error", "message": msg}

@app.get("/api/vpn/bov/{tid}/peer-config")
async def api_bov_peer_config(tid: int):
    tunnel = next((t for t in database.get_bov_tunnels() if t["id"] == tid), None)
    if not tunnel:
        raise HTTPException(404)
    conf = bov_manager.export_peer_config(tunnel)
    return StreamingResponse(
        io.StringIO(conf), media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=bov-{tunnel['name']}-peer.conf"}
    )

@app.post("/api/vpn/bov/apply-ipsec")
async def api_apply_ipsec():
    ok, msg = bov_manager.apply_ipsec_tunnels()
    return {"status": "ok" if ok else "error", "message": msg}

@app.get("/api/vpn/bov/ipsec-status")
async def api_bov_ipsec_status():
    return {"output": bov_manager.get_ipsec_status()}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — Multi-WAN
# ══════════════════════════════════════════════════════════════════════════════

class WanLinkCreate(BaseModel):
    name: str; interface: str; gateway: str
    weight: int = 1; priority: int = 1; mode: str = "failover"
    check_ip: str = "8.8.8.8"; check_interval: int = 10
    check_timeout: int = 3; check_failures: int = 3
    enabled: int = 1; description: str = ""

@app.get("/api/network/wan-links")
async def api_get_wan_links():
    return multiwan_manager.get_status()

@app.post("/api/network/wan-links")
async def api_add_wan_link(link: WanLinkCreate):
    database.add_wan_link(**link.model_dump())
    return {"status": "ok"}

@app.put("/api/network/wan-links/{lid}")
async def api_update_wan_link(lid: int, link: WanLinkCreate):
    database.update_wan_link(lid, **link.model_dump())
    return {"status": "ok"}

@app.delete("/api/network/wan-links/{lid}")
async def api_del_wan_link(lid: int):
    database.delete_wan_link(lid)
    return {"status": "ok"}

@app.post("/api/network/wan-links/apply")
async def api_apply_multiwan():
    ok, msg = multiwan_manager.apply_routing()
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/network/wan-links/{lid}/failover")
async def api_force_failover(lid: int):
    ok, msg = multiwan_manager.failover_to(lid)
    return {"status": "ok" if ok else "error", "message": msg}

@app.get("/api/network/wan-links/status")
async def api_wan_status():
    return multiwan_manager.get_status()


# ══════════════════════════════════════════════════════════════════════════════
# REST API — High Availability
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ha/config")
async def api_get_ha():
    return database.get_ha_config()

@app.post("/api/ha/config")
async def api_save_ha(request: Request):
    data = await request.json()
    database.save_ha_config(**data)
    return {"status": "ok"}

@app.post("/api/ha/apply")
async def api_apply_ha():
    ok, msg = ha_manager.apply_ha()
    return {"status": "ok" if ok else "error", "message": msg}

@app.post("/api/ha/stop")
async def api_stop_ha():
    ok, msg = ha_manager.stop_ha()
    return {"status": "ok" if ok else "error", "message": msg}

@app.get("/api/ha/status")
async def api_ha_status():
    return ha_manager.get_ha_status()

@app.post("/api/ha/sync")
async def api_ha_sync():
    ok, msg = ha_manager.sync_now()
    return {"status": "ok" if ok else "error", "message": msg}


# ══════════════════════════════════════════════════════════════════════════════
# REST API — License
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/license")
async def api_license_status():
    status, info = license_manager.validate_license(force=True)
    return {"status": status, **info}

@app.post("/api/license")
async def api_license_save(request: Request):
    data = await request.json()
    # Accept both "key" (from GUI) and "license_key" (legacy)
    key = (data.get("key") or data.get("license_key") or "").strip()
    if not key:
        raise HTTPException(400, "License key is required")
    import base64 as _b64, json as _json
    try:
        _json.loads(_b64.b64decode(key).decode())
    except Exception:
        raise HTTPException(400, "Invalid license key format")
    try:
        run(["mkdir", "-p", "/etc/aegisguard"])
        ok, out, err = run(["bash", "-c", f'printf "%s" "{key}" > /etc/aegisguard/license.key'])
        if not ok:
            raise HTTPException(500, f"Could not write license file: {err}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))
    status, info = license_manager.validate_license(force=True)
    if status == "invalid":
        raise HTTPException(400, "License key saved but validation failed — check MAC address or signature")
    database.add_log("INFO", details=f"License updated: {status}, customer={info.get('customer','')}, expires={info.get('expires','')}")
    # Re-apply licensed features now that license is active
    if IS_LINUX and status in ("valid", "expiring"):
        try:
            web_filter.apply_filters()
        except Exception:
            pass
        try:
            from core import geoblock as _gb
            _gb.apply_geoblock()
        except Exception:
            pass
    return {"status": status, **info}

@app.delete("/api/license")
async def api_license_remove():
    run(["rm", "-f", "/etc/aegisguard/license.key"])
    license_manager.validate_license(force=True)
    return {"status": "ok", "message": "License removed"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.api:app", host="0.0.0.0", port=8080, reload=False)
