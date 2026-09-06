#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║            CSCAN — Cybersecurity Scanner Toolkit             ║
║        Professional Penetration Testing & Recon Suite        ║
║ For Authorized Testing ONLY | by charlie                     ║
╚══════════════════════════════════════════════════════════════╝
Usage: python cscan.py
"""

import os
import sys
import argparse
import asyncio
import inspect
import functools

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

VERSION = "0.9.0"
SUPPORTED_MODULES = {
    "dns": "DNS and host intelligence",
    "web": "Web vulnerability checks and header review",
    "crawl": "Crawler-based endpoint discovery",
    "ssl": "TLS and certificate inspection",
    "ports": "Common-port and full-port discovery",
    "nuclei": "Fast template-based vulnerability checks with Nuclei",
    "osint-origin": "Find real server IP behind Cloudflare/WAF (passive OSINT)",
    "auto": "Default end-to-end scan pipeline"
}

async def _run_sync(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))

import json
import time
import random
from datetime import datetime

# Prevent UnicodeEncodeError kwenye Windows terminals
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# ── Dependency check ──────────────────────────────────────────────────────────
REQUIRED = {'requests': 'requests', 'colorama': 'colorama',
            'whois': 'python-whois'}

OPTIONAL = {'paramiko': 'paramiko', 'nmap': 'python-nmap'}

missing = []
for mod, pkg in REQUIRED.items():
    try:
        __import__(mod)
    except ImportError:
        missing.append(pkg)

if missing:
    print(f"\n[!] Missing required packages: {', '.join(missing)}")
    print(f"[!] Please install dependencies securely by running:")
    print(f"    pip install -r requirements.txt\n")
    sys.exit(1)

# Check optional dependencies
unavailable_optional = []
for mod, pkg in OPTIONAL.items():
    try:
        __import__(mod)
    except ImportError:
        unavailable_optional.append(pkg)

# ── Language system must be loaded BEFORE ui ────────────────
from modules.lang import (
    T, get_lang, set_lang, save_language,
    is_first_launch, load_saved_language
)
load_saved_language()

# ── Import our modules ────────────────────────────────────────────────────────
from modules.ui        import *
from modules.recon     import dns_lookup, whois_lookup, subdomain_enum, geoip_lookup, reverse_dns
from modules.recon     import set_stealth_session as recon_set_stealth
from modules.scanner   import port_scan_common, port_scan_full, banner_grabber, ssl_inspect, COMMON_PORTS, set_scan_timeout
from modules.web       import web_vuln_scan, http_header_audit, dir_bruteforce, cms_detect, auto_cve_mapping
from modules.web       import set_stealth_session as web_set_stealth, set_insecure_ssl as web_set_insecure_ssl
from modules.exploit   import ssh_audit, ftp_anon_check, http_auth_brute
from modules.exploit   import set_stealth_session as exploit_set_stealth, set_insecure_ssl as exploit_set_insecure_ssl
from modules.ai_analyst import (
    prompt_api_key, analyze_findings, quick_host_analysis,
    cve_lookup, ask_ai, generate_formal_report
)
from modules.stealth   import StealthSession, TIMING_PROFILES, WAF_SIGNATURES
from modules.cloudflare_bypass import handle_cf_bypass_menu, inject_cf_cookies, _CAMOUFOX_AVAILABLE
from modules.cloudflare_bypass import CloudflareBypassConfig, solve_cloudflare_waf
from modules.browser_engine import (
    menu_js_render, menu_network_capture, menu_login_test,
    menu_screenshot, menu_fingerprint_probe, menu_harvest_cookies,
    menu_js_secrets
)
# ── New v2.2 modules ──────────────────────────────────────────────────────────
from modules.active_vuln  import active_vuln_scan, scan_sqli_target
from modules.active_vuln  import set_stealth_session as activevuln_set_stealth
from modules.active_vuln  import set_auth_header as activevuln_set_auth_header
from modules.nvd_cve      import live_cve_mapping, menu_nvd_lookup
from modules.udp_scanner  import udp_scan_suite
from modules.ssl_audit    import ssl_deep_audit
from modules.osint        import menu_osint
from modules.service_brute import service_brute_suite
# ── v3.0 — Crawler & Auth ────────────────────────────────────────────────────
from modules.crawler      import crawl_target
from modules.crawler      import set_stealth_session as crawler_set_stealth
from modules.crawler      import set_insecure_ssl as crawler_set_insecure_ssl
# ── v3.1 — Path/API Enumerator ───────────────────────────────────────────────
from modules.path_api_enum import enumerate_api
from modules.path_api_enum import set_stealth_session as apienum_set_stealth
from modules.path_api_enum import set_insecure_ssl as apienum_set_insecure_ssl
from modules.mobile_api_enum import enumerate_mobile_api_endpoints
from modules.nuclei import run_nuclei_scan, nuclei_available, install_nuclei_instructions
from modules.utils import normalize_target
from modules.osnit_origin_ip import find_origin_ip

# ── Session state ─────────────────────────────────────────────────────────────
SESSION = {
    'target':      None,
    'ip':          None,
    'use_ssl':     False,
    'results':     {},
    'log':         [],
    'start_time':  None,
    'gemini_key':  None,   # Gemini API key (stored in-memory only)
    'credential_testing': False,
    'interactive':       False,   # True only in menu-driven interactive mode
    'auth': {
        'cookies':     {},     # dict of cookie name→value for authenticated scanning
        'header':      None,   # Authorization header value (e.g. 'Bearer xxx')
    },
    'stealth': {
        'enabled':      False,
        'proxy':        None,
        'jitter_min':   0.5,
        'jitter_max':   2.0,
        'timing':       'normal',
        'mutate_paths': False,
        'rotate_ua':    True,
        'try_nmap':     False,
        'insecure_ssl': False,
        'scan_timeout': None,   # None = use timing-profile default; float = override in seconds
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  LANGUAGE PICKER  (shown only on very first launch)
# ─────────────────────────────────────────────────────────────────────────────

def run_language_picker():
    """
    Display a bilingual language selection screen on the very first launch.
    The choice is persisted to ~/.cscan_config.json so it is never asked again.
    """
    cls()

    # Bilingual header — shown before any language is chosen
    print(f"""
{BR}{C}  ╔══════════════════════════════════════════════════════════╗
  ║        LANGUAGE SELECTION  /  CHAGUA LUGHA              ║
  ╚══════════════════════════════════════════════════════════╝{RS}

  {W}Welcome to CSCAN!  /  Karibu CSCAN!{RS}

  {C}Please choose your preferred language.
  Tafadhali chagua lugha unayopendelea.{RS}

  {BR}{G}[1]{RS}  English
  {BR}{G}[2]{RS}  Kiswahili

""")

    raw = input(f"  {BR}{M}[>]{RS} {BR}{W}Enter choice / Ingiza chaguo [1/2]: {RS}").strip()

    if raw == '2':
        save_language('sw')
        print(f"\n  {BR}{G}[OK]{RS}  Kiswahili imechaguliwa. / Kiswahili selected.")
    else:
        save_language('en')
        if raw != '1':
            print(f"\n  {BR}{Y}[!]{RS}  Invalid choice — using English.")
        else:
            print(f"\n  {BR}{G}[OK]{RS}  English selected.")

    time.sleep(1)


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def cls():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_target(force: bool = False) -> str:
    """Return current target or prompt for one."""
    if SESSION['target'] and (not force or not SESSION.get('interactive')):
        return SESSION['target']
    print()
    t = prompt_target(T("prompt_target"))
    if not t:
        return None
    try:
        t = normalize_target(t)
    except ValueError as exc:
        alert(str(exc))
        return None
    SESSION['target'] = t
    SESSION['use_ssl'] = t.startswith('https://')
    return t

def set_target():
    """Manually set / change the active target."""
    section(T("set_target_title"))
    t = prompt_target()
    if not t:
        return
    try:
        t = normalize_target(t)
    except ValueError as exc:
        alert(str(exc))
        return
    SESSION['target'] = t
    SESSION['use_ssl'] = t.startswith('https://')
    ok(f"{T('target_set')} {BR}{G}{t}{RS}")

    # Quick DNS resolve
    import socket
    import ipaddress
    from urllib.parse import urlparse
    hostname = urlparse(t).hostname if '://' in t else t.split('/')[0]
    try:
        ip = socket.gethostbyname(hostname)
        SESSION['ip'] = ip
        info(f"{T('resolved_ip')} {BR}{G}{ip}{RS}")
    except Exception:
        warn(T("no_resolve_warn"))

def _apply_stealth():
    """Push current stealth config down to the network/web modules."""
    cfg = SESSION['stealth']
    insecure_ssl = cfg.get('insecure_ssl', False)
    web_set_insecure_ssl(insecure_ssl)
    exploit_set_insecure_ssl(insecure_ssl)

    # FIX #6: push custom scan timeout to scanner module
    set_scan_timeout(cfg.get('scan_timeout'))  # None clears override

    apienum_set_insecure_ssl(insecure_ssl)
    crawler_set_insecure_ssl(insecure_ssl)
    activevuln_set_auth_header(SESSION['auth'].get('header'))

    if cfg['enabled']:
        sess = StealthSession(
            proxy=cfg['proxy'],
            jitter_min=cfg['jitter_min'],
            jitter_max=cfg['jitter_max'],
            rotate_ua=cfg['rotate_ua'],
            random_headers=True,
            cookie_persist=True,
            insecure_ssl=insecure_ssl
        )
        web_set_stealth(sess)
        recon_set_stealth(sess)
        exploit_set_stealth(sess)
        activevuln_set_stealth(sess)
        crawler_set_stealth(sess)
        apienum_set_stealth(sess)
    else:
        web_set_stealth(None)
        recon_set_stealth(None)
        exploit_set_stealth(None)
        activevuln_set_stealth(None)
        crawler_set_stealth(None)
        apienum_set_stealth(None)


def show_status():
    """Show current session status bar."""
    from modules.ui import DM, C, BR, W, G, Y, M, RS, T
    t   = SESSION['target'] or f"{DM}{T('status_not_set')}{RS}"
    ip  = SESSION['ip']     or f"{DM}{T('status_unknown')}{RS}"
    ssl = f"{G}HTTPS{RS}" if SESSION['use_ssl'] else f"{Y}HTTP{RS}"
    ai  = f"{M}ON{RS}" if SESSION['gemini_key'] else f"{DM}OFF{RS}"
    st  = f"{G}ON{RS}" if SESSION['stealth']['enabled'] else f"{DM}OFF{RS}"
    
    dur = ''
    if SESSION['start_time']:
        secs = int(time.time() - SESSION['start_time'])
        dur  = f"   {BR}{W}TIME:{RS} {secs}s"

    # Show origin IP in status if found
    origin_display = ""
    if 'origin_ip' in SESSION['results']:
        origin_res = SESSION['results']['origin_ip']
        if origin_res and hasattr(origin_res, 'confirmed') and origin_res.confirmed():
            real_ip = origin_res.confirmed()[0].ip
            origin_display = f"   {BR}{R}REAL IP:{RS} {real_ip}"

    print(f"\n  {BR}{W}TARGET:{RS} {C}{t}{RS}   {BR}{W}IP:{RS} {ip}{origin_display}   {BR}{W}PROTO:{RS} {ssl}   {BR}{W}STEALTH:{RS} {st}   {BR}{W}AI:{RS} {ai}{dur}")


# ─────────────────────────────────────────────────────────────────────────────
#  MENU HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_dns():
    t = get_target()
    if not t: return
    res = await _run_sync(dns_lookup, t)
    SESSION['results']['dns'] = res
    if res.get('ipv4'):
        SESSION['ip'] = res['ipv4'][0]
    pause()

async def handle_whois():
    t = get_target()
    if not t: return
    res = await _run_sync(whois_lookup, t)
    SESSION['results']['whois'] = res
    pause()

async def handle_subdomain():
    t = get_target()
    if not t: return
    section(T("subdomain_title"))
    wl = None
    bundled = os.path.join(os.path.dirname(__file__), 'wordlists', 'subdomains.txt')
    if os.path.isfile(bundled):
        with open(bundled) as f:
            wl = [line.strip() for line in f if line.strip()]
        info(T("wordlist_loaded", n=len(wl)))
    timing = SESSION['stealth']['timing'] if SESSION['stealth']['enabled'] else 'normal'
    workers = TIMING_PROFILES.get(timing, {}).get('workers', 30)
    res = await _run_sync(subdomain_enum, t, wl, workers=workers)
    SESSION['results']['subdomains'] = res
    pause()

async def handle_geoip():
    t = get_target()
    if not t: return
    res = await _run_sync(geoip_lookup, t)
    SESSION['results']['geoip'] = res
    pause()

async def handle_reverse_dns():
    t = get_target()
    if not t: return
    res = await _run_sync(reverse_dns, t)
    SESSION['results']['reverse_dns'] = res
    pause()

async def handle_port_common():
    t = get_target()
    if not t: return
    _apply_stealth()
    timing = SESSION['stealth']['timing']
    try_nmap = SESSION['stealth']['try_nmap']
    res = await _run_sync(port_scan_common, t, timing=timing, try_nmap=try_nmap)
    SESSION['results']['ports_common'] = res
    # Store IP if we got one
    if res and not SESSION['ip']:
        import socket
        try:
            SESSION['ip'] = socket.gethostbyname(t.split('//')[-1].split('/')[0])
        except Exception:
            pass
    pause()

async def handle_port_full():
    t = get_target()
    if not t: return
    _apply_stealth()
    section(T("port_full_title"))
    start, end = 1, 65535
    timing = SESSION['stealth']['timing']
    try_nmap = SESSION['stealth']['try_nmap']
    res = await _run_sync(port_scan_full, t, start, end, timing=timing, try_nmap=try_nmap)
    SESSION['results']['ports_full'] = res
    pause()

async def handle_banner_grab():
    t = get_target()
    if not t: return
    section(T("banner_title"))
    # Use ports from previous scan if available, otherwise scan common ports
    ports = None
    prev_ports = SESSION['results'].get('ports_common', [])
    if prev_ports:
        ports = [p['port'] for p in prev_ports if isinstance(p, dict) and 'port' in p]
    res = await _run_sync(banner_grabber, t, ports)
    SESSION['results']['banners'] = res
    pause()

async def handle_ssl():
    t = get_target()
    if not t: return
    port = 443
    res = await _run_sync(ssl_inspect, t, port)
    SESSION['results']['ssl'] = res
    pause()

async def handle_web_vuln():
    t = get_target()
    if not t: return
    _apply_stealth()
    mutate = SESSION['stealth']['mutate_paths']
    timing = SESSION['stealth']['timing'] if SESSION['stealth']['enabled'] else 'normal'
    workers = TIMING_PROFILES.get(timing, {}).get('workers', 20)
    res = await _run_sync(web_vuln_scan, t, SESSION['use_ssl'], mutate=mutate, workers=workers)
    SESSION['results']['web_vuln'] = res
    pause()

async def handle_header_audit():
    t = get_target()
    if not t: return
    res = await _run_sync(http_header_audit, t, SESSION['use_ssl'])
    SESSION['results']['headers'] = res
    pause()

async def handle_dir_brute():
    t = get_target()
    if not t: return
    _apply_stealth()
    section(T("dir_brute_title"))
    wl = None
    bundled = os.path.join(os.path.dirname(__file__), 'wordlists', 'dir_bruteforce.txt')
    if os.path.isfile(bundled):
        with open(bundled) as f:
            wl = [l.strip() for l in f if l.strip()]
        info(T("wordlist_loaded", n=len(wl)))
    mutate = SESSION['stealth']['mutate_paths']
    timing = SESSION['stealth']['timing'] if SESSION['stealth']['enabled'] else 'normal'
    workers = TIMING_PROFILES.get(timing, {}).get('workers', 20)
    res = await _run_sync(dir_bruteforce, t, SESSION['use_ssl'], wl, mutate=mutate, workers=workers)
    SESSION['results']['dir_brute'] = res
    pause()

async def handle_cms():
    t = get_target()
    if not t: return
    res = await _run_sync(cms_detect, t, SESSION['use_ssl'])
    SESSION['results']['cms'] = res
    pause()

async def handle_ssh():
    if 'paramiko' in unavailable_optional:
        alert("SSH Auditing is not available (paramiko not installed)")
        info("On Termux: SSH auditing is disabled due to cryptography build requirements")
        pause()
        return
    
    t = get_target()
    if not t: return
    _apply_stealth()
    section(T("ssh_title"))
    port = 22

    # Auto-load SSH creds wordlist
    creds = None
    creds_file = os.path.join(os.path.dirname(__file__), 'wordlists', 'ssh_creds.txt')
    if os.path.isfile(creds_file):
        try:
            with open(creds_file) as f:
                creds = [tuple(l.strip().split(':', 1)) for l in f if ':' in l]
            info(T("creds_loaded", n=len(creds)))
        except Exception:
            pass

    delay = 0.0
    if SESSION['stealth']['enabled']:
        delay = random.uniform(SESSION['stealth']['jitter_min'], SESSION['stealth']['jitter_max'])
    res = await _run_sync(ssh_audit, t, port, creds, delay,
                          SESSION['credential_testing'])
    SESSION['results']['ssh'] = res
    pause()

async def handle_ftp():
    t = get_target()
    if not t: return
    port = 21
    res = await _run_sync(ftp_anon_check, t, port)
    SESSION['results']['ftp'] = res
    pause()

async def handle_http_auth():
    t = get_target()
    if not t: return
    _apply_stealth()
    section(T("http_auth_title"))
    path = '/'
    res  = await _run_sync(http_auth_brute, t, path, None,
                           SESSION['credential_testing'])
    SESSION['results']['http_auth'] = res
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  NEW V2.2 HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_active_vuln():
    t = get_target()
    if not t: return
    _apply_stealth()
    crawl_data = SESSION['results'].get('crawl', None)
    cookies = SESSION['auth'].get('cookies') or None
    if not crawl_data:
        warn("No crawl data found. Running Web Crawler first for best results...")
        await handle_crawl()
        crawl_data = SESSION['results'].get('crawl', None)
    res = await _run_sync(active_vuln_scan, t, SESSION['use_ssl'],
                          crawl_data=crawl_data, cookies=cookies)
    SESSION['results']['active_vuln'] = res
    pause()


async def handle_nvd_cve():
    """Live NVD CVE lookup — searches against detected software versions."""
    t = get_target()
    if not t: return
    # Re-use any versions already extracted in this session
    detected = {}
    auto = SESSION['results'].get('auto_scan', {})
    for key, val in auto.items():
        if 'CVE' in key and isinstance(val, dict):
            for tech, td in val.items():
                if isinstance(td, dict) and 'version' in td:
                    detected[tech] = td['version']
    # Also check web extract
    from modules.web import extract_versions
    web_vers = await _run_sync(extract_versions, t, SESSION['use_ssl'])
    detected.update(web_vers)

    ports_data = SESSION['results'].get('ports_common', [])
    res = await _run_sync(live_cve_mapping, detected, ports_data)
    SESSION['results']['live_cve'] = res
    pause()


async def handle_nvd_manual():
    """Manual NVD keyword lookup."""
    res = await _run_sync(menu_nvd_lookup)
    if res:
        SESSION['results']['nvd_lookup'] = res
    pause()


async def handle_udp_scan():
    t = get_target()
    if not t: return
    res = await _run_sync(udp_scan_suite, t, None)
    SESSION['results']['udp_scan'] = res
    pause()


async def handle_ssl_deep():
    t = get_target()
    if not t: return
    port = 443
    res = await _run_sync(ssl_deep_audit, t, port)
    SESSION['results']['ssl_deep'] = res
    pause()


async def handle_osint():
    t = get_target()
    if not t: return
    res = await _run_sync(menu_osint, SESSION)
    if res:
        SESSION['results']['osint'] = res
    pause()


async def handle_service_brute():
    t = get_target()
    if not t: return
    open_ports = SESSION['results'].get('ports_common', [])
    if not open_ports:
        warn("No port scan data found. Run port scan first (or proceed to check all default ports).")
    res = await _run_sync(service_brute_suite, t, open_ports or None,
                          SESSION['credential_testing'])
    SESSION['results']['service_brute'] = res
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  v3.0 HANDLERS — CRAWLER & AUTH
# ─────────────────────────────────────────────────────────────────────────────

async def handle_crawl():
    """Run the web crawler to discover pages, forms, parameters."""
    t = get_target()
    if not t: return
    _apply_stealth()

    depth = 3
    pages = 100
    cookies = SESSION['auth'].get('cookies') or None
    auth_header = SESSION['auth'].get('header') or None

    res = await _run_sync(crawl_target, t, SESSION['use_ssl'],
                          max_depth=depth, max_pages=pages,
                          cookies=cookies, auth_header=auth_header)
    SESSION['results']['crawl'] = res
    pause()


def handle_auth_config():
    """Configure authentication cookies/tokens for authenticated scanning."""
    section("AUTHENTICATED SCANNING CONFIGURATION")
    auth = SESSION['auth']

    info("Configure auth to scan behind login walls.")
    info("All subsequent scans (crawler, vuln scan, etc.) will use these credentials.\n")

    # Show current state
    if auth.get('cookies'):
        ok(f"Current cookies: {len(auth['cookies'])} configured")
        for name in auth['cookies']:
            print(f"    {G}•{RS} {name}")
    if auth.get('header'):
        ok(f"Auth header: {auth['header'][:30]}...")
    print()

    print(f"  {BR}{C}[1]{RS} Set cookies manually (name=value pairs)")
    print(f"  {BR}{C}[2]{RS} Set Authorization header (Bearer token, Basic auth)")
    print(f"  {BR}{C}[3]{RS} Import cookies from browser (paste JSON)")
    print(f"  {BR}{C}[4]{RS} Clear all auth")
    print(f"  {BR}{Y}[Enter]{RS} Keep current\n")

    choice = input(f"  {BR}{M}[>]{RS} {BR}{W}Choice: {RS}").strip()

    if choice == '1':
        info("Enter cookies one per line as name=value. Empty line to finish.")
        cookies = {}
        while True:
            line = input(f"  {G}cookie>{RS} ").strip()
            if not line:
                break
            if '=' in line:
                name, val = line.split('=', 1)
                cookies[name.strip()] = val.strip()
        auth['cookies'] = cookies
        ok(f"{len(cookies)} cookie(s) configured.")

    elif choice == '2':
        header = input(f"  {BR}{W}Authorization header value (e.g. 'Bearer eyJ...'): {RS}").strip()
        if header:
            auth['header'] = header
            ok("Authorization header configured.")

    elif choice == '3':
        info("Paste a JSON object of cookies ({\"name\": \"value\", ...}):")
        raw = input(f"  {G}json>{RS} ").strip()
        try:
            import json as _json
            cookies = _json.loads(raw)
            if isinstance(cookies, dict):
                auth['cookies'] = cookies
                ok(f"{len(cookies)} cookie(s) imported.")
            else:
                warn("Expected a JSON object, not a list.")
        except Exception as e:
            alert(f"Invalid JSON: {e}")

    elif choice == '4':
        auth['cookies'] = {}
        auth['header'] = None
        ok("Auth cleared.")

    pause()


# ── v3.1 — Path/API Enumerator Handler ───────────────────────────────────────
async def handle_api_enum():
    """Handler for Path/API Endpoint Enumerator."""
    t = get_target()
    if not t:
        return
    _apply_stealth()

    # Auto-load the extended wordlist if available, otherwise use built-in defaults
    wl = None
    bundled = os.path.join(os.path.dirname(__file__), 'wordlists', 'api_paths.txt')
    if os.path.isfile(bundled):
        with open(bundled) as f:
            wl = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        info(f"Loaded {len(wl)} paths from api_paths.txt.")

    timing = SESSION['stealth']['timing'] if SESSION['stealth']['enabled'] else 'normal'
    from modules.stealth import TIMING_PROFILES
    workers = TIMING_PROFILES.get(timing, {}).get('workers', 15)

    res = await _run_sync(enumerate_api, t, SESSION['use_ssl'],
                          wordlist=wl, workers=workers, probe_methods=True,
                          probe_unsafe_methods=False)
    SESSION['results']['api_enum'] = res
    pause()


async def handle_mobile_api_enum():
    """Lightweight API enumeration aimed at mobile and constrained environments."""
    t = get_target()
    if not t:
        return

    wl = None
    bundled = os.path.join(os.path.dirname(__file__), 'wordlists', 'api_paths.txt')
    if os.path.isfile(bundled):
        with open(bundled) as f:
            wl = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    res = await _run_sync(
        enumerate_mobile_api_endpoints,
        t,
        SESSION['use_ssl'],
        wordlist=wl,
        probe=True,
        timeout=6.0,
    )
    SESSION['results']['mobile_api_enum'] = res
    pause()


def _probe_waf(target: str) -> list:
    """
    Send a suspicious GET request to the target and check response headers/body
    for known WAF signatures. Returns a list of detected WAF names.
    """
    import requests as _req
    from urllib.parse import urlparse as _up

    url = target if target.startswith(('http://', 'https://')) else f'http://{target}'
    detected = []
    try:
        # Send a suspicious payload to trigger an active WAF block
        probe_url = url.rstrip('/') + '/?id=1%27%20OR%20%271%27=%271'
        r = _req.get(
            probe_url, timeout=8, verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CSCAN-WAF-Probe'},
            allow_redirects=True,
        )
        combined = (r.text or '').lower()
        for k, v in r.headers.items():
            combined += f' {k.lower()}: {v.lower()}'
            
        # Only consider it a WAF if it actively blocks us or returns WAF-specific headers
        if r.status_code in (403, 406, 429, 503):
            for waf_name, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in combined:
                        detected.append(waf_name)
                        break
            if not detected:
                generic_phrases = ['access denied', 'blocked', 'forbidden', 'security', 'firewall', 'ddos', 'attention required']
                if any(p in combined for p in generic_phrases):
                    detected.append('generic')
    except Exception:
        pass
    return list(set(detected))


def _auto_waf_evasion(target: str) -> dict:
    """
    Probes target for WAF presence, then auto-escalates stealth settings
    and optionally solves Cloudflare UAM so the full auto-scan can proceed.

    Returns a dict with:
        wafs_found   - list of detected WAF names
        cf_bypassed  - True if Cloudflare was solved successfully
        evasion_on   - True if any evasion was applied
    """
    from modules.ui import section, ok, warn, alert, info, critical
    section("WAF PRE-SCAN DETECTION & AUTO-EVASION")
    info(f"Probing target for WAF/firewall signatures: {BR}{C}{target}{RS}")

    wafs = _probe_waf(target)
    result = {'wafs_found': wafs, 'cf_bypassed': False, 'evasion_on': False, 'techniques_applied': []}

    if not wafs:
        ok("No WAF detected — full scan will run at normal speed.")
        return result

    # Report what we found
    for w in wafs:
        warn(f"WAF detected: {BR}{Y}{w.upper()}{RS}")

    # ── Step 1: Always force stealth mode ON when WAF is present ──────────────
    cfg = SESSION['stealth']
    cfg['enabled']     = True
    cfg['rotate_ua']   = True
    cfg['mutate_paths'] = True
    result['evasion_on'] = True
    result['techniques_applied'].extend(['stealth_headers', 'rotate_user_agent', 'mutate_paths'])

    # ── Step 2: Escalate timing to 'sneaky' unless user already set something slower
    current_timing = cfg.get('timing', 'normal')
    slow_profiles   = ('paranoid', 'sneaky', 'polite')
    if current_timing not in slow_profiles:
        cfg['timing'] = 'sneaky'
        result['techniques_applied'].append('escalate_timing_to_sneaky')
        info(f"Timing escalated to {BR}{Y}sneaky{RS} to reduce WAF trigger rate.")

    # ── Step 3: Enable jitter if not already configured ───────────────────────
    if cfg['jitter_max'] <= 0.5:
        cfg['jitter_min'] = 1.0
        cfg['jitter_max'] = 3.5
        result['techniques_applied'].append('add_jitter')
        info(f"Request jitter set to {BR}{Y}1.0 – 3.5 s{RS} to mimic organic traffic.")

    # Push updated config to all network modules
    _apply_stealth()
    ok("Stealth mode AUTO-ENABLED with WAF-evasion settings.")

    # ── Step 4: Cloudflare-specific — attempt cf_clearance bypass ─────────────
    if 'cloudflare' in wafs:
        result['techniques_applied'].append('cf_uam_bypass_attempt')
        if _CAMOUFOX_AVAILABLE:
            print(f"\n  {BR}{M}[CF]{RS}  {Y}Cloudflare detected — attempting UAM bypass via browser engine...{RS}")
            proxy = cfg.get('proxy') if cfg.get('enabled') else None
            cf_cfg = CloudflareBypassConfig(
                domain=target if target.startswith('http') else f'https://{target}',
                headless=True,
                proxy=proxy,
                humanize=True,
                geoip=bool(proxy),
                os='windows',
                i_know_what_im_doing=True,
                timeout_ms=35_000,
            )
            cf_result = solve_cloudflare_waf(cf_cfg)
            if cf_result:
                cf_clearance, user_agent = cf_result
                ok(f"cf_clearance obtained — injecting into stealth session.")
                # Build a fresh stealth session and inject the cookie
                sess_obj = StealthSession(
                    proxy=cfg.get('proxy'),
                    jitter_min=cfg['jitter_min'],
                    jitter_max=cfg['jitter_max'],
                    rotate_ua=False,   # keep the CF-matched UA fixed
                    random_headers=True,
                    cookie_persist=True,
                    insecure_ssl=cfg.get('insecure_ssl', False),
                )
                from urllib.parse import urlparse as _up2
                domain_host = _up2(target).hostname or target
                inject_cf_cookies(sess_obj._session, target, cf_clearance, user_agent)
                web_set_stealth(sess_obj)
                recon_set_stealth(sess_obj)
                exploit_set_stealth(sess_obj)
                SESSION['results']['cf_bypass'] = {
                    'cf_clearance': cf_clearance,
                    'user_agent': user_agent,
                    'domain': target,
                }
                result['cf_bypassed'] = True
                result['techniques_applied'].append('cf_uam_bypass_success')
            else:
                warn("Cloudflare bypass attempt failed — continuing with stealth headers only.")
                result['techniques_applied'].append('cf_uam_bypass_failed')
        else:
            warn("Cloudflare detected but camoufox is not installed.")
            warn("Install with: pip install \"camoufox[geoip]\" && python -m camoufox fetch")
            warn("Continuing with stealth headers — some paths may still be blocked.")
            result['techniques_applied'].append('cf_uam_bypass_skipped_no_camoufox')

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  FULL AUTO PIPELINE
# ─────────────────────────────────────────────────────────────────────────────


def _build_auto_scan_steps(target: str, workers: int, use_ssl: bool,
                          cookies=None, auth_header=None,
                          wafs_found=None, mutate: bool = False,
                          timing: str = 'normal', try_nmap: bool = False,
                          ssh_delay: float = 0.0):
    """Return an ordered list of auto-scan steps used by section 17."""
    wafs_found = wafs_found or []
    effective_mutate = mutate or bool(wafs_found)
    steps = [
        ("DNS Lookup", _run_sync, (dns_lookup, target)),
        ("WHOIS Intelligence", _run_sync, (whois_lookup, target)),
        ("GeoIP Location", _run_sync, (geoip_lookup, target)),
        ("Port Scan (Common)", _run_sync, (port_scan_common, target, timing, try_nmap)),
        ("SSL Certificate", _run_sync, (ssl_inspect, target, 443)),
        ("API Enumeration", _run_sync, (enumerate_mobile_api_endpoints, target, use_ssl, None, True, 6.0, False)),
        ("Web Crawl", _run_sync, (crawl_target, target, use_ssl, 3, 50, cookies, auth_header)),
        ("HTTP Header Audit", _run_sync, (http_header_audit, target, use_ssl)),
        ("SQLi Smoke", _run_sync, (scan_sqli_target, target, None, cookies)),
        ("Web Vuln Scan", _run_sync, (web_vuln_scan, target, use_ssl, effective_mutate, workers)),
    ]

    if 'paramiko' not in unavailable_optional:
        steps.append(("SSH Audit", _run_sync, (ssh_audit, target, 22, None, ssh_delay, SESSION['credential_testing'])))

    if _CAMOUFOX_AVAILABLE:
        from modules.browser_engine import _build_cfg, browser_js_render, browser_scan_js_secrets

        def _auto_js_render():
            cfg = _build_cfg(SESSION)
            data = browser_js_render(cfg)
            from modules.browser_engine import display_js_render
            if data:
                display_js_render(data)
            return data

        def _auto_js_secrets():
            cfg = _build_cfg(SESSION)
            data = browser_scan_js_secrets(cfg)
            from modules.browser_engine import display_js_secrets
            if data:
                display_js_secrets(data)
            return data

        steps.append(("SPA & JS Render", _run_sync, (_auto_js_render,)))
        steps.append(("JS Secrets Scan", _run_sync, (_auto_js_secrets,)))

    # Renumber labels dynamically since length varies
    numbered = []
    for idx, step in enumerate(steps, start=1):
        label, fn, args = step
        numbered.append((f"{idx}/{len(steps)+1}  {label}", fn, args))
    return numbered


async def handle_nuclei_scan():
    """Run Nuclei template scan for the current target."""
    t = get_target()
    if not t:
        return
    if not nuclei_available():
        alert("Nuclei is not installed or not on PATH.")
        print(install_nuclei_instructions())
        pause()
        return
    res = await _run_sync(run_nuclei_scan, t)
    SESSION['results']['nuclei'] = res
    pause()


async def handle_auto_scan():
    section(T("auto_title"))
    t = get_target(force=True)
    if not t: return

    _apply_stealth()
    start = time.time()
    SESSION['start_time'] = start

    # ── WAF detection + auto-evasion BEFORE any scanning step ─────────────────
    print(f"\n  {BR}{M}[*]{RS}  {T('auto_starting')} {BR}{C}{t}{RS}\n")
    waf_info = await _run_sync(_auto_waf_evasion, t)
    wafs_found   = waf_info.get('wafs_found', [])
    cf_bypassed  = waf_info.get('cf_bypassed', False)
    evasion_on   = waf_info.get('evasion_on', False)
    SESSION['results']['waf_detection'] = waf_info

    # Re-read timing after auto-escalation (may have been changed by evasion)
    timing    = SESSION['stealth']['timing']
    try_nmap  = SESSION['stealth']['try_nmap']
    mutate    = SESSION['stealth']['mutate_paths']
    ssh_delay = 0.0
    if SESSION['stealth']['enabled']:
        ssh_delay = random.uniform(
            SESSION['stealth']['jitter_min'],
            SESSION['stealth']['jitter_max'],
        )

    # Worker count respects the (possibly escalated) timing profile
    workers = TIMING_PROFILES.get(timing, {}).get('workers', 20)
    # When WAF is present, cap workers further to reduce noise
    if wafs_found:
        workers = min(workers, 10)
        info(f"Worker threads capped at {BR}{Y}{workers}{RS} to stay under WAF rate limits.")

    # ── Pipeline steps ─────────────────────────────────────────────────────────
    cookies = SESSION['auth'].get('cookies') or None
    auth_header = SESSION['auth'].get('header') or None
    steps = _build_auto_scan_steps(
        target=t,
        workers=workers,
        use_ssl=SESSION['use_ssl'],
        cookies=cookies,
        auth_header=auth_header,
        wafs_found=wafs_found,
        mutate=mutate,
        timing=timing,
        try_nmap=try_nmap,
        ssh_delay=ssh_delay,
    )

    # ── If Cloudflare detected, add origin IP discovery step ───────────────────
    if 'cloudflare' in wafs_found:
        steps.insert(0, ("Origin IP Discovery (OSINT)", _run_sync, (find_origin_ip, t, None)))

    all_results = {}
    effective_mutate = mutate or bool(wafs_found)
    for step in steps:
        label, fn, args = step[0], step[1], step[2]
        print(f"\n  {BR}{C}┌── {label} {DM}{'─' * (45 - len(label))} ─►{RS}")

        # WAF evasion: show active status on each step
        if evasion_on:
            evade_tags = []
            if SESSION['stealth']['enabled']:  evade_tags.append('stealth')
            if cf_bypassed:                    evade_tags.append('CF-cookie')
            if effective_mutate:               evade_tags.append('path-mutate')
            print(f"  {DM}  evasion: [{', '.join(evade_tags)}]{RS}")

        try:
            r = await fn(*args)
            all_results[label] = r
            
            if label == "Origin IP Discovery (OSINT)":
                SESSION['results']['origin_ip'] = r

            # WAF block recovery: if web step got no results, retry once
            if wafs_found and r is not None and 'Web Vuln Scan' in label:
                exposed = r.get('exposed', []) if isinstance(r, dict) else []
                if not exposed:
                    info("Web vuln step returned no exposures — retrying with deeper path mutation...")
                    import time as _t; _t.sleep(random.uniform(2.0, 5.0))
                    r2 = await _run_sync(
                        web_vuln_scan, t, SESSION['use_ssl'],
                        True,
                        max(5, workers // 2),
                    )
                    if isinstance(r2, dict) and r2.get('exposed'):
                        for k in ('exposed', 'forbidden', 'auth_required'):
                            r[k].extend(r2.get(k, []))
                        all_results[label] = r
                        ok(f"Retry found {len(r2.get('exposed', []))} additional exposure(s).")

            if r and isinstance(r, dict) and r.get('ipv4'):
                SESSION['ip'] = r['ipv4'][0]

        except Exception as e:
            alert(f"{T('auto_step_fail')} {e}")
            if wafs_found and any(code in str(e) for code in ('403', '429', '503')):
                backoff = random.uniform(5.0, 12.0)
                warn(f"WAF block signal detected — backing off for {backoff:.1f}s before next step.")
                await asyncio.sleep(backoff)

    # ── Auto CVE Mapping Step (runs after all others to use ports data) ────────
    cve_label = f"{len(steps)+1}/{len(steps)+1}  CVE Auto-Mapping"
    print(f"\n  {BR}{C}┌── {cve_label} {DM}{'─' * (45 - len(cve_label))} ─►{RS}")

    ports_data = []
    for k in all_results:
        if 'Port Scan' in k:
            ports_data = all_results[k]
            break
            
    try:
        cve_res = await _run_sync(auto_cve_mapping, t, SESSION['use_ssl'], ports_data)
        all_results[cve_label] = cve_res
    except Exception as e:
        alert(f"{T('auto_step_fail')} {e}")

    SESSION['results']['auto_scan'] = all_results

    elapsed = time.time() - start
    _print_auto_summary(t, all_results, elapsed, wafs_found, cf_bypassed)
    pause()


def _find_result(results: dict, keyword: str):
    """Find a result by keyword in the label — fixes the hardcoded step-number problem."""
    for label, data in results.items():
        if keyword in label:
            return data
    return None


def _print_auto_summary(target, results, elapsed, wafs_found=None, cf_bypassed=False):
    section(f"{T('auto_summary_title')} — {target}")
    print(f"\n  {DM}{T('auto_completed', s=f'{elapsed:.1f}')}  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RS}\n")

    # WAF evasion summary row
    if wafs_found:
        waf_names = ', '.join(w.upper() for w in wafs_found)
        print(f"  {BR}{Y}◈{RS}  WAF Detected    : {Y}{waf_names}{RS}")
        cf_status = f"{G}BYPASSED via cf_clearance{RS}" if cf_bypassed else f"{Y}stealth-headers only{RS}"
        if 'cloudflare' in wafs_found:
            print(f"  {BR}{Y}◈{RS}  CF Bypass       : {cf_status}")
        print(f"  {BR}{G}◈{RS}  Evasion Applied : stealth timing + path mutation + adaptive backoff")
        print()

    # DNS (dynamic label match)
    dns = _find_result(results, 'DNS Lookup')
    if dns and isinstance(dns, dict) and dns.get('ipv4'):
        ok(f"{T('auto_ip_addrs')} {', '.join(dns['ipv4'])}")

    # Ports (dynamic label match)
    ports = _find_result(results, 'Port Scan')
    if ports and isinstance(ports, list):
        warn(f"{T('auto_open_ports')} {', '.join(str(p) for p, _ in ports)}")
    else:
        ok(f"{T('auto_open_ports')} {T('auto_no_ports')}")

    # SSL (dynamic label match)
    ssl_data = _find_result(results, 'SSL Certificate')
    if ssl_data:
        ok(T("auto_ssl_found"))

    # Web Crawl (dynamic label match)
    crawl = _find_result(results, 'Web Crawl')
    if crawl and isinstance(crawl, dict):
        ok(f"Crawler: {crawl.get('pages_crawled', 0)} pages, {len(crawl.get('forms', []))} forms, {len(crawl.get('parameters', {}))} params")

    # Web (dynamic label match)
    web = _find_result(results, 'Web Vuln')
    if web and isinstance(web, dict):
        exposed = web.get('exposed', [])
        if exposed:
            alert(T("auto_web_exposed", n=len(exposed)))
        else:
            ok(T("auto_web_ok"))

    # Active Vuln
    avuln = _find_result(results, 'Active Vuln')
    if avuln and isinstance(avuln, dict):
        total = avuln.get('total', 0)
        if total > 0:
            alert(f"Active Vuln: {total} vulnerability(ies) confirmed!")
        else:
            ok("Active Vuln: No vulnerabilities found.")

    # Headers (dynamic label match)
    hdr = _find_result(results, 'Header Audit')
    if hdr and isinstance(hdr, dict):
        score = hdr.get('score', 0)
        col = G if score >= 80 else (Y if score >= 50 else R)
        print(f"  {DM}◈{RS}  {T('auto_hdr_score')} {col}{score:.0f}%{RS}")

    # SSH (dynamic label match)
    ssh = _find_result(results, 'SSH Audit')
    if ssh and isinstance(ssh, dict):
        if ssh.get('vulnerable'):
            u, p = ssh['credential']
            critical(f"{T('auto_ssh_vuln')} {u}:{p}")
        elif ssh.get('open'):
            ok(T("auto_ssh_ok"))
        else:
            info(T("auto_ssh_closed"))

    # CVE Mapping
    cve = _find_result(results, 'CVE')
    if cve and isinstance(cve, dict):
        vuln_count = sum(len(v.get('cves', [])) for v in cve.values() if isinstance(v, dict))
        if vuln_count:
            alert(f"CVE Mapping: {vuln_count} known CVE(s) matched!")
        else:
            ok("CVE Mapping: No known CVEs matched.")

    # Origin IP Discovery
    origin = _find_result(results, 'Origin IP')
    if origin and hasattr(origin, 'confirmed'):
        confirmed = origin.confirmed()
        possible = origin.possible()
        cf_ips = getattr(origin, 'cf_ips', [])
        if cf_ips:
            print(f"  {BR}{Y}◈{RS}  Cloudflare IPs  : {Y}{', '.join(cf_ips)}{RS}")
        
        if confirmed:
            real_ips_str = ', '.join(c.ip for c in confirmed)
            print(f"  {BR}{R}◈{RS}  Real Server IP  : {R}{real_ips_str}{RS}")
            critical(f"Origin IP FOUND: {real_ips_str}")
            for c in confirmed:
                src = c.source
                print(f"       {DM}Source: {src} | {c.evidence}{RS}")
        elif possible:
            warn(f"Possible origin IPs: {', '.join(c.ip for c in possible)}")
            for c in possible:
                src = c.source
                print(f"       {DM}Source: {src} | {c.evidence}{RS}")
        else:
            ok("Origin IP: No non-Cloudflare origin found (well-protected)")

    print()


# ─────────────────────────────────────────────────────────────────────────────
#  EXPORT RESULTS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_export():
    section(T("export_title"))
    if not SESSION['results']:
        warn(T("no_results_yet"))
        pause()
        return

    sensitive_keys = {
        'password', 'passwd', 'secret', 'token', 'cookie', 'cookies',
        'authorization', 'credential', 'credentials', 'private_key',
        'api_key', 'access_key',
    }

    def _clean(obj, key_name=''):
        """Recursively make any value JSON-safe.
        datetime/date → ISO 8601 str, dataclass → dict, tuple → list, anything else → str() fallback."""
        normalized_key = key_name.lower().replace('-', '_')
        if (normalized_key in sensitive_keys or
            normalized_key.endswith(('_secret', '_token', '_key'))):
            return '[REDACTED]'
        import dataclasses
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {f.name: _clean(getattr(obj, f.name), f.name) for f in dataclasses.fields(obj)}
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, dict):
            return {str(k): _clean(v, str(k)) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_clean(i, key_name) for i in obj]
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)

    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    json_name = os.path.join(reports_dir, f"cscan_report_{ts}.json")
    txt_name  = os.path.join(reports_dir, f"cscan_report_{ts}.txt")

    export = {
        'target':    SESSION['target'],
        'ip':        SESSION['ip'],
        'timestamp': datetime.now().isoformat(),
        'report_redacted': True,
        'results':   {k: _clean(v, k) for k, v in SESSION['results'].items()},
    }

    # Generate well-formatted TXT report
    lines = []
    lines.append("============================================================")
    lines.append("                 CSCAN SECURITY REPORT")
    lines.append("============================================================")
    lines.append(f"Target:      {export.get('target', 'N/A')}")
    lines.append(f"IP Address:  {export.get('ip', 'N/A')}")
    lines.append(f"Timestamp:   {export.get('timestamp', 'N/A')}")
    lines.append("============================================================\n")

    # Build Executive Summary
    total_critical = 0
    total_high = 0
    open_ports = 0
    cves_found = 0
    
    auto_res = export['results'].get('auto_scan', {})
    for key, val in auto_res.items():
        if 'Web Vuln Scan' in key and isinstance(val, dict):
            total_critical += len(val.get('critical', []))
            total_high += len(val.get('high', []))
        if 'Port Scan' in key and isinstance(val, list):
            open_ports += len(val)
        if 'CVE Auto-Mapping' in key and isinstance(val, dict):
            for tech_data in val.values():
                cves_found += len(tech_data.get('cves', []))

    lines.append("[EXECUTIVE SUMMARY]")
    lines.append("-" * 60)
    lines.append(f"  - Critical Exposures : {total_critical}")
    lines.append(f"  - High Exposures     : {total_high}")
    lines.append(f"  - Open Ports         : {open_ports}")
    lines.append(f"  - Vulnerable CVEs    : {cves_found}")
    lines.append("\n")

    def _format_value(val, indent=2):
        ind = " " * indent
        if isinstance(val, dict):
            for k, v in val.items():
                if not v and v is not False and v != 0:
                    continue
                if isinstance(v, (dict, list)):
                    lines.append(f"{ind}- {k}:")
                    _format_value(v, indent + 4)
                else:
                    lines.append(f"{ind}- {k}: {v}")
        elif isinstance(val, list):
            for i in val:
                # If the item was originally a tuple (converted to list of length 2 or 3)
                if isinstance(i, list) and len(i) in (2, 3) and not isinstance(i[0], (dict, list)):
                    if len(i) == 2:
                        lines.append(f"{ind}* {i[0]}: {i[1]}")
                    else:
                        lines.append(f"{ind}* {i[0]}: {i[1]} ({i[2]})")
                elif isinstance(i, (dict, list)):
                    _format_value(i, indent + 2)
                else:
                    lines.append(f"{ind}* {i}")
        else:
            lines.append(f"{ind}{val}")

    for module, data in export['results'].items():
        if not data and data is not False and data != 0: 
            lines.append(f"[{module.upper()}]")
            lines.append("-" * 60)
            lines.append("  - No findings (Clean / Empty)\n")
            continue
            
        lines.append(f"[{module.upper()}]")
        lines.append("-" * 60)
        _format_value(data, 2)
        lines.append("")

    try:
        # Save JSON
        with open(json_name, 'w', encoding='utf-8') as f:
            json.dump(export, f, indent=2)
        # Save TXT
        with open(txt_name, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        
        ok(f"{T('export_ok')} {BR}{G}{txt_name}{RS} (and .json)")
    except Exception as e:
        alert(f"{T('export_fail')} {e}")
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  AI ANALYSIS HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

def _require_ai_key() -> str:
    """
    Ensure a Gemini API key is available.
    If not, prompt the user to enter one.
    Returns the key or None if setup fails.
    """
    if SESSION.get('gemini_key'):
        return SESSION['gemini_key']

    # Show key setup screen
    section(T("ai_key_title"))
    print(f"""
  {BR}{M}┌─────────────────────────────────────────────────────────┐
  │   {T("ai_key_heading"):<53}│
  └─────────────────────────────────────────────────────────┘{RS}

  {C}{T("ai_key_desc1")}
  {T("ai_key_desc2")}

  {W}{T("ai_key_info1")}{RS}
    {G}+{RS}  {T("ai_key_bullet1")}
    {G}+{RS}  {T("ai_key_bullet2")}
    {G}+{RS}  {T("ai_key_bullet3")}

  {DM}{T("ai_key_get")}{RS}
""")

    key = prompt_api_key()
    if key:
        SESSION['gemini_key'] = key
        ok(T("ai_active"))
        return key
    else:
        warn(T("ai_no_key"))
        return None


async def handle_ai_analyze():
    """Full AI analysis of all collected scan results."""
    key = _require_ai_key()
    if not key: return pause()
    t   = get_target()
    if not t: return
    if not SESSION['results']:
        warn(T("no_scan_results"))
        pause()
        return
    res = await _run_sync(analyze_findings, key, t, SESSION['results'])
    if res:
        SESSION['results']['ai_analysis'] = res
    pause()


async def handle_ai_quick():
    """Quick AI overview without needing prior scan data."""
    key = _require_ai_key()
    if not key: return pause()
    t   = get_target()
    if not t: return
    res = await _run_sync(quick_host_analysis, key, t)
    if res:
        SESSION['results']['ai_quick'] = res
    pause()


async def handle_ai_cve():
    """CVE and vulnerability lookup via Gemini."""
    key = _require_ai_key()
    if not key: return pause()
    res = await _run_sync(cve_lookup, key)
    if res:
        SESSION['results']['ai_cve'] = res
    pause()


async def handle_ai_ask():
    """Free-form security question to Gemini."""
    key = _require_ai_key()
    if not key: return pause()
    res = await _run_sync(ask_ai, key)
    pause()


async def handle_ai_report():
    """Generate and save a formal security report via Gemini."""
    key = _require_ai_key()
    if not key: return pause()
    t   = get_target()
    if not t: return
    if not SESSION['results']:
        warn(T("no_scan_to_report"))
        pause()
        return
    res = await _run_sync(generate_formal_report, key, t, SESSION['results'])
    if res:
        SESSION['results']['ai_report'] = res
    pause()


def handle_ai_key_change():
    """Allow user to change or clear the Gemini API key."""
    section(T("ai_change_title"))
    if SESSION['gemini_key']:
        masked = SESSION['gemini_key'][:8] + '…' + SESSION['gemini_key'][-4:]
        info(f"{T('ai_current_key')} {DM}{masked}{RS}")
        if prompt_yes(T("q_clear_key")):
            SESSION['gemini_key'] = None
        else:
            return
    key = prompt_api_key()
    if key:
        SESSION['gemini_key'] = key
        ok(T("ai_key_updated"))
    pause()


def handle_stealth_config():
    """Configure stealth / WAF-evasion settings."""
    section(T("stealth_title"))
    cfg = SESSION['stealth']

    info(T("stealth_current"))
    print(f"    {'Enabled':<20} : {cfg['enabled']}")
    print(f"    {'Proxy':<20} : {cfg['proxy'] or 'None'}")
    print(f"    {'Jitter':<20} : {cfg['jitter_min']}s - {cfg['jitter_max']}s")
    print(f"    {'Timing Profile':<20} : {cfg['timing']}")
    print(f"    {'Mutate Paths':<20} : {cfg['mutate_paths']}")
    print(f"    {'Rotate UA':<20} : {cfg['rotate_ua']}")
    print(f"    {'Try nmap':<20} : {cfg['try_nmap']}")
    print(f"    {'Insecure SSL':<20} : {cfg.get('insecure_ssl', False)}")
    # FIX #6: show custom timeout
    _t = cfg.get('scan_timeout')
    print(f"    {'Scan Timeout':<20} : {f'{_t}s' if _t else 'profile default'}")
    print()

    proxy = input(f"  {BR}{W}{T('stealth_proxy_prompt')}: {RS}").strip()
    cfg['proxy'] = proxy if proxy else None

    try:
        jmin = float(input(f"  {BR}{W}{T('stealth_jitter_min')}: {RS}").strip() or '0.5')
    except ValueError:
        jmin = 0.5
    try:
        jmax = float(input(f"  {BR}{W}{T('stealth_jitter_max')}: {RS}").strip() or '2.0')
    except ValueError:
        jmax = 2.0
    cfg['jitter_min'] = min(jmin, jmax)
    cfg['jitter_max'] = max(jmin, jmax)

    timing = input(f"  {BR}{W}{T('stealth_timing_prompt')}: {RS}").strip().lower()
    if timing in TIMING_PROFILES:
        cfg['timing'] = timing
    else:
        cfg['timing'] = 'normal'

    # FIX #6: custom port scan timeout override
    raw_to = input(f"  {BR}{W}Custom scan timeout in seconds (Enter = use profile default): {RS}").strip()
    try:
        cfg['scan_timeout'] = float(raw_to) if raw_to else None
    except ValueError:
        cfg['scan_timeout'] = None

    cfg['mutate_paths'] = prompt_yes(T("stealth_mutate_prompt"))
    cfg['rotate_ua']    = prompt_yes(T("stealth_ua_prompt"))
    cfg['try_nmap']     = prompt_yes(T("stealth_nmap_prompt"))
    cfg['insecure_ssl'] = prompt_yes("Allow insecure SSL certificates (MITM risk)?")

    _apply_stealth()
    ok("Stealth configuration updated.")
    pause()


def handle_stealth_toggle():
    """Quickly toggle stealth mode on/off."""
    cfg = SESSION['stealth']
    cfg['enabled'] = not cfg['enabled']
    _apply_stealth()
    if cfg['enabled']:
        ok(T("stealth_enabled"))
    else:
        warn(T("stealth_disabled"))
    pause()


def handle_lang_toggle():
    """Switch UI language between English and Kiswahili, persist the choice."""
    section(T("lang_toggle_title"))
    current = get_lang()
    info(T("lang_current"))                # shows current lang in current lang
    print()
    print(f"  {BR}{G}[1]{RS}  English")
    print(f"  {BR}{C}[2]{RS}  Kiswahili")
    print(f"  {BR}{Y}[Enter]{RS}  Keep current  ({current})")
    print()
    choice = input(f"  {BR}{M}[>]{RS} {BR}{W}Choose / Chagua [1/2]: {RS}").strip()
    if choice == '1':
        save_language('en')
        ok(T("lang_toggled_en"))           # prints in the NEW language (English)
    elif choice == '2':
        save_language('sw')
        ok(T("lang_toggled_sw"))           # prints in the NEW language (Kiswahili)
    else:
        info(f"Language unchanged  /  Lugha haijabadilishwa  ({get_lang()})")
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  CLOUDFLARE WAF BYPASS HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

def handle_cf_bypass():
    """Menu item 26 — Solve CF UAM challenge and display cookie."""
    result = handle_cf_bypass_menu(SESSION)
    if result:
        SESSION['results']['cf_bypass'] = result
        info("Cookie stored in session results (use 'CF Bypass + Inject' to apply to stealth session).")
    pause()


def handle_cf_bypass_inject():
    """
    Menu item 27 — Solve CF UAM challenge AND inject the resulting
    cf_clearance cookie + User-Agent into the active stealth session
    so subsequent scans bypass Cloudflare automatically.
    """
    result = handle_cf_bypass_menu(SESSION)
    if not result:
        pause()
        return

    SESSION['results']['cf_bypass'] = result

    # FIX #9: Inject into session regardless of proxy — proxy is optional
    cfg = SESSION['stealth']
    if cfg.get('enabled'):
        sess = StealthSession(
            proxy=cfg.get('proxy'),          # None is valid (no proxy)
            jitter_min=cfg['jitter_min'],
            jitter_max=cfg['jitter_max'],
            rotate_ua=False,                 # keep the CF-matched UA fixed
            random_headers=True,
            cookie_persist=True,
            insecure_ssl=cfg.get('insecure_ssl', False),
        )
        inject_cf_cookies(
            sess._session,
            result['domain'],
            result['cf_clearance'],
            result['user_agent'],
        )
        web_set_stealth(sess)
        recon_set_stealth(sess)
        exploit_set_stealth(sess)
        ok("cf_clearance + User-Agent injected into active stealth session!")
        if not cfg.get('proxy'):
            info("Note: No proxy configured — cookie is active but source IP is not masked.")
        ok("All subsequent scans will use the solved Cloudflare cookie.")
    else:
        warn("Stealth mode is OFF — enable stealth first (press S or use menu 25).")
        warn("cf_clearance saved to results only (not injected into HTTP session).")
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  BROWSER ENGINE HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

def handle_js_render():
    menu_js_render(SESSION)
    pause()

def handle_network_capture():
    menu_network_capture(SESSION)
    pause()

def handle_login_test():
    menu_login_test(SESSION)
    pause()

def handle_screenshot():
    menu_screenshot(SESSION)
    pause()

def handle_fingerprint_probe():
    menu_fingerprint_probe(SESSION)
    pause()

def handle_harvest_cookies():
    menu_harvest_cookies(SESSION)
    pause()

def handle_js_secrets():
    menu_js_secrets(SESSION)
    pause()


# ── Origin IP Discovery (Cloudflare bypass via OSINT) ─────────────────────
async def handle_origin_ip():
    """Find the real server IP behind Cloudflare/WAF using passive OSINT."""
    t = get_target()
    if not t: return
    st_key = None
    if SESSION.get('interactive'):
        st_raw = input(f"  {BR}{W}SecurityTrails API key (optional, Enter to skip): {RS}").strip()
        if st_raw:
            st_key = st_raw
    res = await _run_sync(find_origin_ip, t, st_key)
    SESSION['results']['origin_ip'] = res
    if SESSION.get('interactive'):
        pause()


HANDLERS = {
    '1':  handle_dns,
    '2':  handle_whois,
    '3':  handle_subdomain,
    '4':  handle_geoip,
    '5':  handle_reverse_dns,
    '6':  handle_port_common,
    '7':  handle_port_full,
    '8':  handle_banner_grab,
    '9':  handle_ssl,
    '10': handle_web_vuln,
    '11': handle_header_audit,
    '12': handle_dir_brute,
    '13': handle_cms,
    '15': handle_ftp,
    '16': handle_http_auth,
    '17': handle_auto_scan,
    '18': handle_export,
    # AI Analysis
    '19': handle_ai_analyze,
    '20': handle_ai_quick,
    '21': handle_ai_cve,
    '22': handle_ai_ask,
    '23': handle_ai_report,
    # Stealth
    '24': handle_stealth_config,
    '25': handle_stealth_toggle,
    # Cloudflare WAF bypass
    '26': handle_cf_bypass,
    '27': handle_cf_bypass_inject,
    # Browser Engine
    '28': handle_js_render,
    '29': handle_network_capture,
    '30': handle_login_test,
    '31': handle_screenshot,
    '32': handle_fingerprint_probe,
    '33': handle_harvest_cookies,
    '34': handle_js_secrets,
    # ── v2.2 New Modules ──────────────────────────────────────────────────────
    '35': handle_active_vuln,
    '36': handle_nvd_cve,
    '37': handle_nvd_manual,
    '38': handle_udp_scan,
    '39': handle_ssl_deep,
    '40': handle_osint,
    '41': handle_service_brute,
    # ── v3.0 Crawler & Auth ───────────────────────────────────────────────────
    '42': handle_crawl,
    '43': handle_auth_config,
    # ── v3.1 — Path/API Enumerator ───────────────────────────────────────────
    '44': handle_api_enum,
    '45': handle_mobile_api_enum,
    '46': handle_nuclei_scan,
    '47': handle_origin_ip,
    # Navigation
    't':  set_target,
    'T':  set_target,
    'k':  handle_ai_key_change,
    'K':  handle_ai_key_change,
    's':  handle_stealth_toggle,
    'S':  handle_stealth_toggle,
    'l':  handle_lang_toggle,
    'L':  handle_lang_toggle,
}

# Add SSH handler only if paramiko is available
if 'paramiko' not in unavailable_optional:
    HANDLERS['14'] = handle_ssh


def _build_disclaimer() -> str:
    return f"""
{BR}{R}  ╔═══════════════════════════════════════════╗
  ║  {T("disclaimer_title"):<43}║
  ╠═══════════════════════════════════════════╣
  ║  {T("disclaimer_line1"):<43}║
  ║  {T("disclaimer_line2"):<43}║
  ║                                           ║
  ║  {T("disclaimer_line3"):<43}║
  ║  {T("disclaimer_line4"):<43}║
  ║                                           ║
  ║  {T("disclaimer_line5"):<43}║
  ║  {T("disclaimer_line6"):<43}║
  ╚═══════════════════════════════════════════╝{RS}
"""




async def interactive_mode():
    SESSION['interactive'] = True
    if is_first_launch():
        run_language_picker()
    cls()
    print(_build_disclaimer())
    if not prompt_yes(T("disclaimer_confirm")):
        sys.exit(0)
    SESSION['start_time'] = time.time()
    while True:
        cls()
        show_banner()
        show_status()
        show_menu()
        show_footer()
        choice = prompt_choice(T("prompt_select"))
        if choice == '0':
            sys.exit(0)
        handler = HANDLERS.get(choice)
        if handler:
            cls()
            show_banner()
            show_status()
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler()
                else:
                    handler()
            except KeyboardInterrupt:
                pause()
        else:
            time.sleep(1)

def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "CSCAN is an authorized web reconnaissance and assessment toolkit. "
            "It is intended for owned or explicitly authorized targets and focuses on "
            "targeted discovery, inspection, and structured reporting."
        )
    )
    parser.add_argument("-v", "--version", action="version", version=f"CSCAN {VERSION}")
    parser.add_argument("-t", "--target", help="Target URL or IP to scan")
    parser.add_argument(
        "-m", "--module",
        choices=sorted(SUPPORTED_MODULES),
        help="Workflow to run: " + ", ".join(f"{k} ({v})" for k, v in SUPPORTED_MODULES.items())
    )
    parser.add_argument("--stealth", action="store_true", help="Enable stealth / evasion settings")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure SSL certificates")
    parser.add_argument(
        "--credential-testing", action="store_true",
        help="Enable credential guessing only for targets you own or for which you have explicit written authorization",
    )
    parser.add_argument("--list-modules", action="store_true", help="List supported non-interactive modules")
    return parser


async def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_modules:
        print("Supported modules:")
        for name, description in SUPPORTED_MODULES.items():
            print(f"  - {name}: {description}")
        return

    if args.target:
        try:
            SESSION['target'] = normalize_target(args.target)
        except ValueError as exc:
            parser.error(str(exc))
        SESSION['use_ssl'] = SESSION['target'].startswith('https://')
        if args.stealth:
            SESSION['stealth']['enabled'] = True
        if args.insecure:
            SESSION['stealth']['insecure_ssl'] = True
        SESSION['credential_testing'] = args.credential_testing

        _apply_stealth()
        mod = args.module or "auto"
        if mod == "web":
            await handle_web_vuln()
        elif mod == "dns":
            await handle_dns()
        elif mod == "crawl":
            await handle_crawl()
        elif mod == "ssl":
            await handle_ssl()
        elif mod == "ports":
            await handle_port_common()
        elif mod == "nuclei":
            await handle_nuclei_scan()
        elif mod == "osint-origin":
            await handle_origin_ip()
        else:
            await handle_auto_scan()
    else:
        await interactive_mode()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

