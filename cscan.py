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
import functools

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
from modules.scanner   import port_scan_common, port_scan_full, banner_grabber, ssl_inspect, COMMON_PORTS
from modules.web       import web_vuln_scan, http_header_audit, dir_bruteforce, cms_detect
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

# ── Session state ─────────────────────────────────────────────────────────────
SESSION = {
    'target':      None,
    'ip':          None,
    'use_ssl':     False,
    'results':     {},
    'log':         [],
    'start_time':  None,
    'gemini_key':  None,   # Gemini API key (stored in-memory only)
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
    if SESSION['target'] and not force:
        return SESSION['target']
    print()
    t = prompt_target(T("prompt_target"))
    if not t:
        return None
    SESSION['target']  = t
    SESSION['use_ssl'] = t.startswith('https://')
    return t

def set_target():
    """Manually set / change the active target."""
    section(T("set_target_title"))
    t = prompt_target()
    if not t:
        return
    SESSION['target'] = t
    SESSION['use_ssl'] = t.startswith('https://')
    ok(f"{T('target_set')} {BR}{G}{t}{RS}")

    if prompt_yes(T("q_use_ssl")):
        SESSION['use_ssl'] = True
        ok(T("ssl_enabled"))

    # Quick DNS resolve
    import socket
    import ipaddress
    from urllib.parse import urlparse
    hostname = urlparse(t).hostname if '://' in t else t.split('/')[0]
    try:
        ip = socket.gethostbyname(hostname)
        SESSION['ip'] = ip
        info(f"{T('resolved_ip')} {BR}{G}{ip}{RS}")
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                warn(f"Warning: The target resolves to an internal/private IP ({ip}).")
                if not prompt_yes("Are you sure you want to scan this internal IP?"):
                    SESSION['target'] = None
                    SESSION['ip'] = None
                    return
        except ValueError:
            pass

    except Exception:
        warn(T("no_resolve_warn"))

def _apply_stealth():
    """Push current stealth config down to the network/web modules."""
    cfg = SESSION['stealth']
    insecure_ssl = cfg.get('insecure_ssl', False)
    web_set_insecure_ssl(insecure_ssl)
    exploit_set_insecure_ssl(insecure_ssl)

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
    else:
        web_set_stealth(None)
        recon_set_stealth(None)
        exploit_set_stealth(None)


def show_status():
    """Show current session status bar."""
    t   = SESSION['target'] or f"{DM}{T('status_not_set')}{RS}"
    ip  = SESSION['ip']     or f"{DM}{T('status_unknown')}{RS}"
    ssl = f"{G}HTTPS{RS}" if SESSION['use_ssl'] else f"{Y}HTTP{RS}"
    ai  = f"{BR}{M}{T('status_ai_on')}{RS}" if SESSION['gemini_key'] else f"{DM}{T('status_ai_off')}{RS}"
    st  = f"{BR}{G}{T('status_stealth_on')}{RS}" if SESSION['stealth']['enabled'] else f"{DM}STEALTH OFF{RS}"
    dur = ''
    if SESSION['start_time']:
        secs = int(time.time() - SESSION['start_time'])
        dur  = f"  {DM}│{RS}  {secs}s"

    print(f"\n  {DM}┌─ Target: {BR}{C}{t}{RS}  {DM}│ IP: {BR}{W}{ip}{RS}  {DM}│ {ssl}  │ {st}  │ {ai}{dur}")


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
    if prompt_yes(T("q_custom_wordlist")):
        path = input(f"  {BR}{W}{T('wordlist_path')}: {RS}").strip()
        try:
            with open(path) as f:
                wl = [line.strip() for line in f if line.strip()]
            info(T("wordlist_loaded", n=len(wl)))
        except Exception as e:
            warn(T("wordlist_err", e=e))
            wl = None
    else:
        wl = None
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
    info(T("port_full_info"))
    try:
        start = int(input(f"  {BR}{W}{T('port_start')}: {RS}").strip() or '1')
        end   = int(input(f"  {BR}{W}{T('port_end')}: {RS}").strip() or '65535')
    except ValueError:
        start, end = 1, 65535
    warn(T("port_scanning_warn", n=end - start + 1))
    timing = SESSION['stealth']['timing']
    try_nmap = SESSION['stealth']['try_nmap']
    res = await _run_sync(port_scan_full, t, start, end, timing=timing, try_nmap=try_nmap)
    SESSION['results']['ports_full'] = res
    pause()

async def handle_banner_grab():
    t = get_target()
    if not t: return
    section(T("banner_title"))
    info(T("banner_info"))
    raw = input(f"  {BR}{W}{T('banner_prompt')}: {RS}").strip()
    ports = None
    if raw:
        try:
            ports = [int(p.strip()) for p in raw.split(',')]
        except ValueError:
            warn(T("banner_invalid"))
    res = await _run_sync(banner_grabber, t, ports)
    SESSION['results']['banners'] = res
    pause()

async def handle_ssl():
    t = get_target()
    if not t: return
    raw = input(f"  {BR}{W}{T('ssl_port_prompt')}: {RS}").strip()
    port = int(raw) if raw.isdigit() else 443
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
    if prompt_yes(T("q_custom_dir_wl")):
        path = input(f"  {BR}{W}{T('wordlist_path')}: {RS}").strip()
        try:
            with open(path) as f:
                wl = [l.strip() for l in f if l.strip()]
            info(T("wordlist_loaded", n=len(wl)))
        except Exception as e:
            warn(T("wordlist_err", e=e))
            wl = None
    else:
        wl = None
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
    raw_port = input(f"  {BR}{W}{T('ssh_port_prompt')}: {RS}").strip()
    port = int(raw_port) if raw_port.isdigit() else 22

    creds = None
    if prompt_yes(T("q_custom_creds")):
        path  = input(f"  {BR}{W}{T('creds_file_prompt')}: {RS}").strip()
        try:
            with open(path) as f:
                creds = [tuple(l.strip().split(':', 1)) for l in f if ':' in l]
            info(T("creds_loaded", n=len(creds)))
        except Exception as e:
            warn(T("creds_load_err", e=e))

    delay = 0.0
    if SESSION['stealth']['enabled']:
        delay = random.uniform(SESSION['stealth']['jitter_min'], SESSION['stealth']['jitter_max'])
    res = await _run_sync(ssh_audit, t, port, creds, delay=delay)
    SESSION['results']['ssh'] = res
    pause()

async def handle_ftp():
    t = get_target()
    if not t: return
    raw_port = input(f"  {BR}{W}{T('ftp_port_prompt')}: {RS}").strip()
    port = int(raw_port) if raw_port.isdigit() else 21
    res = await _run_sync(ftp_anon_check, t, port)
    SESSION['results']['ftp'] = res
    pause()

async def handle_http_auth():
    t = get_target()
    if not t: return
    _apply_stealth()
    section(T("http_auth_title"))
    path = input(f"  {BR}{W}{T('http_auth_path')}: {RS}").strip() or '/'
    res  = await _run_sync(http_auth_brute, t, path)
    SESSION['results']['http_auth'] = res
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  WAF AUTO-EVASION HELPER  (used by full auto-scan pipeline)
# ─────────────────────────────────────────────────────────────────────────────

def _probe_waf(target: str) -> list:
    """
    Send a plain GET request to the target and check response headers/body
    for known WAF signatures. Returns a list of detected WAF names.
    """
    import requests as _req
    from urllib.parse import urlparse as _up

    url = target if target.startswith(('http://', 'https://')) else f'http://{target}'
    detected = []
    try:
        r = _req.get(
            url, timeout=8, verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            allow_redirects=True,
        )
        combined = (r.text or '').lower()
        for k, v in r.headers.items():
            combined += f' {k.lower()}: {v.lower()}'
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    detected.append(waf_name)
                    break
        # Extra: check for 403/429 with WAF-typical body phrases
        if r.status_code in (403, 429) and not detected:
            generic_phrases = ['access denied', 'blocked', 'forbidden', 'security', 'firewall', 'ddos']
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
    result = {'wafs_found': wafs, 'cf_bypassed': False, 'evasion_on': False}

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

    # ── Step 2: Escalate timing to 'sneaky' unless user already set something slower
    current_timing = cfg.get('timing', 'normal')
    slow_profiles   = ('paranoid', 'sneaky', 'polite')
    if current_timing not in slow_profiles:
        cfg['timing'] = 'sneaky'
        info(f"Timing escalated to {BR}{Y}sneaky{RS} to reduce WAF trigger rate.")

    # ── Step 3: Enable jitter if not already configured ───────────────────────
    if cfg['jitter_max'] <= 0.5:
        cfg['jitter_min'] = 1.0
        cfg['jitter_max'] = 3.5
        info(f"Request jitter set to {BR}{Y}1.0 – 3.5 s{RS} to mimic organic traffic.")

    # Push updated config to all network modules
    _apply_stealth()
    ok("Stealth mode AUTO-ENABLED with WAF-evasion settings.")

    # ── Step 4: Cloudflare-specific — attempt cf_clearance bypass ─────────────
    if 'cloudflare' in wafs:
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
            else:
                warn("Cloudflare bypass attempt failed — continuing with stealth headers only.")
        else:
            warn("Cloudflare detected but camoufox is not installed.")
            warn("Install with: pip install \"camoufox[geoip]\" && python -m camoufox fetch")
            warn("Continuing with stealth headers — some paths may still be blocked.")

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  FULL AUTO PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

async def handle_auto_scan():
    section(T("auto_title"))
    t = get_target(force=True)
    if not t: return

    bold(T("auto_warn"))
    warn(T("auto_time_est"))
    if not prompt_yes(T("q_proceed")):
        return

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
    # Web steps use mutate=True whenever WAF is detected (even if user didn't set it)
    effective_mutate = mutate or bool(wafs_found)

    steps = [
        ("1/8  DNS Lookup",         _run_sync, (dns_lookup, t)),
        ("2/8  WHOIS Intelligence", _run_sync, (whois_lookup, t)),
        ("3/8  GeoIP Location",     _run_sync, (geoip_lookup, t)),
        ("4/8  Port Scan (Common)", _run_sync, (port_scan_common, t, timing, try_nmap)),
        ("5/8  SSL Certificate",    _run_sync, (ssl_inspect, t, 443)),
        ("6/8  Web Vuln Scan",      _run_sync, (web_vuln_scan, t, SESSION['use_ssl'], effective_mutate, workers)),
        ("7/8  HTTP Header Audit",  _run_sync, (http_header_audit, t, SESSION['use_ssl'])),
    ]

    if 'paramiko' not in unavailable_optional:
        steps.append(("8/8  SSH Audit", _run_sync, (ssh_audit, t, 22, None, ssh_delay)))

    all_results = {}
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

            # ── WAF block recovery: if web step got no results, retry once
            #    with a fresh set of mutated paths and longer jitter
            if wafs_found and r is not None and label.startswith('6/'):
                exposed = r.get('exposed', []) if isinstance(r, dict) else []
                if not exposed:
                    info("Web vuln step returned no exposures — retrying with deeper path mutation...")
                    import time as _t; _t.sleep(random.uniform(2.0, 5.0))
                    r2 = await _run_sync(
                        web_vuln_scan, t, SESSION['use_ssl'],
                        True,          # force mutate=True
                        max(5, workers // 2),  # even fewer threads on retry
                    )
                    # Merge retry findings into original
                    if isinstance(r2, dict) and r2.get('exposed'):
                        for k in ('exposed', 'forbidden', 'auth_required'):
                            r[k].extend(r2.get(k, []))
                        all_results[label] = r
                        ok(f"Retry found {len(r2.get('exposed', []))} additional exposure(s).")

            if r and isinstance(r, dict) and r.get('ipv4'):
                SESSION['ip'] = r['ipv4'][0]

        except Exception as e:
            alert(f"{T('auto_step_fail')} {e}")
            # On WAF-related block signals, back off before continuing
            if wafs_found and any(code in str(e) for code in ('403', '429', '503')):
                backoff = random.uniform(5.0, 12.0)
                warn(f"WAF block signal detected — backing off for {backoff:.1f}s before next step.")
                await asyncio.sleep(backoff)

    SESSION['results']['auto_scan'] = all_results

    elapsed = time.time() - start
    _print_auto_summary(t, all_results, elapsed, wafs_found, cf_bypassed)
    pause()


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

    # DNS
    dns = results.get('1/8  DNS Lookup', {})
    if dns and dns.get('ipv4'):
        ok(f"{T('auto_ip_addrs')} {', '.join(dns['ipv4'])}")

    # Ports
    ports = results.get('4/8  Port Scan (Common)', [])
    if ports:
        warn(f"{T('auto_open_ports')} {', '.join(str(p) for p, _ in ports)}")
    else:
        ok(f"{T('auto_open_ports')} {T('auto_no_ports')}")

    # SSL
    ssl = results.get('5/8  SSL Certificate', {})
    if ssl:
        ok(T("auto_ssl_found"))

    # Web
    web = results.get('6/8  Web Vuln Scan', {})
    if web:
        exposed = web.get('exposed', [])
        if exposed:
            alert(T("auto_web_exposed", n=len(exposed)))
        else:
            ok(T("auto_web_ok"))

    # Headers
    hdr = results.get('7/8  HTTP Header Audit', {})
    if hdr:
        score = hdr.get('score', 0)
        col = G if score >= 80 else (Y if score >= 50 else R)
        print(f"  {DM}◈{RS}  {T('auto_hdr_score')} {col}{score:.0f}%{RS}")

    # SSH
    ssh = results.get('8/8  SSH Audit', {})
    if ssh:
        if ssh.get('vulnerable'):
            u, p = ssh['credential']
            critical(f"{T('auto_ssh_vuln')} {u}:{p}")
        elif ssh.get('open'):
            ok(T("auto_ssh_ok"))
        else:
            info(T("auto_ssh_closed"))

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

    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    name = f"cscan_report_{ts}.json"

    export = {
        'target':    SESSION['target'],
        'ip':        SESSION['ip'],
        'timestamp': datetime.now().isoformat(),
        'results':   {}
    }

    # Serialise  (some results may contain non-JSON-serialisable objects)
    for key, val in SESSION['results'].items():
        try:
            json.dumps(val)
            export['results'][key] = val
        except (TypeError, ValueError):
            export['results'][key] = str(val)

    try:
        with open(name, 'w') as f:
            json.dump(export, f, indent=2, default=str)
        ok(f"{T('export_ok')} {BR}{G}{name}{RS}")
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

    # Inject into stealth session if one is active
    cfg = SESSION['stealth']
    if cfg.get('enabled') and cfg.get('proxy') is not None:
        sess = StealthSession(
            proxy=cfg['proxy'],
            jitter_min=cfg['jitter_min'],
            jitter_max=cfg['jitter_max'],
            rotate_ua=False,   # don't rotate; keep the CF-matched UA
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
        ok("All subsequent scans will use the solved Cloudflare cookie.")
    else:
        warn("Stealth mode is OFF — enable stealth and configure a proxy first.")
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
    # Navigation
    't':  set_target,
    'T':  set_target,
    'k':  handle_ai_key_change,
    'K':  handle_ai_key_change,
    's':  handle_stealth_toggle,
    'S':  handle_stealth_toggle,
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
        choice = prompt_choice(T("prompt_select"))
        if choice == '0':
            sys.exit(0)
        handler = HANDLERS.get(choice)
        if handler:
            cls()
            show_banner()
            show_status()
            try:
                if asyncio.iscoroutinefunction(handler) or getattr(handler, '__name__', '') in ['handle_dns', 'handle_whois', 'handle_subdomain', 'handle_geoip', 'handle_reverse_dns', 'handle_port_common', 'handle_port_full', 'handle_banner_grab', 'handle_ssl', 'handle_web_vuln', 'handle_header_audit', 'handle_dir_brute', 'handle_cms', 'handle_ssh', 'handle_ftp', 'handle_http_auth', 'handle_auto_scan', 'handle_export', 'handle_ai_analyze', 'handle_ai_quick', 'handle_ai_cve', 'handle_ai_ask', 'handle_ai_report']:
                    await handler()
                else:
                    handler()
            except KeyboardInterrupt:
                pause()
        else:
            time.sleep(1)

async def main():
    parser = argparse.ArgumentParser(description="CSCAN")
    parser.add_argument("-t", "--target", help="Target URL or IP")
    parser.add_argument("-m", "--module", help="Module (web, dns, ssh, auto)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure SSL")
    args = parser.parse_args()

    if args.target:
        SESSION['target'] = args.target
        SESSION['use_ssl'] = args.target.startswith('https://')
        if args.stealth: SESSION['stealth']['enabled'] = True
        if args.insecure: SESSION['stealth']['insecure_ssl'] = True
        
        _apply_stealth()
        mod = args.module
        if mod == 'web': await handle_web_vuln()
        elif mod == 'dns': await handle_dns()
        elif mod == 'ssh': await handle_ssh()
        else: await handle_auto_scan()
    else:
        await interactive_mode()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

