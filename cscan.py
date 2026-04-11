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
import json
import time
from datetime import datetime

# Prevent UnicodeEncodeError kwenye Windows terminals
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# ── Dependency check ──────────────────────────────────────────────────────────
REQUIRED = {'requests': 'requests', 'colorama': 'colorama',
            'paramiko': 'paramiko',  'whois': 'python-whois'}

missing = []
for mod, pkg in REQUIRED.items():
    try:
        __import__(mod)
    except ImportError:
        missing.append(pkg)

if missing:
    print(f"\n[!] Missing packages: {', '.join(missing)}")
    print(f"[!] Run: pip install {' '.join(missing)}\n")
    sys.exit(1)

# ── Language system must be loaded BEFORE ui ────────────────
from modules.lang import (
    T, get_lang, set_lang, save_language,
    is_first_launch, load_saved_language
)

# ── Import our modules ────────────────────────────────────────────────────────
from modules.ui        import *
from modules.recon     import dns_lookup, whois_lookup, subdomain_enum, geoip_lookup, reverse_dns
from modules.scanner   import port_scan_common, port_scan_full, banner_grabber, ssl_inspect, COMMON_PORTS
from modules.web       import web_vuln_scan, http_header_audit, dir_bruteforce, cms_detect
from modules.exploit   import ssh_audit, ftp_anon_check, http_auth_brute
from modules.ai_analyst import (
    prompt_api_key, analyze_findings, quick_host_analysis,
    cve_lookup, ask_ai, generate_formal_report
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

    raw = input(f"  {BR}{M}[»]{RS} {BR}{W}Enter choice / Ingiza chaguo [1/2]: {RS}").strip()

    if raw == '2':
        save_language('sw')
        print(f"\n  {BR}{G}[✔]{RS}  Kiswahili imechaguliwa. / Kiswahili selected.")
    else:
        save_language('en')
        if raw != '1':
            print(f"\n  {BR}{Y}[!]{RS}  Invalid choice — using English.")
        else:
            print(f"\n  {BR}{G}[✔]{RS}  English selected.")

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
    from urllib.parse import urlparse
    hostname = urlparse(t).hostname if '://' in t else t.split('/')[0]
    try:
        ip = socket.gethostbyname(hostname)
        SESSION['ip'] = ip
        info(f"{T('resolved_ip')} {BR}{G}{ip}{RS}")
    except Exception:
        warn(T("no_resolve_warn"))

def show_status():
    """Show current session status bar."""
    t   = SESSION['target'] or f"{DM}{T('status_not_set')}{RS}"
    ip  = SESSION['ip']     or f"{DM}{T('status_unknown')}{RS}"
    ssl = f"{G}HTTPS{RS}" if SESSION['use_ssl'] else f"{Y}HTTP{RS}"
    ai  = f"{BR}{M}{T('status_ai_on')}{RS}" if SESSION['gemini_key'] else f"{DM}{T('status_ai_off')}{RS}"
    dur = ''
    if SESSION['start_time']:
        secs = int(time.time() - SESSION['start_time'])
        dur  = f"  {DM}│{RS}  ⏱ {secs}s"

    print(f"\n  {DM}┌─ Target: {BR}{C}{t}{RS}  {DM}│ IP: {BR}{W}{ip}{RS}  {DM}│ {ssl}  │ {ai}{dur}")


# ─────────────────────────────────────────────────────────────────────────────
#  MENU HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

def handle_dns():
    t = get_target()
    if not t: return
    res = dns_lookup(t)
    SESSION['results']['dns'] = res
    if res.get('ipv4'):
        SESSION['ip'] = res['ipv4'][0]
    pause()

def handle_whois():
    t = get_target()
    if not t: return
    res = whois_lookup(t)
    SESSION['results']['whois'] = res
    pause()

def handle_subdomain():
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
    res = subdomain_enum(t, wl)
    SESSION['results']['subdomains'] = res
    pause()

def handle_geoip():
    t = get_target()
    if not t: return
    res = geoip_lookup(t)
    SESSION['results']['geoip'] = res
    pause()

def handle_reverse_dns():
    t = get_target()
    if not t: return
    res = reverse_dns(t)
    SESSION['results']['reverse_dns'] = res
    pause()

def handle_port_common():
    t = get_target()
    if not t: return
    res = port_scan_common(t)
    SESSION['results']['ports_common'] = res
    # Store IP if we got one
    if res and not SESSION['ip']:
        import socket
        try:
            SESSION['ip'] = socket.gethostbyname(t.split('//')[-1].split('/')[0])
        except Exception:
            pass
    pause()

def handle_port_full():
    t = get_target()
    if not t: return
    section(T("port_full_title"))
    info(T("port_full_info"))
    try:
        start = int(input(f"  {BR}{W}{T('port_start')}: {RS}").strip() or '1')
        end   = int(input(f"  {BR}{W}{T('port_end')}: {RS}").strip() or '65535')
    except ValueError:
        start, end = 1, 65535
    warn(T("port_scanning_warn", n=end - start + 1))
    res = port_scan_full(t, start, end)
    SESSION['results']['ports_full'] = res
    pause()

def handle_banner_grab():
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
    res = banner_grabber(t, ports)
    SESSION['results']['banners'] = res
    pause()

def handle_ssl():
    t = get_target()
    if not t: return
    raw = input(f"  {BR}{W}{T('ssl_port_prompt')}: {RS}").strip()
    port = int(raw) if raw.isdigit() else 443
    res = ssl_inspect(t, port)
    SESSION['results']['ssl'] = res
    pause()

def handle_web_vuln():
    t = get_target()
    if not t: return
    res = web_vuln_scan(t, SESSION['use_ssl'])
    SESSION['results']['web_vuln'] = res
    pause()

def handle_header_audit():
    t = get_target()
    if not t: return
    res = http_header_audit(t, SESSION['use_ssl'])
    SESSION['results']['headers'] = res
    pause()

def handle_dir_brute():
    t = get_target()
    if not t: return
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
    res = dir_bruteforce(t, SESSION['use_ssl'], wl)
    SESSION['results']['dir_brute'] = res
    pause()

def handle_cms():
    t = get_target()
    if not t: return
    res = cms_detect(t, SESSION['use_ssl'])
    SESSION['results']['cms'] = res
    pause()

def handle_ssh():
    t = get_target()
    if not t: return
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

    res = ssh_audit(t, port, creds)
    SESSION['results']['ssh'] = res
    pause()

def handle_ftp():
    t = get_target()
    if not t: return
    raw_port = input(f"  {BR}{W}{T('ftp_port_prompt')}: {RS}").strip()
    port = int(raw_port) if raw_port.isdigit() else 21
    res = ftp_anon_check(t, port)
    SESSION['results']['ftp'] = res
    pause()

def handle_http_auth():
    t = get_target()
    if not t: return
    section(T("http_auth_title"))
    path = input(f"  {BR}{W}{T('http_auth_path')}: {RS}").strip() or '/'
    res  = http_auth_brute(t, path)
    SESSION['results']['http_auth'] = res
    pause()


# ─────────────────────────────────────────────────────────────────────────────
#  FULL AUTO PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def handle_auto_scan():
    section(T("auto_title"))
    t = get_target(force=True)
    if not t: return

    bold(T("auto_warn"))
    warn(T("auto_time_est"))
    if not prompt_yes(T("q_proceed")):
        return

    start = time.time()
    SESSION['start_time'] = start

    print(f"\n  {BR}{M}[★]{RS}  {T('auto_starting')} {BR}{C}{t}{RS}\n")

    steps = [
        ("1/8  DNS Lookup",           lambda: dns_lookup(t)),
        ("2/8  WHOIS Intelligence",   lambda: whois_lookup(t)),
        ("3/8  GeoIP Location",       lambda: geoip_lookup(t)),
        ("4/8  Port Scan (Common)",   lambda: port_scan_common(t)),
        ("5/8  SSL Certificate",      lambda: ssl_inspect(t, 443)),
        ("6/8  Web Vuln Scan",        lambda: web_vuln_scan(t, SESSION['use_ssl'])),
        ("7/8  HTTP Header Audit",    lambda: http_header_audit(t, SESSION['use_ssl'])),
        ("8/8  SSH Audit",            lambda: ssh_audit(t)),
    ]

    all_results = {}
    for label, fn in steps:
        print(f"\n  {BR}{C}┌── {label} {DM}{'─' * (45 - len(label))} ─►{RS}")
        try:
            r = fn()
            all_results[label] = r
            if r and isinstance(r, dict) and r.get('ipv4'):
                SESSION['ip'] = r['ipv4'][0]
        except Exception as e:
            alert(f"{T('auto_step_fail')} {e}")

    SESSION['results']['auto_scan'] = all_results

    elapsed = time.time() - start
    _print_auto_summary(t, all_results, elapsed)
    pause()


def _print_auto_summary(target, results, elapsed):
    section(f"{T('auto_summary_title')} — {target}")
    print(f"\n  {DM}{T('auto_completed', s=f'{elapsed:.1f}')}  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RS}\n")

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

def handle_export():
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
    {G}✔{RS}  {T("ai_key_bullet1")}
    {G}✔{RS}  {T("ai_key_bullet2")}
    {G}✔{RS}  {T("ai_key_bullet3")}

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


def handle_ai_analyze():
    """Full AI analysis of all collected scan results."""
    key = _require_ai_key()
    if not key: return pause()
    t   = get_target()
    if not t: return
    if not SESSION['results']:
        warn(T("no_scan_results"))
        pause()
        return
    res = analyze_findings(key, t, SESSION['results'])
    if res:
        SESSION['results']['ai_analysis'] = res
    pause()


def handle_ai_quick():
    """Quick AI overview without needing prior scan data."""
    key = _require_ai_key()
    if not key: return pause()
    t   = get_target()
    if not t: return
    res = quick_host_analysis(key, t)
    if res:
        SESSION['results']['ai_quick'] = res
    pause()


def handle_ai_cve():
    """CVE and vulnerability lookup via Gemini."""
    key = _require_ai_key()
    if not key: return pause()
    res = cve_lookup(key)
    if res:
        SESSION['results']['ai_cve'] = res
    pause()


def handle_ai_ask():
    """Free-form security question to Gemini."""
    key = _require_ai_key()
    if not key: return pause()
    res = ask_ai(key)
    pause()


def handle_ai_report():
    """Generate and save a formal security report via Gemini."""
    key = _require_ai_key()
    if not key: return pause()
    t   = get_target()
    if not t: return
    if not SESSION['results']:
        warn(T("no_scan_to_report"))
        pause()
        return
    res = generate_formal_report(key, t, SESSION['results'])
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


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────

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
    '14': handle_ssh,
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
    # Navigation
    't':  set_target,
    'T':  set_target,
    'k':  handle_ai_key_change,
    'K':  handle_ai_key_change,
}


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



def main():
    # ── 1. Handle language (prompt every session) ─────────────────────────────
    run_language_picker()

    # ── 2. Legal disclaimer ───────────────────────────────────────────────────
    cls()
    print(_build_disclaimer())
    if not prompt_yes(T("disclaimer_confirm")):
        print(f"\n  {DM}{T('exit_not_ready')}{RS}\n")
        sys.exit(0)

    SESSION['start_time'] = time.time()

    # ── 3. Main loop ──────────────────────────────────────────────────────────
    while True:
        cls()
        show_banner()
        show_status()
        show_menu()

        choice = prompt_choice(T("prompt_select"))

        if choice == '0':
            section(T("goodbye_section"))
            ok(T("goodbye"))
            print()
            sys.exit(0)

        handler = HANDLERS.get(choice)
        if handler:
            cls()
            show_banner()
            show_status()
            try:
                handler()
            except KeyboardInterrupt:
                print(f"\n\n  {Y}[!] {T('interrupted')}{RS}")
                pause()
        else:
            warn(T("unknown_option", c=choice))
            time.sleep(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {BR}{Y}[!]{RS} CSCAN interrupted. {T('goodbye')}\n")
        sys.exit(0)
