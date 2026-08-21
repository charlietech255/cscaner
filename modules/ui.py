#!/usr/bin/env python3
"""
CSCAN — UI: Colors, Banners, Prompts, Progress
"""

import sys
import time
import unicodedata

from modules.lang import T

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

# ── Fallback no-op colour objects ─────────────────────────────────────────────
class _Null:
    def __getattr__(self, _): return ''

if not HAS_COLOR:
    Fore = Back = Style = _Null()

# ── Colour aliases ─────────────────────────────────────────────────────────────
R  = Fore.RED
Y  = Fore.YELLOW
G  = Fore.GREEN
C  = Fore.CYAN
M  = Fore.MAGENTA
W  = Fore.WHITE
B  = Fore.BLUE
BR = Style.BRIGHT
DM = Style.DIM
RS = Style.RESET_ALL

# ── Print helpers ──────────────────────────────────────────────────────────────
def ok(msg):       print(f"  {BR}{G}[+]{RS} {msg}")
def warn(msg):     print(f"  {BR}{Y}[!]{RS} {msg}")
def alert(msg):    print(f"  {BR}{R}[x]{RS} {msg}")
def info(msg):     print(f"  {BR}{C}[>]{RS} {msg}")
def critical(msg): print(f"\n  {BR}{Back.RED}{W} CRITICAL {RS} {BR}{R}{msg}{RS}")
def bold(msg):     print(f"  {BR}{W}{msg}{RS}")

def section(title: str):
    bar = f"{BR}{C}{'─' * 45}{RS}"
    print(f"\n{bar}")
    print(f"  {BR}{M}{title}{RS}")
    print(bar)

def divider():
    print(f"  {DM}{C}{'·' * 45}{RS}")

# ── Wide-character helper (emoji, CJK) ────────────────────────────────────────
def _wide(s: str) -> int:
    """Count extra terminal cells taken by wide chars (each = +1 extra cell)."""
    return sum(1 for ch in s if unicodedata.east_asian_width(ch) in ('W', 'F'))

# ── ASCII Banner (Modern Minimalist) ──────────────────────────────────────────
def _build_banner() -> str:
    subtitle = T("banner_subtitle")
    return f"""
{BR}{C}  ▗▄▄▖ ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖
  ▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌
  ▐▌   ▝▀▚▖ ▐▌   ▐▛▀▜▌▐▌ ▝▜▌
  ▝▚▄▄▖▗▄▄▞▘▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌{RS}
  
  {BR}{W}CSCAN{RS} {DM}—{RS} {subtitle}
  {DM}{'─'*55}{RS}
"""

# ── Modern Flat Menu Layout ──────────────────────────────────────────────────
def _build_menu() -> str:
    # Use dynamic padding for translations
    return f"""
{BR}{C}  ● RECONNAISSANCE & NETWORK{RS}
    {G}[01]{RS} {T("sm1"):<22} {G}[06]{RS} {T("sm6")}
    {G}[02]{RS} {T("sm2"):<22} {G}[07]{RS} {T("sm7")}
    {G}[03]{RS} {T("sm3"):<22} {G}[08]{RS} {T("sm8")}
    {G}[04]{RS} {T("sm4"):<22} {G}[09]{RS} {T("sm9")}
    {G}[05]{RS} {T("sm5"):<22}

{BR}{C}  ● WEB & EXPLOITATION{RS}
    {Y}[10]{RS} {T("sm10"):<22} {Y}[14]{RS} {T("sm14")}
    {Y}[11]{RS} {T("sm11"):<22} {Y}[15]{RS} {T("sm15")}
    {Y}[12]{RS} {T("sm12"):<22} {Y}[16]{RS} {T("sm16")}
    {Y}[13]{RS} {T("sm13"):<22}

{BR}{C}  ● AUTOMATION & AI{RS}
    {M}[17]{RS} {T("sm17"):<22} {M}[20]{RS} {T("sm20")}
    {M}[18]{RS} {T("sm18"):<22} {M}[21]{RS} {T("sm21")}
    {M}[19]{RS} {T("sm19"):<22} {M}[22]{RS} {T("sm22")}
                              {M}[23]{RS} {T("sm23")}

{BR}{C}  ● STEALTH & ADVANCED OPSEC{RS}
    {B}[24]{RS} {T("sm24"):<22} {B}[26]{RS} CF WAF Bypass (solve)
    {B}[25]{RS} {T("sm25"):<22} {B}[27]{RS} CF Bypass + Inject Session

{BR}{C}  ● ADVANCED BROWSER ENGINE{RS}
    {C}[28]{RS} JS-Rendered Page       {C}[32]{RS} Browser Fingerprint
    {C}[29]{RS} Network Traffic        {C}[33]{RS} Cookie Harvester
    {C}[30]{RS} Form Login Tester      {C}[34]{RS} JS Secret Scanner
    {C}[31]{RS} Screenshot Recon

{BR}{C}  ● v2.2 — ACTIVE EXPLOITATION{RS}
    {R}[35]{RS} Active Vuln Scan (XSS/SQLi/SSRF)
    {R}[36]{RS} Live CVE Map (NVD API)    {R}[38]{RS} UDP Scanner (SNMP/TFTP/NTP)
    {R}[37]{RS} NVD Manual CVE Lookup     {R}[39]{RS} Deep SSL/TLS Audit
    {R}[40]{RS} OSINT Passive Recon       {R}[41]{RS} Service Brute (MySQL/Redis/RDP)

{BR}{C}  ● v3.0 — CRAWLER & AUTH{RS}
    {M}[42]{RS} Web Crawler (Discovery)   {M}[43]{RS} Auth / Session Config
    {M}[44]{RS} Path/API Enumerator

  {DM}───────────────────────────────────────────────────────{RS}
    {R}[00]{RS} {T("menu_exit")}
"""


def show_banner():
    print(_build_banner())

def show_menu():
    print(_build_menu())

# ── Prompts ───────────────────────────────────────────────────────────────────
def prompt_target(label: str = None) -> str:
    if label is None:
        label = T("prompt_target")
    print()
    target = input(f"  {BR}{C}[?]{RS} {BR}{W}{label}: {RS}").strip()
    if not target:
        warn(T("no_target"))
        return None
    return target

def prompt_choice(label: str = None) -> str:
    if label is None:
        label = T("prompt_select")
    print()
    return input(f"  {BR}{M}[>]{RS} {BR}{W}{label}: {RS}").strip()

def prompt_yes(question: str) -> bool:
    ans = input(f"  {BR}{Y}[?]{RS} {question} {DM}(y/N){RS} ").strip().lower()
    return ans == 'y'

# ── Spinner / Progress ────────────────────────────────────────────────────────
def spinner(message: str, secs: float = 0.0):
    chars = ['-', '\\', '|', '/']
    end_time = time.time() + secs
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r  {BR}{C}{chars[i % len(chars)]}{RS}  {message}  ")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write('\r' + ' ' * 60 + '\r')

def progress_bar(current: int, total: int, label: str = ''):
    if total <= 0:
        current = 0
        pct = 0
    else:
        current = max(0, min(current, total))
        pct = int((current / total) * 25)
    bar = f"{G}{'#' * pct}{DM}{'.' * (25 - pct)}{RS}"
    sys.stdout.write(f"\r  {C}[{bar}{C}]{RS} {current}/{total} {DM}{label}{RS}  ")
    sys.stdout.flush()

# ── Table renderer ────────────────────────────────────────────────────────────
def print_table(headers: list, rows: list):
    if not rows:
        warn(T("no_results"))
        return
    column_count = max(len(headers), *(len(row) for row in rows))
    normalized_headers = [str(h) for h in headers] + [''] * (column_count - len(headers))
    normalized_rows = [list(row) + [''] * (column_count - len(row)) for row in rows]
    col_w = [len(h) for h in normalized_headers]
    for row in normalized_rows:
        for i, cell in enumerate(row):
            col_w[i] = max(col_w[i], len(str(cell)))
    sep  = f"  {C}+" + "+".join(["─" * (w + 2) for w in col_w]) + f"+{RS}"
    hdr  = f"  {C}|" + "|".join(f" {BR}{W}{h:<{col_w[i]}}{RS}{C}" for i, h in enumerate(normalized_headers)) + f"|{RS}"
    print(sep); print(hdr); print(sep)
    for row in normalized_rows:
        cells = []
        for i, cell in enumerate(row):
            s = str(cell)
            colour = G if 'OPEN' in s or '+' in s else (R if 'VULN' in s or 'x' in s else W)
            cells.append(f" {colour}{s:<{col_w[i]}}{RS}")
        print(f"  {C}|" + "|".join(cells) + f"{C}|{RS}")
    print(sep)

def pause():
    input(f"\n  {DM}{T('press_enter')}{RS}")
